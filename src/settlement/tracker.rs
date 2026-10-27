//! Settlement state machine for a queued envelope, from the moment it's
//! signed offline to final on-chain confirmation (or failure).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::errors::SyncEngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementStatus {
    /// Signed and durably stored on-device; not yet handed to the mesh.
    Queued,
    /// Handed to the gossip layer; propagating toward a relay node.
    Propagating,
    /// A relay node submitted it to Stellar and it was confirmed.
    Settled,
    /// Propagation or submission failed (TTL expired, relay rejected it, etc).
    Failed,
    /// A conflicting envelope was detected for the same account/sequence and
    /// the conflict could not be resolved off-chain — see `crate::conflict`.
    /// Awaiting on-chain arbitration via the `dispute-resolver` contract.
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SettlementStatus::Queued => "queued",
            SettlementStatus::Propagating => "propagating",
            SettlementStatus::Settled => "settled",
            SettlementStatus::Failed => "failed",
            SettlementStatus::Disputed => "disputed",
        }
    }

    /// Whether transitioning from `self` to `next` is a legal state change.
    pub fn can_transition_to(&self, next: SettlementStatus) -> bool {
        use SettlementStatus::*;
        matches!(
            (self, next),
            (Queued, Propagating)
                | (Queued, Failed)
                | (Propagating, Settled)
                | (Propagating, Failed)
                | (Propagating, Disputed)
                | (Disputed, Settled)
                | (Disputed, Failed)
                | (Failed, Propagating)
        )
    }
}

impl FromStr for SettlementStatus {
    type Err = SyncEngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(SettlementStatus::Queued),
            "propagating" => Ok(SettlementStatus::Propagating),
            "settled" => Ok(SettlementStatus::Settled),
            "failed" => Ok(SettlementStatus::Failed),
            "disputed" => Ok(SettlementStatus::Disputed),
            other => Err(SyncEngineError::InvalidStateTransition {
                from: other.to_string(),
                to: "<unknown>".to_string(),
            }),
        }
    }
}

/// In-memory tracker enforcing legal [`SettlementStatus`] transitions per
/// envelope. Durable persistence of status is handled separately by
/// `crate::storage::db::SyncEngineDb` — callers that need both should update
/// the tracker and the DB together.
///
/// # Stuck-propagation funds-safety gate (issue #18)
///
/// When an envelope stays in [`SettlementStatus::Propagating`] past the
/// configured timeout and is swept to [`SettlementStatus::Failed`], the mesh
/// may have delivered the transaction to a relay that submitted it on-chain
/// while the confirmation was dropped on the return path. Blindly retrying
/// `Failed -> Propagating` could re-broadcast or re-create a payment before
/// the device has verified whether the original sequence number already
/// settled on-chain.
///
/// Envelopes moved to `Failed` by [`Self::mark_stuck_failed`] are placed in an
/// explicit reconciliation hold (`needs_reconciliation`). While that hold is
/// active, [`Self::transition`] rejects `Failed -> Propagating` until the
/// caller invokes [`Self::confirm_non_settlement_and_repropagate`] with a
/// verified on-chain sequence strictly lower than the envelope's sequence.
#[derive(Debug, Default)]
pub struct SettlementTracker {
    statuses: HashMap<[u8; 32], SettlementStatus>,
    needs_reconciliation: HashSet<[u8; 32]>,
}

impl SettlementTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly-queued envelope. Fresh entries always start `Queued`.
    pub fn track(&mut self, message_id: [u8; 32]) {
        self.statuses.insert(message_id, SettlementStatus::Queued);
        self.needs_reconciliation.remove(&message_id);
    }

    /// Restore an envelope directly to `status`, bypassing transition
    /// validation. Used when rehydrating the tracker from durable storage on
    /// restart — the persisted status is ground truth and must be taken as-is
    /// rather than re-derived through a (possibly impossible) chain of legal
    /// transitions.
    pub fn restore(&mut self, message_id: [u8; 32], status: SettlementStatus) {
        self.statuses.insert(message_id, status);
        if status != SettlementStatus::Failed {
            self.needs_reconciliation.remove(&message_id);
        }
    }

    /// Restore an envelope along with its reconciliation-hold flag.
    pub fn restore_with_reconciliation(
        &mut self,
        message_id: [u8; 32],
        status: SettlementStatus,
        needs_reconciliation: bool,
    ) {
        self.statuses.insert(message_id, status);
        if status == SettlementStatus::Failed && needs_reconciliation {
            self.needs_reconciliation.insert(message_id);
        } else {
            self.needs_reconciliation.remove(&message_id);
        }
    }

    pub fn status(&self, message_id: &[u8; 32]) -> Option<SettlementStatus> {
        self.statuses.get(message_id).copied()
    }

    /// Whether `message_id` was swept out of `Propagating` due to a timeout
    /// and still awaits on-chain non-settlement confirmation before it may be
    /// re-propagated.
    pub fn requires_reconciliation(&self, message_id: &[u8; 32]) -> bool {
        self.needs_reconciliation.contains(message_id)
    }

    /// Mark an envelope that was stuck in `Propagating` as `Failed` with a
    /// mandatory reconciliation hold blocking automatic `Failed -> Propagating`
    /// retries until [`Self::confirm_non_settlement_and_repropagate`] succeeds.
    pub fn mark_stuck_failed(&mut self, message_id: [u8; 32]) -> Result<(), SyncEngineError> {
        let current = self
            .statuses
            .get(&message_id)
            .copied()
            .ok_or_else(|| SyncEngineError::EnvelopeNotFound(hex::encode(message_id)))?;

        if current != SettlementStatus::Propagating {
            return Err(SyncEngineError::InvalidStateTransition {
                from: current.as_str().to_string(),
                to: SettlementStatus::Failed.as_str().to_string(),
            });
        }

        self.statuses.insert(message_id, SettlementStatus::Failed);
        self.needs_reconciliation.insert(message_id);
        Ok(())
    }

    /// Release the stuck-propagation reconciliation hold and transition the
    /// envelope from `Failed` back to `Propagating` only if the account's
    /// confirmed on-chain sequence number is strictly less than the envelope's
    /// sequence number (`confirmed_on_chain_sequence < envelope_sequence`),
    /// proving that the envelope has not yet settled on-chain.
    pub fn confirm_non_settlement_and_repropagate(
        &mut self,
        message_id: [u8; 32],
        envelope_sequence: i64,
        confirmed_on_chain_sequence: i64,
    ) -> Result<(), SyncEngineError> {
        let current = self
            .statuses
            .get(&message_id)
            .copied()
            .ok_or_else(|| SyncEngineError::EnvelopeNotFound(hex::encode(message_id)))?;

        if current != SettlementStatus::Failed {
            return Err(SyncEngineError::InvalidStateTransition {
                from: current.as_str().to_string(),
                to: SettlementStatus::Propagating.as_str().to_string(),
            });
        }

        if confirmed_on_chain_sequence >= envelope_sequence {
            return Err(SyncEngineError::InvalidStateTransition {
                from: format!(
                    "failed (on-chain sequence {} >= envelope sequence {}; non-settlement not confirmed)",
                    confirmed_on_chain_sequence, envelope_sequence
                ),
                to: SettlementStatus::Propagating.as_str().to_string(),
            });
        }

        self.needs_reconciliation.remove(&message_id);
        self.statuses
            .insert(message_id, SettlementStatus::Propagating);
        Ok(())
    }

    /// Attempt to move `message_id` to `next`. Fails if no such envelope is
    /// tracked, if the transition is not legal from its current status, or if
    /// the envelope was swept from `Propagating` as stuck and has not yet
    /// confirmed non-settlement on-chain.
    pub fn transition(
        &mut self,
        message_id: [u8; 32],
        next: SettlementStatus,
    ) -> Result<(), SyncEngineError> {
        let current = self
            .statuses
            .get(&message_id)
            .copied()
            .ok_or_else(|| SyncEngineError::EnvelopeNotFound(hex::encode(message_id)))?;

        if !current.can_transition_to(next) {
            return Err(SyncEngineError::InvalidStateTransition {
                from: current.as_str().to_string(),
                to: next.as_str().to_string(),
            });
        }

        if current == SettlementStatus::Failed
            && next == SettlementStatus::Propagating
            && self.needs_reconciliation.contains(&message_id)
        {
            return Err(SyncEngineError::InvalidStateTransition {
                from: "failed (awaiting on-chain non-settlement confirmation)".to_string(),
                to: next.as_str().to_string(),
            });
        }

        self.statuses.insert(message_id, next);
        if next != SettlementStatus::Failed {
            self.needs_reconciliation.remove(&message_id);
        }
        Ok(())
    }

    /// Get all tracked entries as a vector of (message_id, status) pairs.
    /// Used by the invariant checker to iterate over all tracked states.
    pub fn get_all_entries(&self) -> Vec<([u8; 32], SettlementStatus)> {
        self.statuses
            .iter()
            .map(|(id, status)| (*id, *status))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_path_queued_to_settled() {
        let mut tracker = SettlementTracker::new();
        let id = [1u8; 32];
        tracker.track(id);
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Queued));

        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.transition(id, SettlementStatus::Settled).unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Settled));
    }

    #[test]
    fn test_disputed_can_recover_to_settled() {
        let mut tracker = SettlementTracker::new();
        let id = [2u8; 32];
        tracker.track(id);
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.transition(id, SettlementStatus::Disputed).unwrap();
        tracker.transition(id, SettlementStatus::Settled).unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Settled));
    }

    #[test]
    fn test_failed_can_retry_to_propagating() {
        let mut tracker = SettlementTracker::new();
        let id = [3u8; 32];
        tracker.track(id);
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.transition(id, SettlementStatus::Failed).unwrap();
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Propagating));
    }

    #[test]
    fn test_illegal_transition_rejected() {
        let mut tracker = SettlementTracker::new();
        let id = [4u8; 32];
        tracker.track(id);
        // Cannot jump straight from Queued to Settled.
        let result = tracker.transition(id, SettlementStatus::Settled);
        assert!(matches!(
            result,
            Err(SyncEngineError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn test_transition_on_untracked_envelope_errors() {
        let mut tracker = SettlementTracker::new();
        let result = tracker.transition([9u8; 32], SettlementStatus::Propagating);
        assert!(matches!(result, Err(SyncEngineError::EnvelopeNotFound(_))));
    }

    #[test]
    fn test_settlement_transition_matrix_is_exhaustive() {
        use SettlementStatus::*;

        // Hand-written ground truth reachability graph, kept independent of
        // `can_transition_to`'s own match arms so this test can actually
        // catch a divergence between the two instead of restating the same
        // logic. Any (from, to) pair not listed here is expected to be illegal.
        let allowed: &[(SettlementStatus, SettlementStatus)] = &[
            (Queued, Propagating),
            (Queued, Failed),
            (Propagating, Settled),
            (Propagating, Failed),
            (Propagating, Disputed),
            (Disputed, Settled),
            (Disputed, Failed),
            (Failed, Propagating),
        ];

        let all_states = [Queued, Propagating, Settled, Failed, Disputed];

        let mut checked = 0;
        for &from in &all_states {
            for &to in &all_states {
                let expected = allowed.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "mismatch for transition {:?} -> {:?}: expected {}",
                    from,
                    to,
                    expected
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked, 25,
            "expected all 25 (from, to) pairs across 5 states"
        );
    }

    #[test]
    fn test_status_roundtrip_via_str() {
        for status in [
            SettlementStatus::Queued,
            SettlementStatus::Propagating,
            SettlementStatus::Settled,
            SettlementStatus::Failed,
            SettlementStatus::Disputed,
        ] {
            let parsed: SettlementStatus = status.as_str().parse().unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_stuck_failed_requires_non_settlement_confirmation_before_retry() {
        let mut tracker = SettlementTracker::new();
        let id = [8u8; 32];
        tracker.track(id);
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.mark_stuck_failed(id).unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Failed));
        assert!(tracker.requires_reconciliation(&id));

        // Direct retry is blocked while awaiting reconciliation.
        assert!(matches!(
            tracker.transition(id, SettlementStatus::Propagating),
            Err(SyncEngineError::InvalidStateTransition { .. })
        ));

        // On-chain sequence >= envelope sequence is also blocked.
        assert!(matches!(
            tracker.confirm_non_settlement_and_repropagate(id, 100, 100),
            Err(SyncEngineError::InvalidStateTransition { .. })
        ));
        assert!(tracker.requires_reconciliation(&id));

        // Confirmed non-settlement (on-chain sequence < envelope sequence) releases hold.
        tracker
            .confirm_non_settlement_and_repropagate(id, 100, 99)
            .unwrap();
        assert!(!tracker.requires_reconciliation(&id));
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Propagating));
    }
}
