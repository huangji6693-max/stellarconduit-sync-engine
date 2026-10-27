//! Durable, on-device storage for queued envelopes, sequence reservations,
//! settlement status, and detected conflicts — so none of it is lost if the
//! device restarts before settlement completes. Mirrors the SQLite-via-
//! `tokio-rusqlite` pattern used in `stellarconduit_core::persistence::db`.
//!
//! # Encryption at Rest
//!
//! This module supports optional encryption of sensitive columns (e.g.,
//! `envelope_bytes`, `tx_id`, `proof_bytes`) using AES-256-GCM. The embedding
//! application must supply the encryption key at initialization time — this
//! crate does NOT generate, store, or manage keys.
//!
//! ## Threat Model
//!
//! Encryption protects against:
//! - Casual file exfiltration of the database file
//! - Physical device compromise (lost/stolen phone)
//! - Forensic analysis of the database file
//!
//! Limitations:
//! - Database metadata (table names, row counts) remain visible
//! - Query patterns are visible (but not query results)
//!
//! ## Design Choice: Column-Level Encryption
//!
//! We chose column-level encryption over full database encryption (e.g.,
//! SQLCipher) for the following reasons:
//!
//! **Advantages:**
//! - Better portability (no external SQLCipher dependency)
//! - Works with bundled SQLite on all platforms
//! - Finer-grained control over what gets encrypted
//! - Smaller attack surface
//!
//! **Tradeoffs:**
//! - Metadata (table structure, row counts) remains visible
//! - Requires application-level encrypt/decrypt logic
//! - Slightly more complex code
//!
//! For a detailed threat model analysis, see `src/encryption.rs`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio_rusqlite::Connection;

use stellarconduit_core::message::relay_proof::RelayChainProof;
use stellarconduit_core::message::types::TransactionEnvelope;

use crate::conflict::{Conflict, DisputeEscalation};
use crate::encryption::{EncryptedData, EncryptionKey};
use crate::errors::SyncEngineError;
use crate::queue::TxPriority;
use crate::settlement::SettlementStatus;

/// Version tag embedded in every [`SyncEngineDb::export_snapshot`] output and
/// checked by [`SyncEngineDb::import_snapshot`].
///
/// Issue #11 ("Implement Schema Versioning and Migrations for SyncEngineDb")
/// had not landed when this was written, so this is a minimal, standalone
/// version tag scoped to the snapshot format rather than a general schema
/// migration scheme. If/when #11 lands, this constant should be replaced
/// with (or defined in terms of) its schema version rather than kept as a
/// second, competing version number.
pub const DB_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Metadata table name for tracking encryption status
const ENCRYPTION_METADATA_TABLE: &str = "encryption_metadata";

/// Metadata key for encryption flag
const ENCRYPTION_ENABLED_KEY: &str = "encryption_enabled";

pub struct SyncEngineDb {
    conn: Connection,
    /// Optional encryption key for sensitive columns.
    /// If None, database operates in plaintext mode.
    encryption_key: Option<Arc<EncryptionKey>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueuedEnvelopeRecord {
    pub envelope: TransactionEnvelope,
    pub source_account: String,
    pub sequence: i64,
    pub priority: TxPriority,
    pub enqueued_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    pub message_id: [u8; 32],
    pub from_status: String,
    pub to_status: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BatchUpdateReport {
    pub applied: Vec<[u8; 32]>,
    pub rejected: Vec<([u8; 32], String)>,
}

/// A single recorded double-spend conflict, as durably stored — unlike
/// [`Conflict`] (which only carries the (account, sequence, envelope) slot
/// identity), this also carries the row `id`, `detected_at` timestamp, and
/// `resolved` flag that [`SyncEngineDb::list_all_conflicts`] needs to
/// distinguish and display individual rows.
#[derive(Debug, Clone, PartialEq)]
pub struct ConflictRecord {
    pub id: i64,
    pub source_account: String,
    pub sequence: i64,
    pub envelope_a: [u8; 32],
    pub envelope_b: [u8; 32],
    pub detected_at: u64,
    pub resolved: bool,
}

/// Row counts and queue age extremes across `SyncEngineDb`'s tables. Built
/// for `sync-engine-cli db summary` (see `src/cli.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DbSummary {
    pub queued_envelopes_count: i64,
    pub settlement_status_count: i64,
    pub sequence_reservations_count: i64,
    pub conflicts_count: i64,
    pub unresolved_conflicts_count: i64,
    pub oldest_queued_at: Option<u64>,
    pub newest_queued_at: Option<u64>,
}

/// A [`DisputeEscalation`] as durably stored, along with the row id used by
/// [`SyncEngineDb::mark_escalation_submitted`] and the originating
/// [`Conflict`]'s account/sequence/envelope bookkeeping.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedEscalation {
    pub id: i64,
    pub source_account: String,
    pub sequence: i64,
    pub envelope_a: [u8; 32],
    pub envelope_b: [u8; 32],
    pub escalation: DisputeEscalation,
    pub created_at: u64,
}

/// Outcome of [`SyncEngineDb::import_snapshot`]: how many rows were restored
/// into each table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportReport {
    pub queued_envelopes_imported: usize,
    pub settlement_status_imported: usize,
    pub sequence_reservations_imported: usize,
    pub conflicts_imported: usize,
    pub settlement_history_imported: usize,
    pub dispute_escalations_imported: usize,
}

// ── Snapshot row types ──────────────────────────────────────────────────
//
// These mirror each table's columns directly (rather than the domain types
// like `Conflict`/`DisputeEscalation` used elsewhere in this file) so that
// `export_snapshot`/`import_snapshot` round-trip the exact bytes SQLite
// holds — including opaque columns like `envelope_bytes` and `proof_bytes`
// — without a re-encode step that could silently normalize or lose data.

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct QueuedEnvelopeRow {
    message_id: Vec<u8>,
    source_account: String,
    sequence: i64,
    priority: i64,
    enqueued_at: i64,
    envelope_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SettlementStatusRow {
    message_id: Vec<u8>,
    status: String,
    updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SequenceReservationRow {
    source_account: String,
    last_reserved: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ConflictRow {
    id: i64,
    source_account: String,
    sequence: i64,
    envelope_a: Vec<u8>,
    envelope_b: Vec<u8>,
    detected_at: i64,
    resolved: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SettlementHistoryRow {
    id: i64,
    message_id: Vec<u8>,
    from_status: String,
    to_status: String,
    timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DisputeEscalationRow {
    id: i64,
    source_account: String,
    sequence: i64,
    envelope_a: Vec<u8>,
    envelope_b: Vec<u8>,
    initiator: String,
    respondent: String,
    tx_id: Vec<u8>,
    proof_bytes: Vec<u8>,
    created_at: i64,
    submitted: i64,
}

/// The full portable contents of a [`SyncEngineDb`], as produced by
/// [`SyncEngineDb::export_snapshot`] and consumed by
/// [`SyncEngineDb::import_snapshot`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DbSnapshot {
    schema_version: u32,
    queued_envelopes: Vec<QueuedEnvelopeRow>,
    settlement_status: Vec<SettlementStatusRow>,
    sequence_reservations: Vec<SequenceReservationRow>,
    conflicts: Vec<ConflictRow>,
    settlement_history: Vec<SettlementHistoryRow>,
    dispute_escalations: Vec<DisputeEscalationRow>,
}

impl SyncEngineDb {
    /// Initialize the embedded SQLite database, creating tables if needed.
    /// Pass `":memory:"` for an ephemeral, test-only database.
    ///
    /// This creates an **unencrypted** database. For encryption support,
    /// use [`Self::init_with_encryption`].
    pub async fn init(db_path: &str) -> Result<Self, SyncEngineError> {
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory().await?
        } else {
            Connection::open(Path::new(db_path)).await?
        };

        conn.call(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS queued_envelopes (
                    message_id      BLOB PRIMARY KEY,
                    source_account  TEXT NOT NULL,
                    sequence        INTEGER NOT NULL,
                    priority        INTEGER NOT NULL,
                    enqueued_at     INTEGER NOT NULL,
                    envelope_bytes  BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settlement_status (
                    message_id  BLOB PRIMARY KEY,
                    status      TEXT NOT NULL,
                    updated_at  INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sequence_reservations (
                    source_account  TEXT PRIMARY KEY,
                    last_reserved   INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS conflicts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_account  TEXT NOT NULL,
                    sequence        INTEGER NOT NULL,
                    envelope_a      BLOB NOT NULL,
                    envelope_b      BLOB NOT NULL,
                    detected_at     INTEGER NOT NULL,
                    resolved        INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settlement_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id  BLOB NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status   TEXT NOT NULL,
                    timestamp   INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS dispute_escalations (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_account  TEXT NOT NULL,
                    sequence        INTEGER NOT NULL,
                    envelope_a      BLOB NOT NULL,
                    envelope_b      BLOB NOT NULL,
                    initiator       TEXT NOT NULL,
                    respondent      TEXT NOT NULL,
                    tx_id           BLOB NOT NULL,
                    proof_bytes     BLOB NOT NULL,
                    created_at      INTEGER NOT NULL,
                    submitted       INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS encryption_metadata (
                    key     TEXT PRIMARY KEY,
                    value   TEXT NOT NULL
                );",
            )?;
            Ok(())
        })
        .await?;

        Ok(Self {
            conn,
            encryption_key: None,
        })
    }

    /// Initialize the database with encryption enabled.
    ///
    /// # Arguments
    /// * `db_path` - Path to the database file (or `":memory:"` for tests)
    /// * `encryption_key` - Encryption key supplied by the embedding application
    ///
    /// # Returns
    /// A database instance with encryption enabled for sensitive columns.
    ///
    /// # Errors
    /// Returns `EncryptionKeyMismatch` if:
    /// - Opening an existing encrypted database with the wrong key
    /// - Opening an encrypted database without providing a key
    /// - Opening an unencrypted database with a key (mismatch)
    ///
    /// # Security
    /// The encryption key must be supplied by the embedding wallet's platform
    /// keystore integration. This crate does NOT generate, store, or manage keys.
    pub async fn init_with_encryption(
        db_path: &str,
        encryption_key: EncryptionKey,
    ) -> Result<Self, SyncEngineError> {
        let mut db = Self::init(db_path).await?;

        // Check if this database was previously encrypted
        let was_encrypted = db.check_encryption_flag().await?;

        // For new databases, set the encryption flag
        if !was_encrypted {
            db.set_encryption_flag().await?;
        }

        db.encryption_key = Some(Arc::new(encryption_key));

        // Verify the key works by attempting a test encrypt/decrypt
        if was_encrypted {
            db.verify_encryption_key().await?;
        }

        Ok(db)
    }

    /// Check if the database has encryption enabled.
    async fn check_encryption_flag(&self) -> Result<bool, SyncEngineError> {
        let result: Option<String> = self
            .conn
            .call(|conn| {
                let result = conn.query_row(
                    &format!(
                        "SELECT value FROM {} WHERE key = ?1",
                        ENCRYPTION_METADATA_TABLE
                    ),
                    rusqlite::params![ENCRYPTION_ENABLED_KEY],
                    |row| row.get(0),
                );
                match result {
                    Ok(value) => Ok(Some(value)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await?;

        Ok(result.map(|v| v == "true").unwrap_or(false))
    }

    /// Set the encryption flag in metadata.
    async fn set_encryption_flag(&self) -> Result<(), SyncEngineError> {
        self.conn
            .call(|conn| {
                conn.execute(
                    &format!(
                        "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
                        ENCRYPTION_METADATA_TABLE
                    ),
                    rusqlite::params![ENCRYPTION_ENABLED_KEY, "true"],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Verify the encryption key by attempting to decrypt existing data.
    ///
    /// This is called when opening an existing encrypted database to ensure
    /// the provided key matches the one used to create it.
    async fn verify_encryption_key(&self) -> Result<(), SyncEngineError> {
        // Try to read and decrypt an existing envelope to verify the key
        let has_envelopes: bool = self
            .conn
            .call(|conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM queued_envelopes", [], |row| {
                        row.get(0)
                    })?;
                Ok(count > 0)
            })
            .await?;

        if !has_envelopes {
            // Empty database, key is valid
            return Ok(());
        }

        // Try to decrypt the first envelope to verify the key
        let test_decrypt = self
            .conn
            .call(|conn| {
                let envelope_bytes: Option<Vec<u8>> = conn.query_row(
                    "SELECT envelope_bytes FROM queued_envelopes LIMIT 1",
                    [],
                    |row| row.get(0),
                )?;
                Ok(envelope_bytes)
            })
            .await?;

        if let Some(encrypted_bytes) = test_decrypt {
            // Try to decrypt with the provided key
            let encrypted = EncryptedData::from_bytes(encrypted_bytes);
            let key = self
                .encryption_key
                .as_ref()
                .ok_or_else(|| SyncEngineError::EncryptionKeyMismatch)?;

            match encrypted.decrypt(key) {
                Ok(_) => Ok(()), // Key is valid
                Err(SyncEngineError::DecryptionFailed) => {
                    Err(SyncEngineError::EncryptionKeyMismatch)
                }
                Err(e) => Err(e),
            }?;
        }

        Ok(())
    }

    /// Encrypt sensitive data if encryption is enabled.
    fn encrypt_if_enabled(&self, plaintext: &[u8]) -> Result<Vec<u8>, SyncEngineError> {
        if let Some(ref key) = self.encryption_key {
            let encrypted = EncryptedData::encrypt(plaintext, key)?;
            Ok(encrypted.as_bytes().to_vec())
        } else {
            Ok(plaintext.to_vec())
        }
    }

    /// Decrypt sensitive data if encryption is enabled.
    fn decrypt_if_needed(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, SyncEngineError> {
        if let Some(ref key) = self.encryption_key {
            let encrypted = EncryptedData::from_bytes(ciphertext);
            encrypted.decrypt(key)
        } else {
            Ok(ciphertext)
        }
    }

    /// Execute a multi-statement closure atomically inside a single SQLite
    /// transaction on the `tokio-rusqlite` connection actor (issue #14).
    ///
    /// If `f` returns `Ok(val)`, the transaction is committed before returning
    /// `Ok(val)`. If `f` returns `Err(e)` (or panics), the `rusqlite::Transaction`
    /// is dropped without committing, rolling back every statement executed
    /// inside `f` so no partial effects remain visible.
    pub async fn transaction<F, T>(&self, f: F) -> Result<T, SyncEngineError>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T, SyncEngineError> + Send + 'static,
        T: Send + 'static,
    {
        let outcome = self
            .conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                match f(&tx) {
                    Ok(value) => {
                        tx.commit()?;
                        Ok(Ok(value))
                    }
                    Err(err) => {
                        drop(tx);
                        Ok(Err(err))
                    }
                }
            })
            .await?;
        outcome
    }

    /// Synchronous helper for recording a sequence reservation inside an
    /// active [`Self::transaction`].
    pub fn save_sequence_reservation_in_tx(
        tx: &rusqlite::Transaction<'_>,
        source_account: &str,
        last_reserved: i64,
    ) -> Result<(), SyncEngineError> {
        tx.execute(
            "INSERT OR REPLACE INTO sequence_reservations (source_account, last_reserved)
             VALUES (?1, ?2)",
            rusqlite::params![source_account, last_reserved],
        )?;
        Ok(())
    }

    /// Synchronous helper for updating an envelope's settlement status and
    /// appending its `settlement_history` audit entry inside an active
    /// [`Self::transaction`].
    pub fn set_settlement_status_in_tx(
        tx: &rusqlite::Transaction<'_>,
        message_id: [u8; 32],
        status: SettlementStatus,
        updated_at: u64,
    ) -> Result<(), SyncEngineError> {
        let id = message_id.to_vec();
        let status_str = status.as_str();
        let from_status: String = tx
            .query_row(
                "SELECT status FROM settlement_status WHERE message_id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .unwrap_or_default();

        tx.execute(
            "INSERT OR REPLACE INTO settlement_status (message_id, status, updated_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![id, status_str, updated_at as i64],
        )?;

        tx.execute(
            "INSERT INTO settlement_history (message_id, from_status, to_status, timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, from_status, status_str, updated_at as i64],
        )?;

        Ok(())
    }

    /// Synchronous helper for recording a conflict inside an active
    /// [`Self::transaction`].
    pub fn record_conflict_in_tx(
        tx: &rusqlite::Transaction<'_>,
        conflict: &Conflict,
        detected_at: u64,
    ) -> Result<(), SyncEngineError> {
        tx.execute(
            "INSERT INTO conflicts (source_account, sequence, envelope_a, envelope_b, detected_at, resolved)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![
                conflict.source_account,
                conflict.sequence,
                conflict.envelope_a.to_vec(),
                conflict.envelope_b.to_vec(),
                detected_at as i64
            ],
        )?;
        Ok(())
    }

    pub async fn enqueue_envelope(
        &self,
        envelope: &TransactionEnvelope,
        source_account: &str,
        sequence: i64,
        priority: TxPriority,
        enqueued_at: u64,
    ) -> Result<(), SyncEngineError> {
        let message_id = envelope.message_id.to_vec();
        let envelope_bytes = rmp_serde::to_vec(envelope)?;

        // Encrypt envelope_bytes if encryption is enabled
        let envelope_bytes = if let Some(ref key) = self.encryption_key {
            let encrypted = EncryptedData::encrypt(&envelope_bytes, key)?;
            encrypted.as_bytes().to_vec()
        } else {
            envelope_bytes
        };

        let source_account = source_account.to_string();
        let priority: i64 = priority.into();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO queued_envelopes
                        (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        message_id,
                        source_account,
                        sequence,
                        priority,
                        enqueued_at as i64,
                        envelope_bytes
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Atomically persist a newly-signed payment in a single SQLite
    /// transaction: its sequence reservation, the queued envelope, and its
    /// initial `Queued` settlement status.
    ///
    /// All three rows share one transaction so that a crash at any instant
    /// leaves the database either fully updated (the call completed) or
    /// entirely unchanged (as if the call never happened) — never a
    /// half-written state. This is what lets [`crate::engine::SyncEngine`] be
    /// restart-safe: a Stellar sequence number cannot be skipped on-chain, so
    /// writing the reservation without the envelope (or the envelope without
    /// the reservation) would either burn a gap or invite a reuse, both of
    /// which are double-spend hazards against the user's own account.
    pub async fn enqueue_transaction(
        &self,
        envelope: &TransactionEnvelope,
        source_account: &str,
        sequence: i64,
        priority: TxPriority,
        enqueued_at: u64,
    ) -> Result<(), SyncEngineError> {
        let message_id = envelope.message_id.to_vec();
        let envelope_bytes = rmp_serde::to_vec(envelope)?;

        // Encrypt envelope_bytes if encryption is enabled
        let envelope_bytes = self.encrypt_if_enabled(&envelope_bytes)?;

        let source_account = source_account.to_string();
        let priority: i64 = priority.into();
        let status = SettlementStatus::Queued.as_str().to_string();

        self.transaction(move |tx| {
            Self::save_sequence_reservation_in_tx(tx, &source_account, sequence)?;
            tx.execute(
                "INSERT OR REPLACE INTO queued_envelopes
                    (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    message_id,
                    source_account,
                    sequence,
                    priority,
                    enqueued_at as i64,
                    envelope_bytes
                ],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO settlement_status (message_id, status, updated_at)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![message_id, status, enqueued_at as i64],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn get_queued_envelope(
        &self,
        message_id: [u8; 32],
    ) -> Result<Option<QueuedEnvelopeRecord>, SyncEngineError> {
        let id = message_id.to_vec();
        let row = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT source_account, sequence, priority, enqueued_at, envelope_bytes
                     FROM queued_envelopes WHERE message_id = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![id])?;
                if let Some(row) = rows.next()? {
                    let source_account: String = row.get(0)?;
                    let sequence: i64 = row.get(1)?;
                    let priority: i64 = row.get(2)?;
                    let enqueued_at: i64 = row.get(3)?;
                    let envelope_bytes: Vec<u8> = row.get(4)?;
                    Ok(Some((
                        source_account,
                        sequence,
                        priority,
                        enqueued_at,
                        envelope_bytes,
                    )))
                } else {
                    Ok(None)
                }
            })
            .await?;

        match row {
            None => Ok(None),
            Some((source_account, sequence, priority, enqueued_at, envelope_bytes)) => {
                // Decrypt envelope_bytes if encryption is enabled
                let envelope_bytes = self.decrypt_if_needed(envelope_bytes)?;
                let envelope: TransactionEnvelope = rmp_serde::from_slice(&envelope_bytes)?;
                Ok(Some(QueuedEnvelopeRecord {
                    envelope,
                    source_account,
                    sequence,
                    priority: TxPriority::try_from(priority)?,
                    enqueued_at: enqueued_at as u64,
                }))
            }
        }
    }

    pub async fn list_queued_envelopes(
        &self,
    ) -> Result<Vec<QueuedEnvelopeRecord>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT source_account, sequence, priority, enqueued_at, envelope_bytes
                     FROM queued_envelopes",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        let source_account: String = row.get(0)?;
                        let sequence: i64 = row.get(1)?;
                        let priority: i64 = row.get(2)?;
                        let enqueued_at: i64 = row.get(3)?;
                        let envelope_bytes: Vec<u8> = row.get(4)?;
                        Ok((
                            source_account,
                            sequence,
                            priority,
                            enqueued_at,
                            envelope_bytes,
                        ))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        rows.into_iter()
            .map(
                |(source_account, sequence, priority, enqueued_at, envelope_bytes)| {
                    // Decrypt envelope_bytes if encryption is enabled
                    let envelope_bytes = self.decrypt_if_needed(envelope_bytes)?;
                    let envelope: TransactionEnvelope = rmp_serde::from_slice(&envelope_bytes)?;
                    Ok(QueuedEnvelopeRecord {
                        envelope,
                        source_account,
                        sequence,
                        priority: TxPriority::try_from(priority)?,
                        enqueued_at: enqueued_at as u64,
                    })
                },
            )
            .collect()
    }

    pub async fn remove_queued_envelope(
        &self,
        message_id: [u8; 32],
    ) -> Result<(), SyncEngineError> {
        let id = message_id.to_vec();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM queued_envelopes WHERE message_id = ?1", [id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn set_settlement_status(
        &self,
        message_id: [u8; 32],
        status: SettlementStatus,
        updated_at: u64,
    ) -> Result<(), SyncEngineError> {
        self.transaction(move |tx| {
            Self::set_settlement_status_in_tx(tx, message_id, status, updated_at)
        })
        .await
    }

    /// Update settlement statuses in bulk inside a single database transaction.
    /// Uses a Best-Effort policy: valid transitions are committed while illegal
    /// transitions (or untracked envelopes) are skipped and reported as `rejected`
    /// in the returned `BatchUpdateReport`.
    /// This prevents a single stale message in a large relayed batch from
    /// rejecting the entire batch and causing massive network re-transmission.
    pub async fn set_settlement_status_batch(
        &self,
        updates: &[([u8; 32], SettlementStatus, u64)],
    ) -> Result<BatchUpdateReport, SyncEngineError> {
        let updates = updates.to_vec();

        self.transaction(move |tx| {
            let mut applied = Vec::new();
            let mut rejected = Vec::new();

            for (message_id, to_status, updated_at) in updates {
                let id = message_id.to_vec();

                let from_status_res: rusqlite::Result<String> = tx.query_row(
                    "SELECT status FROM settlement_status WHERE message_id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                );

                let from_status_str = match from_status_res {
                    Ok(s) => s,
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        rejected.push((message_id, "Untracked envelope".to_string()));
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };

                let is_valid = match from_status_str.parse::<SettlementStatus>() {
                    Ok(current_status) => current_status.can_transition_to(to_status),
                    Err(_) => false,
                };

                if !is_valid {
                    rejected.push((
                        message_id,
                        format!(
                            "Illegal transition from '{}' to '{}'",
                            from_status_str,
                            to_status.as_str()
                        ),
                    ));
                    continue;
                }

                let to_status_str = to_status.as_str().to_string();
                tx.execute(
                    "UPDATE settlement_status SET status = ?1, updated_at = ?2 WHERE message_id = ?3",
                    rusqlite::params![to_status_str, updated_at as i64, id],
                )?;

                tx.execute(
                    "INSERT INTO settlement_history (message_id, from_status, to_status, timestamp)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![id, from_status_str, to_status_str, updated_at as i64],
                )?;

                applied.push(message_id);
            }

            Ok(BatchUpdateReport { applied, rejected })
        })
        .await
    }

    pub async fn get_settlement_status(
        &self,
        message_id: [u8; 32],
    ) -> Result<Option<SettlementStatus>, SyncEngineError> {
        let id = message_id.to_vec();
        let status: Option<String> = self
            .conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT status FROM settlement_status WHERE message_id = ?1")?;
                let mut rows = stmt.query(rusqlite::params![id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row.get::<_, String>(0)?))
                } else {
                    Ok(None)
                }
            })
            .await?;

        status.map(|s| s.parse()).transpose()
    }

    pub async fn history_for(
        &self,
        message_id: [u8; 32],
    ) -> Result<Vec<HistoryEntry>, SyncEngineError> {
        let id = message_id.to_vec();
        let rows = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT message_id, from_status, to_status, timestamp
                     FROM settlement_history
                     WHERE message_id = ?1
                     ORDER BY id",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![id], |row| {
                        let message_id: Vec<u8> = row.get(0)?;
                        let from_status: String = row.get(1)?;
                        let to_status: String = row.get(2)?;
                        let timestamp: i64 = row.get(3)?;
                        Ok(HistoryEntry {
                            message_id: message_id.try_into().unwrap_or([0u8; 32]),
                            from_status,
                            to_status,
                            timestamp: timestamp as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn save_sequence_reservation(
        &self,
        source_account: &str,
        last_reserved: i64,
    ) -> Result<(), SyncEngineError> {
        let source_account = source_account.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO sequence_reservations (source_account, last_reserved)
                     VALUES (?1, ?2)",
                    rusqlite::params![source_account, last_reserved],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn load_sequence_reservation(
        &self,
        source_account: &str,
    ) -> Result<Option<i64>, SyncEngineError> {
        let source_account = source_account.to_string();
        let value = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT last_reserved FROM sequence_reservations WHERE source_account = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![source_account])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row.get::<_, i64>(0)?))
                } else {
                    Ok(None)
                }
            })
            .await?;
        Ok(value)
    }

    /// Load every known account's last-reserved sequence number. Used by
    /// [`crate::engine::SyncEngine::open`] to rehydrate all in-memory sequence
    /// state in one pass after a restart; the per-account
    /// [`Self::load_sequence_reservation`] is for single-account lookups.
    pub async fn list_all_sequence_reservations(
        &self,
    ) -> Result<std::collections::HashMap<String, i64>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT source_account, last_reserved FROM sequence_reservations")?;
                let rows = stmt
                    .query_map([], |row| {
                        let source_account: String = row.get(0)?;
                        let last_reserved: i64 = row.get(1)?;
                        Ok((source_account, last_reserved))
                    })?
                    .collect::<Result<std::collections::HashMap<_, _>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn record_conflict(
        &self,
        conflict: &Conflict,
        detected_at: u64,
    ) -> Result<(), SyncEngineError> {
        let source_account = conflict.source_account.clone();
        let sequence = conflict.sequence;
        let envelope_a = conflict.envelope_a.to_vec();
        let envelope_b = conflict.envelope_b.to_vec();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO conflicts (source_account, sequence, envelope_a, envelope_b, detected_at, resolved)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    rusqlite::params![source_account, sequence, envelope_a, envelope_b, detected_at as i64],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_unresolved_conflicts(&self) -> Result<Vec<Conflict>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT source_account, sequence, envelope_a, envelope_b
                     FROM conflicts WHERE resolved = 0",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        let source_account: String = row.get(0)?;
                        let sequence: i64 = row.get(1)?;
                        let envelope_a: Vec<u8> = row.get(2)?;
                        let envelope_b: Vec<u8> = row.get(3)?;
                        Ok((source_account, sequence, envelope_a, envelope_b))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(source_account, sequence, envelope_a, envelope_b)| Conflict {
                    source_account,
                    sequence,
                    envelope_a: envelope_a.try_into().unwrap_or([0u8; 32]),
                    envelope_b: envelope_b.try_into().unwrap_or([0u8; 32]),
                },
            )
            .collect())
    }

    /// List every recorded conflict, resolved and unresolved alike, oldest
    /// first. Read-only accessor added for `sync-engine-cli conflicts list`
    /// (see `src/cli.rs`): [`list_unresolved_conflicts`](Self::list_unresolved_conflicts)
    /// already existed but only returns unresolved rows and omits `id`,
    /// `detected_at`, and `resolved`, all of which the CLI needs to display
    /// and to implement its `--unresolved-only` filter over the full set.
    pub async fn list_all_conflicts(&self) -> Result<Vec<ConflictRecord>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, source_account, sequence, envelope_a, envelope_b, detected_at, resolved
                     FROM conflicts ORDER BY id",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, source_account, sequence, envelope_a, envelope_b, detected_at, resolved)| {
                    ConflictRecord {
                        id,
                        source_account,
                        sequence,
                        envelope_a: envelope_a.try_into().unwrap_or([0u8; 32]),
                        envelope_b: envelope_b.try_into().unwrap_or([0u8; 32]),
                        detected_at: detected_at as u64,
                        resolved: resolved != 0,
                    }
                },
            )
            .collect())
    }

    /// Row counts per table plus the oldest/newest `queued_envelopes.enqueued_at`.
    /// Read-only accessor added for `sync-engine-cli db summary` (see
    /// `src/cli.rs`) — nothing already exposed on `SyncEngineDb` returns
    /// aggregate counts across tables.
    pub async fn summary(&self) -> Result<DbSummary, SyncEngineError> {
        let summary = self
            .conn
            .call(|conn| {
                let queued_envelopes_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM queued_envelopes", [], |row| {
                        row.get(0)
                    })?;
                let settlement_status_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM settlement_status", [], |row| {
                        row.get(0)
                    })?;
                let sequence_reservations_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM sequence_reservations", [], |row| {
                        row.get(0)
                    })?;
                let conflicts_count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM conflicts", [], |row| row.get(0))?;
                let unresolved_conflicts_count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM conflicts WHERE resolved = 0",
                    [],
                    |row| row.get(0),
                )?;
                let oldest_queued_at: Option<i64> =
                    conn.query_row("SELECT MIN(enqueued_at) FROM queued_envelopes", [], |row| {
                        row.get(0)
                    })?;
                let newest_queued_at: Option<i64> =
                    conn.query_row("SELECT MAX(enqueued_at) FROM queued_envelopes", [], |row| {
                        row.get(0)
                    })?;

                Ok(DbSummary {
                    queued_envelopes_count,
                    settlement_status_count,
                    sequence_reservations_count,
                    conflicts_count,
                    unresolved_conflicts_count,
                    oldest_queued_at: oldest_queued_at.map(|v| v as u64),
                    newest_queued_at: newest_queued_at.map(|v| v as u64),
                })
            })
            .await?;
        Ok(summary)
    }

    /// Durably persist `escalation` (built by
    /// `crate::conflict::escalation::build_escalation` for `conflict`) and
    /// set [`SettlementStatus::Disputed`] on both of `conflict`'s envelopes —
    /// per the architecture, an escalated conflict's envelopes are neither
    /// settled nor failed until on-chain arbitration resolves them.
    ///
    /// Returns the new row's id, which `mark_escalation_submitted` uses to
    /// identify it later.
    pub async fn save_escalation(
        &self,
        conflict: &Conflict,
        escalation: &DisputeEscalation,
        created_at: u64,
    ) -> Result<i64, SyncEngineError> {
        let source_account = conflict.source_account.clone();
        let sequence = conflict.sequence;
        let envelope_a = conflict.envelope_a.to_vec();
        let envelope_b = conflict.envelope_b.to_vec();
        let initiator = escalation.initiator.clone();
        let respondent = escalation.respondent.clone();
        let tx_id = escalation.tx_id.to_vec();
        let proof_bytes = rmp_serde::to_vec(&escalation.proof)?;

        let env_a_arr = conflict.envelope_a;
        let env_b_arr = conflict.envelope_b;

        self.transaction(move |tx| {
            tx.execute(
                "INSERT INTO dispute_escalations
                    (source_account, sequence, envelope_a, envelope_b, initiator, respondent, tx_id, proof_bytes, created_at, submitted)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                rusqlite::params![
                    source_account,
                    sequence,
                    envelope_a,
                    envelope_b,
                    initiator,
                    respondent,
                    tx_id,
                    proof_bytes,
                    created_at as i64
                ],
            )?;
            let id = tx.last_insert_rowid();
            Self::set_settlement_status_in_tx(tx, env_a_arr, SettlementStatus::Disputed, created_at)?;
            Self::set_settlement_status_in_tx(tx, env_b_arr, SettlementStatus::Disputed, created_at)?;
            Ok(id)
        })
        .await
    }

    /// List every escalation not yet marked submitted (`submitted = 0`) —
    /// i.e. still awaiting pickup by a relay node with live Soroban RPC
    /// connectivity.
    pub async fn list_pending_escalations(
        &self,
    ) -> Result<Vec<PersistedEscalation>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, source_account, sequence, envelope_a, envelope_b, initiator,
                            respondent, tx_id, proof_bytes, created_at
                     FROM dispute_escalations WHERE submitted = 0",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                            row.get::<_, Vec<u8>>(8)?,
                            row.get::<_, i64>(9)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        rows.into_iter()
            .map(
                |(
                    id,
                    source_account,
                    sequence,
                    envelope_a,
                    envelope_b,
                    initiator,
                    respondent,
                    tx_id,
                    proof_bytes,
                    created_at,
                )| {
                    let proof: RelayChainProof = rmp_serde::from_slice(&proof_bytes)?;
                    Ok(PersistedEscalation {
                        id,
                        source_account,
                        sequence,
                        envelope_a: envelope_a.try_into().unwrap_or([0u8; 32]),
                        envelope_b: envelope_b.try_into().unwrap_or([0u8; 32]),
                        escalation: DisputeEscalation {
                            initiator,
                            respondent,
                            tx_id: tx_id.try_into().unwrap_or([0u8; 32]),
                            proof,
                        },
                        created_at: created_at as u64,
                    })
                },
            )
            .collect()
    }

    /// Mark the escalation with row id `id` as submitted, excluding it from
    /// future [`list_pending_escalations`](Self::list_pending_escalations)
    /// results. Called by a relay node once it has successfully submitted
    /// the payload to `raise_dispute` on-chain.
    pub async fn mark_escalation_submitted(&self, id: i64) -> Result<(), SyncEngineError> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE dispute_escalations SET submitted = 1 WHERE id = ?1",
                    rusqlite::params![id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn sweep_stale_envelopes(
        &self,
        max_age_secs: u64,
        now: u64,
    ) -> Result<Vec<[u8; 32]>, SyncEngineError> {
        let cutoff = now.saturating_sub(max_age_secs) as i64;
        let stale_id_bytes: Vec<Vec<u8>> = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT q.message_id
                     FROM queued_envelopes q
                     JOIN settlement_status s ON s.message_id = q.message_id
                     WHERE q.enqueued_at < ?1
                       AND s.status IN ('queued', 'propagating')",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![cutoff], |row| {
                        let message_id: Vec<u8> = row.get(0)?;
                        Ok(message_id)
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        let stale_ids: Vec<[u8; 32]> = stale_id_bytes
            .into_iter()
            .filter_map(|v| v.try_into().ok())
            .collect();

        for &mid in &stale_ids {
            self.set_settlement_status(mid, SettlementStatus::Failed, now)
                .await?;
        }

        Ok(stale_ids)
    }

    /// Serialize every table in this database into a single portable,
    /// versioned blob suitable for moving a device's entire sync-engine
    /// state (pending payments, sequence reservations, unresolved
    /// conflicts, dispute escalations, settlement history) to another
    /// device — see issue #15.
    ///
    /// # Format and versioning
    ///
    /// The blob is a MessagePack-encoded [`DbSnapshot`], tagged with
    /// [`DB_SNAPSHOT_SCHEMA_VERSION`]. Issue #11 (schema versioning for
    /// `SyncEngineDb`) had not landed at the time this was written; if it
    /// lands later, this constant should be unified with its scheme rather
    /// than kept as a second version number.
    ///
    /// # Encryption at rest
    ///
    /// This function does **not** encrypt its output. It reads whatever
    /// plaintext rows the current connection can see and serializes them
    /// as-is. Issue #12 (encryption at rest for `SyncEngineDb`) had not
    /// landed at the time this was written; if/when it lands, note that an
    /// exported snapshot is **not** an encrypted artifact merely because
    /// the source database is encrypted at rest — encryption at rest
    /// protects the on-disk SQLite file, not the output of this function.
    /// A snapshot is exactly as sensitive as the payment history it
    /// contains (source accounts, sequence numbers, full transaction
    /// envelopes, dispute proofs) and must be treated as plaintext
    /// financial data by callers: transmit it only over an encrypted
    /// channel (e.g. a direct authenticated device-to-device transfer) and
    /// do not persist it unencrypted at rest. Wrapping the returned bytes
    /// in caller-side encryption (ideally using the same key material as
    /// #12's at-rest encryption, so a snapshot is never a plaintext copy of
    /// something the source database was encrypting) is recommended but
    /// intentionally left to the caller, since #15 is independent of #12
    /// and the two may land in either order.
    ///
    /// # Sequence reservations
    ///
    /// `sequence_reservations` rows are exported and imported as-is. A
    /// sequence baseline reserved on the source device may be stale by the
    /// time it reaches the target device (e.g. the account transacted from
    /// elsewhere in the interim) — see issue #8. **Callers must run stale
    /// sequence reconciliation immediately after [`Self::import_snapshot`]
    /// returns and before queuing anything new**; this function does not
    /// (and cannot, without live network access to the account) validate
    /// the reservation against current on-chain state itself.
    pub async fn export_snapshot(&self) -> Result<Vec<u8>, SyncEngineError> {
        let snapshot = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT message_id, source_account, sequence, priority, enqueued_at, envelope_bytes
                     FROM queued_envelopes",
                )?;
                let queued_envelopes = stmt
                    .query_map([], |row| {
                        Ok(QueuedEnvelopeRow {
                            message_id: row.get(0)?,
                            source_account: row.get(1)?,
                            sequence: row.get(2)?,
                            priority: row.get(3)?,
                            enqueued_at: row.get(4)?,
                            envelope_bytes: row.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;

                let mut stmt = conn
                    .prepare("SELECT message_id, status, updated_at FROM settlement_status")?;
                let settlement_status = stmt
                    .query_map([], |row| {
                        Ok(SettlementStatusRow {
                            message_id: row.get(0)?,
                            status: row.get(1)?,
                            updated_at: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;

                let mut stmt = conn
                    .prepare("SELECT source_account, last_reserved FROM sequence_reservations")?;
                let sequence_reservations = stmt
                    .query_map([], |row| {
                        Ok(SequenceReservationRow {
                            source_account: row.get(0)?,
                            last_reserved: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;

                let mut stmt = conn.prepare(
                    "SELECT id, source_account, sequence, envelope_a, envelope_b, detected_at, resolved
                     FROM conflicts",
                )?;
                let conflicts = stmt
                    .query_map([], |row| {
                        Ok(ConflictRow {
                            id: row.get(0)?,
                            source_account: row.get(1)?,
                            sequence: row.get(2)?,
                            envelope_a: row.get(3)?,
                            envelope_b: row.get(4)?,
                            detected_at: row.get(5)?,
                            resolved: row.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;

                let mut stmt = conn.prepare(
                    "SELECT id, message_id, from_status, to_status, timestamp
                     FROM settlement_history",
                )?;
                let settlement_history = stmt
                    .query_map([], |row| {
                        Ok(SettlementHistoryRow {
                            id: row.get(0)?,
                            message_id: row.get(1)?,
                            from_status: row.get(2)?,
                            to_status: row.get(3)?,
                            timestamp: row.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;

                let mut stmt = conn.prepare(
                    "SELECT id, source_account, sequence, envelope_a, envelope_b, initiator,
                            respondent, tx_id, proof_bytes, created_at, submitted
                     FROM dispute_escalations",
                )?;
                let dispute_escalations = stmt
                    .query_map([], |row| {
                        Ok(DisputeEscalationRow {
                            id: row.get(0)?,
                            source_account: row.get(1)?,
                            sequence: row.get(2)?,
                            envelope_a: row.get(3)?,
                            envelope_b: row.get(4)?,
                            initiator: row.get(5)?,
                            respondent: row.get(6)?,
                            tx_id: row.get(7)?,
                            proof_bytes: row.get(8)?,
                            created_at: row.get(9)?,
                            submitted: row.get(10)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;

                Ok(DbSnapshot {
                    schema_version: DB_SNAPSHOT_SCHEMA_VERSION,
                    queued_envelopes,
                    settlement_status,
                    sequence_reservations,
                    conflicts,
                    settlement_history,
                    dispute_escalations,
                })
            })
            .await?;

        Ok(rmp_serde::to_vec(&snapshot)?)
    }

    /// Restore a snapshot produced by [`Self::export_snapshot`] into this
    /// database — see issue #15.
    ///
    /// # Import policy: reject into a non-empty database
    ///
    /// This function **rejects the import with
    /// [`SyncEngineError::ImportTargetNotEmpty`] if any table in this
    /// database already contains a row.** It does not merge or overwrite.
    ///
    /// This was chosen over merge/overwrite because every table here
    /// guards financial or double-spend-sensitive state: silently merging
    /// two `sequence_reservations` for the same account, or two
    /// `queued_envelopes`/`conflicts` rows, requires a conflict-resolution
    /// policy no less complex than the one `crate::conflict` already exists
    /// to implement for on-chain envelopes — inventing a second, weaker one
    /// just for import would risk exactly the double-spend and
    /// lost-payment hazards this crate is otherwise built to prevent.
    /// Reject-if-nonempty keeps the operation's outcome trivially provable
    /// (empty + snapshot = snapshot, exactly) and matches the intended
    /// use case described in issue #15: restoring onto a new device, whose
    /// database is normally fresh. A caller that genuinely needs to
    /// combine two non-empty databases should do so explicitly at a higher
    /// level, not implicitly inside this function.
    ///
    /// The emptiness check and the insert happen inside the same SQLite
    /// transaction, so a concurrent write landing between "check" and
    /// "insert" cannot cause a corrupt or partial import.
    ///
    /// # Corrupted or truncated input
    ///
    /// A `data` that is not a valid, complete [`DbSnapshot`] encoding fails
    /// with [`SyncEngineError::DeserializationError`] before anything is
    /// written — there is no partial-write state to worry about.
    ///
    /// # Schema version
    ///
    /// A snapshot whose embedded version does not match
    /// [`DB_SNAPSHOT_SCHEMA_VERSION`] is rejected with
    /// [`SyncEngineError::IncompatibleSnapshotSchemaVersion`] rather than
    /// imported speculatively.
    ///
    /// # Sequence reservations and encryption at rest
    ///
    /// See [`Self::export_snapshot`]'s documentation for the recommended
    /// post-import reconciliation flow (issue #8) and this format's
    /// relationship to encryption at rest (issue #12).
    pub async fn import_snapshot(&self, data: &[u8]) -> Result<ImportReport, SyncEngineError> {
        let snapshot: DbSnapshot = rmp_serde::from_slice(data)?;

        if snapshot.schema_version != DB_SNAPSHOT_SCHEMA_VERSION {
            return Err(SyncEngineError::IncompatibleSnapshotSchemaVersion {
                found: snapshot.schema_version,
                expected: DB_SNAPSHOT_SCHEMA_VERSION,
            });
        }

        self.transaction(move |tx| {
            let existing_rows: i64 = tx.query_row(
                "SELECT
                    (SELECT COUNT(*) FROM queued_envelopes) +
                    (SELECT COUNT(*) FROM settlement_status) +
                    (SELECT COUNT(*) FROM sequence_reservations) +
                    (SELECT COUNT(*) FROM conflicts) +
                    (SELECT COUNT(*) FROM settlement_history) +
                    (SELECT COUNT(*) FROM dispute_escalations)",
                [],
                |row| row.get(0),
            )?;

            if existing_rows != 0 {
                return Err(SyncEngineError::ImportTargetNotEmpty);
            }

            for row in &snapshot.queued_envelopes {
                tx.execute(
                    "INSERT INTO queued_envelopes
                        (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        row.message_id,
                        row.source_account,
                        row.sequence,
                        row.priority,
                        row.enqueued_at,
                        row.envelope_bytes
                    ],
                )?;
            }

            for row in &snapshot.settlement_status {
                tx.execute(
                    "INSERT INTO settlement_status (message_id, status, updated_at)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![row.message_id, row.status, row.updated_at],
                )?;
            }

            for row in &snapshot.sequence_reservations {
                tx.execute(
                    "INSERT INTO sequence_reservations (source_account, last_reserved)
                     VALUES (?1, ?2)",
                    rusqlite::params![row.source_account, row.last_reserved],
                )?;
            }

            for row in &snapshot.conflicts {
                tx.execute(
                    "INSERT INTO conflicts
                        (id, source_account, sequence, envelope_a, envelope_b, detected_at, resolved)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        row.id,
                        row.source_account,
                        row.sequence,
                        row.envelope_a,
                        row.envelope_b,
                        row.detected_at,
                        row.resolved
                    ],
                )?;
            }

            for row in &snapshot.settlement_history {
                tx.execute(
                    "INSERT INTO settlement_history
                        (id, message_id, from_status, to_status, timestamp)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        row.id,
                        row.message_id,
                        row.from_status,
                        row.to_status,
                        row.timestamp
                    ],
                )?;
            }

            for row in &snapshot.dispute_escalations {
                tx.execute(
                    "INSERT INTO dispute_escalations
                        (id, source_account, sequence, envelope_a, envelope_b, initiator,
                         respondent, tx_id, proof_bytes, created_at, submitted)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    rusqlite::params![
                        row.id,
                        row.source_account,
                        row.sequence,
                        row.envelope_a,
                        row.envelope_b,
                        row.initiator,
                        row.respondent,
                        row.tx_id,
                        row.proof_bytes,
                        row.created_at,
                        row.submitted
                    ],
                )?;
            }

            Ok(ImportReport {
                queued_envelopes_imported: snapshot.queued_envelopes.len(),
                settlement_status_imported: snapshot.settlement_status.len(),
                sequence_reservations_imported: snapshot.sequence_reservations.len(),
                conflicts_imported: snapshot.conflicts.len(),
                settlement_history_imported: snapshot.settlement_history.len(),
                dispute_escalations_imported: snapshot.dispute_escalations.len(),
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_envelope(message_id: u8) -> TransactionEnvelope {
        TransactionEnvelope {
            message_id: [message_id; 32],
            origin_pubkey: [1u8; 32],
            tx_xdr: "mock_xdr".to_string(),
            ttl_hops: 10,
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    #[tokio::test]
    async fn test_enqueue_and_get_queued_envelope() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let envelope = mock_envelope(1);
        db.enqueue_envelope(&envelope, "GABC", 101, TxPriority::Emergency, 1000)
            .await
            .unwrap();

        let record = db.get_queued_envelope([1u8; 32]).await.unwrap().unwrap();
        assert_eq!(record.envelope, envelope);
        assert_eq!(record.source_account, "GABC");
        assert_eq!(record.sequence, 101);
        assert_eq!(record.priority, TxPriority::Emergency);
        assert_eq!(record.enqueued_at, 1000);
    }

    #[tokio::test]
    async fn test_get_missing_envelope_returns_none() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        assert!(db.get_queued_envelope([9u8; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_queued_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        db.enqueue_envelope(&mock_envelope(2), "GABC", 102, TxPriority::Low, 1001)
            .await
            .unwrap();

        let records = db.list_queued_envelopes().await.unwrap();
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_queued_envelope() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        db.remove_queued_envelope([1u8; 32]).await.unwrap();
        assert!(db.get_queued_envelope([1u8; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_settlement_status_roundtrip() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Propagating, 2000)
            .await
            .unwrap();
        let status = db.get_settlement_status([1u8; 32]).await.unwrap();
        assert_eq!(status, Some(SettlementStatus::Propagating));
    }

    #[tokio::test]
    async fn test_sequence_reservation_roundtrip() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        assert_eq!(db.load_sequence_reservation("GABC").await.unwrap(), None);
        db.save_sequence_reservation("GABC", 101).await.unwrap();
        assert_eq!(
            db.load_sequence_reservation("GABC").await.unwrap(),
            Some(101)
        );
    }

    #[tokio::test]
    async fn test_batch_applies_all_valid_transitions() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        // Insert initial queued status
        db.set_settlement_status([1u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.set_settlement_status([2u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();

        let report = db
            .set_settlement_status_batch(&[
                ([1u8; 32], SettlementStatus::Propagating, 1001),
                ([2u8; 32], SettlementStatus::Failed, 1001),
            ])
            .await
            .unwrap();

        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.rejected.len(), 0);

        assert_eq!(
            db.get_settlement_status([1u8; 32]).await.unwrap(),
            Some(SettlementStatus::Propagating)
        );
        assert_eq!(
            db.get_settlement_status([2u8; 32]).await.unwrap(),
            Some(SettlementStatus::Failed)
        );
    }

    #[tokio::test]
    async fn test_batch_handles_mixed_valid_and_invalid_per_documented_policy() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Settled, 1000)
            .await
            .unwrap();
        db.set_settlement_status([2u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();

        let report = db
            .set_settlement_status_batch(&[
                // Invalid: Settled -> Propagating
                ([1u8; 32], SettlementStatus::Propagating, 1001),
                // Valid: Queued -> Propagating
                ([2u8; 32], SettlementStatus::Propagating, 1001),
                // Invalid: Untracked envelope
                ([3u8; 32], SettlementStatus::Propagating, 1001),
            ])
            .await
            .unwrap();

        // Best effort: only valid ones are applied
        assert_eq!(report.applied, vec![[2u8; 32]]);
        assert_eq!(report.rejected.len(), 2);

        // Status unchanged for invalid transition
        assert_eq!(
            db.get_settlement_status([1u8; 32]).await.unwrap(),
            Some(SettlementStatus::Settled)
        );
        // Status changed for valid transition
        assert_eq!(
            db.get_settlement_status([2u8; 32]).await.unwrap(),
            Some(SettlementStatus::Propagating)
        );
    }

    #[tokio::test]
    async fn test_batch_report_accurately_reflects_outcomes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();

        let report = db
            .set_settlement_status_batch(&[
                ([1u8; 32], SettlementStatus::Propagating, 1001),
                ([9u8; 32], SettlementStatus::Propagating, 1001),
            ])
            .await
            .unwrap();

        assert_eq!(report.applied, vec![[1u8; 32]]);
        assert_eq!(report.rejected[0].0, [9u8; 32]);
        assert_eq!(report.rejected[0].1, "Untracked envelope");
    }

    #[tokio::test]
    async fn test_batch_is_faster_than_sequential() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let count = 500;

        for i in 0..count {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            db.set_settlement_status(id, SettlementStatus::Queued, 1000)
                .await
                .unwrap();
        }

        let mut sequential_updates = Vec::new();
        let mut batch_updates = Vec::new();
        for i in 0..count {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            if i % 2 == 0 {
                sequential_updates.push((id, SettlementStatus::Propagating, 1001));
            } else {
                batch_updates.push((id, SettlementStatus::Propagating, 1001));
            }
        }

        let start_seq = std::time::Instant::now();
        for (id, status, time) in sequential_updates {
            db.set_settlement_status(id, status, time).await.unwrap();
        }
        let seq_duration = start_seq.elapsed();

        let start_batch = std::time::Instant::now();
        db.set_settlement_status_batch(&batch_updates)
            .await
            .unwrap();
        let batch_duration = start_batch.elapsed();

        assert!(
            batch_duration < seq_duration,
            "Batch: {:?}, Seq: {:?}",
            batch_duration,
            seq_duration
        );
    }

    #[tokio::test]
    async fn test_conflict_record_and_list_unresolved() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let conflict = Conflict {
            source_account: "GABC".to_string(),
            sequence: 101,
            envelope_a: [1u8; 32],
            envelope_b: [2u8; 32],
        };
        db.record_conflict(&conflict, 3000).await.unwrap();

        let unresolved = db.list_unresolved_conflicts().await.unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0], conflict);
    }

    // ── Issue 2: settlement_history tests ──

    #[tokio::test]
    async fn test_successful_transitions_are_recorded_in_order() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [1u8; 32];

        db.set_settlement_status(id, SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Propagating, 1001)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Settled, 1002)
            .await
            .unwrap();

        let history = db.history_for(id).await.unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].from_status, "");
        assert_eq!(history[0].to_status, "queued");
        assert_eq!(history[0].timestamp, 1000);
        assert_eq!(history[1].from_status, "queued");
        assert_eq!(history[1].to_status, "propagating");
        assert_eq!(history[1].timestamp, 1001);
        assert_eq!(history[2].from_status, "propagating");
        assert_eq!(history[2].to_status, "settled");
        assert_eq!(history[2].timestamp, 1002);
    }

    #[tokio::test]
    async fn test_history_for_unknown_envelope_is_empty() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let history = db.history_for([99u8; 32]).await.unwrap();
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_full_lifecycle_produces_complete_history() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [2u8; 32];

        db.set_settlement_status(id, SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Propagating, 1001)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Disputed, 1002)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Settled, 1003)
            .await
            .unwrap();

        let history = db.history_for(id).await.unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].to_status, "queued");
        assert_eq!(history[1].to_status, "propagating");
        assert_eq!(history[2].to_status, "disputed");
        assert_eq!(history[3].to_status, "settled");
    }

    // ── Issue 3: staleness sweep tests ──

    #[tokio::test]
    async fn test_sweep_identifies_stale_queued_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let stale_id = [1u8; 32];
        let fresh_id = [2u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(stale_id, SettlementStatus::Queued, 100)
            .await
            .unwrap();

        db.enqueue_envelope(&mock_envelope(2), "GABC", 102, TxPriority::Normal, 900)
            .await
            .unwrap();
        db.set_settlement_status(fresh_id, SettlementStatus::Queued, 900)
            .await
            .unwrap();

        // now=1000, max_age=500 => cutoff=500; stale (enqueued_at=100) is past, fresh (900) is not
        let stale = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert_eq!(stale, vec![stale_id]);
    }

    #[tokio::test]
    async fn test_sweep_ignores_fresh_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [1u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 800)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Queued, 800)
            .await
            .unwrap();

        let stale = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_ignores_already_terminal_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let settled_id = [1u8; 32];
        let failed_id = [2u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(settled_id, SettlementStatus::Settled, 100)
            .await
            .unwrap();

        db.enqueue_envelope(&mock_envelope(2), "GABC", 102, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(failed_id, SettlementStatus::Failed, 100)
            .await
            .unwrap();

        let stale = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_is_idempotent() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [1u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Queued, 100)
            .await
            .unwrap();

        let first = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(!first.is_empty());

        let second = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(second.is_empty());
    }

    // ── Issue 2: dispute escalation tests ──

    use crate::conflict::escalation::{build_escalation, EscalationInput};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn temp_db_path() -> (TempDir, String) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("escalation-test.sqlite3");
        (dir, path.to_string_lossy().into_owned())
    }

    fn escalation_input(
        message_id: [u8; 32],
        origin_pubkey: [u8; 32],
        seen_at: u64,
    ) -> EscalationInput {
        let key = SigningKey::generate(&mut OsRng);
        EscalationInput {
            message_id,
            origin_pubkey,
            first_seen_locally_at: seen_at,
            proof: RelayChainProof::sign(&key, &message_id, &[9u8; 32], 101),
        }
    }

    fn sample_conflict() -> Conflict {
        Conflict {
            source_account: "GABC".to_string(),
            sequence: 101,
            envelope_a: [1u8; 32],
            envelope_b: [2u8; 32],
        }
    }

    #[tokio::test]
    async fn test_escalation_persists_across_restart() {
        let (_dir, path) = temp_db_path();
        let conflict = sample_conflict();
        let escalation = {
            let db = SyncEngineDb::init(&path).await.unwrap();
            let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
            let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
            let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();
            db.save_escalation(&conflict, &escalation, 3000)
                .await
                .unwrap();
            escalation
            // `db` dropped here, closing the connection -- simulates a restart.
        };

        let reopened = SyncEngineDb::init(&path).await.unwrap();
        let pending = reopened.list_pending_escalations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_account, conflict.source_account);
        assert_eq!(pending[0].sequence, conflict.sequence);
        assert_eq!(pending[0].envelope_a, conflict.envelope_a);
        assert_eq!(pending[0].envelope_b, conflict.envelope_b);
        assert_eq!(pending[0].escalation, escalation);

        // Escalating both envelopes must have set them Disputed too.
        assert_eq!(
            reopened
                .get_settlement_status(conflict.envelope_a)
                .await
                .unwrap(),
            Some(SettlementStatus::Disputed)
        );
        assert_eq!(
            reopened
                .get_settlement_status(conflict.envelope_b)
                .await
                .unwrap(),
            Some(SettlementStatus::Disputed)
        );
    }

    #[tokio::test]
    async fn test_mark_submitted_excludes_from_pending_list() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let conflict = sample_conflict();
        let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();

        let id = db
            .save_escalation(&conflict, &escalation, 3000)
            .await
            .unwrap();

        assert_eq!(db.list_pending_escalations().await.unwrap().len(), 1);

        db.mark_escalation_submitted(id).await.unwrap();

        assert!(db.list_pending_escalations().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_pending_escalations_excludes_only_submitted() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();

        let conflict_1 = sample_conflict();
        let envelope_a_1 = escalation_input(conflict_1.envelope_a, [10u8; 32], 1000);
        let envelope_b_1 = escalation_input(conflict_1.envelope_b, [20u8; 32], 2000);
        let escalation_1 = build_escalation(&conflict_1, &envelope_a_1, &envelope_b_1).unwrap();
        let id_1 = db
            .save_escalation(&conflict_1, &escalation_1, 3000)
            .await
            .unwrap();

        let conflict_2 = Conflict {
            source_account: "GXYZ".to_string(),
            sequence: 202,
            envelope_a: [3u8; 32],
            envelope_b: [4u8; 32],
        };
        let envelope_a_2 = escalation_input(conflict_2.envelope_a, [30u8; 32], 1500);
        let envelope_b_2 = escalation_input(conflict_2.envelope_b, [40u8; 32], 2500);
        let escalation_2 = build_escalation(&conflict_2, &envelope_a_2, &envelope_b_2).unwrap();
        db.save_escalation(&conflict_2, &escalation_2, 3500)
            .await
            .unwrap();

        db.mark_escalation_submitted(id_1).await.unwrap();

        let pending = db.list_pending_escalations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_account, "GXYZ");
    }

    #[tokio::test]
    async fn test_escalation_survives_conflicting_concurrent_writes() {
        // Two conflicting escalations for the same tx_id, written concurrently,
        // must both land intact -- tokio_rusqlite serializes calls through a
        // single connection actor, so this must never corrupt storage.
        let db = std::sync::Arc::new(SyncEngineDb::init(":memory:").await.unwrap());

        let conflict = sample_conflict();
        let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
        let escalation_1 = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();
        let escalation_2 = escalation_1.clone();

        let conflict_1 = conflict.clone();
        let conflict_2 = conflict.clone();
        let db_1 = db.clone();
        let db_2 = db.clone();

        let (r1, r2) = tokio::join!(
            tokio::spawn(
                async move { db_1.save_escalation(&conflict_1, &escalation_1, 3000).await }
            ),
            tokio::spawn(
                async move { db_2.save_escalation(&conflict_2, &escalation_2, 3001).await }
            ),
        );
        r1.unwrap().unwrap();
        r2.unwrap().unwrap();

        let pending = db.list_pending_escalations().await.unwrap();
        assert_eq!(
            pending.len(),
            2,
            "both concurrent writes must be durably recorded, not corrupted"
        );
    }

    // ── Issue 15: export/import snapshot tests ──

    /// Puts at least one row into every table `export_snapshot` covers, and
    /// returns the [`Conflict`] used for the conflict/escalation rows so
    /// callers can cross-check against it if needed.
    async fn seed_full_db(db: &SyncEngineDb) -> Conflict {
        db.enqueue_transaction(&mock_envelope(1), "GABC", 101, TxPriority::Emergency, 1000)
            .await
            .unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Propagating, 1001)
            .await
            .unwrap();

        db.enqueue_envelope(&mock_envelope(2), "GXYZ", 55, TxPriority::Low, 2000)
            .await
            .unwrap();

        let conflict = Conflict {
            source_account: "GCONFLICT".to_string(),
            sequence: 202,
            envelope_a: [3u8; 32],
            envelope_b: [4u8; 32],
        };
        db.record_conflict(&conflict, 3000).await.unwrap();

        let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();
        db.save_escalation(&conflict, &escalation, 4000)
            .await
            .unwrap();

        conflict
    }

    #[tokio::test]
    async fn test_export_import_roundtrip_is_lossless() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        seed_full_db(&db).await;

        let summary_before = db.summary().await.unwrap();
        let mut queued_before = db.list_queued_envelopes().await.unwrap();
        let conflicts_before = db.list_all_conflicts().await.unwrap();
        let pending_before = db.list_pending_escalations().await.unwrap();
        let history_before = db.history_for([1u8; 32]).await.unwrap();
        let seq_before = db.list_all_sequence_reservations().await.unwrap();

        let snapshot = db.export_snapshot().await.unwrap();

        let fresh = SyncEngineDb::init(":memory:").await.unwrap();
        let report = fresh.import_snapshot(&snapshot).await.unwrap();

        assert_eq!(report.queued_envelopes_imported, queued_before.len());
        assert_eq!(report.conflicts_imported, conflicts_before.len());
        assert_eq!(report.dispute_escalations_imported, pending_before.len());
        assert_eq!(report.sequence_reservations_imported, seq_before.len());

        // Every table, byte-for-byte, must match what was exported.
        assert_eq!(fresh.summary().await.unwrap(), summary_before);

        let mut queued_after = fresh.list_queued_envelopes().await.unwrap();
        queued_after.sort_by_key(|r| r.envelope.message_id);
        queued_before.sort_by_key(|r| r.envelope.message_id);
        assert_eq!(queued_after, queued_before);

        assert_eq!(fresh.list_all_conflicts().await.unwrap(), conflicts_before);
        assert_eq!(
            fresh.list_pending_escalations().await.unwrap(),
            pending_before
        );
        assert_eq!(fresh.history_for([1u8; 32]).await.unwrap(), history_before);
        assert_eq!(
            fresh.list_all_sequence_reservations().await.unwrap(),
            seq_before
        );
    }

    #[tokio::test]
    async fn test_import_into_nonempty_db_follows_documented_policy() {
        let source = SyncEngineDb::init(":memory:").await.unwrap();
        seed_full_db(&source).await;
        let snapshot = source.export_snapshot().await.unwrap();

        let target = SyncEngineDb::init(":memory:").await.unwrap();
        target
            .enqueue_envelope(&mock_envelope(99), "GOTHER", 1, TxPriority::Normal, 1)
            .await
            .unwrap();

        let result = target.import_snapshot(&snapshot).await;
        assert!(matches!(result, Err(SyncEngineError::ImportTargetNotEmpty)));

        // The documented policy is reject-not-merge: the target's
        // pre-existing state must be untouched and none of the snapshot's
        // rows may have been partially applied.
        let records = target.list_queued_envelopes().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_account, "GOTHER");
        assert!(target.list_all_conflicts().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_import_rejects_corrupted_snapshot() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();

        let garbage = vec![0xff, 0x00, 0x13, 0x37];
        let result = db.import_snapshot(&garbage).await;
        assert!(matches!(
            result,
            Err(SyncEngineError::DeserializationError(_))
        ));

        let source = SyncEngineDb::init(":memory:").await.unwrap();
        seed_full_db(&source).await;
        let snapshot = source.export_snapshot().await.unwrap();
        let truncated = &snapshot[..snapshot.len() / 2];
        let result = db.import_snapshot(truncated).await;
        assert!(matches!(
            result,
            Err(SyncEngineError::DeserializationError(_))
        ));

        // Neither failed attempt may have written anything.
        assert_eq!(db.summary().await.unwrap(), DbSummary::default());
    }

    #[tokio::test]
    async fn test_import_rejects_incompatible_schema_version() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();

        let bogus = DbSnapshot {
            schema_version: DB_SNAPSHOT_SCHEMA_VERSION + 1,
            queued_envelopes: vec![],
            settlement_status: vec![],
            sequence_reservations: vec![],
            conflicts: vec![],
            settlement_history: vec![],
            dispute_escalations: vec![],
        };
        let bytes = rmp_serde::to_vec(&bogus).unwrap();

        let result = db.import_snapshot(&bytes).await;
        match result {
            Err(SyncEngineError::IncompatibleSnapshotSchemaVersion { found, expected }) => {
                assert_eq!(found, DB_SNAPSHOT_SCHEMA_VERSION + 1);
                assert_eq!(expected, DB_SNAPSHOT_SCHEMA_VERSION);
            }
            other => panic!("expected IncompatibleSnapshotSchemaVersion, got {other:?}"),
        }
    }

    // ── Encryption at rest tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_data_is_not_plaintext_on_disk() {
        use crate::encryption::{generate_salt, EncryptionKey};
        use tempfile::NamedTempFile;

        let temp_db = NamedTempFile::new().unwrap();
        let db_path = temp_db.path().to_str().unwrap();

        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();

        let db = SyncEngineDb::init_with_encryption(db_path, key)
            .await
            .unwrap();

        // Store envelope with known plaintext
        let envelope = mock_envelope(1);
        let plaintext_xdr = &envelope.tx_xdr;
        db.enqueue_envelope(&envelope, "GABC", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();

        // Drop the database to ensure it's flushed to disk
        drop(db);

        // Read the raw database file
        let file_bytes = std::fs::read(db_path).unwrap();

        // The plaintext should NOT appear anywhere in the file
        assert!(
            !file_bytes
                .windows(plaintext_xdr.len())
                .any(|w| w == plaintext_xdr.as_bytes()),
            "Plaintext transaction XDR found in database file - encryption failed!"
        );
    }

    #[tokio::test]
    async fn test_correct_key_roundtrips() {
        use crate::encryption::{generate_salt, EncryptionKey};
        use tempfile::NamedTempFile;

        let temp_db = NamedTempFile::new().unwrap();
        let db_path = temp_db.path().to_str().unwrap();

        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("correct passphrase", &salt).unwrap();

        // Write with key
        let db = SyncEngineDb::init_with_encryption(db_path, key.clone())
            .await
            .unwrap();
        let envelope = mock_envelope(42);
        db.enqueue_envelope(&envelope, "GTEST", 123, TxPriority::Normal, 1000)
            .await
            .unwrap();
        drop(db);

        // Reopen with same key
        let db2 = SyncEngineDb::init_with_encryption(db_path, key)
            .await
            .unwrap();
        let retrieved = db2.get_queued_envelope([42u8; 32]).await.unwrap();

        assert!(retrieved.is_some());
        let record = retrieved.unwrap();
        assert_eq!(record.envelope.message_id, [42u8; 32]);
        assert_eq!(record.source_account, "GTEST");
        assert_eq!(record.sequence, 123);
    }

    #[tokio::test]
    async fn test_wrong_key_fails_closed() {
        use crate::encryption::{generate_salt, EncryptionKey};
        use tempfile::NamedTempFile;

        let temp_db = NamedTempFile::new().unwrap();
        let db_path = temp_db.path().to_str().unwrap();

        let salt = generate_salt();
        let correct_key = EncryptionKey::from_passphrase("correct passphrase", &salt).unwrap();
        let wrong_key = EncryptionKey::from_passphrase("wrong passphrase", &salt).unwrap();

        // Write with correct key
        let db = SyncEngineDb::init_with_encryption(db_path, correct_key)
            .await
            .unwrap();
        db.enqueue_envelope(&mock_envelope(1), "GTEST", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        drop(db);

        // Try to open with wrong key - should error
        let result = SyncEngineDb::init_with_encryption(db_path, wrong_key).await;
        assert!(
            matches!(result, Err(SyncEngineError::EncryptionKeyMismatch)),
            "Expected EncryptionKeyMismatch error, got {:?}",
            result.as_ref().err()
        );
    }

    #[tokio::test]
    async fn test_missing_key_on_encrypted_db_errors_clearly() {
        use crate::encryption::{generate_salt, EncryptionKey};
        use tempfile::NamedTempFile;

        let temp_db = NamedTempFile::new().unwrap();
        let db_path = temp_db.path().to_str().unwrap();

        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();

        // Create encrypted database
        let db = SyncEngineDb::init_with_encryption(db_path, key)
            .await
            .unwrap();
        db.enqueue_envelope(&mock_envelope(1), "GTEST", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        drop(db);

        // Try to open as unencrypted - should fail when trying to decrypt
        let db_unencrypted = SyncEngineDb::init(db_path).await.unwrap();
        let result = db_unencrypted.get_queued_envelope([1u8; 32]).await;

        // Should get a deserialization error (can't decrypt without key)
        assert!(
            result.is_err() || result.unwrap().is_none(),
            "Expected error or None when reading encrypted DB without key"
        );
    }

    // ── Issue 14: multi-table atomic transaction tests ────────────────────────

    #[tokio::test]
    async fn test_transaction_commits_all_or_nothing_on_success() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let envelope = mock_envelope(77);
        let envelope_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let conflict = Conflict {
            source_account: "GATOMIC".to_string(),
            sequence: 500,
            envelope_a: [77u8; 32],
            envelope_b: [78u8; 32],
        };
        let conflict_clone = conflict.clone();

        db.transaction(move |tx| {
            SyncEngineDb::save_sequence_reservation_in_tx(tx, "GATOMIC", 500)?;
            tx.execute(
                "INSERT INTO queued_envelopes
                    (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    envelope.message_id.to_vec(),
                    "GATOMIC",
                    500i64,
                    i64::from(TxPriority::Emergency),
                    1_234i64,
                    envelope_bytes,
                ],
            )?;
            SyncEngineDb::set_settlement_status_in_tx(
                tx,
                [77u8; 32],
                SettlementStatus::Queued,
                1_234,
            )?;
            SyncEngineDb::record_conflict_in_tx(tx, &conflict_clone, 1_234)?;
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(
            db.load_sequence_reservation("GATOMIC").await.unwrap(),
            Some(500)
        );
        let queued = db.get_queued_envelope([77u8; 32]).await.unwrap().unwrap();
        assert_eq!(queued.source_account, "GATOMIC");
        assert_eq!(queued.sequence, 500);
        assert_eq!(
            db.get_settlement_status([77u8; 32]).await.unwrap(),
            Some(SettlementStatus::Queued)
        );
        assert_eq!(db.history_for([77u8; 32]).await.unwrap().len(), 1);
        assert_eq!(
            db.list_unresolved_conflicts().await.unwrap(),
            vec![conflict]
        );
    }

    #[tokio::test]
    async fn test_transaction_rolls_back_all_on_failure() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let envelope = mock_envelope(88);
        let envelope_bytes = rmp_serde::to_vec(&envelope).unwrap();

        // First statement succeeds (inserts sequence reservation and queued_envelopes),
        // third statement fails with a UNIQUE constraint violation on settlement_status.
        let result: Result<(), SyncEngineError> = db
            .transaction(move |tx| {
                SyncEngineDb::save_sequence_reservation_in_tx(tx, "GROLLBACK", 900)?;
                tx.execute(
                    "INSERT INTO queued_envelopes
                        (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        envelope.message_id.to_vec(),
                        "GROLLBACK",
                        900i64,
                        i64::from(TxPriority::Normal),
                        2_000i64,
                        envelope_bytes,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO settlement_status (message_id, status, updated_at)
                     VALUES (?1, 'queued', 2000)",
                    rusqlite::params![envelope.message_id.to_vec()],
                )?;
                // Intentional PRIMARY KEY violation on the same message_id without OR REPLACE:
                tx.execute(
                    "INSERT INTO settlement_status (message_id, status, updated_at)
                     VALUES (?1, 'propagating', 2001)",
                    rusqlite::params![envelope.message_id.to_vec()],
                )?;
                Ok(())
            })
            .await;

        assert!(
            matches!(result, Err(SyncEngineError::SqliteError(_))),
            "expected SqliteError from constraint violation, got {result:?}"
        );

        // Every prior write inside the failed transaction must be rolled back.
        assert_eq!(
            db.load_sequence_reservation("GROLLBACK").await.unwrap(),
            None
        );
        assert!(db.get_queued_envelope([88u8; 32]).await.unwrap().is_none());
        assert_eq!(db.get_settlement_status([88u8; 32]).await.unwrap(), None);
        assert_eq!(db.summary().await.unwrap(), DbSummary::default());
    }

    #[tokio::test]
    async fn test_concurrent_transactions_do_not_corrupt_state() {
        let db = std::sync::Arc::new(SyncEngineDb::init(":memory:").await.unwrap());
        let mut handles = Vec::new();

        for i in 0u8..16u8 {
            let db_clone = db.clone();
            handles.push(tokio::spawn(async move {
                let account = format!("GCONC_{i}");
                let seq = i64::from(i) + 1;
                let mut msg_id = [0u8; 32];
                msg_id[0] = i;
                let mut env = mock_envelope(i);
                env.message_id = msg_id;

                db_clone
                    .enqueue_transaction(
                        &env,
                        &account,
                        seq,
                        TxPriority::Normal,
                        5_000 + u64::from(i),
                    )
                    .await
                    .unwrap();

                // Also run a failing transaction concurrently to ensure rollbacks
                // interleave cleanly with commits.
                let _: Result<(), SyncEngineError> = db_clone
                    .transaction(move |tx| {
                        SyncEngineDb::save_sequence_reservation_in_tx(tx, "GFAIL_TEMP", 999)?;
                        Err(SyncEngineError::InvalidEnvelope("simulated failure".into()))
                    })
                    .await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let summary = db.summary().await.unwrap();
        assert_eq!(summary.queued_envelopes_count, 16);
        assert_eq!(summary.settlement_status_count, 16);
        assert_eq!(summary.sequence_reservations_count, 16);
        assert_eq!(
            db.load_sequence_reservation("GFAIL_TEMP").await.unwrap(),
            None
        );
    }
}
