//! Durable acknowledgement proof for draft creation.
//!
//! This module records only the information needed to decide whether an APPEND
//! may run again. It deliberately does not compose drafts or persist email
//! content. The caller must hold the installation's account writer lock from
//! before [`DraftJournal::prepare`] through outcome recording. SQLite provides
//! durable state, but cannot own the network side effect or recover a live
//! writer safely.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{fmt, path::Path, time::Duration};
use uuid::Uuid;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEMA_VERSION: i64 = 1;

/// The immutable identity of a draft operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftOperationIdentity {
    pub account_id: Uuid,
    pub account_generation: u64,
    pub operation_id: Uuid,
}

/// The immutable facts that allow a prepared operation to be dispatched.
///
/// `mailbox_identity` is an opaque mailbox identity, never a mutable Drafts
/// alias. `content_sha256` is the hash of frozen MIME bytes; callers retain the
/// bytes and composition input needed to reconstruct them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedDraftOperation {
    pub identity: DraftOperationIdentity,
    pub mailbox_identity: String,
    pub content_sha256: [u8; 32],
}

/// A server-provided identity for a created message, when APPENDUID was present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendedMessageIdentity {
    pub uid_validity: u32,
    pub uid: u32,
}

/// The durable acknowledgement state of a draft operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftOperationState {
    Prepared,
    InFlight,
    Created {
        appended_message: Option<AppendedMessageIdentity>,
    },
    Rejected,
    OutcomeUnknown,
}

/// An immutable operation together with its durable state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedDraftOperation {
    pub operation: PreparedDraftOperation,
    pub state: DraftOperationState,
}

/// Errors intentionally omit SQLite's raw messages and the database path.
///
/// A failure while persisting `Created` after APPEND acknowledgement is not a
/// signal to retry. The caller must retain an uncertain result and use its
/// separately authorized reconciliation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftJournalError {
    Unavailable,
    InvalidDatabase,
    InvalidOperation,
    OperationConflict,
    OperationNotPrepared,
    NotDispatchable(DraftOperationState),
}

impl fmt::Display for DraftJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "The draft journal is unavailable",
            Self::InvalidDatabase => "The draft journal is invalid",
            Self::InvalidOperation => "The draft operation is invalid",
            Self::OperationConflict => "The draft operation conflicts with its recorded input",
            Self::OperationNotPrepared => "The draft operation was not prepared",
            Self::NotDispatchable(DraftOperationState::InFlight) => {
                "The draft operation is already in progress"
            }
            Self::NotDispatchable(DraftOperationState::Created { .. }) => {
                "The draft operation was already acknowledged"
            }
            Self::NotDispatchable(DraftOperationState::Rejected) => {
                "The draft operation was rejected"
            }
            Self::NotDispatchable(DraftOperationState::OutcomeUnknown) => {
                "The draft operation has an uncertain outcome"
            }
            Self::NotDispatchable(DraftOperationState::Prepared) => {
                "The draft operation cannot be dispatched"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DraftJournalError {}

/// A local SQLite journal for the acknowledgement boundary around APPEND.
///
/// The caller owns authorization and the OS-backed account writer lock. Hold
/// that lock across `prepare`, `begin_dispatch`, network I/O, and the matching
/// outcome method. Do not call the transition methods during recovery without
/// proving that the previous writer no longer owns the account.
pub struct DraftJournal {
    connection: Connection,
}

impl DraftJournal {
    /// Opens a local journal and verifies WAL, FULL synchronous mode, and a
    /// finite SQLite busy timeout before exposing it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DraftJournalError> {
        let mut connection = Connection::open(path).map_err(unavailable)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(unavailable)?;
        let tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type IN ('table', 'index', 'trigger', 'view')",
                [],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        match (version, tables) {
            (0, 0) => initialize_schema(&mut connection)?,
            (SCHEMA_VERSION, _) if schema_is_current(&connection)? => {}
            _ => return Err(DraftJournalError::InvalidDatabase),
        }

        connection.busy_timeout(BUSY_TIMEOUT).map_err(unavailable)?;

        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(unavailable)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(DraftJournalError::Unavailable);
        }

        connection
            .execute_batch("PRAGMA synchronous = FULL")
            .map_err(unavailable)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(unavailable)?;
        if synchronous != 2 {
            return Err(DraftJournalError::Unavailable);
        }

        Ok(Self { connection })
    }

    /// Persists a dispatchable operation, or returns its exact prior state.
    ///
    /// Reusing an operation UUID is permitted only when every frozen fact is
    /// identical. This method never changes a prior state.
    pub fn prepare(
        &mut self,
        operation: PreparedDraftOperation,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        validate_operation(&operation)?;
        let account_generation = sqlite_generation(operation.identity.account_generation)?;
        let transaction = self.connection.transaction().map_err(unavailable)?;
        transaction
            .execute(
                "
                INSERT INTO draft_operations (
                    operation_id, account_id, account_generation, mailbox_identity,
                    content_sha256, state, appended_uid_validity, appended_uid
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', NULL, NULL)
                ON CONFLICT(account_id, account_generation, operation_id) DO NOTHING
                ",
                params![
                    operation.identity.operation_id.as_bytes().as_slice(),
                    operation.identity.account_id.as_bytes().as_slice(),
                    account_generation,
                    operation.mailbox_identity,
                    operation.content_sha256.as_slice(),
                ],
            )
            .map_err(unavailable)?;
        let persisted = read_by_identity(&transaction, &operation.identity)?
            .ok_or(DraftJournalError::InvalidDatabase)?;
        if persisted.operation != operation {
            return Err(DraftJournalError::OperationConflict);
        }
        transaction.commit().map_err(unavailable)?;
        Ok(persisted)
    }

    /// Atomically marks a prepared operation as in flight before APPEND bytes
    /// are allowed on the transport.
    pub fn begin_dispatch(
        &mut self,
        operation: &PreparedDraftOperation,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        validate_operation(operation)?;
        let account_generation = sqlite_generation(operation.identity.account_generation)?;
        let transaction = self.connection.transaction().map_err(unavailable)?;
        let persisted = read_by_identity(&transaction, &operation.identity)?
            .ok_or(DraftJournalError::OperationNotPrepared)?;
        if persisted.operation != *operation {
            return Err(DraftJournalError::OperationConflict);
        }
        if persisted.state != DraftOperationState::Prepared {
            return Err(DraftJournalError::NotDispatchable(persisted.state));
        }
        let changed = transaction
            .execute(
                "UPDATE draft_operations SET state = 'in_flight'
                 WHERE account_id = ?1 AND account_generation = ?2 AND operation_id = ?3
                   AND state = 'prepared'",
                params![
                    operation.identity.account_id.as_bytes().as_slice(),
                    account_generation,
                    operation.identity.operation_id.as_bytes().as_slice(),
                ],
            )
            .map_err(unavailable)?;
        if changed != 1 {
            return Err(DraftJournalError::NotDispatchable(
                DraftOperationState::InFlight,
            ));
        }
        transaction.commit().map_err(unavailable)?;
        Ok(PersistedDraftOperation {
            operation: operation.clone(),
            state: DraftOperationState::InFlight,
        })
    }

    /// Records tagged APPEND success. An absent APPENDUID remains a creation.
    pub fn record_created(
        &mut self,
        identity: &DraftOperationIdentity,
        appended_message: Option<AppendedMessageIdentity>,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        self.record_outcome(identity, DraftOperationState::Created { appended_message })
    }

    /// Records a definitive server rejection.
    pub fn record_rejected(
        &mut self,
        identity: &DraftOperationIdentity,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        self.record_outcome(identity, DraftOperationState::Rejected)
    }

    /// Records an uncertain result, including local disconnect or cancellation.
    /// The operation remains non-dispatchable after reopening the journal.
    pub fn record_outcome_unknown(
        &mut self,
        identity: &DraftOperationIdentity,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        self.record_outcome(identity, DraftOperationState::OutcomeUnknown)
    }

    /// Reads a persisted operation without dispatching or recovering it.
    pub fn inspect(
        &self,
        identity: &DraftOperationIdentity,
    ) -> Result<Option<PersistedDraftOperation>, DraftJournalError> {
        read_by_identity(&self.connection, identity)
    }

    fn record_outcome(
        &mut self,
        identity: &DraftOperationIdentity,
        outcome: DraftOperationState,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        let (state, appended_message) = match outcome {
            DraftOperationState::Created { appended_message } => ("created", appended_message),
            DraftOperationState::Rejected => ("rejected", None),
            DraftOperationState::OutcomeUnknown => ("outcome_unknown", None),
            DraftOperationState::Prepared | DraftOperationState::InFlight => {
                return Err(DraftJournalError::InvalidOperation);
            }
        };
        if appended_message.is_some_and(|identity| identity.uid == 0 || identity.uid_validity == 0)
        {
            return Err(DraftJournalError::InvalidOperation);
        }
        let account_generation = sqlite_generation(identity.account_generation)?;
        let transaction = self.connection.transaction().map_err(unavailable)?;
        let persisted = read_by_identity(&transaction, identity)?
            .ok_or(DraftJournalError::OperationNotPrepared)?;
        if persisted.state != DraftOperationState::InFlight {
            return Err(DraftJournalError::NotDispatchable(persisted.state));
        }
        let changed = transaction
            .execute(
                "
                UPDATE draft_operations
                SET state = ?4, appended_uid_validity = ?5, appended_uid = ?6
                WHERE account_id = ?1 AND account_generation = ?2 AND operation_id = ?3
                  AND state = 'in_flight'
                ",
                params![
                    identity.account_id.as_bytes().as_slice(),
                    account_generation,
                    identity.operation_id.as_bytes().as_slice(),
                    state,
                    appended_message.map(|identity| i64::from(identity.uid_validity)),
                    appended_message.map(|identity| i64::from(identity.uid)),
                ],
            )
            .map_err(unavailable)?;
        if changed != 1 {
            return Err(DraftJournalError::NotDispatchable(
                DraftOperationState::InFlight,
            ));
        }
        transaction.commit().map_err(unavailable)?;
        Ok(PersistedDraftOperation {
            operation: persisted.operation,
            state: outcome,
        })
    }
}

fn initialize_schema(connection: &mut Connection) -> Result<(), DraftJournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    transaction
        .execute_batch(
            "
                CREATE TABLE draft_operations (
                    operation_id BLOB NOT NULL CHECK(length(operation_id) = 16),
                    account_id BLOB NOT NULL CHECK(length(account_id) = 16),
                    account_generation INTEGER NOT NULL CHECK(account_generation >= 0),
                    mailbox_identity TEXT NOT NULL CHECK(
                        length(mailbox_identity) > 0 AND length(mailbox_identity) <= 4096
                    ),
                    content_sha256 BLOB NOT NULL CHECK(length(content_sha256) = 32),
                    state TEXT NOT NULL CHECK(state IN (
                        'prepared', 'in_flight', 'created', 'rejected', 'outcome_unknown'
                    )),
                    appended_uid_validity INTEGER,
                    appended_uid INTEGER,
                    CHECK((appended_uid_validity IS NULL) = (appended_uid IS NULL)),
                    CHECK(
                        appended_uid_validity IS NULL
                        OR (
                            state = 'created'
                            AND appended_uid_validity > 0
                            AND appended_uid > 0
                        )
                    ),
                    PRIMARY KEY (account_id, account_generation, operation_id)
                );
                PRAGMA user_version = 1;
            ",
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)
}

struct DatabaseRow {
    operation_id: Vec<u8>,
    account_id: Vec<u8>,
    account_generation: i64,
    mailbox_identity: String,
    content_sha256: Vec<u8>,
    state: String,
    appended_uid_validity: Option<i64>,
    appended_uid: Option<i64>,
}

fn schema_is_current(connection: &Connection) -> Result<bool, DraftJournalError> {
    let expected = [
        ("operation_id", "BLOB", 1, 3),
        ("account_id", "BLOB", 1, 1),
        ("account_generation", "INTEGER", 1, 2),
        ("mailbox_identity", "TEXT", 1, 0),
        ("content_sha256", "BLOB", 1, 0),
        ("state", "TEXT", 1, 0),
        ("appended_uid_validity", "INTEGER", 0, 0),
        ("appended_uid", "INTEGER", 0, 0),
    ];
    let mut statement = connection
        .prepare("PRAGMA table_info(draft_operations)")
        .map_err(unavailable)?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(unavailable)?;
    let columns = columns
        .collect::<Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    Ok(columns.len() == expected.len()
        && columns.iter().zip(expected).all(
            |(
                (name, ty, not_null, primary_key),
                (expected_name, expected_ty, expected_not_null, expected_primary_key),
            )| {
                name == expected_name
                    && ty.eq_ignore_ascii_case(expected_ty)
                    && *not_null == expected_not_null
                    && *primary_key == expected_primary_key
            },
        ))
}

fn read_by_identity(
    connection: &Connection,
    identity: &DraftOperationIdentity,
) -> Result<Option<PersistedDraftOperation>, DraftJournalError> {
    let account_generation = sqlite_generation(identity.account_generation)?;
    let row = connection
        .query_row(
            "
            SELECT operation_id, account_id, account_generation, mailbox_identity,
                   content_sha256, state, appended_uid_validity, appended_uid
            FROM draft_operations
            WHERE account_id = ?1 AND account_generation = ?2 AND operation_id = ?3
            ",
            params![
                identity.account_id.as_bytes().as_slice(),
                account_generation,
                identity.operation_id.as_bytes().as_slice(),
            ],
            |row| {
                Ok(DatabaseRow {
                    operation_id: row.get(0)?,
                    account_id: row.get(1)?,
                    account_generation: row.get(2)?,
                    mailbox_identity: row.get(3)?,
                    content_sha256: row.get(4)?,
                    state: row.get(5)?,
                    appended_uid_validity: row.get(6)?,
                    appended_uid: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(unavailable)?;
    row.map(decode_row).transpose()
}

fn decode_row(row: DatabaseRow) -> Result<PersistedDraftOperation, DraftJournalError> {
    let operation_id =
        Uuid::from_slice(&row.operation_id).map_err(|_| DraftJournalError::InvalidDatabase)?;
    let account_id =
        Uuid::from_slice(&row.account_id).map_err(|_| DraftJournalError::InvalidDatabase)?;
    let account_generation =
        u64::try_from(row.account_generation).map_err(|_| DraftJournalError::InvalidDatabase)?;
    let content_sha256: [u8; 32] = row
        .content_sha256
        .try_into()
        .map_err(|_| DraftJournalError::InvalidDatabase)?;
    let appended_message = match (row.appended_uid_validity, row.appended_uid) {
        (None, None) => None,
        (Some(uid_validity), Some(uid)) => {
            let uid_validity =
                u32::try_from(uid_validity).map_err(|_| DraftJournalError::InvalidDatabase)?;
            let uid = u32::try_from(uid).map_err(|_| DraftJournalError::InvalidDatabase)?;
            if uid_validity == 0 || uid == 0 {
                return Err(DraftJournalError::InvalidDatabase);
            }
            Some(AppendedMessageIdentity { uid_validity, uid })
        }
        _ => return Err(DraftJournalError::InvalidDatabase),
    };
    if row.mailbox_identity.is_empty() || row.mailbox_identity.chars().count() > 4096 {
        return Err(DraftJournalError::InvalidDatabase);
    }
    let state = match row.state.as_str() {
        "prepared" if appended_message.is_none() => DraftOperationState::Prepared,
        "in_flight" if appended_message.is_none() => DraftOperationState::InFlight,
        "created" => DraftOperationState::Created { appended_message },
        "rejected" if appended_message.is_none() => DraftOperationState::Rejected,
        "outcome_unknown" if appended_message.is_none() => DraftOperationState::OutcomeUnknown,
        _ => return Err(DraftJournalError::InvalidDatabase),
    };
    Ok(PersistedDraftOperation {
        operation: PreparedDraftOperation {
            identity: DraftOperationIdentity {
                account_id,
                account_generation,
                operation_id,
            },
            mailbox_identity: row.mailbox_identity,
            content_sha256,
        },
        state,
    })
}

fn validate_operation(operation: &PreparedDraftOperation) -> Result<(), DraftJournalError> {
    if operation.mailbox_identity.is_empty() || operation.mailbox_identity.chars().count() > 4096 {
        return Err(DraftJournalError::InvalidOperation);
    }
    sqlite_generation(operation.identity.account_generation)?;
    Ok(())
}

fn sqlite_generation(generation: u64) -> Result<i64, DraftJournalError> {
    i64::try_from(generation).map_err(|_| DraftJournalError::InvalidDatabase)
}

fn unavailable(_: rusqlite::Error) -> DraftJournalError {
    DraftJournalError::Unavailable
}
