//! Durable acknowledgement proof for draft creation.
//!
//! This module records only the information needed to decide whether an APPEND
//! may run again. It deliberately does not compose drafts or persist email
//! content. The caller must hold the installation's account writer lock from
//! before [`DraftJournal::prepare`] through outcome recording. SQLite provides
//! durable state, but cannot own the network side effect or recover a live
//! writer safely.

use crate::draft::DraftMessageIdentity;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    fmt,
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEMA_VERSION: i64 = 3;

pub use crate::domain::DraftIdentity as DraftOperationIdentity;

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
    pub reconstruction: Option<DraftReconstruction>,
}

/// Frozen, content-free parameters for deterministic reconstruction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftReconstruction {
    pub uid_validity: u32,
    pub input_sha256: [u8; 32],
    pub from_configuration_sha256: [u8; 32],
    #[serde(default)]
    pub selected_from_sha256: Option<[u8; 32]>,
    pub date_unix: i64,
    pub encoder_version: u32,
}

/// The durable acknowledgement state of a draft operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftOperationState {
    Prepared,
    InFlight,
    Created {
        appended_message: Option<DraftMessageIdentity>,
    },
    Duplicate {
        appended_message: DraftMessageIdentity,
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
    Full,
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
            Self::Full => "The draft journal is full",
            Self::InvalidDatabase => "The draft journal is invalid",
            Self::InvalidOperation => "The draft operation is invalid",
            Self::OperationConflict => "The draft operation conflicts with its recorded input",
            Self::OperationNotPrepared => "The draft operation was not prepared",
            Self::NotDispatchable(DraftOperationState::InFlight) => {
                "The draft operation is already in progress"
            }
            Self::NotDispatchable(
                DraftOperationState::Created { .. } | DraftOperationState::Duplicate { .. },
            ) => "The draft operation was already acknowledged",
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
/// Journal paths must not contain symbolic links, including parent directories.
pub struct DraftJournal {
    connection: Connection,
}

impl DraftJournal {
    /// Opens a local journal and verifies WAL, FULL synchronous mode, and a
    /// finite SQLite busy timeout before exposing it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DraftJournalError> {
        Self::connect(path.as_ref(), true, BUSY_TIMEOUT)
    }
    /// Opens existing history without creating or migrating a database.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, DraftJournalError> {
        Self::connect(path.as_ref(), false, BUSY_TIMEOUT)
    }
    /// Runtime calls fail immediately on SQLite contention; async account leases
    /// own waiting, and SQLite must not sleep inside an async executor poll.
    pub fn open_existing_nowait(path: impl AsRef<Path>) -> Result<Self, DraftJournalError> {
        Self::connect(path.as_ref(), false, Duration::ZERO)
    }
    fn connect(
        path: &Path,
        initialize: bool,
        busy_timeout: Duration,
    ) -> Result<Self, DraftJournalError> {
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
            | if initialize {
                rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            } else {
                rusqlite::OpenFlags::empty()
            };
        let mut connection = Connection::open_with_flags(path, flags).map_err(unavailable)?;
        connection.busy_timeout(busy_timeout).map_err(unavailable)?;
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
            (0, 0) if initialize => initialize_schema(&mut connection)?,
            (SCHEMA_VERSION, _) if schema_is_current(&connection)? => {}
            _ => return Err(DraftJournalError::InvalidDatabase),
        }

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

    /// Check admission for a new record without changing retained outcomes.
    pub fn check_capacity(&self, maximum: usize) -> Result<(), DraftJournalError> {
        check_capacity(&self.connection, maximum)
    }
    /// Check all retained rows and the reconstruction needed by prepared work.
    /// Run offline under exclusive installation maintenance before an upgrade.
    pub fn verify(&self) -> Result<(), DraftJournalError> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(unavailable)?;
        if integrity != "ok" {
            return Err(DraftJournalError::InvalidDatabase);
        }
        self.verify_rows(None, usize::MAX)
    }
    /// Bound pre-dispatch verification by time and the supported history ceiling.
    /// Call on a blocking worker; inspection alone never needs a full scan.
    pub fn verify_for_dispatch(
        &self,
        deadline: Instant,
        maximum: usize,
    ) -> Result<(), DraftJournalError> {
        self.verify_rows(Some(deadline), maximum)
    }
    fn verify_rows(
        &self,
        deadline: Option<Instant>,
        maximum: usize,
    ) -> Result<(), DraftJournalError> {
        let mut statement = self.connection.prepare("SELECT operation_id, account_id, account_generation, mailbox_identity, content_sha256, reconstruction, state, appended_uid_validity, appended_uid FROM draft_operations").map_err(unavailable)?;
        let mut rows = statement.query([]).map_err(unavailable)?;
        let mut count = 0;
        loop {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(DraftJournalError::Unavailable);
            }
            let Some(row) = rows.next().map_err(unavailable)? else {
                break;
            };
            count += 1;
            if count > maximum {
                return Err(DraftJournalError::Unavailable);
            }
            let operation = decode_row(database_row(row).map_err(unavailable)?)?;
            if operation.state == DraftOperationState::Prepared
                && operation
                    .operation
                    .reconstruction
                    .as_ref()
                    .is_none_or(|frozen| {
                        frozen.encoder_version != crate::draft::ENCODER_VERSION
                            || frozen.uid_validity == 0
                            || frozen.selected_from_sha256.is_none()
                    })
            {
                return Err(DraftJournalError::InvalidOperation);
            }
        }
        Ok(())
    }

    /// Copies a consistent database, including committed WAL state. The caller
    /// holds exclusive installation maintenance and supplies a new private file.
    pub fn snapshot(&self, destination: &Path) -> Result<(), DraftJournalError> {
        self.connection
            .execute(
                "VACUUM main INTO ?1",
                [destination.to_str().ok_or(DraftJournalError::Unavailable)?],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    /// Persists a dispatchable operation, or returns its exact prior state.
    ///
    /// Reusing an operation UUID is permitted only when every frozen fact is
    /// identical. This method never changes a prior state.
    pub fn prepare(
        &mut self,
        operation: PreparedDraftOperation,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        self.prepare_with_limit(operation, 1_000_000)
    }
    pub fn prepare_with_limit(
        &mut self,
        operation: PreparedDraftOperation,
        maximum: usize,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        validate_operation(&operation)?;
        let account_generation = sqlite_generation(operation.identity.account_generation)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        if let Some(persisted) = read_by_identity(&transaction, &operation.identity)? {
            if persisted.operation != operation {
                return Err(DraftJournalError::OperationConflict);
            }
            transaction.commit().map_err(unavailable)?;
            return Ok(persisted);
        }
        check_capacity(&transaction, maximum)?;
        transaction
            .execute(
                "
                INSERT INTO draft_operations (
                    operation_id, account_id, account_generation, mailbox_identity,
                    content_sha256, reconstruction, state, appended_uid_validity, appended_uid
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared', NULL, NULL)
                ",
                params![
                    operation.identity.operation_id.as_bytes().as_slice(),
                    operation.identity.account_id.as_bytes().as_slice(),
                    account_generation,
                    operation.mailbox_identity,
                    operation.content_sha256.as_slice(),
                    operation
                        .reconstruction
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|_| DraftJournalError::InvalidOperation)?,
                ],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        Ok(PersistedDraftOperation {
            operation,
            state: DraftOperationState::Prepared,
        })
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
            operation: persisted.operation,
            state: DraftOperationState::InFlight,
        })
    }

    /// Records tagged APPEND success. An absent APPENDUID remains a creation.
    pub fn record_created(
        &mut self,
        identity: &DraftOperationIdentity,
        appended_message: Option<DraftMessageIdentity>,
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

    /// Records independent verification while the caller holds the account writer lock.
    pub fn record_duplicate(
        &mut self,
        identity: &DraftOperationIdentity,
        appended_message: DraftMessageIdentity,
    ) -> Result<PersistedDraftOperation, DraftJournalError> {
        self.record_outcome(
            identity,
            DraftOperationState::Duplicate { appended_message },
        )
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
            DraftOperationState::Duplicate { appended_message } => {
                ("duplicate", Some(appended_message))
            }
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
        let (expected, expected_name) = if matches!(outcome, DraftOperationState::Duplicate { .. })
        {
            (DraftOperationState::OutcomeUnknown, "outcome_unknown")
        } else {
            (DraftOperationState::InFlight, "in_flight")
        };
        if persisted.state != expected {
            return Err(DraftJournalError::NotDispatchable(persisted.state));
        }
        let changed = transaction
            .execute(
                "
                UPDATE draft_operations
                SET state = ?4, appended_uid_validity = ?5, appended_uid = ?6
                WHERE account_id = ?1 AND account_generation = ?2 AND operation_id = ?3
                  AND state = ?7
                ",
                params![
                    identity.account_id.as_bytes().as_slice(),
                    account_generation,
                    identity.operation_id.as_bytes().as_slice(),
                    state,
                    appended_message.map(|identity| i64::from(identity.uid_validity)),
                    appended_message.map(|identity| i64::from(identity.uid)),
                    expected_name,
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

fn check_capacity(connection: &Connection, maximum: usize) -> Result<(), DraftJournalError> {
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM draft_operations", [], |row| {
            row.get(0)
        })
        .map_err(unavailable)?;
    if u64::try_from(count).map_err(|_| DraftJournalError::InvalidDatabase)? >= maximum as u64 {
        Err(DraftJournalError::Full)
    } else {
        Ok(())
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
                    reconstruction TEXT,
                    state TEXT NOT NULL CHECK(state IN (
                        'prepared', 'in_flight', 'created', 'rejected', 'outcome_unknown', 'duplicate'
                    )),
                    appended_uid_validity INTEGER,
                    appended_uid INTEGER,
                    CHECK((appended_uid_validity IS NULL) = (appended_uid IS NULL)),
                    CHECK(
                        appended_uid_validity IS NULL
                        OR (
                            state IN ('created', 'duplicate')
                            AND appended_uid_validity > 0
                            AND appended_uid > 0
                        )
                    ),
                    PRIMARY KEY (account_id, account_generation, operation_id)
                );
                PRAGMA user_version = 3;
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
    reconstruction: Option<String>,
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
        ("reconstruction", "TEXT", 0, 0),
        ("state", "TEXT", 1, 0),
        ("appended_uid_validity", "INTEGER", 0, 0),
        ("appended_uid", "INTEGER", 0, 0),
    ];
    let mut statement = connection
        .prepare("PRAGMA table_info(draft_operations)")
        .map_err(unavailable)?;
    let mut columns = statement.query([]).map_err(unavailable)?;
    for (name, ty, not_null, primary_key) in expected {
        let Some(column) = columns.next().map_err(unavailable)? else {
            return Ok(false);
        };
        if column.get::<_, String>(1).map_err(unavailable)? != name
            || !column
                .get::<_, String>(2)
                .map_err(unavailable)?
                .eq_ignore_ascii_case(ty)
            || column.get::<_, i64>(3).map_err(unavailable)? != not_null
            || column.get::<_, i64>(5).map_err(unavailable)? != primary_key
        {
            return Ok(false);
        }
    }
    Ok(columns.next().map_err(unavailable)?.is_none())
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
                   content_sha256, reconstruction, state, appended_uid_validity, appended_uid
            FROM draft_operations
            WHERE account_id = ?1 AND account_generation = ?2 AND operation_id = ?3
            ",
            params![
                identity.account_id.as_bytes().as_slice(),
                account_generation,
                identity.operation_id.as_bytes().as_slice(),
            ],
            database_row,
        )
        .optional()
        .map_err(unavailable)?;
    row.map(decode_row).transpose()
}

fn database_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatabaseRow> {
    Ok(DatabaseRow {
        operation_id: row.get(0)?,
        account_id: row.get(1)?,
        account_generation: row.get(2)?,
        mailbox_identity: row.get(3)?,
        content_sha256: row.get(4)?,
        reconstruction: row.get(5)?,
        state: row.get(6)?,
        appended_uid_validity: row.get(7)?,
        appended_uid: row.get(8)?,
    })
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
            Some(DraftMessageIdentity { uid_validity, uid })
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
        "duplicate" => DraftOperationState::Duplicate {
            appended_message: appended_message.ok_or(DraftJournalError::InvalidDatabase)?,
        },
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
            reconstruction: row
                .reconstruction
                .map(|s| serde_json::from_str(&s).map_err(|_| DraftJournalError::InvalidDatabase))
                .transpose()?,
        },
        state,
    })
}

fn validate_operation(operation: &PreparedDraftOperation) -> Result<(), DraftJournalError> {
    if operation.mailbox_identity.is_empty() || operation.mailbox_identity.chars().count() > 4096 {
        return Err(DraftJournalError::InvalidOperation);
    }
    Ok(())
}

fn sqlite_generation(generation: u64) -> Result<i64, DraftJournalError> {
    i64::try_from(generation).map_err(|_| DraftJournalError::InvalidDatabase)
}

fn unavailable(error: rusqlite::Error) -> DraftJournalError {
    match error {
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::Utf8Error(..) => DraftJournalError::InvalidDatabase,
        rusqlite::Error::SqliteFailure(error, _)
            if matches!(
                error.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            DraftJournalError::InvalidDatabase
        }
        _ => DraftJournalError::Unavailable,
    }
}
