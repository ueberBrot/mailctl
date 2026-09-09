use mailctl::draft_journal::{
    AppendedMessageIdentity, DraftJournal, DraftJournalError, DraftOperationIdentity,
    DraftOperationState, PreparedDraftOperation,
};
use rusqlite::{Connection, params};
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

struct TemporaryJournal {
    path: PathBuf,
}

impl TemporaryJournal {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir()
                .join(format!("mailctl-draft-journal-{}.sqlite", Uuid::new_v4())),
        }
    }
}

impl Drop for TemporaryJournal {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = if suffix.is_empty() {
                self.path.clone()
            } else {
                PathBuf::from(format!("{}{suffix}", self.path.display()))
            };
            let _ = fs::remove_file(path);
        }
    }
}

fn operation(
    account_id: Uuid,
    generation: u64,
    operation_id: Uuid,
    hash: u8,
) -> PreparedDraftOperation {
    PreparedDraftOperation {
        identity: DraftOperationIdentity {
            account_id,
            account_generation: generation,
            operation_id,
        },
        mailbox_identity: "mailbox-opaque-id".into(),
        content_sha256: [hash; 32],
    }
}

fn child_operation() -> PreparedDraftOperation {
    operation(Uuid::from_u128(1), 1, Uuid::from_u128(2), 12)
}

fn run_abort_child(temporary: &TemporaryJournal, outcome: &str) {
    let executable = env::current_exe().unwrap();
    let mut child = Command::new(executable)
        .args([
            "--exact",
            "subprocess_death_preserves_committed_journal_state",
            "--nocapture",
        ])
        .env("MAILCTL_DRAFT_JOURNAL_CHILD_PATH", &temporary.path)
        .env("MAILCTL_DRAFT_JOURNAL_CHILD_OUTCOME", outcome)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (ready, received) = mpsc::sync_channel(1);
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) if line == "journal child ready" => {
                    let _ = ready.send(true);
                    return;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = ready.send(false);
    });
    let is_ready = received
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or(false);
    if !is_ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("journal child did not become ready");
    }
    assert_child_exits_within(&mut child, Duration::from_secs(5));
}

fn assert_child_exits_within(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("journal child did not exit after aborting");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn acknowledged_creation_without_appenduid_persists_and_never_redispatches() {
    let temporary = TemporaryJournal::new();
    let prepared = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 1);
    let mut journal = DraftJournal::open(&temporary.path).unwrap();

    assert_eq!(
        journal.prepare(prepared.clone()).unwrap().state,
        DraftOperationState::Prepared
    );
    assert_eq!(
        journal.begin_dispatch(&prepared).unwrap().state,
        DraftOperationState::InFlight
    );
    assert_eq!(
        journal
            .record_created(&prepared.identity, None)
            .unwrap()
            .state,
        DraftOperationState::Created {
            appended_message: None
        }
    );
    drop(journal);

    let mut reopened = DraftJournal::open(&temporary.path).unwrap();
    assert_eq!(
        reopened.inspect(&prepared.identity).unwrap().unwrap().state,
        DraftOperationState::Created {
            appended_message: None
        }
    );
    assert_eq!(
        reopened.begin_dispatch(&prepared),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::Created {
                appended_message: None
            }
        ))
    );
}

#[test]
fn cancellation_is_durable_uncertainty_after_reopening() {
    let temporary = TemporaryJournal::new();
    let prepared = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 2);
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    journal.prepare(prepared.clone()).unwrap();
    journal.begin_dispatch(&prepared).unwrap();
    journal.record_outcome_unknown(&prepared.identity).unwrap();
    drop(journal);

    let mut reopened = DraftJournal::open(&temporary.path).unwrap();
    assert_eq!(
        reopened.inspect(&prepared.identity).unwrap().unwrap().state,
        DraftOperationState::OutcomeUnknown
    );
    assert_eq!(
        reopened.begin_dispatch(&prepared),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::OutcomeUnknown
        ))
    );
}

#[test]
fn full_identity_tuple_allows_the_same_operation_uuid_for_distinct_history() {
    let temporary = TemporaryJournal::new();
    let operation_id = Uuid::new_v4();
    let first = operation(Uuid::new_v4(), 1, operation_id, 3);
    let second = operation(Uuid::new_v4(), 1, operation_id, 4);
    let later_generation = operation(first.identity.account_id, 2, operation_id, 5);
    let mut journal = DraftJournal::open(&temporary.path).unwrap();

    for prepared in [&first, &second, &later_generation] {
        assert_eq!(
            journal.prepare(prepared.clone()).unwrap().state,
            DraftOperationState::Prepared
        );
        assert_eq!(
            journal
                .inspect(&prepared.identity)
                .unwrap()
                .unwrap()
                .operation,
            *prepared
        );
    }
    let conflicting = operation(
        first.identity.account_id,
        first.identity.account_generation,
        first.identity.operation_id,
        6,
    );
    assert_eq!(
        journal.prepare(conflicting),
        Err(DraftJournalError::OperationConflict)
    );
}

#[test]
fn every_recorded_non_prepared_state_refuses_another_dispatch() {
    let temporary = TemporaryJournal::new();
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    let created = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 7);
    let rejected = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 8);
    let uncertain = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 9);

    journal.prepare(created.clone()).unwrap();
    journal.begin_dispatch(&created).unwrap();
    journal
        .record_created(
            &created.identity,
            Some(AppendedMessageIdentity {
                uid_validity: 10,
                uid: 11,
            }),
        )
        .unwrap();
    journal.prepare(rejected.clone()).unwrap();
    journal.begin_dispatch(&rejected).unwrap();
    journal.record_rejected(&rejected.identity).unwrap();
    journal.prepare(uncertain.clone()).unwrap();
    journal.begin_dispatch(&uncertain).unwrap();

    assert_eq!(
        journal.begin_dispatch(&created),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::Created {
                appended_message: Some(AppendedMessageIdentity {
                    uid_validity: 10,
                    uid: 11,
                })
            }
        ))
    );
    assert_eq!(
        journal.begin_dispatch(&rejected),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::Rejected
        ))
    );
    assert_eq!(
        journal.begin_dispatch(&uncertain),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::InFlight
        ))
    );
}

#[test]
fn failed_created_write_leaves_in_flight_non_dispatchable_after_reopening() {
    let temporary = TemporaryJournal::new();
    let prepared = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 10);
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    journal.prepare(prepared.clone()).unwrap();
    journal.begin_dispatch(&prepared).unwrap();
    let connection = Connection::open(&temporary.path).unwrap();
    connection
        .execute_batch(
            "
            CREATE TRIGGER fail_created_outcome
            BEFORE UPDATE OF state ON draft_operations
            WHEN NEW.state = 'created'
            BEGIN
                SELECT RAISE(ABORT, 'injected failure');
            END;
            ",
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        journal.record_created(&prepared.identity, None),
        Err(DraftJournalError::Unavailable)
    );
    drop(journal);

    let mut reopened = DraftJournal::open(&temporary.path).unwrap();
    assert_eq!(
        reopened.inspect(&prepared.identity).unwrap().unwrap().state,
        DraftOperationState::InFlight
    );
    assert_eq!(
        reopened.begin_dispatch(&prepared),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::InFlight
        ))
    );
}

#[test]
fn refusing_an_unknown_schema_preserves_it_before_pragmas_can_mutate_it() {
    let temporary = TemporaryJournal::new();
    let connection = Connection::open(&temporary.path).unwrap();
    connection
        .execute_batch("CREATE TABLE unrelated (value TEXT);")
        .unwrap();
    drop(connection);

    assert!(matches!(
        DraftJournal::open(&temporary.path),
        Err(DraftJournalError::InvalidDatabase)
    ));

    let connection = Connection::open(&temporary.path).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let unrelated_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'unrelated')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 0);
    assert!(unrelated_exists);
}

#[test]
fn invalid_persisted_uid_identity_is_refused() {
    let temporary = TemporaryJournal::new();
    let operation = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 13);
    DraftJournal::open(&temporary.path).unwrap();
    let connection = Connection::open(&temporary.path).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection
        .execute(
            "
            INSERT INTO draft_operations (
                operation_id, account_id, account_generation, mailbox_identity,
                content_sha256, state, appended_uid_validity, appended_uid
            ) VALUES (?1, ?2, ?3, ?4, ?5, 'created', 0, 1)
            ",
            params![
                operation.identity.operation_id.as_bytes().as_slice(),
                operation.identity.account_id.as_bytes().as_slice(),
                1_i64,
                operation.mailbox_identity,
                operation.content_sha256.as_slice(),
            ],
        )
        .unwrap();
    drop(connection);

    let journal = DraftJournal::open(&temporary.path).unwrap();
    assert_eq!(
        journal.inspect(&operation.identity),
        Err(DraftJournalError::InvalidDatabase)
    );
}

#[test]
fn subprocess_death_preserves_committed_journal_state() {
    if let Ok(path) = env::var("MAILCTL_DRAFT_JOURNAL_CHILD_PATH") {
        let mut journal = DraftJournal::open(path).unwrap();
        let operation = child_operation();
        journal.prepare(operation.clone()).unwrap();
        journal.begin_dispatch(&operation).unwrap();
        match env::var("MAILCTL_DRAFT_JOURNAL_CHILD_OUTCOME").as_deref() {
            Ok("created") => journal.record_created(&operation.identity, None).unwrap(),
            Ok("in_flight") => journal.inspect(&operation.identity).unwrap().unwrap(),
            _ => panic!("invalid journal child outcome"),
        };
        println!("journal child ready");
        std::io::stdout().flush().unwrap();
        std::process::abort();
    }

    for (outcome, expected) in [
        ("in_flight", DraftOperationState::InFlight),
        (
            "created",
            DraftOperationState::Created {
                appended_message: None,
            },
        ),
    ] {
        let temporary = TemporaryJournal::new();
        run_abort_child(&temporary, outcome);
        let mut journal = DraftJournal::open(&temporary.path).unwrap();
        assert_eq!(
            journal
                .inspect(&child_operation().identity)
                .unwrap()
                .unwrap()
                .state,
            expected
        );
        assert_eq!(
            journal.begin_dispatch(&child_operation()),
            Err(DraftJournalError::NotDispatchable(expected))
        );
    }
}
