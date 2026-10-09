use mailctl::draft::DraftMessageIdentity;
use mailctl::draft_journal::{
    DraftJournal, DraftJournalError, DraftOperationIdentity, DraftOperationState,
    PreparedDraftOperation,
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
                .canonicalize()
                .unwrap()
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
        reconstruction: None,
    }
}

fn child_operation() -> PreparedDraftOperation {
    operation(Uuid::from_u128(1), 1, Uuid::from_u128(2), 12)
}

fn reconstruction(
    operation: &PreparedDraftOperation,
) -> mailctl::draft_journal::DraftReconstruction {
    let mut frozen = mailctl::draft_journal::DraftReconstruction {
        uid_validity: 17,
        input_sha256: [42; 32],
        from_configuration_sha256: [43; 32],
        selected_from_sha256: Some([44; 32]),
        date_unix: 1_700_000_000,
        encoder_version: 3,
        facts_sha256: None,
    };
    frozen.facts_sha256 = Some(
        frozen
            .fingerprint(&operation.identity, &operation.mailbox_identity)
            .unwrap(),
    );
    frozen
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
fn full_journal_retries_preserve_outcomes_and_still_reject_conflicting_input() {
    let temporary = TemporaryJournal::new();
    let prepared = operation(Uuid::new_v4(), 1, Uuid::new_v4(), 15);
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    journal.prepare_with_limit(prepared.clone(), 1).unwrap();
    journal.begin_dispatch(&prepared).unwrap();
    let recorded = journal.record_created(&prepared.identity, None).unwrap();

    assert_eq!(
        journal.prepare_with_limit(prepared.clone(), 0).unwrap(),
        recorded
    );
    let mut conflicting = prepared;
    conflicting.content_sha256 = [16; 32];
    assert_eq!(
        journal.prepare_with_limit(conflicting, 0),
        Err(DraftJournalError::OperationConflict)
    );
    assert_eq!(
        journal.prepare_with_limit(operation(Uuid::new_v4(), 1, Uuid::new_v4(), 17), 1),
        Err(DraftJournalError::Full)
    );
    assert_eq!(
        journal.inspect(&recorded.operation.identity).unwrap(),
        Some(recorded)
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
            Some(DraftMessageIdentity {
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
                appended_message: Some(DraftMessageIdentity {
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
fn schema_validation_rejects_missing_extra_and_renamed_columns() {
    for change in [
        "ALTER TABLE draft_operations DROP COLUMN content_sha256",
        "ALTER TABLE draft_operations ADD COLUMN unexpected TEXT",
        "ALTER TABLE draft_operations RENAME COLUMN mailbox_identity TO target",
    ] {
        let temporary = TemporaryJournal::new();
        DraftJournal::open(&temporary.path).unwrap();
        let connection = Connection::open(&temporary.path).unwrap();
        connection.execute_batch(change).unwrap();
        drop(connection);

        assert!(matches!(
            DraftJournal::open(&temporary.path),
            Err(DraftJournalError::InvalidDatabase)
        ));
    }
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
fn writer_lock_contention_fails_with_the_finite_busy_timeout() {
    let temporary = TemporaryJournal::new();
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    let connection = Connection::open(&temporary.path).unwrap();
    connection.execute_batch("BEGIN EXCLUSIVE;").unwrap();

    let started = Instant::now();
    let result = journal.prepare(operation(Uuid::new_v4(), 1, Uuid::new_v4(), 14));
    let elapsed = started.elapsed();
    connection.execute_batch("ROLLBACK;").unwrap();

    assert!(matches!(result, Err(DraftJournalError::Busy)));
    assert!(elapsed >= Duration::from_secs(4));
    // SQLite accumulates requested sleeps; scheduler oversleep adds wall-clock time.
    assert!(elapsed < Duration::from_secs(15));
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

#[test]
fn verified_duplicate_is_durable_and_never_dispatchable() {
    let temporary = TemporaryJournal::new();
    let operation = child_operation();
    let uid = DraftMessageIdentity {
        uid_validity: 77,
        uid: 4,
    };
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    journal.prepare(operation.clone()).unwrap();
    assert!(journal.record_duplicate(&operation.identity, uid).is_err());
    journal.begin_dispatch(&operation).unwrap();
    assert!(journal.record_duplicate(&operation.identity, uid).is_err());
    journal.record_outcome_unknown(&operation.identity).unwrap();
    let receipt = journal.record_duplicate(&operation.identity, uid).unwrap();
    assert_eq!(
        receipt.state,
        DraftOperationState::Duplicate {
            appended_message: uid
        }
    );
    drop(journal);
    let mut journal = DraftJournal::open_existing(&temporary.path).unwrap();
    assert_eq!(journal.inspect(&operation.identity).unwrap(), Some(receipt));
    assert!(matches!(
        journal.begin_dispatch(&operation),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::Duplicate { .. }
        ))
    ));
    assert!(journal.record_outcome_unknown(&operation.identity).is_err());
}

#[test]
fn dispatch_verification_refuses_expired_time_and_excess_history_without_changes() {
    let temporary = TemporaryJournal::new();
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    let operation = child_operation();
    let original = journal.prepare(operation.clone()).unwrap();
    assert_eq!(
        journal.verify_for_dispatch(Instant::now(), 1),
        Err(DraftJournalError::Unavailable)
    );
    assert_eq!(
        journal.verify_for_dispatch(Instant::now() + Duration::from_secs(1), 0),
        Err(DraftJournalError::Unavailable)
    );
    assert_eq!(
        journal.inspect(&operation.identity).unwrap(),
        Some(original)
    );
}

#[test]
fn retained_history_verification_avoids_heap_copies_of_fixed_identity_fields() {
    let temporary = TemporaryJournal::new();
    let journal = DraftJournal::open(&temporary.path).unwrap();
    let database = Connection::open(&temporary.path).unwrap();
    let records = 5000;
    database.execute_batch(&format!(
        "WITH RECURSIVE records(number) AS (VALUES(1) UNION ALL SELECT number + 1 FROM records WHERE number < {records})
         INSERT INTO draft_operations(operation_id, account_id, account_generation, mailbox_identity, content_sha256, state)
         SELECT randomblob(16), zeroblob(16), 1, 'retained-mailbox', zeroblob(32), 'created' FROM records;"
    )).unwrap();
    let allocations = allocation_counter::measure(|| {
        journal
            .verify_for_dispatch(Instant::now() + Duration::from_secs(5), records)
            .unwrap();
    });
    eprintln!("retained history verification: {allocations:?}");
    assert!(
        allocations.count_total < 3 * records as u64,
        "{allocations:?}"
    );
}

#[test]
fn dispatch_verification_borrows_retained_text_without_per_record_heap_growth() {
    let mut measured = Vec::new();
    for records in [512, 4096] {
        let temporary = TemporaryJournal::new();
        let mut journal = DraftJournal::open(&temporary.path).unwrap();
        let mut first = child_operation();
        first.mailbox_identity = format!("Drafts {}", "synthetic ".repeat(100));
        first.reconstruction = Some(reconstruction(&first));
        let original = journal.prepare(first.clone()).unwrap();
        let mut database = Connection::open(&temporary.path).unwrap();
        let transaction = database.transaction().unwrap();
        for index in 1..records {
            let mut operation = first.clone();
            operation.identity.operation_id = Uuid::from_u128(index as u128 + 2);
            operation.reconstruction = Some(reconstruction(&operation));
            transaction.execute(
                "INSERT INTO draft_operations(operation_id, account_id, account_generation, mailbox_identity, content_sha256, reconstruction, state)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, 'prepared')",
                params![
                    operation.identity.operation_id.as_bytes(),
                    operation.identity.account_id.as_bytes(),
                    operation.mailbox_identity,
                    operation.content_sha256,
                    serde_json::to_string(&operation.reconstruction.unwrap()).unwrap(),
                ],
            ).unwrap();
        }
        transaction.commit().unwrap();
        let started = Instant::now();
        let allocations = allocation_counter::measure(|| {
            journal
                .verify_for_dispatch(Instant::now() + Duration::from_secs(5), records)
                .unwrap();
        });
        eprintln!(
            "borrowed retained text: records={records}, elapsed={:?}, {allocations:?}",
            started.elapsed()
        );
        assert_eq!(journal.inspect(&first.identity).unwrap(), Some(original));
        measured.push(allocations);
    }
    // Verification retains no row data. Its heap budget should not scale with
    // the number or length of supported mailbox and reconstruction text fields.
    for allocations in measured {
        assert!(allocations.bytes_total < 64 * 1024, "{allocations:?}");
    }
}

#[test]
fn borrowed_verification_preserves_text_corruption_and_legacy_state_checks() {
    for (assignment, expected) in [
        (
            "mailbox_identity = CAST(X'ff' AS TEXT)",
            DraftJournalError::InvalidDatabase,
        ),
        (
            "reconstruction = CAST(X'ff' AS TEXT)",
            DraftJournalError::InvalidDatabase,
        ),
        (
            "state = CAST(X'ff' AS TEXT)",
            DraftJournalError::InvalidDatabase,
        ),
        (
            "mailbox_identity = X'6162'",
            DraftJournalError::InvalidDatabase,
        ),
        (
            "reconstruction = X'6162'",
            DraftJournalError::InvalidDatabase,
        ),
        ("state = X'6162'", DraftJournalError::InvalidDatabase),
        ("mailbox_identity = ''", DraftJournalError::InvalidDatabase),
        ("reconstruction = '{'", DraftJournalError::InvalidDatabase),
        ("state = 'unknown'", DraftJournalError::InvalidDatabase),
        (
            "account_generation = -1",
            DraftJournalError::InvalidDatabase,
        ),
        (
            "account_generation = 'synthetic'",
            DraftJournalError::InvalidDatabase,
        ),
        ("appended_uid = 1", DraftJournalError::InvalidDatabase),
        (
            "state = 'created', appended_uid_validity = 4294967296, appended_uid = 1",
            DraftJournalError::InvalidDatabase,
        ),
        (
            "state = 'rejected', appended_uid_validity = 1, appended_uid = 1",
            DraftJournalError::InvalidDatabase,
        ),
        ("state = 'duplicate'", DraftJournalError::InvalidDatabase),
        ("reconstruction = NULL", DraftJournalError::InvalidOperation),
    ] {
        let temporary = TemporaryJournal::new();
        let mut journal = DraftJournal::open(&temporary.path).unwrap();
        let mut operation = child_operation();
        operation.reconstruction = Some(reconstruction(&operation));
        journal.prepare(operation.clone()).unwrap();
        let database = Connection::open(&temporary.path).unwrap();
        database
            .execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON; UPDATE draft_operations SET {assignment}"
            ))
            .unwrap();
        assert_eq!(
            journal.verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1),
            Err(expected),
            "{assignment}"
        );
        if assignment.starts_with("account_generation =") {
            assert_eq!(journal.inspect(&operation.identity).unwrap(), None);
        } else if expected == DraftJournalError::InvalidDatabase {
            assert_eq!(
                journal.inspect(&operation.identity),
                Err(expected),
                "{assignment}"
            );
        }
    }

    for state in [
        "created",
        "in_flight",
        "rejected",
        "outcome_unknown",
        "duplicate",
    ] {
        let temporary = TemporaryJournal::new();
        let mut journal = DraftJournal::open(&temporary.path).unwrap();
        let operation = child_operation();
        journal.prepare(operation.clone()).unwrap();
        let database = Connection::open(&temporary.path).unwrap();
        let uid = if state == "duplicate" { "1" } else { "NULL" };
        database.execute_batch(&format!(
            "UPDATE draft_operations SET state = '{state}', appended_uid_validity = {uid}, appended_uid = {uid}"
        )).unwrap();
        journal
            .verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1)
            .unwrap();
        assert_eq!(
            journal
                .inspect(&operation.identity)
                .unwrap()
                .unwrap()
                .operation,
            operation,
            "legacy {state} reconstruction must stay optional"
        );
    }
}

#[test]
fn borrowed_verification_retains_mailbox_character_and_prepared_evidence_bounds() {
    let temporary = TemporaryJournal::new();
    let mut journal = DraftJournal::open(&temporary.path).unwrap();
    let mut operation = child_operation();
    operation.mailbox_identity = "é".repeat(4096);
    let mut reconstruction = reconstruction(&operation);
    operation.reconstruction = Some(reconstruction.clone());
    let original = journal.prepare(operation.clone()).unwrap();
    journal
        .verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1)
        .unwrap();
    assert_eq!(
        journal.inspect(&operation.identity).unwrap(),
        Some(original.clone())
    );
    let database = Connection::open(&temporary.path).unwrap();
    database
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    database
        .execute(
            "UPDATE draft_operations SET mailbox_identity = ?1",
            ["é".repeat(4097)],
        )
        .unwrap();
    assert_eq!(
        journal.verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1),
        Err(DraftJournalError::InvalidDatabase)
    );
    database
        .execute(
            "UPDATE draft_operations SET mailbox_identity = ?1",
            [&operation.mailbox_identity],
        )
        .unwrap();
    for field in ["encoder", "validity", "selected-from"] {
        match field {
            "encoder" => reconstruction.encoder_version = 999,
            "validity" => reconstruction.uid_validity = 0,
            "selected-from" => reconstruction.selected_from_sha256 = None,
            _ => unreachable!(),
        }
        database
            .execute(
                "UPDATE draft_operations SET reconstruction = ?1",
                [serde_json::to_string(&reconstruction).unwrap()],
            )
            .unwrap();
        assert_eq!(
            journal.verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1),
            Err(DraftJournalError::InvalidOperation),
            "{field}"
        );
        reconstruction = operation.reconstruction.clone().unwrap();
    }
    database
        .execute(
            "UPDATE draft_operations SET reconstruction = ?1",
            [serde_json::to_string(&reconstruction).unwrap()],
        )
        .unwrap();
    journal
        .verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1)
        .unwrap();
    assert_eq!(
        journal.inspect(&operation.identity).unwrap(),
        Some(original)
    );
}

#[test]
fn retained_history_verification_rejects_incorrect_fixed_blob_lengths() {
    for column in ["operation_id", "account_id", "content_sha256"] {
        let temporary = TemporaryJournal::new();
        let mut journal = DraftJournal::open(&temporary.path).unwrap();
        journal.prepare(child_operation()).unwrap();
        let database = Connection::open(&temporary.path).unwrap();
        database
            .execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON;
             UPDATE draft_operations SET {column} = zeroblob(3);"
            ))
            .unwrap();
        assert_eq!(
            journal.verify_for_dispatch(Instant::now() + Duration::from_secs(5), 1),
            Err(DraftJournalError::InvalidDatabase),
            "malformed {column} must not become dispatchable",
        );
    }
}
