mod support;
use mailctl::{
    config::{Config, CredentialSource, HistoricalDraftScope, Limits},
    domain::{DraftStatusInput, Error, ErrorCode, Operation, OperationResult, SaveDraftInput},
    draft::{DraftMessageIdentity, PreparedDraft},
    draft_journal::{DraftJournal, DraftOperationState},
    imap::AppendOutcome,
    service::{DraftAppend, DraftBackend, DraftPreparation, MailboxTarget, Service},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

struct Backend {
    routes: Mutex<Vec<(u64, String, CredentialSource, String)>>,
    bytes: Mutex<Vec<Vec<u8>>>,
    verifications: Mutex<Vec<(u32, String, [u8; 32])>>,
    outcome: AppendOutcome,
    evidence: Mutex<Result<mailctl::draft::DraftEvidence, ErrorCode>>,
    validity: Mutex<Result<u32, ErrorCode>>,
}
impl DraftBackend for Backend {
    fn reconcile<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        expected: &'a mailctl::draft::DraftVerification,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<mailctl::draft::DraftEvidence, Error>> + Send + 'a>>
    {
        Box::pin(async move {
            self.verifications.lock().unwrap().push((
                expected.uid_validity,
                expected.message_id.clone(),
                expected.content_sha256,
            ));
            let selection = self.prepare(target, mailbox, limits).await?;
            if selection.uid_validity() != expected.uid_validity {
                return Err(Error::new(ErrorCode::StaleReference));
            }
            self.evidence.lock().unwrap().map_err(Error::new)
        })
    }
    fn prepare<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        _: &'a Limits,
    ) -> DraftPreparation<'a> {
        Box::pin(async move {
            self.routes.lock().unwrap().push((
                target.generation,
                target.config.server.clone(),
                target.config.credential.clone(),
                mailbox.into(),
            ));
            let validity = self.validity.lock().unwrap().map_err(Error::new)?;
            Ok(Box::new(Append(self, validity)) as Box<dyn DraftAppend>)
        })
    }
}
struct Append<'a>(&'a Backend, u32);
impl DraftAppend for Append<'_> {
    fn uid_validity(&self) -> u32 {
        self.1
    }
    fn append<'a>(
        self: Box<Self>,
        draft: &'a PreparedDraft,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a,
    {
        Box::pin(async move {
            self.0.bytes.lock().unwrap().push(draft.bytes().to_vec());
            Ok(self.0.outcome)
        })
    }
}
struct Fixture {
    _installation: support::Installation,
    config: Config,
    backend: Arc<Backend>,
    input: SaveDraftInput,
}
impl Fixture {
    async fn new(state: DraftOperationState) -> Self {
        let installation = support::Installation::two_accounts();
        let mut config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        config.accounts[0].from_identities = vec!["original@example.test".into()];
        config.accounts[0].retain_history = true;
        Service::setup(config.clone()).unwrap();
        let backend = Arc::new(Backend {
            routes: Mutex::new(Vec::new()),
            bytes: Mutex::new(Vec::new()),
            verifications: Mutex::new(Vec::new()),
            validity: Mutex::new(Ok(77)),
            evidence: Mutex::new(Ok(mailctl::draft::DraftEvidence::Verified(
                DraftMessageIdentity {
                    uid_validity: 77,
                    uid: 4,
                },
            ))),
            outcome: match state {
                DraftOperationState::Rejected => AppendOutcome::Rejected,
                DraftOperationState::OutcomeUnknown => AppendOutcome::Unknown,
                _ => AppendOutcome::Created {
                    uid: Some(DraftMessageIdentity {
                        uid_validity: 77,
                        uid: 4,
                    }),
                },
            },
        });
        let service = Service::open(config.clone())
            .unwrap()
            .with_draft_backend(backend.clone());
        let context = service.context("writer", &Default::default()).unwrap();
        let OperationResult::Accounts(accounts) = service
            .execute(&context, Operation::ListAccounts(Default::default()))
            .await
            .unwrap()
        else {
            panic!()
        };
        let input = SaveDraftInput {
            account_id: accounts.accounts[0].account_id.parse().unwrap(),
            account_generation: 1,
            operation_id: uuid::Uuid::new_v4(),
            mailbox: "Drafts".into(),
            draft: Box::new(mailctl::domain::DraftContent {
                subject: "Historical synthetic draft".into(),
                body: "Synthetic retained input".into(),
                ..Default::default()
            }),
        };
        let database = rusqlite::Connection::open(config.state_dir.join("drafts.sqlite")).unwrap();
        if state == DraftOperationState::Prepared {
            database.execute_batch("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;").unwrap();
        }
        let result = service
            .execute(&context, Operation::SaveDraft(input.clone()))
            .await;
        match state {
            DraftOperationState::Prepared => {
                assert_eq!(result.unwrap_err().code, ErrorCode::JournalUnavailable);
                database
                    .execute_batch("DROP TRIGGER stop_dispatch")
                    .unwrap();
            }
            DraftOperationState::OutcomeUnknown => {
                assert_eq!(result.unwrap_err().code, ErrorCode::OutcomeUnknown)
            }
            _ => {
                result.unwrap();
            }
        }
        Self {
            _installation: installation,
            config,
            backend,
            input,
        }
    }
    fn repoint(&mut self) {
        let account = &mut self.config.accounts[0];
        account.alias = "renamed".into();
        account.server = "replacement.example.test".into();
        account.credential = CredentialSource::Session {};
        account.mailboxes = vec!["New Drafts".into()].into();
        account.drafts_mailbox = Some("New Drafts".into());
        account
            .from_identities
            .insert(0, "replacement@example.test".into());
        let grant = self
            .config
            .grants
            .iter_mut()
            .find(|g| g.name == "writer")
            .unwrap();
        grant.mailboxes = vec!["New Drafts".into()].into();
        grant.historical_drafts = vec![HistoricalDraftScope {
            account_id: self.input.account_id,
            account_generation: 1,
            mailbox: "Drafts".into(),
        }];
    }
    fn open(&self) -> Service {
        Service::setup(self.config.clone()).unwrap();
        Service::open(self.config.clone())
            .unwrap()
            .with_draft_backend(self.backend.clone())
    }
    fn record(&self) -> mailctl::draft_journal::PersistedDraftOperation {
        DraftJournal::open_existing(self.config.state_dir.join("drafts.sqlite"))
            .unwrap()
            .inspect(&self.input.identity())
            .unwrap()
            .unwrap()
    }
    fn status(&self) -> Operation {
        Operation::DraftStatus(DraftStatusInput {
            account_id: self.input.account_id,
            account_generation: 1,
            operation_id: self.input.operation_id,
            mailbox: "Drafts".into(),
            reconcile: false,
        })
    }
    fn message_id(&self) -> String {
        format!(
            "{}.{}.{}@mailctl.invalid",
            self.input.account_id, self.input.account_generation, self.input.operation_id
        )
    }
    fn mutate_reconstruction(&self, field: &str, value: serde_json::Value) {
        let database =
            rusqlite::Connection::open(self.config.state_dir.join("drafts.sqlite")).unwrap();
        let mut frozen =
            serde_json::to_value(self.record().operation.reconstruction.unwrap()).unwrap();
        frozen[field] = value;
        database
            .execute(
                "UPDATE draft_operations SET reconstruction = ?1",
                [frozen.to_string()],
            )
            .unwrap();
    }
    fn use_previous_encoder(&self) {
        self.mutate_reconstruction("encoder", "mail-builder/0.5.0".into());
        let database =
            rusqlite::Connection::open(self.config.state_dir.join("drafts.sqlite")).unwrap();
        // Represent MIME emitted by the previous dependency without retaining
        // that dependency merely to reproduce its obsolete folding rules.
        database
            .execute(
                "UPDATE draft_operations SET content_sha256 = ?1",
                [[0x5a_u8; 32].as_slice()],
            )
            .unwrap();
    }
}
async fn run(service: &Service, operation: Operation) -> Result<OperationResult, Error> {
    let context = service.context("writer", &Default::default()).unwrap();
    service.execute(&context, operation).await
}

#[tokio::test]
async fn all_outcomes_keep_original_identity_and_prepared_retry_uses_retained_route() {
    for state in [
        DraftOperationState::Prepared,
        DraftOperationState::OutcomeUnknown,
        DraftOperationState::Created {
            appended_message: None,
        },
        DraftOperationState::Rejected,
    ] {
        let mut f = Fixture::new(state).await;
        let original = f.record();
        f.repoint();
        let service = f.open();
        let status = run(&service, f.status()).await;
        if state == DraftOperationState::OutcomeUnknown {
            let error = status.unwrap_err();
            assert_eq!(error.code, ErrorCode::OutcomeUnknown);
            assert_eq!(error.draft_operation.unwrap().identity, f.input.identity());
        } else {
            let OperationResult::Draft(receipt) = status.unwrap() else {
                panic!()
            };
            assert_eq!(receipt.account_generation, 1);
            assert_eq!(receipt.mailbox, "Drafts");
            assert_eq!(receipt.uid_validity, 77);
        }
        let result = run(&service, Operation::SaveDraft(f.input.clone())).await;
        if state == DraftOperationState::OutcomeUnknown {
            assert_eq!(result.unwrap_err().code, ErrorCode::OutcomeUnknown);
        } else {
            result.unwrap();
        }
        let attempts = f.backend.bytes.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        if state == DraftOperationState::Prepared {
            let routes = f.backend.routes.lock().unwrap();
            assert_eq!(routes.len(), 2);
            assert_eq!(
                routes[1],
                (
                    1,
                    "imap.example.test".into(),
                    CredentialSource::Native {},
                    "Drafts".into()
                )
            );
            let text = String::from_utf8_lossy(&attempts[0]);
            assert!(text.contains("original@example.test"));
            assert!(!text.contains("replacement@example.test"));
            assert_eq!(
                f.record().operation.content_sha256,
                original.operation.content_sha256
            );
        } else {
            assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn previous_encoder_prepared_retry_reencodes_once_and_preserves_frozen_parameters() {
    let mut f = Fixture::new(DraftOperationState::Prepared).await;
    let current_encoder = f.record().operation.reconstruction.unwrap().encoder;
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let dependency = manifest["dependencies"]["mail-builder"]["version"]
        .as_str()
        .unwrap()
        .strip_prefix('=')
        .unwrap();
    assert_eq!(current_encoder, format!("mail-builder/{dependency}"));
    f.use_previous_encoder();
    let previous = f.record();
    Service::verify_state(&f.config).unwrap();
    assert_eq!(f.record(), previous);
    f.repoint();
    let service = f.open();
    run(&service, Operation::SaveDraft(f.input.clone()))
        .await
        .unwrap();
    let migrated = f.record();
    let mut expected_frozen = previous.operation.reconstruction.unwrap();
    expected_frozen.encoder = current_encoder;
    assert_eq!(
        migrated.operation.reconstruction,
        Some(expected_frozen.clone())
    );
    assert_eq!(migrated.operation.identity, previous.operation.identity);
    assert_eq!(migrated.operation.mailbox_identity, "Drafts");
    assert_ne!(migrated.operation.content_sha256, [0x5a; 32]);
    let expected_mime = PreparedDraft::compose(
        mailctl::draft::DraftInput {
            from: "original@example.test".into(),
            to: f.input.draft.to.clone(),
            cc: f.input.draft.cc.clone(),
            bcc: f.input.draft.bcc.clone(),
            subject: f.input.draft.subject.clone(),
            body: f.input.draft.body.clone(),
            message_id: f.message_id(),
            date_unix: expected_frozen.date_unix,
            in_reply_to: f.input.draft.in_reply_to.clone(),
            references: f.input.draft.references.clone(),
        },
        f.config.limits.draft_mime_bytes,
    )
    .unwrap();
    assert_eq!(migrated.operation.content_sha256, expected_mime.sha256());
    {
        let attempts = f.backend.bytes.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0], expected_mime.bytes());
    }
    assert_eq!(
        f.backend.routes.lock().unwrap()[1],
        (
            1,
            "imap.example.test".into(),
            CredentialSource::Native {},
            "Drafts".into()
        )
    );
    run(&service, Operation::SaveDraft(f.input.clone()))
        .await
        .unwrap();
    assert_eq!(f.record(), migrated);
    assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
    assert_eq!(f.backend.routes.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn changed_terminal_operation_identity_blocks_another_append_and_offline_verification() {
    for state in [
        DraftOperationState::Created {
            appended_message: None,
        },
        DraftOperationState::Rejected,
        DraftOperationState::OutcomeUnknown,
    ] {
        let f = Fixture::new(state).await;
        let original = f.record();
        let mut moved_identity = original.operation.identity.clone();
        moved_identity.operation_id = uuid::Uuid::new_v4();
        let database =
            rusqlite::Connection::open(f.config.state_dir.join("drafts.sqlite")).unwrap();
        database
            .execute(
                "UPDATE draft_operations SET operation_id = ?1",
                [moved_identity.operation_id.as_bytes().as_slice()],
            )
            .unwrap();
        drop(database);

        let service = f.open();
        let append_count = f.backend.bytes.lock().unwrap().len();
        assert_eq!(
            run(&service, Operation::SaveDraft(f.input.clone()))
                .await
                .unwrap_err()
                .code,
            ErrorCode::JournalUnavailable
        );
        assert_eq!(f.backend.bytes.lock().unwrap().len(), append_count);
        drop(service);
        assert_eq!(
            Service::verify_state(&f.config).unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );

        // Read-only inspection still exposes retained history for recovery.
        let journal =
            DraftJournal::open_existing(f.config.state_dir.join("drafts.sqlite")).unwrap();
        assert!(journal.inspect(&f.input.identity()).unwrap().is_none());
        let moved = journal.inspect(&moved_identity).unwrap().unwrap();
        assert_eq!(moved.state, original.state);
        assert_eq!(
            moved.operation.content_sha256,
            original.operation.content_sha256
        );
    }
}

#[tokio::test]
async fn previous_encoder_terminal_retries_preserve_receipts_without_another_append() {
    for state in [
        DraftOperationState::Created {
            appended_message: None,
        },
        DraftOperationState::Rejected,
        DraftOperationState::Duplicate {
            appended_message: DraftMessageIdentity {
                uid_validity: 77,
                uid: 4,
            },
        },
    ] {
        let initial = if matches!(state, DraftOperationState::Duplicate { .. }) {
            DraftOperationState::OutcomeUnknown
        } else {
            state
        };
        let f = Fixture::new(initial).await;
        if matches!(state, DraftOperationState::Duplicate { .. }) {
            let service = f.open();
            let Operation::DraftStatus(mut input) = f.status() else {
                panic!()
            };
            input.reconcile = true;
            run(&service, Operation::DraftStatus(input)).await.unwrap();
        }
        f.use_previous_encoder();
        let previous = f.record();
        Service::verify_state(&f.config).unwrap();
        let routes = f.backend.routes.lock().unwrap().len();
        let service = f.open();
        let OperationResult::Draft(status) = run(&service, f.status()).await.unwrap() else {
            panic!()
        };
        let OperationResult::Draft(replayed) = run(&service, Operation::SaveDraft(f.input.clone()))
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(status.content_sha256, "5a".repeat(32));
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            serde_json::to_value(replayed).unwrap()
        );
        assert_eq!(f.record(), previous);
        assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
        assert_eq!(f.backend.routes.lock().unwrap().len(), routes);
    }
}

#[tokio::test]
async fn previous_encoder_uncertain_retries_reconcile_with_the_original_mime_identity() {
    for in_flight in [false, true] {
        let f = Fixture::new(DraftOperationState::OutcomeUnknown).await;
        f.use_previous_encoder();
        if in_flight {
            let database =
                rusqlite::Connection::open(f.config.state_dir.join("drafts.sqlite")).unwrap();
            database
                .execute("UPDATE draft_operations SET state = 'in_flight'", [])
                .unwrap();
        }
        let previous = f.record().operation;
        let service = f.open();
        assert_eq!(
            run(&service, f.status()).await.unwrap_err().code,
            if in_flight {
                ErrorCode::OperationInProgress
            } else {
                ErrorCode::OutcomeUnknown
            }
        );
        let error = run(&service, Operation::SaveDraft(f.input.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutcomeUnknown);
        assert_eq!(error.draft_operation.unwrap().identity, f.input.identity());
        assert_eq!(f.record().operation, previous);
        assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
        assert!(f.backend.verifications.lock().unwrap().is_empty());
        let Operation::DraftStatus(mut input) = f.status() else {
            panic!()
        };
        input.reconcile = true;
        let OperationResult::Draft(receipt) =
            run(&service, Operation::DraftStatus(input)).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(receipt.state, mailctl::domain::DraftState::Duplicate);
        assert_eq!(receipt.content_sha256, "5a".repeat(32));
        assert_eq!(
            f.backend.verifications.lock().unwrap().as_slice(),
            [(77, f.message_id(), [0x5a; 32])]
        );
        run(&service, Operation::SaveDraft(f.input.clone()))
            .await
            .unwrap();
        assert_eq!(f.record().operation, previous);
        assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
        assert_eq!(f.backend.routes.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn previous_encoder_retries_still_reject_changed_input_before_backend_work() {
    for state in [
        DraftOperationState::Prepared,
        DraftOperationState::Created {
            appended_message: None,
        },
        DraftOperationState::OutcomeUnknown,
    ] {
        let f = Fixture::new(state).await;
        f.use_previous_encoder();
        let previous = f.record();
        let appends = f.backend.bytes.lock().unwrap().len();
        let service = f.open();
        let mut conflicting = f.input.clone();
        conflicting.draft.body = "Changed operation input".into();
        assert_eq!(
            run(&service, Operation::SaveDraft(conflicting))
                .await
                .unwrap_err()
                .code,
            ErrorCode::OperationConflict
        );
        assert_eq!(f.record(), previous);
        assert_eq!(f.backend.bytes.lock().unwrap().len(), appends);
        assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn previous_encoder_prepared_retry_requires_the_original_mailbox_and_durable_update() {
    for failure in ["incarnation", "journal"] {
        let f = Fixture::new(DraftOperationState::Prepared).await;
        f.use_previous_encoder();
        let previous = f.record();
        let expected = if failure == "incarnation" {
            *f.backend.validity.lock().unwrap() = Ok(88);
            ErrorCode::DraftMailboxUnavailable
        } else {
            let database =
                rusqlite::Connection::open(f.config.state_dir.join("drafts.sqlite")).unwrap();
            database.execute_batch("CREATE TRIGGER stop_upgrade BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;").unwrap();
            ErrorCode::JournalUnavailable
        };
        let service = f.open();
        assert_eq!(
            run(&service, Operation::SaveDraft(f.input.clone()))
                .await
                .unwrap_err()
                .code,
            expected,
            "{failure}"
        );
        assert_eq!(f.record(), previous, "{failure}");
        assert!(f.backend.bytes.lock().unwrap().is_empty(), "{failure}");
    }
}

#[tokio::test]
async fn previous_encoder_prepared_retry_rejects_changed_frozen_facts_without_overwriting_identity()
{
    let f = Fixture::new(DraftOperationState::Prepared).await;
    f.use_previous_encoder();
    f.mutate_reconstruction("date_unix", 0.into());
    let changed = f.record();
    let service = f.open();
    run(&service, f.status()).await.unwrap();
    assert_eq!(
        run(&service, Operation::SaveDraft(f.input.clone()))
            .await
            .unwrap_err()
            .code,
        ErrorCode::OperationConflict
    );
    assert_eq!(f.record(), changed);
    assert!(f.backend.bytes.lock().unwrap().is_empty());
    assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn missing_frozen_facts_fences_retained_history_and_new_drafts() {
    for state in [
        DraftOperationState::Prepared,
        DraftOperationState::Created {
            appended_message: None,
        },
        DraftOperationState::OutcomeUnknown,
    ] {
        for missing in [true, false] {
            let f = Fixture::new(state).await;
            let database =
                rusqlite::Connection::open(f.config.state_dir.join("drafts.sqlite")).unwrap();
            let mut frozen =
                serde_json::to_value(f.record().operation.reconstruction.unwrap()).unwrap();
            if missing {
                frozen.as_object_mut().unwrap().remove("facts_sha256");
            } else {
                frozen["facts_sha256"] = serde_json::Value::Null;
            }
            let corrupted = frozen.to_string();
            database
                .execute(
                    "UPDATE draft_operations SET reconstruction = ?1",
                    [&corrupted],
                )
                .unwrap();
            assert_eq!(
                Service::verify_state(&f.config).unwrap_err().code,
                ErrorCode::JournalUnavailable
            );
            let service = f.open();
            let append_count = f.backend.bytes.lock().unwrap().len();
            assert_eq!(
                run(&service, f.status()).await.unwrap_err().code,
                ErrorCode::JournalUnavailable
            );
            assert_eq!(
                run(&service, Operation::SaveDraft(f.input.clone()))
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::JournalUnavailable
            );
            let mut new = f.input.clone();
            new.operation_id = uuid::Uuid::new_v4();
            assert_eq!(
                run(&service, Operation::SaveDraft(new))
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::JournalUnavailable
            );
            assert_eq!(f.backend.bytes.lock().unwrap().len(), append_count);
            let retained: String = database
                .query_row("SELECT reconstruction FROM draft_operations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(retained, corrupted);
        }
    }
}

#[tokio::test]
async fn historical_retries_preserve_current_generation_availability() {
    use mailctl::domain::Availability;

    for current in [
        Availability::Unknown,
        Availability::Available,
        Availability::Unavailable,
    ] {
        for historical in [Ok(77), Err(ErrorCode::AuthenticationFailed)] {
            let mut f = Fixture::new(DraftOperationState::Prepared).await;
            f.repoint();
            let service = f.open();
            if current != Availability::Unknown {
                *f.backend.validity.lock().unwrap() = if current == Availability::Available {
                    Ok(77)
                } else {
                    Err(ErrorCode::ProviderUnavailable)
                };
                let mut input = f.input.clone();
                input.account_generation = 2;
                input.operation_id = uuid::Uuid::new_v4();
                input.mailbox = "New Drafts".into();
                input.draft.from = Some("replacement@example.test".into());
                let result = run(&service, Operation::SaveDraft(input)).await;
                if current == Availability::Available {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().code, ErrorCode::ProviderUnavailable);
                }
            }
            *f.backend.validity.lock().unwrap() = historical;
            let result = run(&service, Operation::SaveDraft(f.input.clone())).await;
            match historical {
                Ok(_) => {
                    result.unwrap();
                }
                Err(code) => assert_eq!(result.unwrap_err().code, code),
            }
            let OperationResult::Health(health) = run(&service, Operation::Health).await.unwrap()
            else {
                panic!()
            };
            assert_eq!(health.accounts.len(), 1);
            assert_eq!(health.accounts[0].generation, 2);
            assert_eq!(health.accounts[0].availability, current);
            let OperationResult::Accounts(accounts) =
                run(&service, Operation::ListAccounts(Default::default()))
                    .await
                    .unwrap()
            else {
                panic!()
            };
            assert_eq!(accounts.accounts[0].generation, 2);
            assert_eq!(accounts.accounts[0].availability, current);
        }
    }
}

#[tokio::test]
async fn prepared_retry_refuses_missing_routing_target_from_or_reconstruction() {
    for failure in ["routing", "missing", "recreated", "from", "encoder", "hash"] {
        let mut f = Fixture::new(DraftOperationState::Prepared).await;
        f.repoint();
        let expected = match failure {
            "routing" => {
                f.config.accounts[0].retain_history = false;
                ErrorCode::DraftMailboxUnavailable
            }
            "missing" => {
                *f.backend.validity.lock().unwrap() = Err(ErrorCode::DraftMailboxUnavailable);
                ErrorCode::DraftMailboxUnavailable
            }
            "recreated" => {
                *f.backend.validity.lock().unwrap() = Ok(88);
                ErrorCode::DraftMailboxUnavailable
            }
            "from" => {
                f.config.accounts[0].from_identities = vec!["replacement@example.test".into()];
                ErrorCode::PermissionDenied
            }
            "encoder" => {
                f.mutate_reconstruction("encoder", "".into());
                ErrorCode::UnsupportedCapability
            }
            _ => {
                f.mutate_reconstruction("date_unix", 0.into());
                ErrorCode::OperationConflict
            }
        };
        let service = f.open();
        run(&service, f.status()).await.unwrap();
        assert_eq!(
            run(&service, Operation::SaveDraft(f.input.clone()))
                .await
                .unwrap_err()
                .code,
            expected,
            "{failure}"
        );
        assert!(f.backend.bytes.lock().unwrap().is_empty(), "{failure}");
        assert_eq!(f.record().state, DraftOperationState::Prepared);
    }
}

#[tokio::test]
async fn historical_denials_hide_existence_and_conflicts_and_obey_narrowing() {
    for scope in [
        "absent",
        "all_folders",
        "uuid",
        "generation",
        "mailbox",
        "read_only",
        "account",
    ] {
        let mut f = Fixture::new(DraftOperationState::Prepared).await;
        f.repoint();
        if scope == "all_folders" {
            f.config.accounts[0].mailboxes = mailctl::config::MailboxScope::All;
        }
        let grant = f
            .config
            .grants
            .iter_mut()
            .find(|g| g.name == "writer")
            .unwrap();
        match scope {
            "absent" => grant.historical_drafts.clear(),
            "all_folders" => {
                grant.mailboxes = mailctl::config::MailboxScope::All;
                grant.historical_drafts.clear();
            }
            "uuid" => grant.historical_drafts[0].account_id = uuid::Uuid::new_v4(),
            "generation" => grant.historical_drafts[0].account_generation = 2,
            "mailbox" => grant.historical_drafts[0].mailbox = "New Drafts".into(),
            _ => {}
        }
        let service = f.open();
        let narrowing = mailctl::policy::Narrowing {
            read_only: scope == "read_only",
            accounts: (scope == "account").then(|| vec!["personal".into()]),
        };
        let context = service.context("writer", &narrowing).unwrap();
        for known in [true, false] {
            let mut input = f.input.clone();
            input.draft.body = "conflicting".into();
            if !known {
                input.operation_id = uuid::Uuid::new_v4();
            }
            for operation in [
                Operation::SaveDraft(input.clone()),
                Operation::DraftStatus(DraftStatusInput {
                    account_id: input.account_id,
                    account_generation: 1,
                    operation_id: input.operation_id,
                    mailbox: "Drafts".into(),
                    reconcile: false,
                }),
            ] {
                let error = service.execute(&context, operation).await.unwrap_err();
                assert_eq!(
                    error.code,
                    if scope == "account" {
                        ErrorCode::AccountNotAllowed
                    } else {
                        ErrorCode::PermissionDenied
                    },
                    "{scope}"
                );
                assert!(error.draft_operation.is_none());
            }
        }
        assert!(f.backend.bytes.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn full_journal_reconciles_historical_work_and_replays_without_another_append() {
    let mut f = Fixture::new(DraftOperationState::OutcomeUnknown).await;
    f.repoint();
    f.config.accounts[0].from_identities = vec!["replacement@example.test".into()];
    f.config.limits.journal_records = 1;
    for grant in &mut f.config.grants {
        grant.limits.journal_records = 1;
    }
    let service = f.open();
    let mut status = f.status();
    if let Operation::DraftStatus(input) = &mut status {
        input.reconcile = true;
    }
    let OperationResult::Draft(receipt) = run(&service, status.clone()).await.unwrap() else {
        panic!()
    };
    assert_eq!(receipt.state, mailctl::domain::DraftState::Duplicate);
    assert_eq!(receipt.account_generation, 1);
    assert!(receipt.message_reference.is_some());
    assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
    assert_eq!(f.backend.routes.lock().unwrap().len(), 2);
    assert_eq!(f.backend.routes.lock().unwrap()[1].1, "imap.example.test");
    drop(service);
    let service = f.open();
    for request in [status, Operation::SaveDraft(f.input.clone())] {
        let OperationResult::Draft(replayed) = run(&service, request).await.unwrap() else {
            panic!()
        };
        assert_eq!(
            serde_json::to_value(replayed).unwrap(),
            serde_json::to_value(&receipt).unwrap()
        );
    }
    assert_eq!(f.backend.routes.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn reconciliation_keeps_safe_uncertainty_for_insufficient_evidence_and_failed_commit() {
    use mailctl::draft::DraftEvidence;
    for evidence in [
        Ok(DraftEvidence::Absent),
        Ok(DraftEvidence::Ambiguous),
        Ok(DraftEvidence::ContentMismatch),
        Err(ErrorCode::ResponseTooLarge),
        Err(ErrorCode::CredentialUnavailable),
        Err(ErrorCode::StaleReference),
        Ok(DraftEvidence::Verified(DraftMessageIdentity {
            uid_validity: 77,
            uid: 4,
        })),
    ] {
        let f = Fixture::new(DraftOperationState::OutcomeUnknown).await;
        *f.backend.evidence.lock().unwrap() = evidence;
        if matches!(evidence, Ok(DraftEvidence::Verified(_))) {
            let database =
                rusqlite::Connection::open(f.config.state_dir.join("drafts.sqlite")).unwrap();
            database.execute_batch("CREATE TRIGGER stop_verification BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic private data'); END;").unwrap();
        }
        let service = f.open();
        let mut status = f.status();
        if let Operation::DraftStatus(input) = &mut status {
            input.reconcile = true;
        }
        let error = run(&service, status).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::OutcomeUnknown);
        assert!(!error.retryable);
        assert_eq!(error.draft_operation.unwrap().identity, f.input.identity());
        assert!(!error.message.contains("synthetic private data"));
        assert_eq!(f.record().state, DraftOperationState::OutcomeUnknown);
        assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn reconciliation_of_prepared_work_is_journal_only_and_denials_hide_existence() {
    let mut f = Fixture::new(DraftOperationState::Prepared).await;
    let service = f.open();
    let mut status = f.status();
    if let Operation::DraftStatus(input) = &mut status {
        input.reconcile = true;
    }
    let OperationResult::Draft(receipt) = run(&service, status.clone()).await.unwrap() else {
        panic!()
    };
    assert_eq!(receipt.state, mailctl::domain::DraftState::Prepared);
    assert!(f.backend.bytes.lock().unwrap().is_empty());
    assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
    drop(service);
    f.repoint();
    f.config
        .grants
        .iter_mut()
        .find(|grant| grant.name == "writer")
        .unwrap()
        .historical_drafts
        .clear();
    let service = f.open();
    for known in [true, false] {
        if !known && let Operation::DraftStatus(input) = &mut status {
            input.operation_id = uuid::Uuid::new_v4();
        }
        let error = run(&service, status.clone()).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.draft_operation.is_none());
    }
}

#[tokio::test]
async fn failed_owner_death_recovery_retains_uncertainty_and_original_identity() {
    let f = Fixture::new(DraftOperationState::OutcomeUnknown).await;
    let database = rusqlite::Connection::open(f.config.state_dir.join("drafts.sqlite")).unwrap();
    database.execute_batch("UPDATE draft_operations SET state = 'in_flight'; CREATE TRIGGER stop_recovery BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;").unwrap();
    let service = f.open();
    let mut status = f.status();
    if let Operation::DraftStatus(input) = &mut status {
        input.reconcile = true;
    }
    let error = run(&service, status).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::OutcomeUnknown);
    assert!(!error.retryable);
    assert_eq!(error.draft_operation.unwrap().identity, f.input.identity());
    assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
    assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn reconciliation_retains_uncertainty_when_the_original_target_is_unavailable() {
    for fault in ["routing", "missing", "incarnation"] {
        let mut f = Fixture::new(DraftOperationState::OutcomeUnknown).await;
        f.repoint();
        match fault {
            "routing" => f.config.accounts[0].retain_history = false,
            "missing" => {
                *f.backend.validity.lock().unwrap() = Err(ErrorCode::DraftMailboxUnavailable)
            }
            _ => *f.backend.validity.lock().unwrap() = Ok(88),
        }
        let service = f.open();
        let mut status = f.status();
        if let Operation::DraftStatus(input) = &mut status {
            input.reconcile = true;
        }
        let error = run(&service, status).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::OutcomeUnknown, "{fault}");
        assert!(!error.retryable);
        assert_eq!(error.draft_operation.unwrap().identity, f.input.identity());
        assert_eq!(f.record().state, DraftOperationState::OutcomeUnknown);
        assert_eq!(f.backend.bytes.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn restored_history_preserves_receipts_but_never_dispatches_post_backup_operations() {
    let f = Fixture::new(DraftOperationState::Created {
        appended_message: None,
    })
    .await;
    let original = f.record();
    let backup = f.config.state_dir.parent().unwrap().join("backup");
    Service::backup(&f.config, &backup).unwrap();
    let mut later = f.input.clone();
    later.operation_id = uuid::Uuid::new_v4();
    {
        let service = f.open();
        run(&service, Operation::SaveDraft(later.clone()))
            .await
            .unwrap();
    }
    Service::restore(&f.config, &backup).unwrap();
    assert_eq!(f.record(), original);
    let appends = f.backend.bytes.lock().unwrap().len();
    let service = f.open();
    run(&service, f.status()).await.unwrap();
    let health = serde_json::to_value(run(&service, Operation::Health).await.unwrap()).unwrap();
    assert_eq!(health["status"], "degraded");
    for operation in [
        Operation::SaveDraft(later.clone()),
        Operation::DraftStatus(DraftStatusInput {
            account_id: later.account_id,
            account_generation: later.account_generation,
            operation_id: later.operation_id,
            mailbox: later.mailbox,
            reconcile: false,
        }),
    ] {
        assert_eq!(
            run(&service, operation).await.unwrap_err().code,
            ErrorCode::JournalUnavailable
        );
    }
    assert_eq!(f.backend.bytes.lock().unwrap().len(), appends);
    let read = service.context("default", &Default::default()).unwrap();
    service
        .execute(&read, Operation::ListAccounts(Default::default()))
        .await
        .unwrap();
}

#[tokio::test]
async fn snapshots_preserve_all_outcomes_original_targets_and_reconstruction() {
    for state in [
        "prepared",
        "in_flight",
        "created",
        "rejected",
        "outcome_unknown",
        "duplicate",
    ] {
        let initial = match state {
            "prepared" | "in_flight" => DraftOperationState::Prepared,
            "rejected" => DraftOperationState::Rejected,
            "outcome_unknown" | "duplicate" => DraftOperationState::OutcomeUnknown,
            _ => DraftOperationState::Created {
                appended_message: None,
            },
        };
        let mut f = Fixture::new(initial).await;
        if state == "in_flight" {
            DraftJournal::open_existing(f.config.state_dir.join("drafts.sqlite"))
                .unwrap()
                .begin_dispatch(&f.record().operation)
                .unwrap();
        }
        if state == "duplicate" {
            let service = f.open();
            let Operation::DraftStatus(mut input) = f.status() else {
                panic!()
            };
            input.reconcile = true;
            run(&service, Operation::DraftStatus(input)).await.unwrap();
        }
        f.repoint();
        Service::setup(f.config.clone()).unwrap();
        let expected = f.record();
        let registry = std::fs::read(f.config.state_dir.join("accounts.json")).unwrap();
        Service::verify_state(&f.config).unwrap();
        let backup = f.config.state_dir.parent().unwrap().join("history-backup");
        Service::backup(&f.config, &backup).unwrap();
        Service::restore(&f.config, &backup).unwrap();
        assert_eq!(f.record(), expected, "{state}");
        assert_eq!(
            std::fs::read(f.config.state_dir.join("accounts.json")).unwrap(),
            registry
        );
        let service = f.open();
        let appends = f.backend.bytes.lock().unwrap().len();
        let replay = run(&service, Operation::SaveDraft(f.input.clone())).await;
        match state {
            "prepared" => assert_eq!(replay.unwrap_err().code, ErrorCode::JournalUnavailable),
            "in_flight" | "outcome_unknown" => {
                assert_eq!(replay.unwrap_err().code, ErrorCode::OutcomeUnknown)
            }
            _ => {
                replay.unwrap();
            }
        }
        assert_eq!(f.backend.bytes.lock().unwrap().len(), appends);
        if state == "outcome_unknown" {
            let Operation::DraftStatus(mut input) = f.status() else {
                panic!()
            };
            input.reconcile = true;
            run(&service, Operation::DraftStatus(input)).await.unwrap();
            assert!(matches!(
                f.record().state,
                DraftOperationState::Duplicate { .. }
            ));
        }
    }
}

#[tokio::test]
async fn upgrade_verification_refuses_incompatible_prepared_reconstruction_without_changes() {
    for encoder in [
        String::new(),
        "mail builder/1.0.0".into(),
        "mail-builder/\u{7f}".into(),
        "mail-builder/東京".into(),
        "x".repeat(129),
    ] {
        let f = Fixture::new(DraftOperationState::Prepared).await;
        f.mutate_reconstruction("encoder", encoder.into());
        let before = f.record();
        assert_eq!(
            Service::verify_state(&f.config).unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );
        let service = f.open();
        run(&service, f.status()).await.unwrap();
        assert_eq!(
            run(&service, Operation::SaveDraft(f.input.clone()))
                .await
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedCapability
        );
        assert_eq!(f.record(), before);
        assert!(f.backend.bytes.lock().unwrap().is_empty());
        assert_eq!(f.backend.routes.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn coherent_local_rollback_cannot_prove_absence_against_an_external_witness() {
    let f = Fixture::new(DraftOperationState::Created {
        appended_message: None,
    })
    .await;
    let backup = f.config.state_dir.parent().unwrap().join("rollback-backup");
    Service::backup(&f.config, &backup).unwrap();
    let mut later = f.input.clone();
    later.operation_id = uuid::Uuid::new_v4();
    {
        let service = f.open();
        run(&service, Operation::SaveDraft(later.clone()))
            .await
            .unwrap();
    }
    Service::restore(&f.config, &backup).unwrap();
    // Simulate rollback of *all* local state, including the restore fence, to
    // the healthy backup. The independent provider still retains both APPENDs.
    std::fs::remove_file(f.config.state_dir.join("drafts.suspended")).unwrap();
    Service::verify_state(&f.config).unwrap();
    let service = f.open();
    let result = run(
        &service,
        Operation::DraftStatus(DraftStatusInput {
            account_id: later.account_id,
            account_generation: later.account_generation,
            operation_id: later.operation_id,
            mailbox: later.mailbox,
            reconcile: false,
        }),
    )
    .await;
    assert_eq!(result.unwrap_err().code, ErrorCode::OperationNotFound);
    assert_eq!(f.backend.bytes.lock().unwrap().len(), 2);
}
