mod support;
use mailctl::{
    config::{Config, CredentialSource, HistoricalDraftScope, Limits},
    domain::{DraftStatusInput, Error, ErrorCode, Operation, OperationResult, SaveDraftInput},
    draft::PreparedDraft,
    draft_journal::{DraftJournal, DraftOperationState},
    imap::{AppendOutcome, AppendUid},
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
    outcome: AppendOutcome,
    validity: Mutex<Result<u32, ErrorCode>>,
}
impl DraftBackend for Backend {
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
            validity: Mutex::new(Ok(77)),
            outcome: match state {
                DraftOperationState::Rejected => AppendOutcome::Rejected,
                DraftOperationState::OutcomeUnknown => AppendOutcome::Unknown,
                _ => AppendOutcome::Created {
                    uid: Some(AppendUid {
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
        account.mailboxes = vec!["New Drafts".into()];
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
        grant.mailboxes = vec!["New Drafts".into()];
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
                f.mutate_reconstruction("encoder_version", 999.into());
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
        "uuid",
        "generation",
        "mailbox",
        "read_only",
        "account",
    ] {
        let mut f = Fixture::new(DraftOperationState::Prepared).await;
        f.repoint();
        let grant = f
            .config
            .grants
            .iter_mut()
            .find(|g| g.name == "writer")
            .unwrap();
        match scope {
            "absent" => grant.historical_drafts.clear(),
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
