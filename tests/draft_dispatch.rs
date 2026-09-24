mod support;
use mailctl::{
    config::{Config, Limits},
    domain::{Error, ErrorCode, Operation, OperationResult, SaveDraftInput},
    draft::PreparedDraft,
    draft_journal::{DraftJournal, DraftOperationState},
    imap::{AppendOutcome, AppendUid},
    service::{DraftAppend, DraftBackend, MailboxTarget, Service},
};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;

struct Backend {
    outcome: AppendOutcome,
    validity: AtomicU32,
    appends: AtomicUsize,
    path: PathBuf,
    fail_outcome: bool,
    stall: bool,
    entered: Notify,
}
impl DraftBackend for Backend {
    fn prepare<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        _: &'a Limits,
    ) -> mailctl::service::DraftPreparation<'a> {
        Box::pin(async move {
            assert_eq!(mailbox, "Drafts");
            Ok(Box::new(Prepared(self)) as Box<dyn DraftAppend>)
        })
    }
}
struct Prepared<'a>(&'a Backend);
impl DraftAppend for Prepared<'_> {
    fn uid_validity(&self) -> u32 {
        self.0.validity.load(Ordering::SeqCst)
    }
    fn append<'a>(
        self: Box<Self>,
        _: &'a PreparedDraft,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a,
    {
        Box::pin(async move {
            self.0.appends.fetch_add(1, Ordering::SeqCst);
            if self.0.fail_outcome {
                rusqlite::Connection::open(&self.0.path).unwrap().execute_batch(
                    "CREATE TRIGGER fail_outcome BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;"
                ).unwrap();
            }
            self.0.entered.notify_one();
            if self.0.stall {
                std::future::pending::<()>().await;
            }
            Ok(self.0.outcome)
        })
    }
}
struct Fixture {
    _installation: support::Installation,
    config: Config,
    service: Arc<Service>,
    backend: Arc<Backend>,
    input: SaveDraftInput,
}
impl Fixture {
    async fn new(outcome: AppendOutcome, fail_outcome: bool, stall: bool) -> Self {
        let installation = support::Installation::two_accounts();
        let mut config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        config.accounts[0].from_identities = vec!["work@example.test".into()];
        config.limits.operation_seconds = 2;
        config.limits.connection_seconds = 1;
        config.limits.initialization_seconds = 1;
        for grant in &mut config.grants {
            grant.limits = config.limits.clone();
        }
        Service::setup(config.clone()).unwrap();
        let backend = Arc::new(Backend {
            outcome,
            validity: AtomicU32::new(77),
            appends: AtomicUsize::new(0),
            path: config.state_dir.join("drafts.sqlite"),
            fail_outcome,
            stall,
            entered: Notify::new(),
        });
        let service = Arc::new(
            Service::open(config.clone())
                .unwrap()
                .with_draft_backend(backend.clone()),
        );
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
            draft: Default::default(),
        };
        Self {
            _installation: installation,
            config,
            service,
            backend,
            input,
        }
    }
    async fn save(&self) -> Result<OperationResult, Error> {
        save(&self.service, self.input.clone()).await
    }
    fn state(&self) -> DraftOperationState {
        DraftJournal::open_existing(&self.backend.path)
            .unwrap()
            .inspect(&self.input.identity())
            .unwrap()
            .unwrap()
            .state
    }
    async fn status(&self) -> Result<OperationResult, Error> {
        let context = self.service.context("writer", &Default::default()).unwrap();
        self.service
            .execute(
                &context,
                Operation::DraftStatus(mailctl::domain::DraftStatusInput {
                    account_id: self.input.account_id,
                    account_generation: 1,
                    operation_id: self.input.operation_id,
                    mailbox: "Drafts".into(),
                    reconcile: false,
                }),
            )
            .await
    }
}
async fn save(service: &Service, input: SaveDraftInput) -> Result<OperationResult, Error> {
    let context = service.context("writer", &Default::default()).unwrap();
    service.execute(&context, Operation::SaveDraft(input)).await
}
fn uncertain(error: Error, input: &SaveDraftInput) {
    assert_eq!(error.code, ErrorCode::OutcomeUnknown);
    assert!(!error.retryable);
    assert_eq!(error.exit_code(), 7);
    let details = error.draft_operation.unwrap();
    assert_eq!(details.identity, input.identity());
    assert_eq!(details.mailbox, "Drafts");
    assert_eq!(details.uid_validity, Some(77));
}

#[tokio::test]
async fn recorded_creation_and_rejection_replay_without_another_append() {
    for outcome in [
        AppendOutcome::Created {
            uid: Some(AppendUid {
                uid_validity: 77,
                uid: 4,
            }),
        },
        AppendOutcome::Created { uid: None },
        AppendOutcome::Rejected,
    ] {
        let f = Fixture::new(outcome, false, false).await;
        let result = serde_json::to_value(f.save().await.unwrap()).unwrap();
        let expected = match outcome {
            AppendOutcome::Created { uid: Some(_) } => "created",
            AppendOutcome::Created { uid: None } => "created_reference_unavailable",
            _ => "rejected",
        };
        assert_eq!(result["state"], expected);
        assert_eq!(
            result["message_reference"].is_string(),
            expected == "created"
        );
        assert_eq!(
            serde_json::to_value(f.save().await.unwrap()).unwrap(),
            result
        );
        assert_eq!(
            serde_json::to_value(f.status().await.unwrap()).unwrap(),
            result
        );
        let mut changed = f.input.clone();
        changed.draft.subject = "Changed".into();
        assert_eq!(
            save(&f.service, changed).await.unwrap_err().code,
            ErrorCode::OperationConflict
        );
        assert_eq!(f.backend.appends.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn uncertain_acceptance_and_failed_outcome_commit_never_redispatch() {
    for fail_commit in [false, true] {
        let outcome = if fail_commit {
            AppendOutcome::Created { uid: None }
        } else {
            AppendOutcome::Unknown
        };
        let f = Fixture::new(outcome, fail_commit, false).await;
        uncertain(f.save().await.unwrap_err(), &f.input);
        if fail_commit {
            assert_eq!(f.state(), DraftOperationState::InFlight);
            uncertain(f.save().await.unwrap_err(), &f.input);
            rusqlite::Connection::open(&f.backend.path)
                .unwrap()
                .execute_batch("DROP TRIGGER fail_outcome")
                .unwrap();
        }
        uncertain(f.save().await.unwrap_err(), &f.input);
        uncertain(f.status().await.unwrap_err(), &f.input);
        assert_eq!(f.state(), DraftOperationState::OutcomeUnknown);
        assert_eq!(f.backend.appends.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn failed_prepare_and_in_flight_commits_prevent_network_dispatch() {
    for transition in ["INSERT", "UPDATE"] {
        let f = Fixture::new(AppendOutcome::Created { uid: None }, false, false).await;
        let database = rusqlite::Connection::open(&f.backend.path).unwrap();
        database.execute_batch(&format!("CREATE TRIGGER fail_transition BEFORE {transition} ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;")).unwrap();
        assert_eq!(
            f.save().await.unwrap_err().code,
            ErrorCode::JournalUnavailable
        );
        assert_eq!(f.backend.appends.load(Ordering::SeqCst), 0);
        if transition == "UPDATE" {
            assert_eq!(f.state(), DraftOperationState::Prepared);
        }
        database
            .execute_batch("DROP TRIGGER fail_transition")
            .unwrap();
        f.save().await.unwrap();
        assert_eq!(f.backend.appends.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn live_owner_is_pending_and_cancellation_records_uncertainty_before_unlock() {
    let f = Fixture::new(AppendOutcome::Created { uid: None }, false, true).await;
    let service = f.service.clone();
    let input = f.input.clone();
    let owner = tokio::spawn(async move { save(&service, input).await });
    f.backend.entered.notified().await;
    let other = Service::open(f.config.clone()).unwrap();
    assert_eq!(f.state(), DraftOperationState::InFlight);
    assert_eq!(
        f.status().await.unwrap_err().code,
        ErrorCode::OperationInProgress
    );
    assert_eq!(
        save(&other, f.input.clone()).await.unwrap_err().code,
        ErrorCode::OperationInProgress
    );
    assert_eq!(f.state(), DraftOperationState::InFlight);
    owner.abort();
    let _ = owner.await;
    assert_eq!(f.state(), DraftOperationState::OutcomeUnknown);
    uncertain(save(&other, f.input.clone()).await.unwrap_err(), &f.input);
    assert_eq!(f.backend.appends.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn dispatched_deadline_returns_uncertainty_instead_of_retryable_timeout() {
    let f = Fixture::new(AppendOutcome::Created { uid: None }, false, true).await;
    uncertain(f.save().await.unwrap_err(), &f.input);
    assert_eq!(f.state(), DraftOperationState::OutcomeUnknown);
    uncertain(f.save().await.unwrap_err(), &f.input);
    assert_eq!(f.backend.appends.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn prepared_operation_refuses_a_recreated_target() {
    let f = Fixture::new(AppendOutcome::Created { uid: None }, false, false).await;
    let database = rusqlite::Connection::open(&f.backend.path).unwrap();
    database.execute_batch("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;").unwrap();
    assert_eq!(
        f.save().await.unwrap_err().code,
        ErrorCode::JournalUnavailable
    );
    assert_eq!(f.state(), DraftOperationState::Prepared);
    database
        .execute_batch("DROP TRIGGER stop_dispatch")
        .unwrap();
    f.backend.validity.store(88, Ordering::SeqCst);
    assert_eq!(
        f.save().await.unwrap_err().code,
        ErrorCode::DraftMailboxUnavailable
    );
    assert_eq!(f.state(), DraftOperationState::Prepared);
    assert_eq!(f.backend.appends.load(Ordering::SeqCst), 0);
}
