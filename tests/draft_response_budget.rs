mod support;

use mailctl::{
    config::{Config, Limits, MailboxScope},
    domain::{
        DraftContent, DraftState, DraftStatusInput, Error, ErrorCode, Operation, OperationResult,
        SaveDraftInput,
    },
    draft::{DraftEvidence, DraftMessageIdentity, DraftVerification, PreparedDraft},
    draft_journal::{DraftJournal, DraftOperationState},
    imap::AppendOutcome,
    service::{DraftAppend, DraftBackend, DraftPreparation, MailboxTarget, Service},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Backend {
    appends: AtomicUsize,
    uid: Option<DraftMessageIdentity>,
}
impl DraftBackend for Backend {
    fn prepare<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a Limits,
    ) -> DraftPreparation<'a> {
        Box::pin(async { Ok(Box::new(Append(self)) as Box<dyn DraftAppend>) })
    }
    fn reconcile<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a DraftVerification,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<DraftEvidence, Error>> + Send + 'a>> {
        Box::pin(async { panic!("response admission never reconciles") })
    }
}
struct Append<'a>(&'a Backend);
impl DraftAppend for Append<'_> {
    fn uid_validity(&self) -> u32 {
        77
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
            Ok(AppendOutcome::Created { uid: self.0.uid })
        })
    }
}

struct Fixture {
    service: Service,
    config: Config,
    backend: Arc<Backend>,
    input: SaveDraftInput,
    _installation: support::Installation,
}
impl Fixture {
    async fn new(mailbox: String, uid: Option<DraftMessageIdentity>) -> Self {
        let installation = support::Installation::two_accounts();
        let mut config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        config.accounts[0].mailboxes = MailboxScope::Only(vec![mailbox.clone()]);
        config.accounts[0].from_identities = vec!["fixture@example.test".into()];
        config.accounts[0].drafts_mailbox = Some(mailbox.clone());
        config.accounts[0].credential = mailctl::config::CredentialSource::Session {};
        config
            .grants
            .iter_mut()
            .find(|grant| grant.name == "writer")
            .unwrap()
            .mailboxes = MailboxScope::Only(vec![mailbox.clone()]);
        Service::setup(config.clone()).unwrap();
        let backend = Arc::new(Backend {
            appends: AtomicUsize::new(0),
            uid,
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
            panic!("fixture account")
        };
        let input = SaveDraftInput {
            account_id: accounts.accounts[0].account_id.parse().unwrap(),
            account_generation: 1,
            operation_id: uuid::Uuid::new_v4(),
            mailbox,
            draft: Box::new(DraftContent {
                body: "Synthetic draft response admission.".into(),
                ..Default::default()
            }),
        };
        Self {
            _installation: installation,
            config,
            service,
            backend,
            input,
        }
    }
    async fn save(&self, response_limit: usize) -> Result<OperationResult, Error> {
        let context = self
            .service
            .context("writer", &Default::default())
            .unwrap()
            .with_response_limit(response_limit);
        self.service
            .execute(&context, Operation::SaveDraft(self.input.clone()))
            .await
    }
}

#[tokio::test]
async fn small_response_rejects_creation_before_append_and_allows_a_larger_retry() {
    let fixture = Fixture::new("a".repeat(900), None).await;
    assert_eq!(
        fixture.save(1024).await.unwrap_err().code,
        ErrorCode::ResponseTooLarge
    );
    assert_eq!(fixture.backend.appends.load(Ordering::SeqCst), 0);
    let history =
        DraftJournal::open_existing_nowait(fixture.config.state_dir.join("drafts.sqlite")).unwrap();
    assert!(
        history
            .inspect(&fixture.input.identity())
            .unwrap()
            .is_none()
    );
    drop(history);
    let OperationResult::Draft(receipt) = fixture.save(4096).await.unwrap() else {
        panic!("created receipt")
    };
    assert_eq!(receipt.state, DraftState::CreatedReferenceUnavailable);
    assert_eq!(fixture.backend.appends.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn small_response_retains_the_identity_of_an_existing_creation() {
    let fixture = Fixture::new("a".repeat(900), None).await;
    fixture.save(4096).await.unwrap();
    let error = fixture.save(1024).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::OutcomeUnknown);
    assert!(!error.retryable);
    assert_eq!(
        error.draft_operation.unwrap().identity,
        fixture.input.identity()
    );
    assert_eq!(fixture.backend.appends.load(Ordering::SeqCst), 1);
    let history =
        DraftJournal::open_existing_nowait(fixture.config.state_dir.join("drafts.sqlite")).unwrap();
    assert!(matches!(
        history
            .inspect(&fixture.input.identity())
            .unwrap()
            .unwrap()
            .state,
        DraftOperationState::Created { .. }
    ));
}

#[tokio::test]
async fn small_response_omits_an_optional_reference_without_losing_creation() {
    let fixture = Fixture::new(
        "a".repeat(64),
        Some(DraftMessageIdentity {
            uid_validity: 77,
            uid: 4,
        }),
    )
    .await;
    let result = fixture.save(1024).await.unwrap();
    assert!(serde_json::to_vec(&result).unwrap().len() <= 512);
    let OperationResult::Draft(receipt) = result else {
        panic!("created receipt")
    };
    assert_eq!(receipt.state, DraftState::CreatedReferenceUnavailable);
    assert!(receipt.message_reference.is_none());
    let context = fixture
        .service
        .context("writer", &Default::default())
        .unwrap();
    let identity = fixture.input.identity();
    let OperationResult::Draft(receipt) = fixture
        .service
        .execute(
            &context,
            Operation::DraftStatus(DraftStatusInput {
                account_id: identity.account_id,
                account_generation: 1,
                operation_id: identity.operation_id,
                mailbox: fixture.input.mailbox.clone(),
                reconcile: false,
            }),
        )
        .await
        .unwrap()
    else {
        panic!("full receipt")
    };
    assert_eq!(receipt.state, DraftState::Created);
    assert!(receipt.message_reference.is_some());
    assert_eq!(fixture.backend.appends.load(Ordering::SeqCst), 1);
}
