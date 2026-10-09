mod fuzz_support;
mod support;
use mailctl::{
    config::{Config, Limits},
    domain::{Error, ErrorCode, Operation, OperationResult, SaveDraftInput},
    draft::{DraftMessageIdentity, PreparedDraft},
    draft_journal::{DraftJournal, DraftOperationState},
    imap::AppendOutcome,
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

#[test]
fn draft_deserialization_reuses_the_owned_body_input() {
    let bytes = 1024 * 1024;
    let input = serde_json::json!({"body": "x".repeat(bytes)});
    let allocations = allocation_counter::measure(|| {
        let content: mailctl::domain::DraftContent = serde_json::from_value(input).unwrap();
        assert_eq!(content.body.len(), bytes);
    });
    assert!(allocations.bytes_total < 64 * 1024, "{allocations:?}");
}

#[test]
fn small_draft_composition_allocates_for_content_instead_of_the_mime_ceiling() {
    let input = mailctl::draft::DraftInput {
        from: "work@example.test".into(),
        message_id: "small@mailctl.invalid".into(),
        date_unix: 1_700_000_000,
        body: "A short synthetic draft.".into(),
        ..Default::default()
    };
    let mut draft = None;
    let allocations = allocation_counter::measure(|| {
        draft = Some(PreparedDraft::compose(input, 8 * 1024 * 1024).unwrap());
    });
    eprintln!("small draft composition: {allocations:?}");
    assert!(allocations.bytes_total < 64 * 1024, "{allocations:?}");
    let draft = draft.unwrap();
    assert!(draft.bytes().len() < 1024);
    let parsed = mail_parser::MessageParser::default()
        .parse(draft.bytes())
        .unwrap();
    assert_eq!(
        parsed.body_text(0).unwrap().trim_end(),
        "A short synthetic draft."
    );
}

#[test]
fn large_draft_composition_sizes_storage_for_supported_encoded_content() {
    let maximum = 8 * 1024 * 1024;
    let mut measured = Vec::new();
    for bytes in [64 * 1024, 2 * 1024 * 1024] {
        for (kind, line) in [
            (
                "ascii",
                "A short synthetic line of ASCII text.\n".to_owned(),
            ),
            (
                "crlf",
                "A short synthetic line of ASCII text.\r\n".to_owned(),
            ),
            ("dense-newlines", "\n".to_owned()),
            ("long-ascii", "A".repeat(128)),
            ("equals", format!("{}\n", "=".repeat(76))),
            ("trailing-space", "A synthetic line \n".to_owned()),
            ("trailing-tab", "A synthetic line\t\n".to_owned()),
            (
                "control-del",
                "A short synthetic DEL \u{7f} line.\n".to_owned(),
            ),
            (
                "near-selector-del",
                format!("{}{}", "A".repeat(21), "\u{7f}".repeat(4)),
            ),
            ("near-selector-unicode", format!("{}éé", "A".repeat(21))),
            ("equals-dense-newlines", format!("={}", "\n".repeat(15))),
            (
                "nonuniform-clean",
                format!("{}{}", "A".repeat(128), "\n".repeat(128)),
            ),
            ("unicode", "München 東京 Αθήνα synthetic\n".to_owned()),
            (
                "quoted-printable",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA é\n".to_owned(),
            ),
        ] {
            let body = line.repeat(bytes / line.len());
            let body_bytes = body.len();
            let expected = body.replace("\r\n", "\n").replace('\r', "\n");
            let input = mailctl::draft::DraftInput {
                from: "work@example.test".into(),
                message_id: "large@mailctl.invalid".into(),
                date_unix: 1_700_000_000,
                body,
                ..Default::default()
            };
            let repeat_input = input.clone();
            let mut draft = None;
            let started = std::time::Instant::now();
            let allocations = allocation_counter::measure(|| {
                draft = Some(PreparedDraft::compose(input, maximum).unwrap());
            });
            let elapsed = started.elapsed();
            let draft = draft.unwrap();
            let mime_bytes = draft.bytes().len();
            eprintln!(
                "large composition: kind={kind}, input={body_bytes}, mime={mime_bytes}, elapsed={elapsed:?}, {allocations:?}"
            );
            let parsed = mail_parser::MessageParser::default()
                .parse(draft.bytes())
                .unwrap();
            assert_eq!(
                parsed.body_text(0).unwrap().replace("\r\n", "\n"),
                expected,
                "{kind} decoded composition changed"
            );
            let exact = PreparedDraft::compose(repeat_input.clone(), mime_bytes).unwrap();
            assert_eq!(exact.bytes(), draft.bytes());
            assert_eq!(exact.sha256(), draft.sha256());
            assert!(matches!(
                PreparedDraft::compose(repeat_input, mime_bytes - 1),
                Err(mailctl::draft::Error::Limit)
            ));
            measured.push((kind, allocations, mime_bytes, body_bytes));
        }
    }
    for (kind, allocations, mime_bytes, body_bytes) in measured {
        if matches!(kind, "near-selector-del" | "near-selector-unicode") {
            // The pinned encoder allocates transient formatting scratch for
            // every escape in these stress bodies. Peak memory isolates the
            // frozen representation and its storage overhead from that churn.
            let budget = mime_bytes as u64 + 128 * 1024;
            assert!(
                allocations.bytes_max <= budget,
                "{kind}, mime={mime_bytes}, peak budget={budget}, {allocations:?}"
            );
            continue;
        }
        // Plain content needs its frozen representation and header overhead;
        // CRLF normalization can additionally own one body. Encoded variants
        // allow transient storage from the pinned quoted-printable encoder.
        let budget = match kind {
            "ascii" | "long-ascii" | "dense-newlines" => mime_bytes,
            "crlf" => mime_bytes + body_bytes,
            _ => 2 * mime_bytes,
        } as u64
            + 128 * 1024;
        assert!(
            allocations.bytes_total <= budget,
            "{kind}, mime={mime_bytes}, budget={budget}, {allocations:?}"
        );
    }
}

#[test]
fn mixed_line_endings_are_normalized_with_one_bounded_body_allocation() {
    let repetitions = 65_536;
    let body = "one\r\ntwo\rthree\n".repeat(repetitions);
    let body_bytes = body.len();
    let maximum_mime_bytes = 2 * 1024 * 1024;
    let input = mailctl::draft::DraftInput {
        from: "work@example.test".into(),
        message_id: "normalization@mailctl.invalid".into(),
        date_unix: 1_700_000_000,
        body,
        ..Default::default()
    };
    let mut draft = None;
    let allocations = allocation_counter::measure(|| {
        draft = Some(PreparedDraft::compose(input, maximum_mime_bytes).unwrap());
    });
    assert!(
        allocations.bytes_total <= maximum_mime_bytes as u64 + body_bytes as u64 + 128 * 1024,
        "{allocations:?}"
    );
    let draft = draft.unwrap();
    let message = mail_parser::MessageParser::default()
        .parse(draft.bytes())
        .unwrap();
    assert_eq!(
        message.body_text(0).unwrap().replace("\r\n", "\n"),
        "one\ntwo\nthree\n".repeat(repetitions)
    );
}

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
    fn reconcile<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a mailctl::draft::DraftVerification,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<mailctl::draft::DraftEvidence, Error>> + Send + 'a>>
    {
        Box::pin(async { Err(Error::new(ErrorCode::UnsupportedCapability)) })
    }
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
            uid: Some(DraftMessageIdentity {
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

#[tokio::test]
async fn reconciliation_deadline_includes_admission_waiting() {
    let f = Fixture::new(AppendOutcome::Unknown, false, true).await;
    let Fixture {
        _installation,
        mut config,
        service,
        backend,
        input,
    } = f;
    drop(service);
    config.limits.account_connections = 1;
    for grant in &mut config.grants {
        grant.limits.account_connections = 1;
    }
    let mut quick = config
        .grants
        .iter()
        .find(|grant| grant.name == "writer")
        .unwrap()
        .clone();
    quick.name = "quick".into();
    quick.limits.operation_seconds = 1;
    config.grants.push(quick);
    Service::setup(config.clone()).unwrap();
    let service = Arc::new(
        Service::open(config)
            .unwrap()
            .with_draft_backend(backend.clone()),
    );
    let owner = {
        let service = service.clone();
        let input = input.clone();
        tokio::spawn(async move { save(&service, input).await })
    };
    backend.entered.notified().await;
    let context = service.context("quick", &Default::default()).unwrap();
    let status = Operation::DraftStatus(mailctl::domain::DraftStatusInput {
        account_id: input.account_id,
        account_generation: 1,
        operation_id: input.operation_id,
        mailbox: "Drafts".into(),
        reconcile: true,
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        service.execute(&context, status),
    )
    .await
    .expect("admission exceeded the caller's deadline");
    assert_eq!(result.unwrap_err().code, ErrorCode::Timeout);
    assert!(!owner.is_finished());
    owner.abort();
    let _ = owner.await;
    assert_eq!(backend.appends.load(Ordering::SeqCst), 1);
}

const RETRY_CORPUS: &[&[u8]] = &[
    include_bytes!("fuzz_corpus/drafts/header-injection.json"),
    include_bytes!("fuzz_corpus/drafts/nul-body.json"),
    b"{}",
];

async fn reject_uncertain_retry(fixture: &Fixture, bytes: &[u8]) {
    if let Ok(draft) = serde_json::from_slice::<mailctl::domain::DraftContent>(bytes) {
        let mut input = fixture.input.clone();
        *input.draft = draft;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            save(&fixture.service, input),
        )
        .await
        .expect("uncertain retry exceeded its deadline")
        .expect_err("uncertain retry must retain a safe failure");
        assert!(matches!(
            error.code,
            ErrorCode::OutcomeUnknown | ErrorCode::OperationConflict | ErrorCode::InvalidRequest
        ));
        assert!(!error.retryable);
    }
    assert_eq!(fixture.backend.appends.load(Ordering::SeqCst), 1);
    uncertain(fixture.status().await.unwrap_err(), &fixture.input);
}

#[tokio::test]
async fn retained_malformed_retries_never_redispatch_an_uncertain_draft() {
    let fixture = Fixture::new(AppendOutcome::Unknown, false, false).await;
    uncertain(fixture.save().await.unwrap_err(), &fixture.input);
    for bytes in RETRY_CORPUS {
        reject_uncertain_retry(&fixture, bytes).await;
    }
}

#[test]
#[ignore = "explicit bounded fuzz campaign; retained regressions run in ordinary CI"]
fn fuzz_uncertain_draft_retries() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new(AppendOutcome::Unknown, false, false));
    uncertain(
        runtime.block_on(fixture.save()).unwrap_err(),
        &fixture.input,
    );
    let campaign = fuzz_support::Campaign::from_env("uncertain_draft_retries");
    for (index, bytes) in campaign.cases(RETRY_CORPUS) {
        let allocations = allocation_counter::measure(|| {
            runtime.block_on(reject_uncertain_retry(&fixture, &bytes))
        });
        assert!(
            allocations.bytes_max < 8 * 1024 * 1024,
            "draft retry case {index} exceeded its allocation ceiling"
        );
        assert!(allocations.bytes_total < 16 * 1024 * 1024);
    }
    campaign.finish();
}
