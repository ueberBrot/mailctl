mod support;

use mailctl::{
    config::{Config, Limits},
    domain::{Error, ErrorCode, ListMailboxesInput, MailboxMetadata, Operation},
    service::{MailboxBackend, MailboxTarget, Service},
};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, mpsc};

struct Provider {
    entered: mpsc::UnboundedSender<String>,
    release: Semaphore,
    fail: std::sync::atomic::AtomicBool,
}
impl MailboxBackend for Provider {
    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        _: &'a [String],
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.send(target.config.key.clone()).unwrap();
            self.release.acquire().await.unwrap().forget();
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::new(ErrorCode::ProviderUnavailable));
            }
            Ok(vec![])
        })
    }
}

fn fixture() -> (Arc<Service>, Arc<Provider>, mpsc::UnboundedReceiver<String>) {
    fixture_with_limits(Limits {
        active_requests: 2,
        queued_requests: 2,
        account_connections: 1,
        account_pending_requests: 2,
        ..Default::default()
    })
}
fn fixture_with_limits(
    limits: Limits,
) -> (Arc<Service>, Arc<Provider>, mpsc::UnboundedReceiver<String>) {
    let installation = support::Installation::two_accounts();
    let mut config =
        Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.limits = limits;
    let mut third = config.accounts[0].clone();
    third.key = "shared".into();
    third.alias = "shared".into();
    config.accounts.push(third);
    config
        .grants
        .iter_mut()
        .find(|grant| grant.name == "all")
        .unwrap()
        .accounts
        .push("shared".into());
    for grant in &mut config.grants {
        grant.limits = config.limits.clone();
    }
    config.grants[0].limits.account_connections = 1;
    config.grants[0].limits.operation_seconds = 1;
    config.grants[0].limits.connection_seconds = 1;
    config.grants[0].limits.initialization_seconds = 1;
    let (entered, receiver) = mpsc::unbounded_channel();
    let provider = Arc::new(Provider {
        entered,
        release: Semaphore::new(0),
        fail: std::sync::atomic::AtomicBool::new(false),
    });
    let service = Service::in_memory(config)
        .unwrap()
        .with_mailbox_backend(provider.clone());
    (Arc::new(service), provider, receiver)
}

#[tokio::test]
async fn health_reports_only_observed_failures_in_the_effective_scope() {
    let (service, provider, _receiver) = fixture();
    let context = service.context("all", &Default::default()).unwrap();
    provider
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    provider.release.add_permits(1);
    assert_eq!(
        read(service.clone(), "work")
            .await
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::ProviderUnavailable
    );
    let mailctl::domain::OperationResult::Health(health) =
        service.execute(&context, Operation::Health).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(health.status, "degraded");
    assert_eq!(
        health
            .accounts
            .iter()
            .filter(|account| account.availability == mailctl::domain::Availability::Unavailable)
            .count(),
        1
    );
    let personal = service
        .context(
            "all",
            &mailctl::policy::Narrowing {
                accounts: Some(vec!["personal".into()]),
                ..Default::default()
            },
        )
        .unwrap();
    let mailctl::domain::OperationResult::Health(health) =
        service.execute(&personal, Operation::Health).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(health.status, "ready");
    assert_eq!(
        health.accounts[0].availability,
        mailctl::domain::Availability::Unknown
    );
    provider
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    provider.release.add_permits(1);
    read(service.clone(), "work").await.unwrap().unwrap();
    let mailctl::domain::OperationResult::Health(health) =
        service.execute(&context, Operation::Health).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(health.status, "ready");
}

fn read(
    service: Arc<Service>,
    account: &str,
) -> tokio::task::JoinHandle<Result<mailctl::domain::OperationResult, Error>> {
    read_with_grant(service, account, "all")
}
fn read_with_grant(
    service: Arc<Service>,
    account: &str,
    grant: &'static str,
) -> tokio::task::JoinHandle<Result<mailctl::domain::OperationResult, Error>> {
    let account = account.to_owned();
    tokio::spawn(async move {
        let context = service.context(grant, &Default::default()).unwrap();
        service
            .execute(
                &context,
                Operation::ListMailboxes(ListMailboxesInput {
                    account: Some(account),
                    ..Default::default()
                }),
            )
            .await
    })
}

async fn entered(receiver: &mut mpsc::UnboundedReceiver<String>) -> String {
    tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap()
}

fn service_with_host(host: Arc<dyn mailctl::host::HostEnvironment>) -> Service {
    let installation = support::Installation::two_accounts();
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    Service::in_memory(config).unwrap().with_environment(host)
}

#[tokio::test]
async fn a_busy_account_does_not_take_another_accounts_active_capacity() {
    let (service, provider, mut receiver) = fixture();
    let first = read(service.clone(), "work");
    assert_eq!(entered(&mut receiver).await, "work");
    let waiting = read(service.clone(), "work");
    let waiting_again = read(service.clone(), "work");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let other = read(service, "personal");
    assert_eq!(entered(&mut receiver).await, "personal");
    provider.release.add_permits(2);
    first.await.unwrap().unwrap();
    other.await.unwrap().unwrap();
    assert_eq!(entered(&mut receiver).await, "work");
    provider.release.add_permits(1);
    waiting.await.unwrap().unwrap();
    assert_eq!(entered(&mut receiver).await, "work");
    provider.release.add_permits(1);
    waiting_again.await.unwrap().unwrap();
}

#[tokio::test]
async fn request_saturation_and_cancellation_release_only_local_capacity() {
    let (service, provider, mut receiver) = fixture();
    let first = read(service.clone(), "work");
    let other = read(service.clone(), "personal");
    entered(&mut receiver).await;
    entered(&mut receiver).await;
    let waiting = read(service.clone(), "work");
    let waiting_other = read(service.clone(), "personal");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let overflow = read(service.clone(), "work");
    let result = tokio::time::timeout(Duration::from_millis(200), overflow)
        .await
        .expect("saturation must reject without waiting")
        .unwrap();
    assert_eq!(result.unwrap_err().code, ErrorCode::RateLimited);
    waiting.abort();
    waiting.await.unwrap_err();
    let replacement = read(service, "work");
    first.abort();
    first.await.unwrap_err();
    assert_eq!(entered(&mut receiver).await, "work");
    provider.release.add_permits(3);
    other.await.unwrap().unwrap();
    replacement.await.unwrap().unwrap();
    waiting_other.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelled_initialization_keeps_only_one_native_trust_worker() {
    use mailctl::{
        credentials::{Availability, Secret, SecretSource, SourceError},
        host::HostEnvironment,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Host(AtomicUsize);
    struct Source;
    impl SecretSource for Source {
        fn availability(&self, _: uuid::Uuid) -> Availability {
            Availability::Available
        }
        fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
            unreachable!()
        }
    }
    impl HostEnvironment for Host {
        fn credential_source(
            &self,
            _: &mailctl::config::CredentialSource,
        ) -> Arc<dyn SecretSource> {
            Arc::new(Source)
        }
        fn tls_roots(&self) -> Result<tokio_rustls::rustls::RootCertStore, SourceError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(400));
            Ok(tokio_rustls::rustls::RootCertStore::empty())
        }
    }
    let host = Arc::new(Host(AtomicUsize::new(0)));
    let service = service_with_host(host.clone());
    let context = service.context("all", &Default::default()).unwrap();
    for _ in 0..4 {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), service.doctor(&context, false))
                .await
                .is_err()
        );
    }
    assert_eq!(host.0.load(Ordering::SeqCst), 1);
    service.doctor(&context, false).await.unwrap();
    assert_eq!(host.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn panicked_trust_initialization_returns_a_stable_error_without_retrying() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct PanickingTrust(AtomicUsize);
    impl mailctl::host::HostEnvironment for PanickingTrust {
        fn credential_source(
            &self,
            _: &mailctl::config::CredentialSource,
        ) -> Arc<dyn mailctl::credentials::SecretSource> {
            panic!("trust failed before credentials");
        }
        fn tls_roots(
            &self,
        ) -> Result<tokio_rustls::rustls::RootCertStore, mailctl::credentials::SourceError>
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("synthetic trust loader panic");
        }
    }
    let host = Arc::new(PanickingTrust(AtomicUsize::new(0)));
    let service = service_with_host(host.clone());
    let context = service.context("all", &Default::default()).unwrap();
    for _ in 0..2 {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), service.doctor(&context, false))
                .await
                .expect("panicked initialization must wake its waiters")
                .unwrap_err()
                .code,
            ErrorCode::InternalError
        );
    }
    assert_eq!(host.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn waiting_accounts_rotate_and_requests_within_an_account_stay_fifo() {
    let (service, provider, mut receiver) = fixture_with_limits(Limits {
        active_requests: 1,
        queued_requests: 6,
        account_connections: 1,
        ..Default::default()
    });
    let first = read(service.clone(), "work");
    assert_eq!(entered(&mut receiver).await, "work");
    let work_one = read(service.clone(), "work");
    tokio::task::yield_now().await;
    let work_two = read(service.clone(), "work");
    tokio::task::yield_now().await;
    let personal = read(service.clone(), "personal");
    tokio::task::yield_now().await;
    let shared = read(service, "shared");
    tokio::task::yield_now().await;
    provider.release.add_permits(1);
    first.await.unwrap().unwrap();
    for (account, task) in [
        ("personal", personal),
        ("shared", shared),
        ("work", work_one),
        ("work", work_two),
    ] {
        assert_eq!(entered(&mut receiver).await, account);
        provider.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("FIFO request finishes before the next permit")
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn queued_deadlines_release_capacity_without_provider_work() {
    let (service, provider, mut receiver) = fixture_with_limits(Limits {
        active_requests: 1,
        queued_requests: 2,
        account_connections: 1,
        operation_seconds: 3,
        connection_seconds: 1,
        initialization_seconds: 1,
        ..Default::default()
    });
    let first = read(service.clone(), "work");
    assert_eq!(entered(&mut receiver).await, "work");
    // Keep the active read alive longer than the caller's queue deadline.
    let queued = read_with_grant(service.clone(), "work", "default");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), queued)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Timeout
    );
    assert!(receiver.try_recv().is_err());
    assert!(!first.is_finished());
    first.abort();
    first.await.unwrap_err();
    let replacement = read(service, "personal");
    assert_eq!(entered(&mut receiver).await, "personal");
    provider.release.add_permits(1);
    replacement.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_broader_grant_cannot_overtake_an_older_request_for_the_same_account() {
    let (service, provider, mut receiver) = fixture_with_limits(Limits {
        active_requests: 3,
        queued_requests: 4,
        account_connections: 2,
        ..Default::default()
    });
    let first = read(service.clone(), "work");
    entered(&mut receiver).await;
    let narrow = read_with_grant(service.clone(), "work", "default");
    tokio::task::yield_now().await;
    let broad = read(service, "work");
    tokio::task::yield_now().await;
    assert!(
        receiver.try_recv().is_err(),
        "newer broad work must wait behind narrowed work"
    );
    provider.release.add_permits(1);
    first.await.unwrap().unwrap();
    assert_eq!(entered(&mut receiver).await, "work");
    assert_eq!(entered(&mut receiver).await, "work");
    provider.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), narrow)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    provider.release.add_permits(1);
    broad.await.unwrap().unwrap();
}

#[tokio::test]
async fn failed_trust_initialization_marks_only_the_attempted_account_unavailable() {
    struct FailingTrust;
    impl mailctl::host::HostEnvironment for FailingTrust {
        fn credential_source(
            &self,
            _: &mailctl::config::CredentialSource,
        ) -> Arc<dyn mailctl::credentials::SecretSource> {
            panic!("trust failed before credentials");
        }
        fn tls_roots(
            &self,
        ) -> Result<tokio_rustls::rustls::RootCertStore, mailctl::credentials::SourceError>
        {
            Err(mailctl::credentials::SourceError::Unavailable)
        }
    }
    let service = Arc::new(service_with_host(Arc::new(FailingTrust)));
    assert_eq!(
        read(service.clone(), "work")
            .await
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::CredentialUnavailable
    );
    let context = service.context("all", &Default::default()).unwrap();
    let mailctl::domain::OperationResult::Health(health) =
        service.execute(&context, Operation::Health).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(health.status, "degraded");
    assert_eq!(
        health
            .accounts
            .iter()
            .filter(|account| account.availability == mailctl::domain::Availability::Unknown)
            .count(),
        1
    );
    assert_eq!(
        health
            .accounts
            .iter()
            .filter(|account| account.availability == mailctl::domain::Availability::Unavailable)
            .count(),
        1
    );
}
