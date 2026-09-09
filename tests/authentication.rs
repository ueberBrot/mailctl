#[allow(dead_code)]
mod imap_support;

use mailctl::{
    authentication::{Account, Error, Runtime},
    config::{AccountConfig, CredentialSource, Limits, TlsMode},
    credentials::{Availability, Secret, SecretSource, SourceError},
};
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer},
};
use uuid::Uuid;

struct Source {
    calls: AtomicUsize,
    blocked: Mutex<bool>,
    changed: Condvar,
}
impl Source {
    fn new(blocked: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            blocked: Mutex::new(blocked),
            changed: Condvar::new(),
        })
    }
    fn unblock(&self) {
        *self.blocked.lock().unwrap() = false;
        self.changed.notify_all();
    }
    fn call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut blocked = self.blocked.lock().unwrap();
        while *blocked {
            let (next, timeout) = self
                .changed
                .wait_timeout(blocked, Duration::from_secs(5))
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "test must release the synthetic source"
            );
            blocked = next;
        }
    }
    async fn wait_calls(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.calls.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }
}
impl SecretSource for Source {
    fn availability(&self, _: Uuid) -> Availability {
        self.call();
        Availability::Configured
    }
    fn resolve(&self, _: Uuid) -> Result<Secret, SourceError> {
        self.call();
        Secret::new(b"disposable-password".to_vec())
    }
}

fn account(port: u16, source: Arc<dyn SecretSource>) -> Account {
    Account {
        id: Uuid::new_v4(),
        generation: 1,
        source,
        config: AccountConfig {
            key: "primary".into(),
            alias: "Synthetic".into(),
            server: "127.0.0.1".into(),
            port,
            tls: TlsMode::Implicit,
            username: "fixture".into(),
            mailboxes: vec!["INBOX".into()],
            from_identities: vec![],
            drafts_mailbox: None,
            credential: CredentialSource::Session {},
            retain_history: false,
        },
    }
}

async fn fixture(
    sessions: usize,
    logout: bool,
) -> (u16, RootCertStore, tokio::task::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let tls = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let mut tasks = Vec::new();
        for _ in 0..sessions {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let acceptor = acceptor.clone();
            tasks.push(tokio::spawn(async move {
                let mut wire: imap_support::Wire = Box::new(acceptor.accept(socket).await.unwrap());
                imap_support::write(&mut wire, "* OK synthetic server ready\r\n").await;
                imap_support::authenticate(&mut wire).await;
                if logout {
                    imap_support::logout(&mut wire).await;
                } else {
                    imap_support::dropped(&mut wire).await;
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    });
    (port, roots, task)
}

#[tokio::test]
async fn availability_is_distinct_from_provider_authentication_and_has_no_cache() {
    let runtime = Runtime::new(Limits::default(), RootCertStore::empty()).unwrap();
    let source = Source::new(false);
    let id = Uuid::new_v4();
    assert_eq!(
        runtime.inspect(id, 1, source.clone()).await,
        Ok(Availability::Configured)
    );
    assert_eq!(
        runtime.inspect(id, 1, source.clone()).await,
        Ok(Availability::Configured)
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn doctor_authenticates_then_logs_out_and_limits_each_runtime_independently() {
    let (port, roots, fixture) = fixture(2, true).await;
    let source = Source::new(false);
    let account = account(port, source.clone());
    let limits = Limits::default();
    let first = Runtime::new(limits.clone(), roots.clone()).unwrap();
    let second = Runtime::new(limits.clone(), roots).unwrap();
    assert_eq!(first.doctor(&account, &limits).await, Ok(()));
    assert_eq!(
        first.doctor(&account, &limits).await,
        Err(Error::RateLimited)
    );
    assert_eq!(second.doctor(&account, &limits).await, Ok(()));
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    fixture.await.unwrap();
}

#[tokio::test]
async fn pooled_connections_reuse_authentication_and_expire_at_clean_boundaries() {
    let (port, roots, fixture) = fixture(4, false).await;
    let limits = Limits {
        connection_lifetime_seconds: 1,
        ..Default::default()
    };
    let first = Runtime::new(limits.clone(), roots.clone()).unwrap();
    let second = Runtime::new(limits.clone(), roots).unwrap();
    let source = Source::new(false);
    let mut account = account(port, source.clone());
    first.acquire(&account, &limits).await.unwrap().release();
    first.acquire(&account, &limits).await.unwrap().release();
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    let active = first.acquire(&account, &limits).await.unwrap();
    second.acquire(&account, &limits).await.unwrap().release();
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    active.release();
    first.acquire(&account, &limits).await.unwrap().release();
    assert_eq!(source.calls.load(Ordering::SeqCst), 3);
    account.generation += 1;
    first.acquire(&account, &limits).await.unwrap().release();
    assert_eq!(source.calls.load(Ordering::SeqCst), 4);
    account.generation -= 1;
    assert!(matches!(
        first.acquire(&account, &limits).await,
        Err(Error::InvalidInput)
    ));
    drop((first, second));
    fixture.await.unwrap();
}

#[tokio::test]
async fn cancelled_native_calls_keep_worker_and_dedup_reservations_until_they_finish() {
    let limits = Limits {
        credential_workers: 1,
        queued_credentials: 1,
        ..Default::default()
    };
    let runtime = Arc::new(Runtime::new(limits, RootCertStore::empty()).unwrap());
    let source = Source::new(true);
    let id = Uuid::new_v4();
    let inspect = |id| {
        let runtime = runtime.clone();
        let source = source.clone();
        tokio::spawn(async move { runtime.inspect(id, 1, source).await })
    };
    let first = inspect(id);
    source.wait_calls(1).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let duplicate = inspect(id);
    let queued = inspect(Uuid::new_v4());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let excess = inspect(Uuid::new_v4());
    assert_eq!(excess.await.unwrap(), Err(Error::RateLimited));
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    source.unblock();
    assert_eq!(duplicate.await.unwrap(), Ok(Availability::Configured));
    assert_eq!(queued.await.unwrap(), Ok(Availability::Configured));
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn narrowed_credential_worker_limits_share_the_process_admission() {
    let runtime = Arc::new(Runtime::new(Limits::default(), RootCertStore::empty()).unwrap());
    let source = Source::new(true);
    let narrow = Limits {
        credential_workers: 1,
        queued_credentials: 1,
        ..Default::default()
    };
    let inspect = || {
        let runtime = runtime.clone();
        let source = source.clone();
        let limits = narrow.clone();
        tokio::spawn(async move {
            runtime
                .inspect_with_limits(Uuid::new_v4(), 1, source, &limits)
                .await
        })
    };
    let first = inspect();
    source.wait_calls(1).await;
    let queued = inspect();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(inspect().await.unwrap(), Err(Error::RateLimited));
    source.unblock();
    first.await.unwrap().unwrap();
    queued.await.unwrap().unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancelling_queued_credential_work_releases_its_reservation() {
    let limits = Limits {
        credential_workers: 1,
        queued_credentials: 1,
        ..Default::default()
    };
    let runtime = Arc::new(Runtime::new(limits, RootCertStore::empty()).unwrap());
    let source = Source::new(true);
    let inspect = || {
        let runtime = runtime.clone();
        let source = source.clone();
        tokio::spawn(async move { runtime.inspect(Uuid::new_v4(), 1, source).await })
    };
    let first = inspect();
    source.wait_calls(1).await;
    let queued = inspect();
    tokio::time::sleep(Duration::from_millis(20)).await;
    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let replacement = inspect();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!replacement.is_finished());
    source.unblock();
    first.await.unwrap().unwrap();
    replacement.await.unwrap().unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn immediate_same_account_replacement_survives_queued_cancellation() {
    let limits = Limits {
        credential_workers: 1,
        queued_credentials: 2,
        ..Default::default()
    };
    for _ in 0..64 {
        let runtime = Arc::new(Runtime::new(limits.clone(), RootCertStore::empty()).unwrap());
        let source = Source::new(true);
        let active = {
            let runtime = runtime.clone();
            let source = source.clone();
            tokio::spawn(async move { runtime.inspect(Uuid::new_v4(), 1, source).await })
        };
        source.wait_calls(1).await;
        let queued_id = Uuid::new_v4();
        // Poll the public operation into its occupied worker queue, then cancel it.
        tokio::select! {
            biased;
            result = runtime.inspect(queued_id, 1, source.clone()) => {
                panic!("queued inspection completed before cancellation: {result:?}");
            }
            _ = tokio::task::yield_now() => {}
        }
        let replacement = {
            let runtime = runtime.clone();
            let source = source.clone();
            tokio::spawn(async move { runtime.inspect(queued_id, 1, source).await })
        };
        source.unblock();
        assert_eq!(active.await.unwrap(), Ok(Availability::Configured));
        assert_eq!(replacement.await.unwrap(), Ok(Availability::Configured));
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn account_connections_and_pending_requests_are_bounded_and_cancel_safe() {
    let (port, roots, fixture) = fixture(2, false).await;
    let limits = Limits {
        account_connections: 1,
        account_pending_requests: 1,
        ..Default::default()
    };
    let runtime = Arc::new(Runtime::new(limits.clone(), roots).unwrap());
    let source = Source::new(false);
    let account = account(port, source.clone());
    let first = runtime.acquire(&account, &limits).await.unwrap();
    let acquire = || {
        let runtime = runtime.clone();
        let account = account.clone();
        let limits = limits.clone();
        tokio::spawn(async move { runtime.acquire(&account, &limits).await })
    };
    let queued = acquire();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(matches!(
        runtime.acquire(&account, &limits).await,
        Err(Error::RateLimited)
    ));
    queued.abort();
    assert!(queued.await.is_err());
    let replacement = acquire();
    drop(first);
    drop(replacement.await.unwrap().unwrap());
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    drop(runtime);
    fixture.await.unwrap();
}

#[tokio::test]
async fn credentials_stay_bounded_after_an_operation_deadline() {
    let limits = Limits {
        credential_workers: 1,
        queued_credentials: 1,
        operation_seconds: 1,
        connection_seconds: 1,
        initialization_seconds: 1,
        ..Default::default()
    };
    let runtime = Arc::new(Runtime::new(limits, RootCertStore::empty()).unwrap());
    let source = Source::new(true);
    let id = Uuid::new_v4();
    assert_eq!(
        runtime.inspect(id, 1, source.clone()).await,
        Err(Error::Timeout)
    );
    let duplicate = {
        let runtime = runtime.clone();
        let source = source.clone();
        tokio::spawn(async move { runtime.inspect(id, 1, source).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    source.unblock();
    assert_eq!(duplicate.await.unwrap(), Ok(Availability::Configured));
}

#[tokio::test]
async fn concurrent_authentications_share_only_the_in_flight_secret_resolution() {
    let (port, roots, fixture) = fixture(3, false).await;
    let limits = Limits::default();
    let runtime = Arc::new(Runtime::new(limits.clone(), roots).unwrap());
    let source = Source::new(true);
    let account = account(port, source.clone());
    let acquire = || {
        let runtime = runtime.clone();
        let account = account.clone();
        let limits = limits.clone();
        tokio::spawn(async move { runtime.acquire(&account, &limits).await })
    };
    let first = acquire();
    source.wait_calls(1).await;
    let second = acquire();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    source.unblock();
    drop(first.await.unwrap().unwrap());
    drop(second.await.unwrap().unwrap());
    drop(runtime.acquire(&account, &limits).await.unwrap());
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    fixture.await.unwrap();
}

#[tokio::test]
async fn source_failures_retain_their_safe_categories_before_provider_access() {
    struct Failure(SourceError);
    impl SecretSource for Failure {
        fn availability(&self, _: Uuid) -> Availability {
            self.0.into()
        }
        fn resolve(&self, _: Uuid) -> Result<Secret, SourceError> {
            Err(self.0)
        }
    }
    let limits = Limits::default();
    let runtime = Runtime::new(limits.clone(), RootCertStore::empty()).unwrap();
    for failure in [
        SourceError::Missing,
        SourceError::Locked,
        SourceError::AccessDenied,
        SourceError::Unavailable,
        SourceError::InvalidSecret,
        SourceError::InteractionRequired,
        SourceError::Internal,
    ] {
        let account = account(9, Arc::new(Failure(failure)));
        assert_eq!(
            runtime.doctor(&account, &limits).await,
            Err(Error::Source(failure))
        );
    }
    let source = Source::new(false);
    let account = account(9, source);
    let narrow = Limits {
        secret_bytes: 8,
        ..limits
    };
    assert_eq!(
        runtime.doctor(&account, &narrow).await,
        Err(Error::Source(SourceError::InvalidSecret))
    );
}

#[tokio::test]
async fn idle_connections_close_at_the_narrowed_lifetime_without_another_request() {
    let (port, roots, mut fixture) = fixture(1, false).await;
    let limits = Limits {
        connection_lifetime_seconds: 1,
        ..Default::default()
    };
    let broad = Limits::default();
    let runtime = Runtime::new(broad.clone(), roots).unwrap();
    let account = account(port, Source::new(false));
    runtime.acquire(&account, &broad).await.unwrap().release();
    runtime.acquire(&account, &limits).await.unwrap().release();
    let closed = tokio::time::timeout(Duration::from_millis(1400), &mut fixture).await;
    drop(runtime);
    if closed.is_err() {
        fixture.await.unwrap();
    }
    closed
        .expect("an idle provider connection must close by its lifetime")
        .unwrap();
}

#[tokio::test]
async fn a_broader_grant_cannot_extend_an_existing_connections_lifetime() {
    let (port, roots, mut fixture) = fixture(1, false).await;
    let broad = Limits::default();
    let narrow = Limits {
        connection_lifetime_seconds: 1,
        ..broad.clone()
    };
    let runtime = Runtime::new(broad.clone(), roots).unwrap();
    let source = Source::new(false);
    let account = account(port, source.clone());
    runtime.acquire(&account, &narrow).await.unwrap().release();
    let lease = runtime.acquire(&account, &broad).await.unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    assert!(
        !fixture.is_finished(),
        "an active lease finishes at an operation boundary"
    );
    lease.release();
    let closed = tokio::time::timeout(Duration::from_millis(200), &mut fixture).await;
    drop(runtime);
    if closed.is_err() {
        fixture.await.unwrap();
    }
    closed
        .expect("the original connection expiry must survive grant widening")
        .unwrap();
}

#[tokio::test]
async fn account_queue_deadline_releases_capacity_without_authenticating() {
    let (port, roots, fixture) = fixture(1, false).await;
    let limits = Limits {
        account_connections: 1,
        account_pending_requests: 1,
        operation_seconds: 1,
        connection_seconds: 1,
        initialization_seconds: 1,
        ..Default::default()
    };
    let runtime = Runtime::new(limits.clone(), roots).unwrap();
    let source = Source::new(false);
    let account = account(port, source.clone());
    let active = runtime.acquire(&account, &limits).await.unwrap();
    assert!(matches!(
        runtime.acquire(&account, &limits).await,
        Err(Error::Timeout)
    ));
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    active.release();
    drop(runtime.acquire(&account, &limits).await.unwrap());
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    fixture.await.unwrap();
}

#[tokio::test]
async fn generation_changes_reject_queued_old_work_and_dispose_old_leases() {
    let (port, roots, fixture) = fixture(2, false).await;
    let limits = Limits {
        account_connections: 1,
        account_pending_requests: 2,
        ..Default::default()
    };
    let runtime = Arc::new(Runtime::new(limits.clone(), roots).unwrap());
    let source = Source::new(false);
    let original = account(port, source.clone());
    let active = runtime.acquire(&original, &limits).await.unwrap();
    let acquire = |account| {
        let runtime = runtime.clone();
        let limits = limits.clone();
        tokio::spawn(async move { runtime.acquire(&account, &limits).await })
    };
    let old = acquire(original.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut current = original;
    current.generation += 1;
    let new = acquire(current);
    tokio::time::sleep(Duration::from_millis(20)).await;
    active.release();
    assert!(matches!(old.await.unwrap(), Err(Error::InvalidInput)));
    drop(new.await.unwrap().unwrap());
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    fixture.await.unwrap();
}
