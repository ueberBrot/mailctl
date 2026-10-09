//! IMAP discovery, search, and body reads share credential resolution.
use super::{MailboxBackend, MailboxTarget, SearchBackend, Service};
use crate::{
    authentication::BorrowedAccount,
    config::{AccountConfig, Config, Limits},
    credentials::SecretSource,
    domain::{BodyText, EmptyBodyReason, Error, ErrorCode, MailboxMetadata},
    search::{SearchBatch, SearchRequest},
};
use std::{future::Future, pin::Pin, sync::Arc};

impl Service {
    pub(super) async fn imap_backend(
        &self,
        target: MailboxTarget<'_>,
    ) -> Result<ImapBackend, Error> {
        Ok(ImapBackend {
            runtime: self.authentication().await.inspect_err(|error| {
                if self.registry.identity(&target.config.key).1 == target.generation {
                    self.observe_failure(target.account_id, error);
                }
            })?,
            account: Arc::new(BackendAccount {
                id: uuid::Uuid::parse_str(target.account_id)
                    .map_err(|_| Error::new(ErrorCode::InternalError))?,
                generation: target.generation,
                config: BackendConfig::for_target(&self.config, target.config),
                source: self.host.credential_source(&target.config.credential),
            }),
        })
    }
}

pub(super) struct ImapBackend {
    runtime: Arc<crate::authentication::Runtime>,
    account: Arc<BackendAccount>,
}
struct BackendAccount {
    id: uuid::Uuid,
    generation: u64,
    config: BackendConfig,
    source: Arc<dyn SecretSource>,
}
enum BackendConfig {
    Configured { config: Arc<Config>, index: usize },
    DraftRoute(Box<AccountConfig>),
}
impl BackendConfig {
    fn for_target(config: &Arc<Config>, target: &AccountConfig) -> Self {
        match config
            .accounts
            .iter()
            .position(|configured| std::ptr::eq(configured, target))
        {
            Some(index) => Self::Configured {
                config: config.clone(),
                index,
            },
            // Historical draft routes carry their original endpoint and source.
            None => Self::DraftRoute(Box::new(target.clone())),
        }
    }
    fn account(&self) -> &AccountConfig {
        match self {
            Self::Configured { config, index } => &config.accounts[*index],
            Self::DraftRoute(route) => route,
        }
    }
}
impl BackendAccount {
    fn borrowed(&self) -> BorrowedAccount<'_> {
        BorrowedAccount {
            id: self.id,
            generation: self.generation,
            config: self.config.account(),
            source: &self.source,
        }
    }
}
impl ImapBackend {
    async fn acquire(&self, limits: &Limits) -> Result<crate::authentication::Lease, Error> {
        self.runtime
            .acquire_borrowed(self.account.borrowed(), limits)
            .await
            .map_err(super::credentials::authentication_error)
    }
    fn mailbox_metadata(rows: Vec<crate::imap::Mailbox>) -> Vec<MailboxMetadata> {
        rows.into_iter()
            .map(|row| MailboxMetadata {
                name: row.name,
                selectable: row.selectable,
                special_use: row
                    .attributes
                    .into_iter()
                    .filter(|attribute| {
                        [
                            "\\All",
                            "\\Archive",
                            "\\Drafts",
                            "\\Flagged",
                            "\\Junk",
                            "\\Sent",
                            "\\Trash",
                        ]
                        .iter()
                        .any(|flag| attribute.eq_ignore_ascii_case(flag))
                    })
                    .collect(),
            })
            .collect()
    }
}
impl MailboxBackend for ImapBackend {
    fn discover_all<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.runtime
                .discover_inventory(self.account.borrowed(), None, limits)
                .await
                .map_err(super::credentials::authentication_error)
                .map(Self::mailbox_metadata)
        })
    }
    fn discover<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.runtime
                .discover_inventory(self.account.borrowed(), Some(names), limits)
                .await
                .map_err(super::credentials::authentication_error)
                .map(Self::mailbox_metadata)
        })
    }
}

impl SearchBackend for ImapBackend {
    fn search<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self.acquire(limits).await?;
            lease
                .with_connection(async |connection| {
                    connection
                        .search(request, limits, &mut crate::imap::Metrics::default())
                        .await
                })
                .await
        })
    }
}
impl super::message::BodyBackend for ImapBackend {
    fn read<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        request: crate::imap::BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<super::BodyRead, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self.acquire(limits).await?;
            lease
                .with_connection(async |connection| {
                    connection
                        .read_body(
                            mailbox,
                            request,
                            &crate::imap::Limits::body(limits),
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map(Into::into)
                .map_err(Into::into)
        })
    }
}
impl From<crate::imap::BodyPage> for super::BodyRead {
    fn from(page: crate::imap::BodyPage) -> Self {
        Self {
            continuation: page.continuation,
            body: BodyText {
                empty_reason: page
                    .selected_part
                    .is_none()
                    .then_some(EmptyBodyReason::NoSupportedBody),
                text: page.text,
                selected_part: page.selected_part,
                source_media_type: page.source_media_type,
                converted: page.converted,
                replacements: page.replacements,
                truncated: page.truncated,
                continuation_available: false,
                next_cursor: None,
            },
        }
    }
}

impl super::AttachmentBackend for ImapBackend {
    fn start(
        &self,
        _: MailboxTarget<'_>,
        mailbox: &str,
        uid: u32,
        validity: u32,
        part: &str,
        limits: &Limits,
    ) -> Result<Box<dyn super::AttachmentReader>, Error> {
        let decoder = crate::imap::AttachmentDecoder::new(
            mailbox,
            uid,
            validity,
            part,
            &crate::imap::Limits::attachment(limits),
        )?;
        Ok(Box::new(ImapAttachment {
            runtime: self.runtime.clone(),
            account: self.account.clone(),
            decoder,
        }))
    }

    fn list<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        request: crate::imap::AttachmentListRequest,
        limits: &'a Limits,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<crate::imap::AttachmentMetadata>, Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.acquire(limits)
                .await?
                .with_connection(async |connection| {
                    connection
                        .list_attachments(
                            mailbox,
                            request,
                            &crate::imap::Limits::attachment(limits),
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(Into::into)
        })
    }
}

struct ImapAttachment {
    runtime: Arc<crate::authentication::Runtime>,
    account: Arc<BackendAccount>,
    decoder: crate::imap::AttachmentDecoder,
}
impl super::AttachmentReader for ImapAttachment {
    fn next<'a>(
        &'a mut self,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AttachmentData, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self
                .runtime
                .acquire_borrowed(self.account.borrowed(), limits)
                .await
                .map_err(super::credentials::authentication_error)?;
            lease
                .with_connection(async |connection| {
                    connection
                        .read_attachment(
                            &mut self.decoder,
                            &crate::imap::Limits::attachment(limits),
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(|error| match error {
                    crate::imap::Error::Limit => Error::new(ErrorCode::AttachmentTooLarge),
                    error => error.into(),
                })
        })
    }
}

impl super::DraftBackend for ImapBackend {
    fn reconcile<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        expected: &'a crate::draft::DraftVerification,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::draft::DraftEvidence, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.acquire(limits)
                .await?
                .with_connection(async |connection| {
                    connection
                        .reconcile_draft(
                            mailbox,
                            expected,
                            limits,
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(Into::into)
        })
    }

    fn prepare<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        limits: &'a Limits,
    ) -> super::DraftPreparation<'a> {
        Box::pin(async move {
            let (lease, validity) = self
                .acquire(limits)
                .await?
                .draft_target(mailbox, &crate::imap::Limits::body(limits))
                .await
                .map_err(|error| match error {
                    crate::imap::Error::UnsafeSelection => {
                        Error::new(ErrorCode::DraftMailboxUnavailable)
                    }
                    error => error.into(),
                })?;
            Ok(Box::new(ImapDraft {
                lease,
                mailbox,
                validity,
            }) as Box<dyn super::DraftAppend>)
        })
    }
}
struct ImapDraft<'a> {
    lease: crate::authentication::Lease,
    mailbox: &'a str,
    validity: u32,
}
impl super::DraftAppend for ImapDraft<'_> {
    fn uid_validity(&self) -> u32 {
        self.validity
    }
    fn append<'a>(
        self: Box<Self>,
        draft: &'a crate::draft::PreparedDraft,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a,
    {
        Box::pin(async move {
            self.lease
                .with_connection(async |connection| {
                    let mut bounds = crate::imap::Limits::body(limits);
                    bounds.max_operation_bytes =
                        limits.draft_mime_bytes.saturating_add(1024 * 1024);
                    connection
                        .append_draft(
                            self.mailbox,
                            draft,
                            &bounds,
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MailboxTarget, Service};
    use crate::{
        config::{AccountConfig, Config, CredentialSource, MailboxScope, TlsMode},
        credentials::{Availability, Secret, SecretSource, SourceError},
        domain::AuthenticationOutcome,
        host::HostEnvironment,
        policy::Narrowing,
    };
    use std::{
        future::Future,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };
    struct Host(AtomicUsize);
    struct Source;
    impl SecretSource for Source {
        fn availability(&self, _: uuid::Uuid) -> Availability {
            Availability::Configured
        }
        fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
            panic!("backend construction must not resolve credentials");
        }
    }
    impl HostEnvironment for Host {
        fn credential_source(&self, _: &CredentialSource) -> Arc<dyn SecretSource> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Arc::new(Source)
        }
        fn tls_roots(&self) -> Result<tokio_rustls::rustls::RootCertStore, SourceError> {
            Ok(tokio_rustls::rustls::RootCertStore::empty())
        }
    }
    fn configuration() -> Config {
        Config::parse(&format!(
            r#"
default_grant = "reader"
state_dir = {state_dir}
[[accounts]]
key = "synthetic"
alias = "synthetic"
server = "imap.example.test"
username = "synthetic@example.test"
mailboxes = ["INBOX"]
from_identities = ["synthetic@example.test"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["synthetic"]
mailboxes = ["INBOX"]
"#,
            state_dir =
                serde_json::to_string(&std::env::temp_dir().join("mailctl-account-copy-contract"))
                    .unwrap()
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn repeated_read_backends_do_not_copy_large_account_configuration() {
        let config = large_configuration();
        let host = Arc::new(Host(AtomicUsize::new(0)));
        let service = Service::in_memory(config)
            .unwrap()
            .with_environment(host.clone());
        let configured = &service.config.accounts[0];
        let (id, generation) = service.registry.identity(&configured.key);
        let target = MailboxTarget {
            account_id: id,
            generation,
            config: configured,
        };
        // Finish trust initialization before measuring account setup and subsequent reads.
        service.authentication().await.unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let initial = allocation_counter::measure(|| {
            let mut backend = std::pin::pin!(service.imap_backend(target));
            let Poll::Ready(Ok(backend)) = backend.as_mut().poll(&mut context) else {
                panic!("initialized backend construction must not wait");
            };
            drop(backend);
        });
        println!(
            "initial read backend: {} allocated bytes, {} retained bytes",
            initial.bytes_total, initial.bytes_current
        );
        assert!(initial.bytes_total <= 2 * 1024 * 1024);
        assert!(initial.bytes_current <= 2 * 1024 * 1024);
        let allocations = allocation_counter::measure(|| {
            for _ in 0..16 {
                let mut backend = std::pin::pin!(service.imap_backend(target));
                let Poll::Ready(Ok(backend)) = backend.as_mut().poll(&mut context) else {
                    panic!("initialized backend construction must not wait");
                };
                drop(backend);
            }
        });
        println!(
            "16 initialized read backends: {} allocations, {} allocated bytes",
            allocations.count_total, allocations.bytes_total
        );
        assert!(
            allocations.bytes_total <= 64 * 1024,
            "initialized read backends copied {} bytes of immutable configuration",
            allocations.bytes_total
        );
        assert_eq!(
            allocations.bytes_current, 0,
            "read setup must not accumulate retained configuration copies"
        );
        // Source selection remains per request; cache configuration, not dynamic source objects.
        assert_eq!(host.0.load(Ordering::SeqCst), 17);
    }

    fn large_configuration() -> Config {
        let mut config = configuration();
        let mut mailboxes = vec!["INBOX".into()];
        mailboxes.extend((0..999).map(|index| format!("Mailbox-{index:04}-{}", "x".repeat(1000))));
        config.accounts[0].mailboxes = MailboxScope::Only(mailboxes);
        config.accounts[0].from_identities = (0..100)
            .map(|index| format!("Sender-{index:03}-{}", "x".repeat(1000)))
            .collect();
        config
    }

    struct MissingSource(Arc<AtomicUsize>);
    impl SecretSource for MissingSource {
        fn availability(&self, _: uuid::Uuid) -> Availability {
            Availability::Configured
        }
        fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(SourceError::Missing)
        }
    }
    struct MissingHost(Arc<AtomicUsize>);
    impl HostEnvironment for MissingHost {
        fn credential_source(&self, _: &CredentialSource) -> Arc<dyn SecretSource> {
            Arc::new(MissingSource(self.0.clone()))
        }
        fn tls_roots(&self) -> Result<tokio_rustls::rustls::RootCertStore, SourceError> {
            Ok(tokio_rustls::rustls::RootCertStore::empty())
        }
    }

    #[test]
    fn doctor_does_not_copy_large_account_configuration() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolutions = Arc::new(AtomicUsize::new(0));
        let service = Service::in_memory(large_configuration())
            .unwrap()
            .with_environment(Arc::new(MissingHost(resolutions.clone())));
        let context = service.context("reader", &Narrowing::default()).unwrap();
        runtime.block_on(service.authentication()).unwrap();
        let mut doctor = None;
        let allocations = allocation_counter::measure(|| {
            doctor = Some(runtime.block_on(service.doctor(&context, true)).unwrap());
        });
        let doctor = doctor.unwrap();
        assert_eq!(doctor.status, "degraded");
        assert!(matches!(
            doctor.accounts[0].authentication.as_ref().unwrap().outcome,
            AuthenticationOutcome::Failed { .. }
        ));
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        println!(
            "initialized doctor check: {} allocated bytes",
            allocations.bytes_total
        );
        assert!(
            allocations.bytes_total <= 64 * 1024,
            "doctor copied {} bytes of immutable configuration",
            allocations.bytes_total
        );
    }

    struct RoutingHost(Mutex<Vec<CredentialSource>>);
    impl HostEnvironment for RoutingHost {
        fn credential_source(&self, source: &CredentialSource) -> Arc<dyn SecretSource> {
            self.0.lock().unwrap().push(source.clone());
            Arc::new(Source)
        }
        fn tls_roots(&self) -> Result<tokio_rustls::rustls::RootCertStore, SourceError> {
            Ok(tokio_rustls::rustls::RootCertStore::empty())
        }
    }

    async fn preserves_owned_draft_route(change: impl FnOnce(&mut AccountConfig)) {
        let mut original = configuration();
        original.accounts[0].drafts_mailbox = Some("INBOX".into());
        let expected = original.accounts[0].clone();
        let host = Arc::new(RoutingHost(Mutex::new(Vec::new())));
        let mut service = Service::in_memory(original.clone())
            .unwrap()
            .with_environment(host.clone());
        // Retain the registered route while the visible configuration changes.
        change(&mut original.accounts[0]);
        service.config = Arc::new(original);
        let current = &service.config.accounts[0];
        let (id, generation) = service.registry.identity(&current.key);
        let route = service
            .registry
            .draft_route(current, generation, "INBOX")
            .unwrap();
        assert!(matches!(route, std::borrow::Cow::Owned(_)));
        let backend = service
            .imap_backend(MailboxTarget {
                account_id: id,
                generation,
                config: &route,
            })
            .await
            .expect("an owned draft route must construct a native backend");
        let account = backend.account.borrowed();
        assert_eq!(account.id.to_string(), id);
        assert_eq!(account.generation, generation);
        assert_eq!(account.config.server, expected.server);
        assert_eq!(account.config.port, expected.port);
        assert_eq!(account.config.tls, expected.tls);
        assert_eq!(account.config.username, expected.username);
        assert_eq!(account.config.credential, expected.credential);
        assert_eq!(account.config.drafts_mailbox, expected.drafts_mailbox);
        assert_eq!(host.0.lock().unwrap().as_slice(), &[expected.credential]);
    }

    #[tokio::test]
    async fn owned_historical_draft_routes_preserve_original_authentication_routing() {
        preserves_owned_draft_route(|current| {
            current.server = "new.example.test".into();
            current.port = 143;
            current.tls = TlsMode::Starttls;
            current.username = "new@example.test".into();
            current.credential = CredentialSource::Native {};
        })
        .await;
    }

    #[tokio::test]
    async fn owned_current_draft_routes_preserve_registered_mailbox_spelling() {
        preserves_owned_draft_route(|current| {
            current.drafts_mailbox = Some("inbox".into());
        })
        .await;
    }
}
