//! Bounded IMAP route proofs. Each operation owns and disposes its connection.
use crate::domain::mailbox_identity;
mod append;
mod attachment;
mod body;
mod fetch;
mod mime;
mod projection;
mod search;
mod wire;

pub use append::{AppendOutcome, AppendResult, AppendUid, DraftInput, PreparedDraft};

pub use attachment::{
    AttachmentChunk, AttachmentIntegrity, AttachmentList, AttachmentListRequest,
    AttachmentMetadata, AttachmentProgress, AttachmentRequest, AttachmentTransfer,
};

pub use body::{BodyCursor, BodyPage, BodyRequest};

use io_imap::{
    rfc3501::{
        capability::ImapCapabilityGet,
        fetch::{ImapMessageFetch, ImapMessageFetchOptions},
        greeting::ImapGreetingGet,
        list::ImapMailboxList,
        login::ImapLogin,
        logout::ImapLogout,
        search::{ImapMessageSearch, ImapMessageSearchOptions},
    },
    types::{mailbox::Mailbox as WireMailbox, response::Capability, search::SearchKey},
};
use projection::Projection;
use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};
use tokio_rustls::rustls::{self, RootCertStore};
use wire::Connection;

/// An authenticated connection with no selected mailbox or retained credential.
pub(crate) struct AuthenticatedConnection(wire::Session);
impl AuthenticatedConnection {
    pub(crate) async fn discover(
        self,
        allowlist: &[String],
        maximum: usize,
    ) -> Result<Vec<Mailbox>, Error> {
        let mut metrics = Metrics::default();
        let mut connection = self.0.resume(&mut metrics);
        let names = allowlist
            .iter()
            .map(|name| (mailbox_identity(name), name.as_str()))
            .collect();
        let result = connection.discover_names(names, maximum).await?;
        connection.drive(ImapLogout::new()).await?;
        Ok(result)
    }
    pub(crate) async fn disconnect(self) -> Result<(), Error> {
        let mut metrics = Metrics::default();
        let mut connection = self.0.resume(&mut metrics);
        connection.drive(ImapLogout::new()).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Unsupported,
    Transport,
    Tls,
    Timeout,
    Eof,
    Protocol,
    Limit,
    Authentication,
    UnsafeSelection,
    StaleCursor,
    TransferExpired,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid IMAP input",
            Self::Unsupported => "unsupported IMAP route",
            Self::Transport => "IMAP transport failed",
            Self::Tls => "IMAP TLS verification failed",
            Self::Timeout => "IMAP operation timed out",
            Self::Eof => "IMAP connection closed",
            Self::Protocol => "invalid IMAP response",
            Self::Limit => "IMAP resource limit exceeded",
            Self::Authentication => "IMAP authentication failed",
            Self::UnsafeSelection => "IMAP read-only selection was not established",
            Self::StaleCursor => "message body continuation is stale",
            Self::TransferExpired => "attachment transfer expired",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Default)]
pub enum TlsMode {
    #[default]
    Implicit,
    StartTls,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_response_bytes: usize,
    pub max_operation_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_responses: usize,
    pub max_parser_steps: usize,
    pub max_nesting: usize,
    pub max_mailboxes: usize,
    pub max_uid_window: usize,
    pub max_messages: usize,
    pub max_header_bytes: usize,
    pub max_mime_parts: usize,
    pub max_body_wire_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_text_bytes: usize,
    pub max_decode_steps: usize,
    pub max_attachment_decoded_bytes: usize,
    pub max_attachment_wire_bytes: usize,
    pub max_attachment_chunk_bytes: usize,
    pub max_transfer_lifetime: Duration,
    pub max_transfers: usize,
    pub operation_timeout: Duration,
    pub connect_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_response_bytes: 64 * 1024,
            max_operation_bytes: 4 * 1024 * 1024,
            max_literal_bytes: 64 * 1024,
            max_responses: 4096,
            max_parser_steps: 8 * 1024 * 1024,
            max_nesting: 20,
            max_mailboxes: 1000,
            max_uid_window: 1000,
            max_messages: 50,
            max_header_bytes: 64 * 1024,
            max_mime_parts: 200,
            max_body_wire_bytes: 2 * 1024 * 1024,
            max_decoded_bytes: 8 * 1024 * 1024,
            max_text_bytes: 256 * 1024,
            max_decode_steps: 32 * 1024 * 1024,
            max_attachment_decoded_bytes: 10 * 1024 * 1024,
            max_attachment_wire_bytes: 16 * 1024 * 1024,
            max_attachment_chunk_bytes: 64 * 1024,
            max_transfer_lifetime: Duration::from_secs(5 * 60),
            max_transfers: 2,
            operation_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
        }
    }
}
impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > 256 * 1024
            || self.max_operation_bytes < self.max_response_bytes
            || self.max_operation_bytes > 16 * 1024 * 1024
            || self.max_literal_bytes == 0
            || self.max_literal_bytes > self.max_response_bytes
            || self.max_responses == 0
            || self.max_responses > 16384
            || self.max_parser_steps == 0
            || self.max_parser_steps > 32 * 1024 * 1024
            || self.max_nesting == 0
            || self.max_nesting > 40
            || self.max_mailboxes == 0
            || self.max_mailboxes > 1000
            || self.max_uid_window == 0
            || self.max_uid_window > 10000
            || self.max_messages == 0
            || self.max_messages > 200
            || self.max_header_bytes == 0
            || self.max_header_bytes > 256 * 1024
            || self.max_mime_parts == 0
            || self.max_mime_parts > 1000
            || self.max_body_wire_bytes == 0
            || self.max_body_wire_bytes > 8 * 1024 * 1024
            || self.max_decoded_bytes == 0
            || self.max_decoded_bytes > 32 * 1024 * 1024
            || self.max_text_bytes < 4
            || self.max_text_bytes > 2 * 1024 * 1024
            || self.max_decode_steps == 0
            || self.max_decode_steps > 128 * 1024 * 1024
            || self.max_attachment_decoded_bytes == 0
            || self.max_attachment_decoded_bytes > 32 * 1024 * 1024
            || self.max_attachment_wire_bytes == 0
            || self.max_attachment_wire_bytes > 64 * 1024 * 1024
            || self.max_attachment_chunk_bytes == 0
            || self.max_attachment_chunk_bytes > 256 * 1024
            || self.max_transfer_lifetime.is_zero()
            || self.max_transfer_lifetime > Duration::from_secs(10 * 60)
            || self.max_transfers == 0
            || self.max_transfers > 4
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(120)
            || self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(30)
        {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub append_outcome: Option<AppendOutcome>,
    pub append_wire_bytes: usize,
    pub mime_bytes: usize,
    pub wire_bytes: usize,
    pub responses: usize,
    pub parser_steps: usize,
    pub max_response_bytes: usize,
    pub max_literal_bytes: usize,
    pub decode_steps: usize,
    pub decoded_bytes: usize,
    /// Cumulative attachment payload bytes obtained over the current transfer.
    pub transfer_wire_bytes: usize,
    pub transfer_decoded_bytes: usize,
    pub transfer_decode_steps: usize,
    pub max_transfer_state_bytes: usize,
    pub active_transfers: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub name: String,
    pub selectable: bool,
    pub attributes: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct Discovery {
    pub mailboxes: Vec<Mailbox>,
    pub metrics: Metrics,
}
#[derive(Clone, Copy, Debug)]
pub struct UidWindow {
    pub first: u32,
    pub last: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub name: Option<String>,
    pub mailbox: Option<String>,
    pub host: Option<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Envelope {
    pub uid: u32,
    pub subject: Option<String>,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub received_date: Option<String>,
    pub sent_date: Option<String>,
    pub flags: Vec<String>,
    pub message_id: Option<String>,
    pub size: Option<u32>,
}
#[derive(Clone, Debug)]
pub struct Search {
    pub uid_validity: u32,
    pub envelopes: Vec<Envelope>,
    pub metrics: Metrics,
}

/// A verified TLS endpoint. Inputs and results contain no raw IMAP commands.
///
/// Authentication accepts printable ASCII credentials; literal authentication remains
/// gated. This proof accepts printable ASCII mailbox names. Wildcard and international
/// names remain gated until exact discovery has dedicated transcript evidence.
/// Search enumerates one bounded UID window; application predicates and cursors
/// are separate delivery work. Overflow returns an error, never a partial list.
pub struct ImapProbe {
    host: String,
    port: u16,
    mode: TlsMode,
    tls: Arc<rustls::ClientConfig>,
    limits: Limits,
    metrics: Metrics,
    transfers: attachment::TransferStore,
}
impl ImapProbe {
    pub(crate) async fn connect_authenticated(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticatedConnection, Error> {
        credentials(username, password)?;
        tokio::time::timeout(self.limits.operation_timeout, async {
            self.authenticate(username, password)
                .await
                .map(|connection| AuthenticatedConnection(connection.into_session()))
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    pub fn new(
        host: String,
        port: u16,
        mode: TlsMode,
        roots: RootCertStore,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if host.is_empty() || host.len() > 253 || port == 0 {
            return Err(Error::InvalidInput);
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            host,
            port,
            mode,
            tls: Arc::new(tls),
            limits,
            metrics: Metrics::default(),
            transfers: attachment::TransferStore::default(),
        })
    }
    /// Last progress snapshot, including a failed or cancelled operation.
    pub fn metrics(&self) -> Metrics {
        Metrics {
            active_transfers: self.transfers.active_count(),
            ..self.metrics
        }
    }
    /// A probe permits one operation at a time, including while its future is suspended.
    ///
    /// ```compile_fail
    /// use mailctl::imap::ImapProbe;
    /// fn overlapping(probe: &mut ImapProbe) {
    ///     let mailboxes = vec!["INBOX".to_owned()];
    ///     let first = probe.discover("fixture", "disposable-password", &mailboxes);
    ///     let second = probe.discover("fixture", "disposable-password", &mailboxes);
    ///     drop((first, second));
    /// }
    /// ```
    pub async fn discover(
        &mut self,
        username: &str,
        password: &str,
        allowlist: &[String],
    ) -> Result<Discovery, Error> {
        self.metrics = Metrics::default();
        credentials(username, password)?;
        if allowlist.len() > self.limits.max_mailboxes {
            return Err(Error::Limit);
        }
        let mut names = BTreeMap::new();
        for name in allowlist {
            mailbox(name)?;
            names.insert(mailbox_identity(name), name.as_str());
        }
        tokio::time::timeout(self.limits.operation_timeout, async {
            let maximum = self.limits.max_mailboxes;
            let mut conn = self.authenticate(username, password).await?;
            let mailboxes = conn.discover_names(names, maximum).await?;
            conn.drive(ImapLogout::new()).await?;
            Ok(Discovery {
                mailboxes,
                metrics: conn.metrics(),
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    pub async fn search(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        window: UidWindow,
    ) -> Result<Search, Error> {
        self.metrics = Metrics::default();
        credentials(username, password)?;
        mailbox(name)?;
        if window.first == 0 || window.last < window.first {
            return Err(Error::InvalidInput);
        }
        if u64::from(window.last) - u64::from(window.first) + 1 > self.limits.max_uid_window as u64
        {
            return Err(Error::Limit);
        }
        let max_messages = self.limits.max_messages;
        tokio::time::timeout(self.limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            let uid_validity = conn.examine(name).await?;
            let range = (window.first..=window.last)
                .try_into()
                .map_err(|_| Error::InvalidInput)?;
            let mut uids = conn
                .drive(ImapMessageSearch::new(
                    vec![SearchKey::Uid(range)]
                        .try_into()
                        .map_err(|_| Error::InvalidInput)?,
                    ImapMessageSearchOptions { uid: true },
                ))
                .await?;
            if uids.len() > max_messages {
                return Err(Error::Limit);
            }
            if uids
                .iter()
                .any(|u| u.get() < window.first || u.get() > window.last)
            {
                return Err(Error::Protocol);
            }
            uids.sort_unstable();
            if uids.windows(2).any(|w| w[0] == w[1]) {
                return Err(Error::Protocol);
            }
            let mut envelopes = BTreeMap::new();
            if !uids.is_empty() {
                let set = uids
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidInput)?;
                let fetched = conn
                    .drive(ImapMessageFetch::new(
                        set,
                        Projection::FIELDS.to_vec().into(),
                        ImapMessageFetchOptions {
                            uid: true,
                            ..Default::default()
                        },
                    ))
                    .await?;
                for items in fetched.into_values() {
                    let envelope = Projection::parse(items.as_ref())?.normalize();
                    if uids
                        .binary_search_by_key(&envelope.uid, |uid| uid.get())
                        .is_err()
                        || envelopes.insert(envelope.uid, envelope).is_some()
                    {
                        return Err(Error::Protocol);
                    }
                }
            }
            conn.drive(ImapLogout::new()).await?;
            Ok(Search {
                uid_validity,
                envelopes: envelopes.into_values().rev().collect(),
                metrics: conn.metrics(),
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    async fn authenticate(&mut self, user: &str, password: &str) -> Result<Connection<'_>, Error> {
        let mut conn = tokio::time::timeout(
            self.limits.connect_timeout,
            Connection::connect(
                &self.host,
                self.port,
                self.mode,
                self.tls.clone(),
                self.limits.clone(),
                &mut self.metrics,
            ),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        conn.drive(ImapGreetingGet::new(Default::default())).await?;
        let mut caps = conn.drive(ImapCapabilityGet::new()).await?;
        if matches!(self.mode, TlsMode::StartTls) {
            if !caps.contains(&Capability::StartTls) {
                return Err(Error::Unsupported);
            }
            conn = conn.upgrade(&self.host, self.tls.clone()).await?;
            caps = conn.drive(ImapCapabilityGet::new()).await?;
        }
        if !caps.contains(&Capability::Imap4Rev1) || caps.contains(&Capability::LoginDisabled) {
            return Err(Error::Unsupported);
        }
        let login =
            ImapLogin::new(user, password, Default::default()).map_err(|_| Error::InvalidInput)?;
        conn.drive(login).await?;
        let caps = conn.drive(ImapCapabilityGet::new()).await?;
        if !caps.contains(&Capability::Imap4Rev1) {
            return Err(Error::Unsupported);
        }
        Ok(conn)
    }
}
fn credentials(user: &str, password: &str) -> Result<(), Error> {
    if user.is_empty() || user.len() > 4096 || password.is_empty() || password.len() > 64 * 1024 {
        return Err(Error::InvalidInput);
    }
    if user
        .bytes()
        .chain(password.bytes())
        .any(|b| !(32..=126).contains(&b))
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
pub(crate) fn mailbox(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > 4096 {
        return Err(Error::InvalidInput);
    }
    if name
        .bytes()
        .any(|b| !(32..=126).contains(&b) || b == b'*' || b == b'%')
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

impl Connection<'_> {
    async fn discover_names(
        &mut self,
        names: BTreeMap<&str, &str>,
        maximum: usize,
    ) -> Result<Vec<Mailbox>, Error> {
        let mut mailboxes = Vec::with_capacity(names.len());
        let mut row_count = 0usize;
        for (expected, name) in names {
            // The coroutine decodes response names; its LIST pattern needs wire encoding.
            let pattern = name
                .replace('&', "&-")
                .try_into()
                .map_err(|_| Error::InvalidInput)?;
            let rows = self
                .drive(ImapMailboxList::new(
                    "".try_into().map_err(|_| Error::InvalidInput)?,
                    pattern,
                ))
                .await?;
            row_count = row_count.saturating_add(rows.len());
            if row_count > maximum {
                return Err(Error::Limit);
            }
            let mut found = None;
            for (returned, _, attrs) in rows {
                let returned = match &returned {
                    WireMailbox::Inbox => "INBOX",
                    WireMailbox::Other(name) => {
                        std::str::from_utf8(name.inner().as_ref()).map_err(|_| Error::Protocol)?
                    }
                };
                if mailbox_identity(returned) != expected {
                    return Err(Error::Protocol);
                }
                let mut attributes: Vec<_> = attrs.iter().map(ToString::to_string).collect();
                attributes.sort();
                attributes.dedup();
                let selectable = !attributes
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case("\\Noselect"));
                let mailbox = Mailbox {
                    name: expected.into(),
                    selectable,
                    attributes,
                };
                if found.as_ref().is_some_and(|previous| previous != &mailbox) {
                    return Err(Error::Protocol);
                }
                found = Some(mailbox);
            }
            if let Some(mailbox) = found {
                mailboxes.push(mailbox);
            }
        }
        Ok(mailboxes)
    }
}

impl From<Error> for crate::domain::Error {
    fn from(error: Error) -> Self {
        use crate::domain::ErrorCode;
        Self::new(match error {
            Error::Authentication => ErrorCode::AuthenticationFailed,
            Error::Tls => ErrorCode::TlsFailed,
            Error::Timeout => ErrorCode::Timeout,
            Error::Unsupported => ErrorCode::UnsupportedCapability,
            Error::Limit => ErrorCode::ResponseTooLarge,
            Error::InvalidInput => ErrorCode::InvalidRequest,
            _ => ErrorCode::ProviderUnavailable,
        })
    }
}
