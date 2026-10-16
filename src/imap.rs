//! Bounded IMAP operations shared by the application and protocol fixtures.
//!
//! Typed decoding follows bounded frame admission. Embedded runtimes should
//! reserve 8 MiB per decoding thread, as the shipped frontends do.
use crate::domain::mailbox_identity;
mod admission;
mod append;
mod attachment;
mod body;
mod fetch;
mod mime;
mod projection;
mod reconcile;
mod search;
mod wire;

pub use append::AppendOutcome;

pub use attachment::{
    AttachmentData, AttachmentDecoder, AttachmentIntegrity, AttachmentListRequest,
    AttachmentMetadata,
};

pub use body::{BodyCursor, BodyPage, BodyRequest};

use base64::{
    Engine,
    alphabet::IMAP_MUTF7,
    engine::general_purpose::{GeneralPurpose, NO_PAD},
};
use imap_proto::{Capability, MailboxDatum, NameAttribute, Response};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};
use tokio_rustls::rustls::{self, RootCertStore};
use wire::Connection;

/// An authenticated connection with no selected mailbox or retained credential.
/// Operations consume the connection; cancellation closes its transport.
/// Progress is borrowed separately so it survives a dropped operation. The application
/// owns the deadline spanning authentication and retrieval.
///
/// A connection cannot run a second operation after being consumed:
/// ```compile_fail
/// use mailctl::imap::{AuthenticatedConnection, Limits, Metrics};
/// async fn reuse(connection: AuthenticatedConnection, limits: &Limits) {
///     let mut metrics = Metrics::default();
///     connection.discover_all(limits, &mut metrics).await.unwrap();
///     connection.discover(&[], limits, &mut metrics).await.unwrap();
/// }
/// ```
/// Progress cannot be inspected while a live operation can still mutate it:
/// ```compile_fail
/// use mailctl::imap::{AuthenticatedConnection, Limits, Metrics};
/// async fn observe(connection: AuthenticatedConnection, limits: &Limits) {
///     let mut metrics = Metrics::default();
///     let operation = connection.discover(&[], limits, &mut metrics);
///     let _snapshot = metrics;
///     operation.await.unwrap();
/// }
/// ```
pub struct AuthenticatedConnection {
    session: wire::Session,
    identity: [u8; 32],
}
impl AuthenticatedConnection {
    /// List the bounded provider inventory without selecting a mailbox.
    pub async fn discover_all(
        self,
        limits: &Limits,
        metrics: &mut Metrics,
    ) -> Result<Vec<Mailbox>, Error> {
        limits.validate()?;
        let mut connection = self.session.resume(metrics);
        connection.limit_body(limits);
        let result = connection.discover_all(limits.max_mailboxes).await?;
        connection.logout().await?;
        Ok(result)
    }
    pub async fn discover(
        self,
        allowlist: &[String],
        limits: &Limits,
        metrics: &mut Metrics,
    ) -> Result<Vec<Mailbox>, Error> {
        limits.validate()?;
        if allowlist.len() > limits.max_mailboxes {
            return Err(Error::Limit);
        }
        for name in allowlist {
            mailbox(name)?;
        }
        let mut connection = self.session.resume(metrics);
        connection.limit_body(limits);
        let names: BTreeMap<_, _> = allowlist
            .iter()
            .map(|name| (mailbox_identity(name), name.as_str()))
            .collect();
        let result = if names.keys().any(|name| name.contains(['*', '%'])) {
            connection
                .discover_all(limits.max_mailboxes)
                .await?
                .into_iter()
                .filter(|mailbox| names.contains_key(mailbox.name.as_str()))
                .collect()
        } else {
            connection
                .discover_names(names, limits.max_mailboxes)
                .await?
        };
        connection.logout().await?;
        Ok(result)
    }
    pub(crate) async fn disconnect(self) -> Result<(), Error> {
        let mut metrics = Metrics::default();
        let mut connection = self.session.resume(&mut metrics);
        connection.logout().await
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
    StaleReference,
    MessageNotFound,
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
            Self::StaleReference => "message reference is stale",
            Self::MessageNotFound => "message was not found",
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
    pub max_header_bytes: usize,
    pub max_mime_parts: usize,
    pub max_body_wire_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_text_bytes: usize,
    pub max_decode_steps: usize,
    pub max_attachment_decoded_bytes: usize,
    pub max_attachment_wire_bytes: usize,
    pub max_attachment_chunk_bytes: usize,
    pub operation_timeout: Duration,
    pub connect_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        let defaults = crate::config::Limits::default();
        Self {
            max_response_bytes: 64 * 1024,
            max_operation_bytes: 4 * 1024 * 1024,
            max_literal_bytes: 64 * 1024,
            max_responses: 4096,
            max_parser_steps: 16 * 1024 * 1024,
            max_nesting: defaults.mime_depth,
            max_mailboxes: defaults.mailbox_inventory,
            max_header_bytes: defaults.header_bytes,
            max_mime_parts: defaults.mime_parts,
            max_body_wire_bytes: defaults.wire_fetch_bytes,
            max_decoded_bytes: 8 * 1024 * 1024,
            max_text_bytes: defaults.text_page_bytes,
            max_decode_steps: 32 * 1024 * 1024,
            max_attachment_decoded_bytes: defaults.attachment_decoded_bytes,
            max_attachment_wire_bytes: defaults.attachment_wire_bytes,
            max_attachment_chunk_bytes: defaults.attachment_chunk_bytes,
            operation_timeout: Duration::from_secs(defaults.operation_seconds as u64),
            connect_timeout: Duration::from_secs(defaults.connection_seconds as u64),
        }
    }
}
impl Limits {
    fn validate(&self) -> Result<(), Error> {
        let maximum = crate::config::Limits::MAXIMUM;
        if self.max_response_bytes == 0
            || self.max_response_bytes > 256 * 1024
            || self.max_operation_bytes < self.max_response_bytes
            || self.max_operation_bytes > 16 * 1024 * 1024
            || self.max_literal_bytes == 0
            || self.max_literal_bytes > self.max_response_bytes
            || self.max_responses == 0
            || self.max_responses > 16384
            || self.max_parser_steps == 0
            || self.max_parser_steps > 64 * 1024 * 1024
            || !(1..=maximum.mime_depth).contains(&self.max_nesting)
            || !(1..=maximum.mailbox_inventory).contains(&self.max_mailboxes)
            || !(1..=maximum.header_bytes).contains(&self.max_header_bytes)
            || !(1..=maximum.mime_parts).contains(&self.max_mime_parts)
            || !(1..=maximum.wire_fetch_bytes).contains(&self.max_body_wire_bytes)
            || self.max_decoded_bytes == 0
            || self.max_decoded_bytes > 32 * 1024 * 1024
            || !(4..=maximum.text_page_bytes).contains(&self.max_text_bytes)
            || self.max_decode_steps == 0
            || self.max_decode_steps > 128 * 1024 * 1024
            || !(1..=maximum.attachment_decoded_bytes).contains(&self.max_attachment_decoded_bytes)
            || !(1..=maximum.attachment_wire_bytes).contains(&self.max_attachment_wire_bytes)
            || !(1..=maximum.attachment_chunk_bytes).contains(&self.max_attachment_chunk_bytes)
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(maximum.operation_seconds as u64)
            || self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(maximum.connection_seconds as u64)
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
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub name: String,
    pub selectable: bool,
    pub attributes: Vec<String>,
}
/// A verified TLS endpoint. Inputs and results contain no raw IMAP commands.
///
/// Authentication accepts printable ASCII credentials; literal authentication remains
/// gated. Mailbox names use Unicode with modified UTF-7 on the IMAP wire.
/// Control characters are unsupported; wildcard characters are literal mailbox names.
pub struct ImapEndpoint {
    host: String,
    port: u16,
    mode: TlsMode,
    tls: Arc<rustls::ClientConfig>,
    limits: Limits,
}
impl ImapEndpoint {
    pub async fn connect_authenticated(
        &self,
        username: &str,
        password: &str,
        metrics: &mut Metrics,
    ) -> Result<AuthenticatedConnection, Error> {
        *metrics = Metrics::default();
        credentials(username, password)?;
        let mut identity = Sha256::new();
        for value in [self.host.as_str(), username] {
            identity.update(value.len().to_be_bytes());
            identity.update(value.as_bytes());
        }
        identity.update(self.port.to_be_bytes());
        tokio::time::timeout(self.limits.operation_timeout, async {
            self.authenticate(username, password, metrics)
                .await
                .map(|connection| AuthenticatedConnection {
                    session: connection.into_session(),
                    identity: identity.finalize().into(),
                })
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
        Self::new_with_shared_roots(host, port, mode, Arc::new(roots), limits)
    }
    pub(crate) fn new_with_shared_roots(
        host: String,
        port: u16,
        mode: TlsMode,
        roots: Arc<RootCertStore>,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if host.is_empty() || host.len() > 253 || port == 0 {
            return Err(Error::InvalidInput);
        }
        // Trust is immutable; each endpoint still owns a fresh client configuration.
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
        })
    }
    async fn authenticate<'a>(
        &self,
        user: &str,
        password: &str,
        metrics: &'a mut Metrics,
    ) -> Result<Connection<'a>, Error> {
        let mut conn = tokio::time::timeout(
            self.limits.connect_timeout,
            Connection::connect(
                &self.host,
                self.port,
                self.mode,
                self.tls.clone(),
                self.limits.clone(),
                metrics,
            ),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        conn.greeting().await?;
        let mut caps = conn.capabilities().await?;
        if matches!(self.mode, TlsMode::StartTls) {
            if !has_capability(&caps, "STARTTLS") {
                return Err(Error::Unsupported);
            }
            conn = conn.upgrade(&self.host, self.tls.clone()).await?;
            caps = conn.capabilities().await?;
        }
        if !caps.contains(&Capability::Imap4rev1) || has_capability(&caps, "LOGINDISABLED") {
            return Err(Error::Unsupported);
        }
        conn.login(user, password).await?;
        let caps = conn.capabilities().await?;
        if !caps.contains(&Capability::Imap4rev1) {
            return Err(Error::Unsupported);
        }
        Ok(conn)
    }
}
fn has_capability(caps: &[Capability<'_>], name: &str) -> bool {
    caps.iter()
        .any(|cap| matches!(cap, Capability::Atom(value) if value.eq_ignore_ascii_case(name)))
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
    if name.is_empty() || name.len() > 1024 {
        return Err(Error::InvalidInput);
    }
    if name.chars().any(char::is_control) {
        return Err(Error::Unsupported);
    }
    Ok(())
}

// Mailbox arguments and LIST patterns use canonical modified UTF-7 wire encoding.
const MODIFIED_UTF7: GeneralPurpose = GeneralPurpose::new(&IMAP_MUTF7, NO_PAD);

fn mailbox_pattern(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    let mut bytes = Vec::new();
    let mut remaining = name;
    while !remaining.is_empty() {
        let end = remaining
            .find(|c: char| c.is_ascii())
            .unwrap_or(remaining.len());
        if end > 0 {
            bytes.clear();
            bytes.extend(remaining[..end].encode_utf16().flat_map(u16::to_be_bytes));
            encoded.push('&');
            MODIFIED_UTF7.encode_string(&bytes, &mut encoded);
            encoded.push('-');
            remaining = &remaining[end..];
        }
        if let Some(ascii) = remaining.bytes().next() {
            encoded.push(char::from(ascii));
            if ascii == b'&' {
                encoded.push('-');
            }
            remaining = &remaining[1..];
        }
    }
    encoded
}

// Reject lossy and noncanonical wire names before they can replace an identity.
fn decode_wire_mailbox_name(wire: &str) -> Result<String, Error> {
    if wire.len() > 4096 || wire.bytes().any(|byte| !(32..=126).contains(&byte)) {
        return Err(Error::Protocol);
    }
    let mut decoded = String::with_capacity(wire.len().min(1024));
    let mut bytes = Vec::new();
    let mut remaining = wire;
    while let Some((plain, shifted)) = remaining.split_once('&') {
        if plain.len() > 1024usize.saturating_sub(decoded.len()) {
            return Err(Error::Protocol);
        }
        decoded.push_str(plain);
        let (payload, tail) = shifted.split_once('-').ok_or(Error::Protocol)?;
        if payload.is_empty() {
            decoded.push('&');
        } else {
            bytes.clear();
            MODIFIED_UTF7
                .decode_vec(payload, &mut bytes)
                .map_err(|_| Error::Protocol)?;
            if bytes.len() % 2 != 0 {
                return Err(Error::Protocol);
            }
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair));
            for character in char::decode_utf16(units) {
                let character = character.map_err(|_| Error::Protocol)?;
                if character.len_utf8() > 1024usize.saturating_sub(decoded.len()) {
                    return Err(Error::Protocol);
                }
                decoded.push(character);
            }
        }
        if decoded.len() > 1024 {
            return Err(Error::Protocol);
        }
        remaining = tail;
    }
    if remaining.len() > 1024usize.saturating_sub(decoded.len()) {
        return Err(Error::Protocol);
    }
    decoded.push_str(remaining);
    // RFC 3501 §5.1.3 forbids superfluous shifts and encoded printable ASCII.
    if decoded.chars().any(char::is_control) || mailbox_pattern(&decoded) != wire {
        return Err(Error::Protocol);
    }
    Ok(decoded)
}

impl Connection<'_> {
    fn decode_mailbox(
        returned: &str,
        attrs: &[NameAttribute<'_>],
    ) -> Result<Option<Mailbox>, Error> {
        let returned = decode_wire_mailbox_name(returned)?;
        let mut attributes = attrs
            .iter()
            .map(|attribute| {
                Ok(match attribute {
                    NameAttribute::NoInferiors => "\\Noinferiors",
                    NameAttribute::NoSelect => "\\Noselect",
                    NameAttribute::Marked => "\\Marked",
                    NameAttribute::Unmarked => "\\Unmarked",
                    NameAttribute::All => "\\All",
                    NameAttribute::Archive => "\\Archive",
                    NameAttribute::Drafts => "\\Drafts",
                    NameAttribute::Flagged => "\\Flagged",
                    NameAttribute::Junk => "\\Junk",
                    NameAttribute::Sent => "\\Sent",
                    NameAttribute::Trash => "\\Trash",
                    NameAttribute::Extension(value) => value.as_ref(),
                    _ => return Err(Error::Unsupported),
                }
                .to_owned())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        attributes.sort_unstable();
        attributes.dedup();
        let selectable = !attributes
            .iter()
            .any(|attribute| attribute.eq_ignore_ascii_case("\\Noselect"));
        if returned.is_empty() && !selectable {
            return Ok(None);
        }
        if returned.is_empty() || returned.len() > 1024 || returned.chars().any(char::is_control) {
            return Err(Error::Protocol);
        }
        Ok(Some(Mailbox {
            name: mailbox_identity(&returned).into(),
            selectable,
            attributes,
        }))
    }
    async fn discover_all(&mut self, maximum: usize) -> Result<Vec<Mailbox>, Error> {
        let rows = self.request("LIST \"\" \"*\"", wire::Kind::List).await?;
        if rows.len() > maximum {
            return Err(Error::Limit);
        }
        let mut mailboxes = Vec::with_capacity(rows.len());
        for row in rows {
            let Response::MailboxData(MailboxDatum::List(data)) = &row else {
                return Err(Error::Protocol);
            };
            let Some(mailbox) = Self::decode_mailbox(&data.name, &data.name_attributes)? else {
                continue;
            };
            mailboxes.push(mailbox);
        }
        mailboxes.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        mailboxes.dedup();
        if mailboxes
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(Error::Protocol);
        }
        Ok(mailboxes)
    }
    async fn discover_names(
        &mut self,
        names: BTreeMap<&str, &str>,
        maximum: usize,
    ) -> Result<Vec<Mailbox>, Error> {
        let mut mailboxes = Vec::with_capacity(names.len());
        let mut row_count = 0usize;
        for (expected, name) in names {
            let pattern = wire::quote(&mailbox_pattern(name))?;
            let rows = self
                .request(&format!("LIST \"\" {pattern}"), wire::Kind::List)
                .await?;
            row_count = row_count.saturating_add(rows.len());
            if row_count > maximum {
                return Err(Error::Limit);
            }
            let mut found = None;
            for row in rows {
                let Response::MailboxData(MailboxDatum::List(data)) = &row else {
                    return Err(Error::Protocol);
                };
                let mailbox = Self::decode_mailbox(&data.name, &data.name_attributes)?
                    .ok_or(Error::Protocol)?;
                if mailbox.name != expected {
                    return Err(Error::Protocol);
                }
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
            Error::StaleReference => ErrorCode::StaleReference,
            Error::StaleCursor => ErrorCode::StaleCursor,
            Error::TransferExpired => ErrorCode::TransferExpired,
            Error::MessageNotFound => ErrorCode::MessageNotFound,
            _ => ErrorCode::ProviderUnavailable,
        })
    }
}
