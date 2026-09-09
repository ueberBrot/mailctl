//! Bounded, read-only IMAP route proof. Each operation owns and disposes its connection.
mod wire;

use io_imap::{
    rfc3501::{
        capability::ImapCapabilityGet,
        examine::ImapMailboxExamine,
        fetch::{ImapMessageFetch, ImapMessageFetchOptions},
        greeting::ImapGreetingGet,
        list::ImapMailboxList,
        login::ImapLogin,
        logout::ImapLogout,
        search::{ImapMessageSearch, ImapMessageSearchOptions},
    },
    types::{
        core::NString,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
        mailbox::Mailbox as WireMailbox,
        response::Capability,
        search::SearchKey,
    },
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_rustls::rustls::{self, RootCertStore};
use wire::Connection;

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
    pub operation_timeout: Duration,
    pub connect_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_response_bytes: 64 * 1024,
            max_operation_bytes: 2 * 1024 * 1024,
            max_literal_bytes: 64 * 1024,
            max_responses: 4096,
            max_parser_steps: 8 * 1024 * 1024,
            max_nesting: 20,
            max_mailboxes: 1000,
            max_uid_window: 1000,
            max_messages: 50,
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
            || self.max_operation_bytes > 8 * 1024 * 1024
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
    pub wire_bytes: usize,
    pub responses: usize,
    pub parser_steps: usize,
    pub max_response_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_buffered_bytes: usize,
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
    metrics: Arc<Mutex<Metrics>>,
}
impl ImapProbe {
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
            metrics: Arc::new(Mutex::new(Metrics::default())),
        })
    }
    /// Last progress snapshot, including a failed or cancelled operation.
    /// Use one probe per concurrent operation when collecting evidence.
    pub fn metrics(&self) -> Metrics {
        *self.metrics.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub async fn discover(
        &self,
        username: &str,
        password: &str,
        allowlist: &[String],
    ) -> Result<Discovery, Error> {
        credentials(username, password)?;
        if allowlist.len() > self.limits.max_mailboxes {
            return Err(Error::Limit);
        }
        let mut names = BTreeMap::new();
        for name in allowlist {
            mailbox(name)?;
            names.insert(identity(name), name);
        }
        tokio::time::timeout(self.limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            let mut mailboxes = BTreeMap::new();
            for (expected, name) in names {
                let pattern = name
                    .replace('&', "&-")
                    .try_into()
                    .map_err(|_| Error::InvalidInput)?;
                let rows = conn
                    .drive(ImapMailboxList::new(
                        "".try_into().map_err(|_| Error::InvalidInput)?,
                        pattern,
                    ))
                    .await?;
                if rows.len() > 1 {
                    return Err(Error::Protocol);
                }
                for (name, _, attrs) in rows {
                    let name = match name {
                        WireMailbox::Inbox => "INBOX".to_owned(),
                        WireMailbox::Other(n) => String::from_utf8(n.inner().as_ref().to_vec())
                            .map_err(|_| Error::Protocol)?,
                    };
                    if identity(&name) != expected {
                        return Err(Error::Protocol);
                    }
                    let attributes: Vec<_> = attrs.iter().map(ToString::to_string).collect();
                    let selectable = !attributes
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case("\\Noselect"));
                    mailboxes.insert(
                        expected.clone(),
                        Mailbox {
                            name,
                            selectable,
                            attributes,
                        },
                    );
                }
            }
            conn.drive(ImapLogout::new()).await?;
            Ok(Discovery {
                mailboxes: mailboxes.into_values().collect(),
                metrics: self.metrics(),
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    pub async fn search(
        &self,
        username: &str,
        password: &str,
        name: &str,
        window: UidWindow,
    ) -> Result<Search, Error> {
        credentials(username, password)?;
        mailbox(name)?;
        if window.first == 0 || window.last < window.first {
            return Err(Error::InvalidInput);
        }
        if u64::from(window.last) - u64::from(window.first) + 1 > self.limits.max_uid_window as u64
        {
            return Err(Error::Limit);
        }
        tokio::time::timeout(self.limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            conn.examining = true;
            let selection = conn
                .drive(ImapMailboxExamine::new(
                    name.to_owned()
                        .try_into()
                        .map_err(|_| Error::InvalidInput)?,
                    Default::default(),
                ))
                .await?;
            conn.examining = false;
            if !conn.read_only {
                return Err(Error::UnsafeSelection);
            }
            let uid_validity = selection.uid_validity.ok_or(Error::UnsafeSelection)?.get();
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
            if uids.len() > self.limits.max_messages {
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
                let items = MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                    MessageDataItemName::Uid,
                    MessageDataItemName::Envelope,
                    MessageDataItemName::Flags,
                    MessageDataItemName::InternalDate,
                    MessageDataItemName::Rfc822Size,
                ]);
                let fetched = conn
                    .drive(ImapMessageFetch::new(
                        set,
                        items,
                        ImapMessageFetchOptions {
                            uid: true,
                            ..Default::default()
                        },
                    ))
                    .await?;
                for items in fetched.into_values() {
                    let mut envelope = Envelope::default();
                    let mut seen = std::collections::BTreeSet::new();
                    for item in items.as_ref() {
                        let key = match item {
                            MessageDataItem::Uid(uid) => {
                                envelope.uid = uid.get();
                                0
                            }
                            MessageDataItem::Envelope(e) => {
                                envelope.subject = string(&e.subject);
                                envelope.from = addresses(&e.from);
                                envelope.to = addresses(&e.to);
                                envelope.cc = addresses(&e.cc);
                                envelope.sent_date = string(&e.date);
                                envelope.message_id = string(&e.message_id);
                                1
                            }
                            MessageDataItem::Flags(flags) => {
                                envelope.flags = flags
                                    .iter()
                                    .map(|flag| match flag {
                                        io_imap::types::flag::FlagFetch::Flag(flag) => {
                                            flag.to_string()
                                        }
                                        io_imap::types::flag::FlagFetch::Recent => {
                                            "\\Recent".to_owned()
                                        }
                                    })
                                    .collect();
                                2
                            }
                            MessageDataItem::InternalDate(date) => {
                                envelope.received_date = Some(date.as_ref().to_rfc3339());
                                3
                            }
                            MessageDataItem::Rfc822Size(size) => {
                                envelope.size = Some(*size);
                                4
                            }
                            _ => return Err(Error::Protocol),
                        };
                        if !seen.insert(key) {
                            return Err(Error::Protocol);
                        }
                    }
                    if seen.len() != 5
                        || !uids.iter().any(|u| u.get() == envelope.uid)
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
                metrics: self.metrics(),
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    async fn authenticate(&self, user: &str, password: &str) -> Result<Connection, Error> {
        *self.metrics.lock().unwrap_or_else(|e| e.into_inner()) = Metrics::default();
        let mut conn = tokio::time::timeout(
            self.limits.connect_timeout,
            Connection::connect(
                &self.host,
                self.port,
                self.mode,
                self.tls.clone(),
                self.limits.clone(),
                self.metrics.clone(),
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
            conn.upgrade(&self.host, self.tls.clone()).await?;
            caps = conn.drive(ImapCapabilityGet::new()).await?;
        }
        if !caps.contains(&Capability::Imap4Rev1) || caps.contains(&Capability::LoginDisabled) {
            return Err(Error::Unsupported);
        }
        let login =
            ImapLogin::new(user, password, Default::default()).map_err(|_| Error::InvalidInput)?;
        conn.authenticating = true;
        conn.drive(login).await?;
        conn.authenticating = false;
        let caps = conn.drive(ImapCapabilityGet::new()).await?;
        if !caps.contains(&Capability::Imap4Rev1) {
            return Err(Error::Unsupported);
        }
        Ok(conn)
    }
}
fn credentials(user: &str, password: &str) -> Result<(), Error> {
    if user
        .bytes()
        .chain(password.bytes())
        .any(|b| !(32..=126).contains(&b))
    {
        return Err(Error::Unsupported);
    }
    if user.is_empty()
        || user.len() > 4096
        || password.is_empty()
        || password.len() > 64 * 1024
        || user
            .bytes()
            .chain(password.bytes())
            .any(|b| b == 0 || b == b'\r' || b == b'\n')
    {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn mailbox(name: &str) -> Result<(), Error> {
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
fn identity(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        "INBOX".to_owned()
    } else {
        name.to_owned()
    }
}
fn string(value: &NString<'_>) -> Option<String> {
    value
        .0
        .as_ref()
        .map(|s| String::from_utf8_lossy(s.as_ref()).into_owned())
}
fn addresses(values: &[io_imap::types::envelope::Address<'_>]) -> Vec<Address> {
    values
        .iter()
        .map(|a| Address {
            name: string(&a.name),
            mailbox: string(&a.mailbox),
            host: string(&a.host),
        })
        .collect()
}
