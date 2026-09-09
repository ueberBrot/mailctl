//! Typed, read-only IMAP observations for GreenMail integration tests.

use crate::{Result, fixtures::EMAIL};
use io_imap::{
    codec::{GreetingCodec, ResponseCodec, fragmentizer::Fragmentizer},
    types::{
        fetch::MessageDataItem,
        flag::{Flag, FlagFetch},
        response::{Code, Data, GreetingKind, Response, Status, StatusKind},
    },
};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, rustls::pki_types::ServerName};

const MAX_RESPONSE_BYTES: u32 = 64 * 1024;
const READ_BUFFER_BYTES: usize = 8 * 1024;
const MAX_RESPONSES_PER_COMMAND: usize = 100;

/// Identity and presentation state observed without selecting a mailbox read-write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxSnapshot {
    pub uid_validity: u32,
    pub messages: Vec<MessageSnapshot>,
}

/// A message's stable IMAP identity and metadata used to prove read preservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageSnapshot {
    pub uid: u32,
    pub message_id: String,
    pub subject: String,
    pub seen: bool,
}

/// Observe the synthetic INBOX through a new verified TLS connection.
///
/// The observer only sends LOGIN, EXAMINE, FETCH, and LOGOUT. It parses every
/// server response with io-imap's re-exported codec, separately from the
/// production adapter.
pub async fn snapshot(port: u16, tls: &TlsConnector, password: &str) -> Result<MailboxSnapshot> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(("127.0.0.1", port)).await?;
        let stream = tls
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let mut wire = ObserverWire::new(stream);
        wire.greeting().await?;
        wire.ok(&format!("LOGIN \"{EMAIL}\" \"{password}\""))
            .await?;

        let examine = wire.ok("EXAMINE INBOX").await?;
        let uid_validity = examine
            .iter()
            .find_map(Reply::uid_validity)
            .ok_or("Independent observer did not receive UIDVALIDITY")?;
        let count = examine
            .iter()
            .find_map(Reply::exists)
            .ok_or("Independent observer did not receive mailbox count")?;

        let fetch = wire.ok("FETCH 1:* (UID FLAGS ENVELOPE)").await?;
        let mut messages = fetch
            .into_iter()
            .filter_map(Reply::into_message)
            .collect::<Result<Vec<_>>>()?;
        messages.sort_by_key(|message| message.uid);
        if messages.len() != count as usize {
            return Err("Independent observer mailbox count/fetch mismatch".into());
        }
        if messages.windows(2).any(|pair| pair[0].uid == pair[1].uid) {
            return Err("Independent observer received duplicate message UIDs".into());
        }

        wire.logout().await?;
        Ok(MailboxSnapshot {
            uid_validity,
            messages,
        })
    })
    .await
    .map_err(|_| "Independent IMAP observer timed out")?
}

/// Check both positive and negative authentication paths over verified TLS.
pub async fn authenticate(
    port: u16,
    tls: &TlsConnector,
    password: &str,
    expected_login: bool,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(("127.0.0.1", port)).await?;
        let stream = tls
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let mut wire = ObserverWire::new(stream);
        wire.greeting().await?;
        let status = wire
            .command(&format!("LOGIN \"{EMAIL}\" \"{password}\""))
            .await?
            .status;
        match (expected_login, status) {
            (true, StatusKind::Ok) => wire.logout().await,
            (false, StatusKind::No) => Ok(()),
            (false, StatusKind::Ok) => {
                Err("Independent IMAP accepted a wrong fixture credential".into())
            }
            (false, _) => Err("Independent IMAP wrong credential did not receive tagged NO".into()),
            (true, _) => Err("Independent IMAP rejected the fixture credential".into()),
        }
    })
    .await
    .map_err(|_| "Independent IMAP/TLS authentication timed out")?
}

struct ObserverWire<S> {
    stream: BufReader<S>,
    parser: Fragmentizer,
    next_tag: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ObserverWire<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: BufReader::new(stream),
            parser: Fragmentizer::new(MAX_RESPONSE_BYTES),
            next_tag: 1,
        }
    }

    async fn greeting(&mut self) -> Result<()> {
        loop {
            if self.parser.progress().is_some() && self.parser.is_message_complete() {
                let greeting = self
                    .parser
                    .decode_message(&GreetingCodec::new())
                    .map_err(|_| "Independent observer received malformed IMAP greeting")?;
                return match greeting.kind {
                    GreetingKind::Ok => Ok(()),
                    GreetingKind::PreAuth | GreetingKind::Bye => {
                        Err("Independent observer received an unusable IMAP greeting".into())
                    }
                };
            }
            self.read_more().await?;
        }
    }

    async fn ok(&mut self, command: &str) -> Result<Vec<Reply>> {
        let result = self.command(command).await?;
        if result.status == StatusKind::Ok {
            Ok(result.replies)
        } else {
            Err(format!(
                "Independent observer {command} returned {:?}",
                result.status
            )
            .into())
        }
    }

    async fn logout(&mut self) -> Result<()> {
        let result = self.command("LOGOUT").await?;
        if result.status != StatusKind::Ok || !result.saw_bye {
            return Err(
                "Independent observer LOGOUT did not complete with BYE and tagged OK".into(),
            );
        }
        Ok(())
    }

    async fn command(&mut self, command: &str) -> Result<CommandResult> {
        let tag = format!("o{}", self.next_tag);
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .ok_or("Independent observer command tag overflow")?;
        self.stream
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await?;
        self.stream.get_mut().flush().await?;

        let mut replies = Vec::new();
        let mut saw_bye = false;
        for _ in 0..MAX_RESPONSES_PER_COMMAND {
            match self.response().await? {
                Reply::Tagged {
                    tag: actual,
                    status,
                    ..
                } if actual == tag => {
                    return Ok(CommandResult {
                        replies,
                        status,
                        saw_bye,
                    });
                }
                Reply::Tagged { .. } => {
                    return Err(
                        "Independent observer received a mismatched IMAP command tag".into(),
                    );
                }
                Reply::Bye if command == "LOGOUT" => saw_bye = true,
                Reply::Bye => return Err("Independent observer received IMAP BYE".into()),
                Reply::Continuation => {
                    return Err(
                        "Independent observer received an unexpected IMAP continuation".into(),
                    );
                }
                reply => replies.push(reply),
            }
        }
        Err("Independent observer response count exceeded fixture budget".into())
    }

    async fn response(&mut self) -> Result<Reply> {
        loop {
            if self.parser.progress().is_some() && self.parser.is_message_complete() {
                let response = self
                    .parser
                    .decode_message(&ResponseCodec::new())
                    .map_err(|_| "Independent observer received malformed IMAP response")?;
                return Reply::from_response(response);
            }
            self.read_more().await?;
        }
    }

    async fn read_more(&mut self) -> Result<()> {
        let mut buffer = [0; READ_BUFFER_BYTES];
        let read = self.stream.read(&mut buffer).await?;
        if read == 0 {
            return Err("Independent observer reached unexpected IMAP EOF".into());
        }
        self.parser.enqueue_bytes(&buffer[..read]);
        Ok(())
    }
}

struct CommandResult {
    replies: Vec<Reply>,
    status: StatusKind,
    saw_bye: bool,
}

enum Reply {
    Exists(u32),
    UidValidity(u32),
    Fetch(MessageSnapshot),
    Tagged {
        tag: String,
        status: StatusKind,
        uid_validity: Option<u32>,
    },
    Bye,
    Continuation,
    Other,
}

impl Reply {
    fn from_response(response: Response<'_>) -> Result<Self> {
        match response {
            Response::Data(Data::Exists(count)) => Ok(Self::Exists(count)),
            Response::Data(Data::Fetch { items, .. }) => Ok(Self::Fetch(message(items)?)),
            Response::Data(_) => Ok(Self::Other),
            Response::Status(Status::Untagged(status)) => Ok(uid_validity(status.code.as_ref())
                .map(Self::UidValidity)
                .unwrap_or(Self::Other)),
            Response::Status(Status::Tagged(tagged)) => Ok(Self::Tagged {
                tag: tagged.tag.as_ref().to_owned(),
                status: tagged.body.kind,
                uid_validity: uid_validity(tagged.body.code.as_ref()),
            }),
            Response::Status(Status::Bye(_)) => Ok(Self::Bye),
            Response::CommandContinuationRequest(_) => Ok(Self::Continuation),
        }
    }

    fn exists(&self) -> Option<u32> {
        match self {
            Self::Exists(count) => Some(*count),
            _ => None,
        }
    }

    fn uid_validity(&self) -> Option<u32> {
        match self {
            Self::UidValidity(value) => Some(*value),
            Self::Tagged { uid_validity, .. } => *uid_validity,
            _ => None,
        }
    }

    fn into_message(self) -> Option<Result<MessageSnapshot>> {
        match self {
            Self::Fetch(message) => Some(Ok(message)),
            _ => None,
        }
    }
}

fn uid_validity(code: Option<&Code<'_>>) -> Option<u32> {
    match code {
        Some(Code::UidValidity(value)) => Some(value.get()),
        _ => None,
    }
}

fn message<'a>(items: impl IntoIterator<Item = MessageDataItem<'a>>) -> Result<MessageSnapshot> {
    let mut uid = None;
    let mut seen = None;
    let mut envelope = None;
    for item in items {
        match item {
            MessageDataItem::Uid(value) => uid = Some(value.get()),
            MessageDataItem::Flags(flags) => {
                seen = Some(
                    flags
                        .into_iter()
                        .any(|flag| matches!(flag, FlagFetch::Flag(Flag::Seen))),
                );
            }
            MessageDataItem::Envelope(value) => envelope = Some(value),
            _ => {}
        }
    }
    let envelope = envelope.ok_or("Independent observer FETCH omitted ENVELOPE")?;
    Ok(MessageSnapshot {
        uid: uid.ok_or("Independent observer FETCH omitted UID")?,
        message_id: nstring(envelope.message_id, "message ID")?,
        subject: nstring(envelope.subject, "subject")?,
        seen: seen.ok_or("Independent observer FETCH omitted FLAGS")?,
    })
}

fn nstring(value: io_imap::types::core::NString<'_>, field: &str) -> Result<String> {
    let value = value
        .into_option()
        .ok_or_else(|| format!("Independent observer envelope omitted {field}"))?;
    String::from_utf8(value.into_owned())
        .map_err(|_| format!("Independent observer envelope {field} was not UTF-8").into())
}
