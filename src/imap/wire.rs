use super::{
    AppendOutcome, AppendUid, Error, Limits, Metrics, TlsMode, fetch::Fetch as BodyFetch,
    projection::Projection,
};
use io_imap::{
    codec::{
        CommandCodec, ResponseCodec,
        decode::Decoder,
        fragmentizer::{FragmentInfo, Fragmentizer, LineEnding},
    },
    coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
    rfc3501::{
        append::ImapMessageAppendOptions,
        append_stream::{ImapMessageAppendStream, ImapMessageAppendStreamYield},
        examine::ImapMailboxExamine,
    },
    send::ImapSend,
    types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        flag::Flag,
        response::{Code, Data, Response, Status, StatusKind},
    },
};
use std::{collections::BTreeSet, io, num::NonZeroU32, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, pki_types::ServerName},
};
use zeroize::Zeroizing;
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub(super) struct Connection<'a> {
    stream: BufReader<Box<dyn Stream>>,
    fragmentizer: Fragmentizer,
    limits: Limits,
    metrics: &'a mut Metrics,
    command: CommandState,
    uid_validity: Option<NonZeroU32>,
}
/// Transport state kept between completed operations, without borrowed metrics.
pub(super) struct Session {
    stream: BufReader<Box<dyn Stream>>,
    fragmentizer: Fragmentizer,
    limits: Limits,
    command: CommandState,
    uid_validity: Option<NonZeroU32>,
}
impl Session {
    pub(super) fn resume(self, metrics: &mut Metrics) -> Connection<'_> {
        Connection {
            stream: self.stream,
            fragmentizer: self.fragmentizer,
            limits: self.limits,
            metrics,
            command: self.command,
            uid_validity: self.uid_validity,
        }
    }
}
impl<'a> Connection<'a> {
    pub(super) fn into_session(self) -> Session {
        Session {
            stream: self.stream,
            fragmentizer: self.fragmentizer,
            limits: self.limits,
            command: self.command,
            uid_validity: self.uid_validity,
        }
    }
    pub async fn connect(
        host: &str,
        port: u16,
        mode: TlsMode,
        tls: Arc<ClientConfig>,
        limits: Limits,
        metrics: &'a mut Metrics,
    ) -> Result<Self, Error> {
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|_| Error::Transport)?;
        let stream: Box<dyn Stream> = match mode {
            TlsMode::Implicit => Box::new(
                TlsConnector::from(tls)
                    .connect(server_name(host)?, tcp)
                    .await
                    .map_err(|_| Error::Tls)?,
            ),
            TlsMode::StartTls => Box::new(tcp),
        };
        Ok(Self {
            stream: BufReader::with_capacity(4096, stream),
            fragmentizer: Fragmentizer::new(limits.max_response_bytes as u32),
            limits,
            metrics,
            command: CommandState::greeting(),
            uid_validity: None,
        })
    }
    pub(super) fn metrics_mut(&mut self) -> &mut Metrics {
        self.metrics
    }
    pub fn metrics(&self) -> Metrics {
        *self.metrics
    }
    pub async fn examine(&mut self, name: &str) -> Result<u32, Error> {
        self.drive(ImapMailboxExamine::new(
            name.to_owned()
                .try_into()
                .map_err(|_| Error::InvalidInput)?,
            Default::default(),
        ))
        .await?;
        self.uid_validity
            .map(NonZeroU32::get)
            .ok_or(Error::UnsafeSelection)
    }
    pub async fn upgrade(mut self, host: &str, tls: Arc<ClientConfig>) -> Result<Self, Error> {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::StartTLS,
        };
        let result = self
            .drive(ImapSend::new(CommandCodec::new(), command))
            .await?;
        if !result
            .tagged
            .is_some_and(|tagged| tagged.body.kind == StatusKind::Ok)
        {
            return Err(Error::Tls);
        }
        let stream = self.stream;
        if !stream.buffer().is_empty() {
            return Err(Error::Protocol);
        }
        let tls = tokio::time::timeout(
            self.limits.connect_timeout,
            TlsConnector::from(tls).connect(server_name(host)?, stream.into_inner()),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Tls)?;
        self.stream = BufReader::with_capacity(4096, Box::new(tls));
        self.fragmentizer = Fragmentizer::new(self.limits.max_response_bytes as u32);
        Ok(self)
    }
    /// The streaming coroutine keeps the frozen MIME out of backend command buffers.
    pub async fn append(&mut self, target: &str, mime: &[u8]) -> Result<(), Error> {
        let mut coroutine = ImapMessageAppendStream::new(
            target
                .to_owned()
                .try_into()
                .map_err(|_| Error::InvalidInput)?,
            u32::try_from(mime.len()).map_err(|_| Error::Limit)?,
            ImapMessageAppendOptions {
                flags: vec![Flag::Draft],
                ..Default::default()
            },
        );
        let mut frame = None;
        let mut header = true;
        loop {
            self.step(1)?;
            let state = coroutine.resume(&mut self.fragmentizer, frame.as_deref());
            frame = None;
            match state {
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsWrite(bytes)) => {
                    if header {
                        let suffix = format!("{{{}}}\r\n", mime.len());
                        let prefix = bytes
                            .strip_suffix(suffix.as_bytes())
                            .ok_or(Error::Protocol)?;
                        let mut empty = prefix.to_vec();
                        empty.extend_from_slice(b"{0}\r\n\r\n");
                        let (remaining, command) = CommandCodec::new()
                            .decode(&empty)
                            .map_err(|_| Error::Protocol)?;
                        if !remaining.is_empty() {
                            return Err(Error::Protocol);
                        }
                        self.command = CommandState::append(command, target)?;
                        self.metrics.append_outcome = Some(AppendOutcome::Unknown);
                        header = false;
                    } else if bytes != b"\r\n"
                        || !matches!(
                            self.command.kind,
                            CommandKind::Append { streamed: true, .. }
                        )
                    {
                        return Err(Error::Protocol);
                    }
                    self.append_write(&bytes).await?;
                }
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsStream) => {
                    let CommandKind::Append {
                        continuation: true,
                        streamed,
                        ..
                    } = &mut self.command.kind
                    else {
                        return Err(Error::Protocol);
                    };
                    if *streamed {
                        return Err(Error::Protocol);
                    }
                    *streamed = true;
                    self.append_write(mime).await?;
                }
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsRead) => {
                    frame = Some(self.frame().await?);
                    if matches!(
                        self.metrics.append_outcome,
                        Some(AppendOutcome::Created { .. } | AppendOutcome::Rejected)
                    ) {
                        // The guarded response is authoritative; the connection is disposed
                        // without further coroutine work or optional reference lookup.
                        return Ok(());
                    }
                }
                ImapCoroutineState::Complete(_) => return Err(Error::Protocol),
            }
        }
    }
    async fn append_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len()
            > self
                .limits
                .max_operation_bytes
                .saturating_sub(self.metrics.wire_bytes)
                .saturating_sub(self.metrics.append_wire_bytes)
        {
            return Err(Error::Limit);
        }
        self.metrics.append_wire_bytes += bytes.len();
        self.stream
            .write_all(bytes)
            .await
            .map_err(|_| Error::Transport)
    }
    pub async fn drive<C, T, E>(&mut self, mut coroutine: C) -> Result<T, Error>
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>,
    {
        let mut frame = None;
        loop {
            self.step(1)?;
            let state = coroutine.resume(&mut self.fragmentizer, frame.as_deref());
            frame = None;
            match state {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    let bytes = Zeroizing::new(bytes);
                    // LOGIN is restricted to a single frame so the complete command can
                    // be validated and its transient encoded bytes cleared after writing.
                    let (remaining, command) = CommandCodec::new()
                        .decode(&bytes)
                        .map_err(|_| Error::Protocol)?;
                    if !remaining.is_empty() {
                        return Err(Error::Protocol);
                    }
                    self.command = CommandState::new(command)?;
                    if self
                        .command
                        .literal_limit()
                        .is_some_and(|count| count > self.limits.max_literal_bytes)
                    {
                        return Err(Error::Limit);
                    }
                    if matches!(self.command.kind, CommandKind::BodyFetch { .. })
                        && self.uid_validity.is_none()
                    {
                        return Err(Error::UnsafeSelection);
                    }
                    self.stream
                        .write_all(&bytes)
                        .await
                        .map_err(|_| Error::Transport)?;
                }
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    let mut received = self.frame().await?;
                    while self.command.needs_logout_completion() {
                        let next = self.frame().await?;
                        if next.len()
                            > self
                                .limits
                                .max_response_bytes
                                .saturating_sub(received.len())
                        {
                            return Err(Error::Limit);
                        }
                        received.extend(next);
                    }
                    frame = Some(received);
                }
                ImapCoroutineState::Complete(Ok(value)) => {
                    if let Some(uid_validity) = self.command.finish()? {
                        self.uid_validity = Some(uid_validity);
                    }
                    return Ok(value);
                }
                ImapCoroutineState::Complete(Err(_)) => {
                    return Err(if matches!(self.command.kind, CommandKind::Login) {
                        Error::Authentication
                    } else {
                        Error::Protocol
                    });
                }
            }
        }
    }
    fn step(&mut self, count: usize) -> Result<(), Error> {
        if count
            > self
                .limits
                .max_parser_steps
                .saturating_sub(self.metrics.parser_steps)
        {
            return Err(Error::Limit);
        }
        self.metrics.parser_steps += count;
        Ok(())
    }
    async fn frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut guard = Fragmentizer::new(self.limits.max_response_bytes as u32);
        let mut bytes = 0usize;
        let mut nesting = 0usize;
        if self.metrics.responses >= self.limits.max_responses {
            return Err(Error::Limit);
        }
        self.metrics.responses += 1;
        loop {
            if bytes >= self.limits.max_response_bytes {
                return Err(Error::Limit);
            }
            if self
                .metrics
                .wire_bytes
                .saturating_add(self.metrics.append_wire_bytes)
                >= self.limits.max_operation_bytes
            {
                return Err(Error::Limit);
            }
            let byte = self.stream.read_u8().await.map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    Error::Eof
                } else {
                    Error::Transport
                }
            })?;
            bytes += 1;
            self.metrics.wire_bytes += 1;
            self.metrics.max_response_bytes = self.metrics.max_response_bytes.max(bytes);
            self.step(1)?;
            guard.enqueue_bytes(&[byte]);
            while let Some(info) = guard.progress() {
                if let FragmentInfo::Line {
                    announcement,
                    ending,
                    ..
                } = info
                {
                    if ending != LineEnding::CrLf {
                        return Err(Error::Protocol);
                    }
                    // Inspect syntax before invoking the recursive typed decoder. Literal
                    // bytes are separate fragments and cannot affect this depth counter.
                    let mut quoted = false;
                    let mut escaped = false;
                    for &b in guard.fragment_bytes(info) {
                        if escaped {
                            escaped = false;
                            continue;
                        }
                        if quoted && b == b'\\' {
                            escaped = true;
                            continue;
                        }
                        if b == b'"' {
                            quoted = !quoted;
                            continue;
                        }
                        if !quoted {
                            if b == b'(' {
                                nesting += 1;
                                if nesting > self.limits.max_nesting {
                                    return Err(Error::Limit);
                                }
                            }
                            if b == b')' {
                                nesting = nesting.saturating_sub(1);
                            }
                        }
                    }
                    if let Some(a) = announcement {
                        let length = a.length as usize;
                        if length > self.limits.max_literal_bytes
                            || self
                                .command
                                .literal_limit()
                                .is_some_and(|count| length > count)
                            || length > self.limits.max_response_bytes.saturating_sub(bytes)
                            || length
                                > self
                                    .limits
                                    .max_operation_bytes
                                    .saturating_sub(self.metrics.wire_bytes)
                        {
                            return Err(Error::Limit);
                        }
                        self.metrics.max_literal_bytes = self.metrics.max_literal_bytes.max(length);
                    }
                }
                if guard.is_message_complete() {
                    self.step(bytes * 2)?;
                    let repaired = match &self.command.kind {
                        CommandKind::BodyFetch { contract, .. } => contract
                            .repair_partial_separator(
                                guard.message_bytes(),
                                self.limits.max_response_bytes,
                            )?,
                        _ => None,
                    };
                    if repaired.is_some() {
                        self.step(bytes + 1)?;
                    }
                    let input = repaired.as_deref().unwrap_or_else(|| guard.message_bytes());
                    let (remaining, response) = ResponseCodec::new()
                        .decode(input)
                        .map_err(|_| Error::Protocol)?;
                    if !remaining.is_empty() {
                        return Err(Error::Protocol);
                    }
                    self.command.inspect(response, self.uid_validity)?;
                    if let CommandKind::Append { outcome, .. } = self.command.kind {
                        self.metrics.append_outcome = Some(outcome);
                    }
                    return Ok(repaired.unwrap_or_else(|| guard.message_bytes().to_vec()));
                }
            }
        }
    }
}

/// A command owns the response requirements implied by its typed request.
struct CommandState {
    tag: Option<String>,
    kind: CommandKind,
}
enum CommandKind {
    Append {
        continuation: bool,
        streamed: bool,
        outcome: AppendOutcome,
    },
    Greeting,
    Capability,
    Login,
    StartTls,
    List,
    Examine {
        uid_validity: Option<NonZeroU32>,
        read_only: bool,
    },
    Search {
        seen: bool,
    },
    Fetch {
        sequences: BTreeSet<u32>,
    },
    BodyFetch {
        contract: BodyFetch,
        seen: bool,
    },
    Logout {
        bye: bool,
        tagged: bool,
    },
}
impl CommandState {
    fn greeting() -> Self {
        Self {
            tag: None,
            kind: CommandKind::Greeting,
        }
    }
    fn append(command: Command<'_>, target: &str) -> Result<Self, Error> {
        let CommandBody::Append {
            mailbox,
            flags,
            date: None,
            ..
        } = &command.body
        else {
            return Err(Error::Unsupported);
        };
        let expected: io_imap::types::mailbox::Mailbox<'_> = target
            .replace('&', "&-")
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        if mailbox != &expected || flags != &[Flag::Draft] {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            tag: Some(command.tag.as_ref().to_owned()),
            kind: CommandKind::Append {
                continuation: false,
                streamed: false,
                outcome: AppendOutcome::Unknown,
            },
        })
    }
    fn new(command: Command<'_>) -> Result<Self, Error> {
        let body_fetch = BodyFetch::from_command(&command.body);
        let kind = match command.body {
            CommandBody::Capability => CommandKind::Capability,
            CommandBody::Login { .. } => CommandKind::Login,
            CommandBody::StartTLS => CommandKind::StartTls,
            CommandBody::List { .. } => CommandKind::List,
            CommandBody::Examine { parameters, .. } if parameters.is_empty() => {
                CommandKind::Examine {
                    uid_validity: None,
                    read_only: false,
                }
            }
            CommandBody::Search { uid: true, .. } => CommandKind::Search { seen: false },
            CommandBody::Fetch {
                uid: true,
                macro_or_item_names,
                modifiers,
                ..
            } if modifiers.is_empty() && macro_or_item_names == Projection::request() => {
                CommandKind::Fetch {
                    sequences: BTreeSet::new(),
                }
            }
            CommandBody::Fetch { .. } => CommandKind::BodyFetch {
                contract: body_fetch.ok_or(Error::Unsupported)?,
                seen: false,
            },
            CommandBody::Logout => CommandKind::Logout {
                bye: false,
                tagged: false,
            },
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            tag: Some(command.tag.as_ref().to_owned()),
            kind,
        })
    }
    fn needs_logout_completion(&self) -> bool {
        matches!(
            self.kind,
            CommandKind::Logout {
                bye: true,
                tagged: false
            }
        )
    }
    fn literal_limit(&self) -> Option<usize> {
        match &self.kind {
            CommandKind::BodyFetch { contract, .. } => contract.literal_limit(),
            _ => None,
        }
    }
    fn finish(&self) -> Result<Option<NonZeroU32>, Error> {
        match self.kind {
            CommandKind::Examine {
                uid_validity: Some(uid_validity),
                read_only: true,
            } => Ok(Some(uid_validity)),
            CommandKind::Examine { .. } => Err(Error::UnsafeSelection),
            CommandKind::Search { seen: false } => Err(Error::Protocol),
            CommandKind::BodyFetch { seen: false, .. } => Err(Error::Protocol),
            CommandKind::Logout { bye: false, .. } | CommandKind::Logout { tagged: false, .. } => {
                Err(Error::Protocol)
            }
            _ => Ok(None),
        }
    }
    fn inspect(
        &mut self,
        response: Response<'_>,
        selected: Option<NonZeroU32>,
    ) -> Result<(), Error> {
        match response {
            Response::Status(status) => {
                let (body, tagged) = match &status {
                    Status::Tagged(tagged) => {
                        if self.tag.as_deref() != Some(tagged.tag.as_ref()) {
                            return Err(Error::Protocol);
                        }
                        if let CommandKind::Logout { tagged, .. } = &mut self.kind {
                            *tagged = true;
                        }
                        if let CommandKind::Append {
                            streamed, outcome, ..
                        } = &mut self.kind
                        {
                            *outcome = match tagged.body.kind {
                                StatusKind::Ok if *streamed => AppendOutcome::Created {
                                    uid: match tagged.body.code {
                                        Some(Code::AppendUid { uid_validity, uid }) => {
                                            Some(AppendUid {
                                                uid_validity: uid_validity.get(),
                                                uid: uid.get(),
                                            })
                                        }
                                        _ => None,
                                    },
                                },
                                StatusKind::No | StatusKind::Bad => AppendOutcome::Rejected,
                                _ => return Err(Error::Protocol),
                            };
                            return Ok(());
                        }
                        (&tagged.body, true)
                    }
                    Status::Untagged(body) => (body, false),
                    Status::Bye(bye) => {
                        check_code(bye.code.as_ref())?;
                        let CommandKind::Logout { bye, .. } = &mut self.kind else {
                            return Err(Error::Eof);
                        };
                        if *bye {
                            return Err(Error::Protocol);
                        }
                        *bye = true;
                        return Ok(());
                    }
                };
                check_code(body.code.as_ref())?;
                if let Some(Code::UidValidity(value)) = body.code {
                    if let CommandKind::Examine { uid_validity, .. } = &mut self.kind {
                        if body.kind != StatusKind::Ok || uid_validity.replace(value).is_some() {
                            return Err(Error::Protocol);
                        }
                    } else if selected.is_some_and(|expected| expected != value) {
                        return Err(Error::UnsafeSelection);
                    }
                }
                if let CommandKind::Examine { read_only, .. } = &mut self.kind
                    && tagged
                {
                    if body.kind != StatusKind::Ok || body.code != Some(Code::ReadOnly) {
                        return Err(Error::UnsafeSelection);
                    }
                    *read_only = true;
                }
            }
            Response::Data(data) => match data {
                Data::Capability(_)
                    if matches!(self.kind, CommandKind::Capability | CommandKind::Login) => {}
                Data::List { .. } if matches!(self.kind, CommandKind::List) => {}
                Data::Flags(_) | Data::Exists(_) | Data::Recent(_) | Data::Expunge(_) => {}
                Data::Search(..) => {
                    let CommandKind::Search { seen } = &mut self.kind else {
                        return Err(Error::Protocol);
                    };
                    if *seen {
                        return Err(Error::Protocol);
                    }
                    *seen = true;
                }
                Data::Fetch { seq, items } => match &mut self.kind {
                    CommandKind::Fetch { sequences } => {
                        if !sequences.insert(seq.get()) {
                            return Err(Error::Protocol);
                        }
                        Projection::parse(items.as_ref())?;
                    }
                    CommandKind::BodyFetch { contract, seen } => {
                        if *seen {
                            return Err(Error::Protocol);
                        }
                        contract.validate(items.as_ref())?;
                        *seen = true;
                    }
                    _ => return Err(Error::Protocol),
                },
                // VANISHED sequence ranges can expand into billions of UIDs in the
                // backend's EXAMINE coroutine. No extensions are enabled in this proof.
                _ => return Err(Error::Unsupported),
            },
            Response::CommandContinuationRequest(_) => {
                let CommandKind::Append {
                    continuation,
                    streamed: false,
                    ..
                } = &mut self.kind
                else {
                    return Err(Error::Protocol);
                };
                if *continuation {
                    return Err(Error::Protocol);
                }
                *continuation = true;
            }
        }
        Ok(())
    }
}

fn server_name(host: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(host.to_owned()).map_err(|_| Error::InvalidInput)
}
fn check_code(code: Option<&Code<'_>>) -> Result<(), Error> {
    match code {
        Some(Code::Referral(_)) => Err(Error::Unsupported),
        Some(Code::ReadWrite) => Err(Error::UnsafeSelection),
        Some(Code::Other(other))
            if other
                .inner()
                .split(|b| b.is_ascii_whitespace())
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(b"REFERRAL")) =>
        {
            Err(Error::Unsupported)
        }
        _ => Ok(()),
    }
}
