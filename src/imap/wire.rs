use super::{Error, Limits, Metrics, TlsMode};
use io_imap::{
    codec::{
        CommandCodec, ResponseCodec,
        decode::Decoder,
        fragmentizer::{FragmentInfo, Fragmentizer, LineEnding},
    },
    coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
    send::ImapSend,
    types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Code, Data, Response, Status, StatusKind},
    },
};
use std::{
    io,
    sync::{Arc, Mutex},
};
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

pub(super) struct Connection {
    stream: Option<BufReader<Box<dyn Stream>>>,
    fragmentizer: Fragmentizer,
    limits: Limits,
    metrics: Arc<Mutex<Metrics>>,
    pub examining: bool,
    pub read_only: bool,
    pub authenticating: bool,
    tag: Option<String>,
    logging_out: bool,
    logout_bye: bool,
    logout_tagged: bool,
    searching: bool,
    search_responses: usize,
    fetch_sequences: std::collections::BTreeSet<u32>,
    uid_validity: Option<u32>,
}
impl Connection {
    pub async fn connect(
        host: &str,
        port: u16,
        mode: TlsMode,
        tls: Arc<ClientConfig>,
        limits: Limits,
        metrics: Arc<Mutex<Metrics>>,
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
            stream: Some(BufReader::with_capacity(4096, stream)),
            fragmentizer: Fragmentizer::new(limits.max_response_bytes as u32),
            limits,
            metrics,
            examining: false,
            read_only: false,
            authenticating: false,
            tag: None,
            logging_out: false,
            logout_bye: false,
            logout_tagged: false,
            searching: false,
            search_responses: 0,
            fetch_sequences: Default::default(),
            uid_validity: None,
        })
    }
    pub async fn upgrade(&mut self, host: &str, tls: Arc<ClientConfig>) -> Result<(), Error> {
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
        let stream = self.stream.take().ok_or(Error::Transport)?;
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
        self.stream = Some(BufReader::with_capacity(4096, Box::new(tls)));
        self.fragmentizer = Fragmentizer::new(self.limits.max_response_bytes as u32);
        Ok(())
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
                    let (_, command) = CommandCodec::new()
                        .decode(&bytes)
                        .map_err(|_| Error::Protocol)?;
                    self.tag = Some(command.tag.as_ref().to_owned());
                    self.logging_out = matches!(command.body, CommandBody::Logout);
                    self.logout_bye = false;
                    self.logout_tagged = false;
                    self.searching = matches!(command.body, CommandBody::Search { .. });
                    self.search_responses = 0;
                    self.fetch_sequences.clear();
                    let result = self
                        .stream
                        .as_mut()
                        .ok_or(Error::Transport)?
                        .write_all(&bytes)
                        .await;
                    result.map_err(|_| Error::Transport)?;
                }
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    let mut received = self.frame().await?;
                    if self.logging_out && self.logout_bye {
                        while !self.logout_tagged {
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
                            let mut metrics =
                                self.metrics.lock().unwrap_or_else(|e| e.into_inner());
                            metrics.max_buffered_bytes =
                                metrics.max_buffered_bytes.max(received.len() * 2 + 4096);
                        }
                    }
                    frame = Some(received);
                }
                ImapCoroutineState::Complete(Ok(value)) => {
                    if self.searching && self.search_responses != 1 {
                        return Err(Error::Protocol);
                    }
                    self.tag = None;
                    return Ok(value);
                }
                ImapCoroutineState::Complete(Err(_)) => {
                    return Err(if self.authenticating {
                        Error::Authentication
                    } else {
                        Error::Protocol
                    });
                }
            }
        }
    }
    fn step(&self, count: usize) -> Result<(), Error> {
        let mut m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        if count > self.limits.max_parser_steps.saturating_sub(m.parser_steps) {
            return Err(Error::Limit);
        }
        m.parser_steps += count;
        Ok(())
    }
    async fn frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut guard = Fragmentizer::new(self.limits.max_response_bytes as u32);
        let mut bytes = 0usize;
        let mut nesting = 0usize;
        {
            let mut m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
            if m.responses >= self.limits.max_responses {
                return Err(Error::Limit);
            }
            m.responses += 1;
        }
        loop {
            if bytes >= self.limits.max_response_bytes {
                return Err(Error::Limit);
            }
            {
                let m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
                if m.wire_bytes >= self.limits.max_operation_bytes {
                    return Err(Error::Limit);
                }
            }
            let byte = self
                .stream
                .as_mut()
                .ok_or(Error::Transport)?
                .read_u8()
                .await
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        Error::Eof
                    } else {
                        Error::Transport
                    }
                })?;
            bytes += 1;
            self.step(1)?;
            {
                let mut m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
                m.wire_bytes += 1;
                m.max_response_bytes = m.max_response_bytes.max(bytes);
                m.max_buffered_bytes = m.max_buffered_bytes.max(bytes * 2 + 4096);
            }
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
                            || length > self.limits.max_response_bytes.saturating_sub(bytes)
                            || length
                                > self.limits.max_operation_bytes.saturating_sub(
                                    self.metrics
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .wire_bytes,
                                )
                        {
                            return Err(Error::Limit);
                        }
                        let mut m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
                        m.max_literal_bytes = m.max_literal_bytes.max(length);
                    }
                }
                if guard.is_message_complete() {
                    self.step(bytes * 2)?;
                    let response = guard
                        .decode_message(&ResponseCodec::new())
                        .map_err(|_| Error::Protocol)?;
                    self.inspect(response)?;
                    return Ok(guard.message_bytes().to_vec());
                }
            }
        }
    }
    fn inspect(&mut self, response: Response<'_>) -> Result<(), Error> {
        match response {
            Response::Status(status) => {
                let (body, tagged) = match &status {
                    Status::Tagged(tagged) => {
                        if self.tag.as_deref() != Some(tagged.tag.as_ref()) {
                            return Err(Error::Protocol);
                        }
                        self.logout_tagged = true;
                        (&tagged.body, true)
                    }
                    Status::Untagged(body) => (body, false),
                    Status::Bye(bye) => {
                        check_code(bye.code.as_ref())?;
                        if self.logout_bye {
                            return Err(Error::Protocol);
                        }
                        self.logout_bye = true;
                        return if self.logging_out {
                            Ok(())
                        } else {
                            Err(Error::Eof)
                        };
                    }
                };
                check_code(body.code.as_ref())?;
                if let Some(Code::UidValidity(value)) = body.code {
                    if self.examining {
                        if self.uid_validity.replace(value.get()).is_some() {
                            return Err(Error::Protocol);
                        }
                    } else if self
                        .uid_validity
                        .is_some_and(|expected| expected != value.get())
                    {
                        return Err(Error::UnsafeSelection);
                    }
                }
                if self.examining && tagged {
                    if body.kind != StatusKind::Ok || body.code != Some(Code::ReadOnly) {
                        return Err(Error::UnsafeSelection);
                    }
                    self.read_only = true;
                }
            }
            Response::Data(data) => match data {
                Data::Capability(_)
                | Data::List { .. }
                | Data::Flags(_)
                | Data::Exists(_)
                | Data::Recent(_)
                | Data::Expunge(_) => {}
                Data::Search(..) => {
                    if !self.searching || self.search_responses != 0 {
                        return Err(Error::Protocol);
                    }
                    self.search_responses += 1;
                }
                Data::Fetch { seq, items } => {
                    if !self.fetch_sequences.insert(seq.get()) {
                        return Err(Error::Protocol);
                    }
                    if self.examining {
                        return Err(Error::Protocol);
                    }
                    if items.as_ref().iter().any(|item| {
                        !matches!(
                            item,
                            io_imap::types::fetch::MessageDataItem::Uid(_)
                                | io_imap::types::fetch::MessageDataItem::Envelope(_)
                                | io_imap::types::fetch::MessageDataItem::Flags(_)
                                | io_imap::types::fetch::MessageDataItem::InternalDate(_)
                                | io_imap::types::fetch::MessageDataItem::Rfc822Size(_)
                        )
                    }) {
                        return Err(Error::Unsupported);
                    }
                }
                // VANISHED sequence ranges can expand into billions of UIDs in the
                // backend's EXAMINE coroutine. No extensions are enabled in this proof.
                _ => return Err(Error::Unsupported),
            },
            Response::CommandContinuationRequest(_) => return Err(Error::Protocol),
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
