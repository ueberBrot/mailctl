//! Supported commands over the maintained async-imap response stream.
use super::{
    AppendOutcome, Error, Limits, Metrics, TlsMode,
    admission::{Admission, Control, FrameContract},
    fetch::Fetch,
    projection::Projection,
};
use imap_proto::{Capability, MailboxDatum, Outcome, Response, ResponseCode, Status};
use std::{collections::BTreeSet, fmt, io, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, pki_types::ServerName},
};
use zeroize::Zeroizing;

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
struct Transport(Box<dyn Stream>);
impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IMAP transport")
    }
}
impl AsyncRead for Transport {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
type Client = async_imap::Client<Admission<Transport>>;

pub(super) struct Session {
    client: Option<Client>,
    control: Control,
    limits: Limits,
    next_tag: u64,
    uid_validity: Option<u32>,
}
pub(super) struct Connection<'a> {
    session: Session,
    progress: Progress<'a>,
}
struct Progress<'a> {
    metrics: &'a mut Metrics,
    control: Control,
}
fn protocol_metrics(target: &mut Metrics, source: Metrics) {
    target.wire_bytes = source.wire_bytes;
    target.responses = source.responses;
    target.parser_steps = source.parser_steps;
    target.max_response_bytes = source.max_response_bytes;
    target.max_literal_bytes = source.max_literal_bytes;
    target.append_outcome = source.append_outcome;
    target.append_wire_bytes = source.append_wire_bytes;
}
impl Drop for Progress<'_> {
    fn drop(&mut self) {
        protocol_metrics(self.metrics, self.control.metrics());
    }
}
impl Session {
    pub(super) fn resume(self, metrics: &mut Metrics) -> Connection<'_> {
        self.control.set_metrics(*metrics);
        Connection {
            progress: Progress {
                metrics,
                control: self.control.clone(),
            },
            session: self,
        }
    }
}
#[derive(Clone)]
pub(super) enum Kind {
    Capability,
    Login,
    StartTls,
    List,
    Examine,
    Search,
    Projection,
    Body(Fetch),
    Logout,
}
impl Kind {
    fn contract(&self) -> FrameContract {
        match self {
            Self::List => FrameContract::List,
            Self::Projection => FrameContract::Metadata,
            Self::Body(fetch) => fetch.contract(),
            _ => FrameContract::Other,
        }
    }
}
pub(super) enum SearchTerm {
    Atom(String),
    Text(&'static str, String),
}
impl<'a> Connection<'a> {
    pub(super) fn into_session(self) -> Session {
        self.session
    }
    fn client(&mut self) -> &mut Client {
        self.session
            .client
            .as_mut()
            .expect("live protocol transport")
    }
    fn prepare(&mut self, contract: FrameContract) {
        self.session.control.set_metrics(self.metrics());
        self.session
            .control
            .configure(self.session.limits.clone(), contract);
    }
    pub(super) fn metrics_mut(&mut self) -> &mut Metrics {
        protocol_metrics(self.progress.metrics, self.session.control.metrics());
        self.progress.metrics
    }
    pub fn metrics(&self) -> Metrics {
        let mut result = *self.progress.metrics;
        protocol_metrics(&mut result, self.session.control.metrics());
        result
    }
    pub(super) fn literal_limit(&self) -> usize {
        self.session.limits.max_literal_bytes
    }
    pub(super) fn limit_body(&mut self, limits: &Limits) {
        self.session.limits = limits.clone();
    }
    pub(super) fn limit_search(&mut self, limits: &crate::config::Limits) {
        self.session.limits.max_literal_bytes = limits.header_bytes;
        self.session.limits.max_response_bytes = limits
            .header_bytes
            .saturating_mul(2)
            .saturating_add(16 * 1024)
            .max(120_000)
            .min(limits.wire_fetch_bytes);
        self.session.limits.max_operation_bytes = limits.wire_fetch_bytes;
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
        let (transport, control) = Admission::new(Transport(stream), limits.clone(), *metrics);
        Ok(Session {
            client: Some(async_imap::Client::new(transport)),
            control,
            limits,
            next_tag: 0,
            uid_validity: None,
        }
        .resume(metrics))
    }
    fn io_error(&self, error: io::Error) -> Error {
        self.session
            .control
            .failure()
            .unwrap_or(match error.kind() {
                io::ErrorKind::UnexpectedEof => Error::Eof,
                io::ErrorKind::InvalidData => Error::Protocol,
                _ => Error::Transport,
            })
    }
    async fn read(&mut self) -> Result<Response<'static>, Error> {
        let mut response = self
            .client()
            .read_response()
            .await
            .map_err(|_| self.session.control.failure().unwrap_or(Error::Protocol))?
            .ok_or(Error::Eof)?;
        match response.parsed() {
            Response::Done { outcome, .. }
            | Response::Data { outcome, .. }
            | Response::Continue(outcome) => self.check_outcome(outcome)?,
            _ => {}
        }
        // The library's response owner is intentionally private. Move its tree
        // through its public closure API, then own the bounded borrowed fields.
        Ok(response.with_dependent_mut(|_, parsed| {
            std::mem::replace(parsed, Response::Expunge(0)).into_owned()
        }))
    }
    fn check_outcome(&self, outcome: &Outcome<'_>) -> Result<(), Error> {
        if matches!(outcome.code, Some(ResponseCode::ReadWrite)) {
            return Err(Error::UnsafeSelection);
        }
        if outcome.information.as_deref().is_some_and(|text| {
            text.split_ascii_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("[REFERRAL"))
        }) {
            return Err(Error::Unsupported);
        }
        if let Some(ResponseCode::UidValidity(validity)) = outcome.code
            && (validity == 0
                || self
                    .session
                    .uid_validity
                    .is_some_and(|expected| validity != expected))
        {
            return Err(Error::UnsafeSelection);
        }
        Ok(())
    }
    async fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.client()
            .get_mut()
            .write_all(bytes)
            .await
            .map_err(|e| self.io_error(e))?;
        self.client()
            .get_mut()
            .flush()
            .await
            .map_err(|e| self.io_error(e))
    }
    fn tag(&mut self) -> Result<String, Error> {
        self.session.next_tag = self.session.next_tag.checked_add(1).ok_or(Error::Limit)?;
        Ok(format!("M{}", self.session.next_tag))
    }
    pub(super) async fn greeting(&mut self) -> Result<(), Error> {
        self.prepare(FrameContract::Other);
        match &self.read().await? {
            Response::Data {
                status: Status::Ok, ..
            } => Ok(()),
            _ => Err(Error::Protocol),
        }
    }
    pub(super) async fn request(
        &mut self,
        command: &str,
        kind: Kind,
    ) -> Result<Vec<Response<'static>>, Error> {
        self.prepare(kind.contract());
        let tag = self.tag()?;
        let bytes = Zeroizing::new(format!("{tag} {command}\r\n"));
        self.write(bytes.as_bytes()).await?;
        self.collect(&tag, kind).await
    }
    async fn collect(&mut self, tag: &str, kind: Kind) -> Result<Vec<Response<'static>>, Error> {
        let mut rows = Vec::new();
        let mut sequences = BTreeSet::new();
        let mut uids = BTreeSet::new();
        let mut validity = None;
        let mut bye = false;
        loop {
            let row = self.read().await?;
            match &row {
                Response::Done {
                    tag: returned,
                    status,
                    outcome,
                } => {
                    if returned.0 != tag {
                        return Err(Error::Protocol);
                    }
                    if *status != Status::Ok {
                        return Err(if matches!(kind, Kind::Login) {
                            Error::Authentication
                        } else {
                            Error::Protocol
                        });
                    }
                    match kind {
                        Kind::Examine => {
                            if outcome.code != Some(ResponseCode::ReadOnly) || validity.is_none() {
                                return Err(Error::UnsafeSelection);
                            }
                            self.session.uid_validity = validity;
                        }
                        Kind::Body(_) if rows.is_empty() => return Err(Error::MessageNotFound),
                        Kind::Search if rows.len() != 1 => return Err(Error::Protocol),
                        Kind::Logout if !bye => return Err(Error::Protocol),
                        _ => {}
                    }
                    return Ok(rows);
                }
                Response::Data {
                    status: Status::Bye,
                    ..
                } => {
                    if !matches!(kind, Kind::Logout) {
                        return Err(Error::Eof);
                    }
                    if bye {
                        return Err(Error::Protocol);
                    }
                    bye = true;
                }
                Response::Data {
                    status: Status::Ok,
                    outcome,
                } => {
                    if matches!(kind, Kind::Examine) {
                        if let Some(ResponseCode::UidValidity(value)) = outcome.code
                            && (value == 0 || validity.replace(value).is_some())
                        {
                            return Err(Error::Protocol);
                        }
                        rows.push(row);
                    }
                }
                Response::Capabilities(_) if matches!(kind, Kind::Capability | Kind::Login) => {
                    rows.push(row)
                }
                Response::MailboxData(MailboxDatum::List(_)) if matches!(kind, Kind::List) => {
                    if rows.len() == self.session.limits.max_mailboxes {
                        return Err(Error::Limit);
                    }
                    rows.push(row);
                }
                Response::MailboxData(MailboxDatum::Search(ids))
                    if matches!(kind, Kind::Search) =>
                {
                    if !rows.is_empty()
                        || ids.contains(&0)
                        || ids.iter().any(|uid| !uids.insert(*uid))
                    {
                        return Err(Error::Protocol);
                    }
                    rows.push(row);
                }
                Response::Fetch(seq, attrs) => {
                    if *seq == 0 || !sequences.insert(*seq) {
                        return Err(Error::Protocol);
                    }
                    match &kind {
                        Kind::Projection => {
                            Projection::parse(attrs)?;
                        }
                        Kind::Body(fetch) if rows.is_empty() => fetch.validate(attrs)?,
                        _ => return Err(Error::Protocol),
                    }
                    let uid = attrs
                        .iter()
                        .find_map(|a| {
                            if let imap_proto::AttributeValue::Uid(id) = a {
                                Some(*id)
                            } else {
                                None
                            }
                        })
                        .ok_or(Error::Protocol)?;
                    if uid == 0 || !uids.insert(uid) {
                        return Err(Error::Protocol);
                    }
                    rows.push(row);
                }
                Response::MailboxData(
                    MailboxDatum::Flags(_) | MailboxDatum::Exists(_) | MailboxDatum::Recent(_),
                )
                | Response::Expunge(_) => {}
                _ => return Err(Error::Unsupported),
            }
        }
    }
    pub(super) async fn capabilities(&mut self) -> Result<Vec<Capability<'static>>, Error> {
        let rows = self.request("CAPABILITY", Kind::Capability).await?;
        if rows.len() != 1 {
            return Err(Error::Protocol);
        }
        let Some(Response::Capabilities(values)) = rows.into_iter().next() else {
            return Err(Error::Protocol);
        };
        Ok(values)
    }
    pub(super) async fn login(&mut self, user: &str, password: &str) -> Result<(), Error> {
        let command = Zeroizing::new(format!("LOGIN {} {}", quote(user)?, quote(password)?));
        self.request(&command, Kind::Login).await?;
        Ok(())
    }
    pub(super) async fn logout(&mut self) -> Result<(), Error> {
        self.request("LOGOUT", Kind::Logout).await?;
        Ok(())
    }
    pub async fn upgrade(mut self, host: &str, tls: Arc<ClientConfig>) -> Result<Self, Error> {
        self.request("STARTTLS", Kind::StartTls).await?;
        let admitted = self
            .session
            .client
            .take()
            .expect("live transport")
            .into_inner();
        if !admitted.is_empty() {
            return Err(Error::Protocol);
        }
        let stream = admitted.into_inner();
        let upgraded = tokio::time::timeout(
            self.session.limits.connect_timeout,
            TlsConnector::from(tls).connect(server_name(host)?, stream),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Tls)?;
        let (admitted, control) = Admission::new(
            Transport(Box::new(upgraded)),
            self.session.limits.clone(),
            self.metrics(),
        );
        self.progress.control = control.clone();
        self.session.control = control;
        self.session.client = Some(async_imap::Client::new(admitted));
        Ok(self)
    }
    pub async fn examine(&mut self, name: &str) -> Result<u32, Error> {
        self.examine_selection(name).await.map(|(v, _)| v)
    }
    pub(super) async fn examine_selection(
        &mut self,
        name: &str,
    ) -> Result<(u32, Option<u32>), Error> {
        let rows = self
            .request(
                &format!("EXAMINE {}", quote(&super::mailbox_pattern(name))?),
                Kind::Examine,
            )
            .await?;
        let mut next = None;
        for row in rows {
            if let Response::Data {
                outcome:
                    Outcome {
                        code: Some(ResponseCode::UidNext(value)),
                        ..
                    },
                ..
            } = &row
                && (*value == 0 || next.replace(*value).is_some())
            {
                return Err(Error::Protocol);
            }
        }
        Ok((
            self.session.uid_validity.ok_or(Error::UnsafeSelection)?,
            next,
        ))
    }
    pub(super) async fn upper_uid(&mut self, next: Option<u32>) -> Result<u32, Error> {
        if let Some(next) = next {
            return next.checked_sub(1).ok_or(Error::Protocol);
        }
        let ids = self
            .search(vec![SearchTerm::Atom("UID *".into())], false)
            .await?;
        if ids.len() > 1 {
            return Err(Error::Protocol);
        }
        Ok(ids.first().copied().unwrap_or(0))
    }
    pub(super) async fn search(
        &mut self,
        terms: Vec<SearchTerm>,
        utf8: bool,
    ) -> Result<Vec<u32>, Error> {
        self.prepare(FrameContract::Other);
        let tag = self.tag()?;
        let mut pending = format!(
            "{tag} UID SEARCH{}",
            if utf8 { " CHARSET UTF-8" } else { "" }
        );
        let mut command_bytes = pending.len();
        for term in terms {
            pending.push(' ');
            match term {
                SearchTerm::Atom(value) => pending.push_str(&value),
                SearchTerm::Text(key, value) => {
                    pending.push_str(key);
                    pending.push(' ');
                    if value.bytes().all(|byte| (32..=126).contains(&byte)) {
                        pending.push_str(&quote(&value)?);
                    } else {
                        pending.push_str(&format!("{{{}}}\r\n", value.len()));
                        command_bytes = command_bytes
                            .saturating_add(pending.len())
                            .saturating_add(value.len());
                        if command_bytes > 32 * 8192 + 2048 {
                            return Err(Error::Limit);
                        }
                        self.write(pending.as_bytes()).await?;
                        if !matches!(&self.read().await?, Response::Continue(_)) {
                            return Err(Error::Protocol);
                        }
                        self.write(value.as_bytes()).await?;
                        pending.clear();
                    }
                }
            }
        }
        pending.push_str("\r\n");
        if command_bytes.saturating_add(pending.len()) > 32 * 8192 + 2048 {
            return Err(Error::Limit);
        }
        self.write(pending.as_bytes()).await?;
        let rows = self.collect(&tag, Kind::Search).await?;
        let Some(Response::MailboxData(MailboxDatum::Search(ids))) = rows.into_iter().next() else {
            return Err(Error::Protocol);
        };
        Ok(ids)
    }
    /// Frozen MIME is streamed after one synchronizing continuation. Outcome is
    /// recorded before returning, including when cancellation drops this future.
    pub async fn append(&mut self, target: &str, mime: &[u8]) -> Result<(), Error> {
        self.prepare(FrameContract::Other);
        let tag = self.tag()?;
        let header = format!(
            "{tag} APPEND {} (\\Draft) {{{}}}\r\n",
            quote(&super::mailbox_pattern(target))?,
            mime.len()
        );
        let mut metrics = self.metrics();
        metrics.append_outcome = Some(AppendOutcome::Unknown);
        self.session.control.set_metrics(metrics);
        self.append_write(header.as_bytes()).await?;
        let mut streamed = false;
        loop {
            let row = self.read().await?;
            match &row {
                Response::Continue(_) if !streamed => {
                    streamed = true;
                    self.append_write(mime).await?;
                    self.append_write(b"\r\n").await?;
                }
                Response::Done {
                    tag: returned,
                    status,
                    outcome,
                } if returned.0 == tag => {
                    let result = match status {
                        Status::No | Status::Bad => AppendOutcome::Rejected,
                        Status::Ok if streamed => {
                            let uid = match &outcome.code {
                                Some(ResponseCode::AppendUid(validity, members)) => {
                                    use imap_proto::rfc4315::UidSetMember;
                                    match members.as_slice() {
                                        [UidSetMember::Uid(uid)] if *validity != 0 && *uid != 0 => {
                                            Some(crate::draft::DraftMessageIdentity {
                                                uid_validity: *validity,
                                                uid: *uid,
                                            })
                                        }
                                        _ => return Err(Error::Protocol),
                                    }
                                }
                                _ => None,
                            };
                            AppendOutcome::Created { uid }
                        }
                        _ => return Err(Error::Protocol),
                    };
                    let mut metrics = self.metrics();
                    metrics.append_outcome = Some(result);
                    self.session.control.set_metrics(metrics);
                    return Ok(());
                }
                Response::MailboxData(
                    MailboxDatum::Flags(_) | MailboxDatum::Exists(_) | MailboxDatum::Recent(_),
                )
                | Response::Expunge(_)
                | Response::Data {
                    status: Status::Ok, ..
                } => {}
                _ => return Err(Error::Protocol),
            }
        }
    }
    async fn append_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut metrics = self.metrics();
        if bytes.len()
            > self
                .session
                .limits
                .max_operation_bytes
                .saturating_sub(metrics.wire_bytes)
                .saturating_sub(metrics.append_wire_bytes)
        {
            return Err(Error::Limit);
        }
        metrics.append_wire_bytes += bytes.len();
        self.session.control.set_metrics(metrics);
        self.write(bytes).await
    }
}
pub(super) fn quote(value: &str) -> Result<String, Error> {
    if value.bytes().any(|b| b < 32 || b == 127) {
        return Err(Error::Unsupported);
    }
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            result.push('\\');
        }
        result.push(character);
    }
    result.push('"');
    Ok(result)
}
fn server_name(host: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(host.to_owned()).map_err(|_| Error::InvalidInput)
}
