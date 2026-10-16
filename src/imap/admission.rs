//! Complete-frame admission before the maintained IMAP client's recursive parser.
//! This is a lexical boundary, not an IMAP parser. The client still validates all
//! response grammar. Literal payloads are never interpreted as protocol syntax.
use super::{Error, Limits, Metrics};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, ReadBuf};

const MAX_PROTOCOL_NESTING: usize = 64;
const BUFFER_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub(super) enum FrameContract {
    Other,
    List,
    Metadata,
    Body {
        section: String,
        offset: u32,
        count: usize,
    },
}

#[derive(Clone)]
pub(super) struct Control(Arc<Mutex<State>>);
struct State {
    limits: Limits,
    metrics: Metrics,
    contract: FrameContract,
    failure: Option<Error>,
}
impl Control {
    pub(super) fn configure(&self, limits: Limits, contract: FrameContract) {
        let mut state = self.0.lock().expect("admission mutex");
        state.limits = limits;
        state.contract = contract;
    }
    pub(super) fn set_metrics(&self, metrics: Metrics) {
        self.0.lock().expect("admission mutex").metrics = metrics;
    }
    pub(super) fn metrics(&self) -> Metrics {
        self.0.lock().expect("admission mutex").metrics
    }
    pub(super) fn failure(&self) -> Option<Error> {
        self.0.lock().expect("admission mutex").failure
    }
    fn fail(&self, error: Error) -> io::Error {
        self.0
            .lock()
            .expect("admission mutex")
            .failure
            .get_or_insert(error);
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

pub(super) struct Admission<S> {
    inner: BufReader<S>,
    control: Control,
    frame: Vec<u8>,
    output: Vec<u8>,
    offset: usize,
    line_start: usize,
    literal_remaining: usize,
    nesting: usize,
    kind: Option<Kind>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Other,
    List,
    Fetch,
}
impl<S> std::fmt::Debug for Admission<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission").finish_non_exhaustive()
    }
}
impl<S: AsyncRead> Admission<S> {
    pub(super) fn new(stream: S, limits: Limits, metrics: Metrics) -> (Self, Control) {
        let control = Control(Arc::new(Mutex::new(State {
            limits,
            metrics,
            contract: FrameContract::Other,
            failure: None,
        })));
        let initial_capacity = BUFFER_BYTES.min(
            control
                .0
                .lock()
                .expect("admission mutex")
                .limits
                .max_response_bytes,
        );
        (
            Self {
                inner: BufReader::with_capacity(BUFFER_BYTES, stream),
                control: control.clone(),
                frame: Vec::with_capacity(initial_capacity),
                output: Vec::new(),
                offset: 0,
                line_start: 0,
                literal_remaining: 0,
                nesting: 0,
                kind: None,
            },
            control,
        )
    }
    pub(super) fn is_empty(&self) -> bool {
        self.inner.buffer().is_empty() && self.frame.is_empty() && self.offset == self.output.len()
    }
    pub(super) fn into_inner(self) -> S {
        self.inner.into_inner()
    }
    fn line(&mut self) -> Result<bool, Error> {
        let line = &self.frame[self.line_start..];
        if !line.ends_with(b"\r\n") {
            return Err(Error::Protocol);
        }
        let syntax = &line[..line.len() - 2];
        if self.kind.is_none() {
            self.kind = Some(classify(syntax));
        }
        let data = self.kind != Some(Kind::Other);
        let mut quoted = false;
        let mut escaped = false;
        let mut announcement = None;
        for (index, &byte) in syntax.iter().enumerate() {
            if matches!(byte, b'\r' | b'\n' | 0) {
                return Err(Error::Protocol);
            }
            if escaped {
                if !matches!(byte, b'\\' | b'"') {
                    return Err(Error::Protocol);
                }
                escaped = false;
            } else if quoted && byte == b'\\' {
                escaped = true;
            } else if byte == b'"' && data {
                quoted = !quoted;
            } else if !quoted && data {
                match byte {
                    b'(' => {
                        self.nesting += 1;
                        if self.nesting > MAX_PROTOCOL_NESTING {
                            return Err(Error::Limit);
                        }
                    }
                    b')' => {
                        self.nesting = self.nesting.checked_sub(1).ok_or(Error::Protocol)?;
                    }
                    b'{' if syntax.last() == Some(&b'}') => {
                        let digits = &syntax[index + 1..syntax.len() - 1];
                        if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) {
                            announcement = Some(decimal(digits).ok_or(Error::Limit)?);
                        }
                    }
                    _ => {}
                }
            }
        }
        if quoted || escaped {
            return Err(Error::Protocol);
        }
        if !data {
            admit_other(syntax)?;
        }
        if let Some(length) = announcement {
            let mut state = self.control.0.lock().expect("admission mutex");
            let body_limit = match state.contract {
                FrameContract::Body { count, .. } => count,
                _ => usize::MAX,
            };
            if length > state.limits.max_literal_bytes
                || length > body_limit
                || length
                    > state
                        .limits
                        .max_response_bytes
                        .saturating_sub(self.frame.len())
                || length
                    > state
                        .limits
                        .max_operation_bytes
                        .saturating_sub(state.metrics.wire_bytes)
                        .saturating_sub(state.metrics.append_wire_bytes)
            {
                return Err(Error::Limit);
            }
            state.metrics.max_literal_bytes = state.metrics.max_literal_bytes.max(length);
            self.literal_remaining = length;
            self.line_start = self.frame.len();
            Ok(false)
        } else {
            Ok(true)
        }
    }
    fn finish(&mut self) -> Result<(), Error> {
        let mut state = self.control.0.lock().expect("admission mutex");
        charge(&mut state, self.frame.len().saturating_mul(3))?;
        self.output = normalize(
            &self.frame,
            self.kind.unwrap_or(Kind::Other),
            &state.contract,
            &state.limits,
        )?;
        if self.output.len() > self.frame.len() {
            charge(&mut state, self.output.len() - self.frame.len())?;
        }
        self.frame.clear();
        if self.frame.capacity() > 32 * 1024 {
            self.frame = Vec::new();
        }
        self.line_start = 0;
        self.nesting = 0;
        self.literal_remaining = 0;
        self.kind = None;
        self.offset = 0;
        Ok(())
    }
}
fn charge(state: &mut State, steps: usize) -> Result<(), Error> {
    if steps
        > state
            .limits
            .max_parser_steps
            .saturating_sub(state.metrics.parser_steps)
    {
        return Err(Error::Limit);
    }
    state.metrics.parser_steps += steps;
    Ok(())
}
impl<S: AsyncRead + Unpin> AsyncRead for Admission<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = this.control.failure() {
            return Poll::Ready(Err(this.control.fail(error)));
        }
        while this.offset == this.output.len() {
            let available = match Pin::new(&mut this.inner).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    let failure = if error.kind() == io::ErrorKind::UnexpectedEof {
                        Error::Eof
                    } else {
                        Error::Transport
                    };
                    return Poll::Ready(Err(this.control.fail(failure)));
                }
                Poll::Ready(Ok([])) => return Poll::Ready(Err(this.control.fail(Error::Eof))),
                Poll::Ready(Ok(available)) => available,
            };
            let literal = this.literal_remaining != 0;
            let desired = if literal {
                available.len().min(this.literal_remaining)
            } else {
                available
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(available.len(), |p| p + 1)
            };
            let mut state = this.control.0.lock().expect("admission mutex");
            if this.frame.is_empty() && this.kind.is_none() {
                if state.metrics.responses >= state.limits.max_responses {
                    drop(state);
                    return Poll::Ready(Err(this.control.fail(Error::Limit)));
                }
                state.metrics.responses += 1;
            }
            let count = desired
                .min(
                    state
                        .limits
                        .max_response_bytes
                        .saturating_sub(this.frame.len()),
                )
                .min(
                    state
                        .limits
                        .max_operation_bytes
                        .saturating_sub(state.metrics.wire_bytes)
                        .saturating_sub(state.metrics.append_wire_bytes),
                )
                .min(
                    state
                        .limits
                        .max_parser_steps
                        .saturating_sub(state.metrics.parser_steps),
                );
            if count == 0 {
                drop(state);
                return Poll::Ready(Err(this.control.fail(Error::Limit)));
            }
            if let Err(error) = extend(
                &mut this.frame,
                &available[..count],
                state.limits.max_response_bytes,
            ) {
                drop(state);
                return Poll::Ready(Err(this.control.fail(error)));
            }
            state.metrics.wire_bytes += count;
            state.metrics.parser_steps += count;
            state.metrics.max_response_bytes =
                state.metrics.max_response_bytes.max(this.frame.len());
            drop(state);
            Pin::new(&mut this.inner).consume(count);
            if literal {
                this.literal_remaining -= count;
                if this.literal_remaining == 0 {
                    this.line_start = this.frame.len();
                }
            } else if this.frame.last() == Some(&b'\n') {
                let completed = match this.line() {
                    Ok(done) => done,
                    Err(error) => return Poll::Ready(Err(this.control.fail(error))),
                };
                if completed && let Err(error) = this.finish() {
                    return Poll::Ready(Err(this.control.fail(error)));
                }
            }
        }
        let count = output.remaining().min(this.output.len() - this.offset);
        output.put_slice(&this.output[this.offset..this.offset + count]);
        this.offset += count;
        if this.offset == this.output.len() && this.output.capacity() > 32 * 1024 {
            this.output = Vec::new();
            this.offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Admission<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().inner.get_mut()).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().inner.get_mut()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().inner.get_mut()).poll_shutdown(cx)
    }
}
fn classify(line: &[u8]) -> Kind {
    if line
        .get(..7)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"* LIST "))
    {
        return Kind::List;
    }
    if let Some(rest) = line.strip_prefix(b"* ") {
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0
            && rest
                .get(digits..digits + 8)
                .is_some_and(|v| v.eq_ignore_ascii_case(b" FETCH ("))
        {
            return Kind::Fetch;
        }
    }
    Kind::Other
}
// Unsupported response kinds are rejected before the client sees them: even a
// response that the operation would later refuse (for example LSUB or STATUS)
// could otherwise announce a large literal to the client's parser.
fn admit_other(line: &[u8]) -> Result<(), Error> {
    if !line.is_ascii() {
        return Err(Error::Unsupported);
    }
    let status_text = if let Some(text) = line.strip_prefix(b"+") {
        Some(text.strip_prefix(b" ").unwrap_or(text))
    } else {
        let mut words = line.splitn(3, |b| *b == b' ');
        let first = words.next().ok_or(Error::Protocol)?;
        let second = words.next().ok_or(Error::Protocol)?;
        let rest = words.next().unwrap_or_default();
        if [b"OK".as_slice(), b"NO", b"BAD", b"BYE", b"PREAUTH"]
            .iter()
            .any(|status| second.eq_ignore_ascii_case(status))
        {
            Some(rest)
        } else if first == b"*"
            && ([b"CAPABILITY".as_slice(), b"FLAGS", b"SEARCH"]
                .iter()
                .any(|name| second.eq_ignore_ascii_case(name))
                || (decimal(second).is_some()
                    && [b"EXISTS".as_slice(), b"RECENT", b"EXPUNGE"]
                        .iter()
                        .any(|name| rest.eq_ignore_ascii_case(name))))
        {
            None
        } else {
            return Err(Error::Unsupported);
        }
    };
    // BADCHARSET's optional list is the only supported status-code grammar
    // containing strings/literals. These operations do not consume that list;
    // reject the code instead of interpreting human response text as literals.
    if status_text.is_some_and(|text| {
        text.get(..11)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"[BADCHARSET"))
    }) {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0usize, |n, b| {
        if b.is_ascii_digit() {
            n.checked_mul(10)?.checked_add((b - b'0') as usize)
        } else {
            None
        }
    })
}

#[derive(Clone, Copy)]
enum TokenKind {
    Atom,
    Quoted { escaped: bool },
    Literal,
    Punctuation(u8),
}
struct Token<'a> {
    start: usize,
    end: usize,
    data: &'a [u8],
    kind: TokenKind,
}
struct Scanner<'a> {
    frame: &'a [u8],
    position: usize,
}
impl<'a> Scanner<'a> {
    fn next(&mut self) -> Result<Option<Token<'a>>, Error> {
        while self
            .frame
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
        let start = self.position;
        let Some(&byte) = self.frame.get(start) else {
            return Ok(None);
        };
        let (data, kind) = match byte {
            b'(' | b')' | b'[' | b']' => {
                self.position += 1;
                (
                    &self.frame[start..self.position],
                    TokenKind::Punctuation(byte),
                )
            }
            b'"' => {
                self.position += 1;
                let mut escaped = false;
                loop {
                    match self.frame.get(self.position) {
                        Some(b'"') => break,
                        Some(b'\\') => {
                            escaped = true;
                            self.position += 1;
                            if !matches!(self.frame.get(self.position), Some(b'\\' | b'"')) {
                                return Err(Error::Protocol);
                            }
                        }
                        Some(b'\r' | b'\n' | 0) | None => return Err(Error::Protocol),
                        _ => {}
                    }
                    self.position += 1;
                }
                self.position += 1;
                (
                    &self.frame[start + 1..self.position - 1],
                    TokenKind::Quoted { escaped },
                )
            }
            b'{' => {
                let digits = self.frame[start + 1..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                let close = start + 1 + digits;
                if self.frame.get(close) != Some(&b'}') {
                    return Err(Error::Protocol);
                }
                let length = decimal(&self.frame[start + 1..close]).ok_or(Error::Protocol)?;
                if self.frame.get(close + 1..close + 3) != Some(b"\r\n") {
                    return Err(Error::Protocol);
                }
                self.position = close
                    .checked_add(3)
                    .and_then(|p| p.checked_add(length))
                    .ok_or(Error::Limit)?;
                let data = self
                    .frame
                    .get(close + 3..self.position)
                    .ok_or(Error::Protocol)?;
                (data, TokenKind::Literal)
            }
            _ => {
                self.position += 1;
                while self.frame.get(self.position).is_some_and(|b| {
                    !b.is_ascii_whitespace()
                        && !matches!(b, b'(' | b')' | b'[' | b']' | b'{' | b'"')
                }) {
                    self.position += 1;
                }
                (&self.frame[start..self.position], TokenKind::Atom)
            }
        };
        Ok(Some(Token {
            start,
            end: self.position,
            data,
            kind,
        }))
    }
}
fn normalize(
    frame: &[u8],
    kind: Kind,
    contract: &FrameContract,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    if kind == Kind::Other {
        return Ok(frame.to_vec());
    }
    let mut scanner = Scanner { frame, position: 0 };
    let mut output = Vec::with_capacity(frame.len());
    let mut copied = 0;
    let mut depth = 0usize;
    let mut attr = &b""[..];
    let mut list_stage = 0;
    let mut payload = false;
    let mut body_seen = false;
    while let Some(token) = scanner.next()? {
        let mut convert = false;
        let mut metadata = true;
        match kind {
            Kind::List => match token.kind {
                TokenKind::Punctuation(b'(') if list_stage == 0 => {
                    list_stage = 1;
                    depth += 1;
                }
                TokenKind::Punctuation(b'(') => depth += 1,
                TokenKind::Punctuation(b')') => {
                    depth = depth.checked_sub(1).ok_or(Error::Protocol)?;
                    if depth == 0 && list_stage == 1 {
                        list_stage = 2;
                    }
                }
                _ if list_stage == 2 => {
                    match token.kind {
                        TokenKind::Quoted { escaped: false } => {}
                        TokenKind::Atom if token.data.eq_ignore_ascii_case(b"NIL") => {}
                        TokenKind::Quoted { escaped: true } => return Err(Error::Unsupported),
                        _ => return Err(Error::Protocol),
                    }
                    list_stage = 3;
                }
                _ if list_stage == 3 => {
                    convert = true;
                    list_stage = 4;
                }
                _ if list_stage >= 4 => return Err(Error::Protocol),
                _ => {}
            },
            Kind::Fetch => {
                match token.kind {
                    TokenKind::Punctuation(b'(') => {
                        depth += 1;
                    }
                    TokenKind::Punctuation(b')') => {
                        depth = depth.checked_sub(1).ok_or(Error::Protocol)?;
                    }
                    TokenKind::Atom if depth == 1 => {
                        if token.data.eq_ignore_ascii_case(b"INTERNALDATE") {
                            let date = scanner.next()?.ok_or(Error::Protocol)?;
                            // imap-proto accepts nstring here and unwraps NIL.
                            // RFC 3501 requires a quoted date-time instead.
                            if !matches!(date.kind, TokenKind::Quoted { escaped: false })
                                || !date.data.is_ascii()
                            {
                                return Err(Error::Protocol);
                            }
                            attr = b"INTERNALDATE";
                            continue;
                        }
                        if token.data.eq_ignore_ascii_case(b"BODY")
                            && frame.get(token.end) == Some(&b'[')
                        {
                            if body_seen {
                                return Err(Error::Protocol);
                            }
                            body_seen = true;
                            let FrameContract::Body {
                                section, offset, ..
                            } = contract
                            else {
                                return Err(Error::Protocol);
                            };
                            let end = token
                                .end
                                .checked_add(1)
                                .and_then(|p| p.checked_add(section.len()))
                                .ok_or(Error::Limit)?;
                            if frame.get(end) != Some(&b']')
                                || !frame.get(token.end + 1..end).is_some_and(|actual| {
                                    actual.eq_ignore_ascii_case(section.as_bytes())
                                })
                            {
                                return Err(Error::Protocol);
                            }
                            let origin_start = end + 1;
                            if frame.get(origin_start) != Some(&b'<') {
                                return Err(Error::Protocol);
                            }
                            let digits = frame[origin_start + 1..]
                                .iter()
                                .take_while(|b| b.is_ascii_digit())
                                .count();
                            let origin_end = origin_start + 1 + digits;
                            if frame.get(origin_end) != Some(&b'>') {
                                return Err(Error::Protocol);
                            }
                            if decimal(&frame[origin_start + 1..origin_end])
                                != Some(*offset as usize)
                            {
                                return Err(Error::Protocol);
                            }
                            scanner.position = origin_end + 1;
                            // Provider quirk: accept the omitted SP only immediately before
                            // a literal in the exact requested partial BODY field.
                            if frame.get(scanner.position) == Some(&b'{') {
                                extend(
                                    &mut output,
                                    &frame[copied..scanner.position],
                                    limits.max_response_bytes,
                                )?;
                                extend(&mut output, b" ", limits.max_response_bytes)?;
                                copied = scanner.position;
                            } else if frame.get(scanner.position) != Some(&b' ') {
                                return Err(Error::Protocol);
                            }
                            payload = true;
                            attr = b"BODY[]";
                        } else {
                            attr = token.data;
                        }
                    }
                    TokenKind::Quoted { .. } | TokenKind::Literal => {
                        if payload {
                            metadata = false;
                            let FrameContract::Body { count, .. } = contract else {
                                return Err(Error::Protocol);
                            };
                            let length = match token.kind {
                                TokenKind::Quoted { escaped: true } => unescaped_len(token.data),
                                _ => token.data.len(),
                            };
                            if length > *count {
                                return Err(Error::Limit);
                            }
                            convert = true;
                            payload = false;
                        } else {
                            convert = attr.eq_ignore_ascii_case(b"ENVELOPE")
                                || attr.eq_ignore_ascii_case(b"BODYSTRUCTURE")
                                || attr.eq_ignore_ascii_case(b"BODY");
                        }
                    }
                    _ => {}
                }
            }
            Kind::Other => unreachable!(),
        }
        if metadata {
            match token.kind {
                TokenKind::Quoted { .. } | TokenKind::Literal => {
                    std::str::from_utf8(token.data).map_err(|_| Error::Unsupported)?;
                }
                _ if !token.data.is_ascii() => return Err(Error::Unsupported),
                _ => {}
            }
        }
        if convert && matches!(token.kind, TokenKind::Quoted { escaped: true }) {
            extend(
                &mut output,
                &frame[copied..token.start],
                limits.max_response_bytes,
            )?;
            let length = unescaped_len(token.data);
            if length > limits.max_literal_bytes {
                return Err(Error::Limit);
            }
            extend(
                &mut output,
                format!("{{{length}}}\r\n").as_bytes(),
                limits.max_response_bytes,
            )?;
            reserve(&mut output, length, limits.max_response_bytes)?;
            let mut i = 0;
            while i < token.data.len() {
                if token.data[i] == b'\\' {
                    i += 1;
                }
                output.push(token.data[i]);
                i += 1;
            }
            copied = token.end;
            if output.len() > limits.max_response_bytes {
                return Err(Error::Limit);
            }
        }
    }
    extend(&mut output, &frame[copied..], limits.max_response_bytes)?;
    if output.len() > limits.max_response_bytes {
        return Err(Error::Limit);
    }
    Ok(output)
}

fn unescaped_len(bytes: &[u8]) -> usize {
    let mut length = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 1;
        }
        length += 1;
        index += 1;
    }
    length
}
fn reserve(output: &mut Vec<u8>, additional: usize, maximum: usize) -> Result<(), Error> {
    let needed = output.len().checked_add(additional).ok_or(Error::Limit)?;
    if needed > maximum {
        return Err(Error::Limit);
    }
    if needed > output.capacity() {
        let capacity = output
            .capacity()
            .max(BUFFER_BYTES)
            .saturating_mul(2)
            .max(needed)
            .min(maximum);
        output
            .try_reserve_exact(capacity - output.len())
            .map_err(|_| Error::Limit)?;
    }
    Ok(())
}
fn extend(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), Error> {
    reserve(output, bytes.len(), maximum)?;
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::TryStreamExt;
    use std::task::Poll;

    struct Fixture {
        bytes: Vec<u8>,
        offset: usize,
        chunk: usize,
        pending: bool,
    }
    impl Fixture {
        fn new(response: &[u8]) -> Self {
            Self {
                bytes: response.to_vec(),
                offset: 0,
                chunk: usize::MAX,
                pending: false,
            }
        }
        fn authenticated(response: &[u8]) -> Self {
            let mut bytes = b"A0001 OK authenticated\r\n".to_vec();
            bytes.extend_from_slice(response);
            bytes.extend_from_slice(b"A0002 OK complete\r\n");
            Self::new(&bytes)
        }
    }
    impl AsyncRead for Fixture {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let count = buffer
                .remaining()
                .min(self.chunk)
                .min(self.bytes.len() - self.offset);
            buffer.put_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            self.pending = self.chunk != usize::MAX;
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Fixture {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    fn body_contract(section: &str, count: usize) -> FrameContract {
        FrameContract::Body {
            section: section.to_owned(),
            offset: 0,
            count,
        }
    }
    async fn fetch(response: &[u8], section: &str) -> Result<Vec<u8>, Error> {
        let (wire, control) = Admission::new(
            Fixture::authenticated(response),
            Limits::default(),
            Metrics::default(),
        );
        let mut session = async_imap::Client::new(wire)
            .login("fixture", "disposable")
            .await
            .map_err(|_| Error::Protocol)?;
        control.configure(Limits::default(), body_contract(section, 128));
        let mut rows = session
            .uid_fetch("4", format!("(UID BODY.PEEK[{section}]<0.128>)"))
            .await
            .map_err(|_| Error::Protocol)?;
        let row = rows
            .try_next()
            .await
            .map_err(|_| control.failure().unwrap_or(Error::Protocol))?
            .ok_or(Error::Protocol)?;
        let bytes = if section == "HEADER" {
            row.header()
        } else {
            row.section(&imap_proto::SectionPath::Part(vec![2], None))
        };
        bytes.map(<[u8]>::to_vec).ok_or(Error::Protocol)
    }
    async fn list(response: &[u8]) -> Result<String, Error> {
        let (wire, control) = Admission::new(
            Fixture::authenticated(response),
            Limits::default(),
            Metrics::default(),
        );
        let mut session = async_imap::Client::new(wire)
            .login("fixture", "disposable")
            .await
            .map_err(|_| Error::Protocol)?;
        control.configure(Limits::default(), FrameContract::List);
        let mut rows = session
            .list(Some(""), Some("*"))
            .await
            .map_err(|_| Error::Protocol)?;
        rows.try_next()
            .await
            .map_err(|_| control.failure().unwrap_or(Error::Protocol))?
            .map(|row| row.name().to_owned())
            .ok_or(Error::Protocol)
    }
    #[tokio::test]
    async fn published_client_preserves_escaped_strings_without_colliding_with_literals() {
        let quoted = fetch(b"* 1 FETCH (UID 4 BODY[2]<0> \"a\\\\b\\\"c\")\r\n", "2")
            .await
            .unwrap();
        let same = fetch(b"* 1 FETCH (UID 4 BODY[2]<0> {5}\r\na\\b\"c)\r\n", "2")
            .await
            .unwrap();
        let different = fetch(b"* 1 FETCH (UID 4 BODY[2]<0> {6}\r\na\\\\b\"c)\r\n", "2")
            .await
            .unwrap();
        assert_eq!(quoted, b"a\\b\"c");
        assert_eq!(quoted, same);
        assert_ne!(quoted, different);
        assert_eq!(
            list(b"* LIST () \"/\" \"a\\\\b\\\"c\"\r\n").await.unwrap(),
            "a\\b\"c"
        );
        assert_eq!(
            list(b"* LIST () \"/\" {5}\r\na\\b\"c\r\n").await.unwrap(),
            "a\\b\"c"
        );
        assert_eq!(
            list(b"* LIST () \"/\" {6}\r\na\\\\b\"c\r\n").await.unwrap(),
            "a\\\\b\"c"
        );
    }
    #[tokio::test]
    async fn published_client_preserves_envelope_and_structure_strings() {
        let response = b"* 1 FETCH (UID 4 INTERNALDATE \"16-Oct-2026 12:00:00 +0000\" ENVELOPE (NIL \"a\\\\b\" NIL NIL NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"INTERNALDATE\" \"a\\\\b\" \"BODYSTRUCTURE\" \"c\\\\d\") NIL NIL \"7BIT\" 3 1))\r\n";
        let (wire, control) = Admission::new(
            Fixture::authenticated(response),
            Limits::default(),
            Metrics::default(),
        );
        let mut session = async_imap::Client::new(wire)
            .login("fixture", "disposable")
            .await
            .map_err(|e| e.0)
            .unwrap();
        control.configure(Limits::default(), FrameContract::Metadata);
        let mut rows = session
            .uid_fetch("4", "(UID INTERNALDATE ENVELOPE BODYSTRUCTURE)")
            .await
            .unwrap();
        let row = rows.try_next().await.unwrap().unwrap();
        assert!(row.internal_date().is_some());
        assert_eq!(
            row.envelope().unwrap().subject.as_deref(),
            Some(&b"a\\b"[..])
        );
        let imap_proto::BodyStructure::Text { common, .. } = row.bodystructure().unwrap() else {
            panic!("expected text body");
        };
        let parameters = common.ty.params.as_ref().unwrap();
        assert_eq!(parameters[0].0, "INTERNALDATE");
        assert_eq!(parameters[0].1, "a\\b");
        assert_eq!(parameters[1].0, "BODYSTRUCTURE");
        assert_eq!(parameters[1].1, "c\\d");
    }
    #[tokio::test]
    async fn binary_literal_payload_has_no_syntax_meaning() {
        let payload = b"\xff\0\"\\BODY[HEADER.FIELDS (X)]\r\n(\n";
        let mut response =
            format!("* 1 FETCH (UID 4 BODY[2]<0> {{{}}}\r\n", payload.len()).into_bytes();
        response.extend_from_slice(payload);
        response.extend_from_slice(b")\r\n");
        assert_eq!(fetch(&response, "2").await.unwrap(), payload);
        assert_eq!(
            fetch(b"* 1 FETCH (UID 4 BODY[2]<0>{3}\r\na\\b)\r\n", "2")
                .await
                .unwrap(),
            b"a\\b"
        );
    }
    #[tokio::test]
    async fn original_sections_reject_before_the_published_parser_erases_identity() {
        for response in [
            &b"* 1 FETCH (UID 4 BODY[HEADER.FIELDS (X)]<0> {6}\r\nX: y\r\n)\r\n"[..],
            &b"* 1 FETCH (UID 4 BODY[HEADER.FIELDS.NOT (X)]<0> {6}\r\nX: y\r\n)\r\n"[..],
            &b"* 1 FETCH (UID 4 BODY[HEADER]<1> {6}\r\nX: y\r\n)\r\n"[..],
            &b"* 1 FETCH (UID 4 BODY[HEADER]<0> {0}\r\n BODY[HEADER]<0> {0}\r\n)\r\n"[..],
        ] {
            assert_eq!(fetch(response, "HEADER").await, Err(Error::Protocol));
        }
        assert_eq!(
            fetch(
                b"* 1 FETCH (UID 4 BODY[HEADER]<0> {6}\r\nX: y\r\n)\r\n",
                "HEADER"
            )
            .await
            .unwrap(),
            b"X: y\r\n"
        );
    }
    #[tokio::test]
    async fn huge_literal_announcement_never_reaches_client_parser() {
        let announcement = b"* 1 FETCH (UID 4 BODY[2]<0> {8388608}\r\n";
        let (wire, control) = Admission::new(
            Fixture::new(announcement),
            Limits::default(),
            Metrics::default(),
        );
        control.configure(Limits::default(), body_contract("2", 128));
        let mut client = async_imap::Client::new(wire);
        assert!(client.read_response().await.is_err());
        assert_eq!(control.failure(), Some(Error::Limit));
        assert_eq!(control.metrics().wire_bytes, announcement.len());
        assert_eq!(control.metrics().max_literal_bytes, 0);
        assert!(client.get_ref().output.is_empty());
        assert!(client.get_ref().frame.capacity() <= BUFFER_BYTES);
    }
    #[tokio::test]
    async fn unsupported_response_literals_cannot_trigger_client_reservation() {
        for input in [
            b"* LSUB () \"/\" {8388608}\r\n".as_slice(),
            b"* STATUS {8388608}\r\n",
            b"* ID ({8388608}\r\n",
            b"M1 NO [BADCHARSET ({8388608}\r\n",
            b"+ [BADCHARSET ({8388608}\r\n",
        ] {
            let (wire, control) =
                Admission::new(Fixture::new(input), Limits::default(), Metrics::default());
            let mut client = async_imap::Client::new(wire);
            assert!(client.read_response().await.is_err());
            assert_eq!(control.failure(), Some(Error::Unsupported));
            assert!(client.get_ref().output.is_empty());
            assert!(client.get_ref().frame.capacity() <= BUFFER_BYTES);
        }
    }
    #[tokio::test]
    async fn fragmented_and_pending_reads_count_one_response() {
        let mut fixture = Fixture::new(b"* OK ready\r\n");
        fixture.chunk = 1;
        fixture.pending = true;
        let (wire, control) = Admission::new(fixture, Limits::default(), Metrics::default());
        let mut client = async_imap::Client::new(wire);
        client.read_response().await.unwrap().unwrap();
        assert_eq!(control.metrics().responses, 1);
        assert_eq!(control.metrics().wire_bytes, b"* OK ready\r\n".len());
    }
    #[tokio::test]
    async fn status_text_is_not_literal_or_quoted_string_syntax() {
        let input = b"* OK human (text \\\" {8388608}\r\n";
        let (wire, control) =
            Admission::new(Fixture::new(input), Limits::default(), Metrics::default());
        let mut client = async_imap::Client::new(wire);
        let response = client.read_response().await.unwrap().unwrap();
        let imap_proto::Response::Data { outcome, .. } = response.parsed() else {
            panic!("expected status");
        };
        assert_eq!(
            outcome.information.as_deref(),
            Some("human (text \\\" {8388608}")
        );
        assert_eq!(control.metrics().max_literal_bytes, 0);
    }
    #[tokio::test]
    async fn unsupported_metadata_is_rejected_without_lossy_replacement() {
        assert_eq!(
            list(b"* LIST () \"/\" {1}\r\n\xff\r\n").await,
            Err(Error::Unsupported)
        );
        assert_eq!(
            list(b"* LIST () \"\\\\\" \"Drafts\"\r\n").await,
            Err(Error::Unsupported)
        );
        assert_eq!(
            list(b"* LIST () \"/\" \"bad\\q\"\r\n").await,
            Err(Error::Protocol)
        );
    }
    #[tokio::test]
    async fn internal_date_requires_a_quoted_value_before_client_decoding() {
        for input in [
            b"* 1 FETCH (UID 4 INTERNALDATE NIL)\r\n".as_slice(),
            b"* 1 FETCH (UID 4 INTERNALDATE NILjunk)\r\n",
            b"* 1 FETCH (UID 4 INTERNALDATE {3}\r\nNIL)\r\n",
            b"* 1 FETCH (UID 4 INTERNALDATE \"bad\\\\date\")\r\n",
        ] {
            assert_eq!(
                rejected(input, Limits::default(), FrameContract::Metadata).await,
                Error::Protocol
            );
        }
    }
    async fn rejected(input: &[u8], limits: Limits, contract: FrameContract) -> Error {
        let (wire, control) =
            Admission::new(Fixture::new(input), limits.clone(), Metrics::default());
        control.configure(limits, contract);
        assert!(async_imap::Client::new(wire).read_response().await.is_err());
        control.failure().unwrap()
    }
    #[tokio::test]
    async fn lexical_and_resource_limits_apply_before_typed_parsing() {
        assert_eq!(
            rejected(b"* OK bare LF\n", Limits::default(), FrameContract::Other).await,
            Error::Protocol
        );
        assert_eq!(
            rejected(
                b"* OK nonASCII \xff\r\n",
                Limits::default(),
                FrameContract::Other
            )
            .await,
            Error::Unsupported
        );
        let mut deeply_nested = b"* 1 FETCH (BODYSTRUCTURE ".to_vec();
        deeply_nested.extend(std::iter::repeat_n(b'(', MAX_PROTOCOL_NESTING));
        deeply_nested.extend_from_slice(b"\r\n");
        assert_eq!(
            rejected(&deeply_nested, Limits::default(), FrameContract::Metadata).await,
            Error::Limit
        );
        for limits in [
            Limits {
                max_response_bytes: 8,
                ..Limits::default()
            },
            Limits {
                max_operation_bytes: 8,
                ..Limits::default()
            },
            Limits {
                max_parser_steps: 8,
                ..Limits::default()
            },
            Limits {
                max_responses: 0,
                ..Limits::default()
            },
        ] {
            assert_eq!(
                rejected(b"* OK ready\r\n", limits, FrameContract::Other).await,
                Error::Limit
            );
        }
        // Quoted-to-literal normalization has its own bounded output allocation.
        let input = b"* LIST () \"/\" \"\\\\\"\r\n";
        assert_eq!(
            rejected(
                input,
                Limits {
                    max_response_bytes: input.len(),
                    ..Limits::default()
                },
                FrameContract::List
            )
            .await,
            Error::Limit
        );
        assert_eq!(
            rejected(
                b"* 1 FETCH (UID 4 BODY[2]<0> \"\\\"\\\"\")\r\n",
                Limits::default(),
                body_contract("2", 1)
            )
            .await,
            Error::Limit
        );
    }
}
