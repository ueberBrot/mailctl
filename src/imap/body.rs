//! A bounded body read owns selection, byte retrieval, representation, and continuation.
mod representation;

use super::{Error, ImapProbe, Limits, Metrics, credentials, mailbox, wire::Connection};
use io_imap::{
    rfc3501::{
        fetch::{ImapMessageFetch, ImapMessageFetchOptions},
        logout::ImapLogout,
    },
    types::{
        body::{Body, BodyStructure, Disposition, SpecificFields},
        command::CommandBody,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Part, Section},
        sequence::{SeqOrUid, Sequence, SequenceSet},
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt::{self, Write},
    num::NonZeroU32,
    time::Instant,
};

/// In-memory continuation for this route proof. Public authenticated tokens belong to
/// the application reading contract. A continuation is revalidated after each fetch.
#[derive(Clone, Debug)]
pub struct BodyCursor {
    fingerprint: [u8; 32],
    offset: usize,
}

#[derive(Clone, Debug)]
pub struct BodyRequest {
    pub uid: u32,
    pub uid_validity: u32,
    pub continuation: Option<BodyCursor>,
}
impl BodyRequest {
    pub fn new(uid: u32, uid_validity: u32) -> Self {
        Self {
            uid,
            uid_validity,
            continuation: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BodyPage {
    pub text: String,
    pub selected_part: Option<String>,
    pub source_media_type: Option<String>,
    pub representation_version: &'static str,
    pub converted: bool,
    pub replacements: bool,
    pub truncated: bool,
    pub continuation: Option<BodyCursor>,
    pub metrics: Metrics,
}

/// A metadata-only attachment locator. Its part identifier is safe to retain in a message
/// reference; it is not a transfer credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentListRequest {
    pub uid: u32,
    pub uid_validity: u32,
}
impl AttachmentListRequest {
    pub fn new(uid: u32, uid_validity: u32) -> Self {
        Self { uid, uid_validity }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentMetadata {
    pub part: String,
    pub filename: Option<String>,
    pub media_type: String,
    /// The transfer-encoded size reported by BODYSTRUCTURE, when the server supplied one.
    pub declared_size: Option<u64>,
    pub available: bool,
}

#[derive(Clone, Debug)]
pub struct AttachmentList {
    pub attachments: Vec<AttachmentMetadata>,
    pub metrics: Metrics,
}

/// Starts a transfer from an attachment part, or consumes a continuation issued by this probe.
/// The continuation constructor intentionally carries no caller-controlled message identity.
#[derive(Debug)]
pub struct AttachmentRequest {
    start: Option<(u32, u32, String)>,
    transfer: Option<AttachmentTransfer>,
}
impl AttachmentRequest {
    pub fn new(uid: u32, uid_validity: u32, part: impl Into<String>) -> Self {
        Self {
            start: Some((uid, uid_validity, part.into())),
            transfer: None,
        }
    }
    pub fn resume(transfer: AttachmentTransfer) -> Self {
        Self {
            start: None,
            transfer: Some(transfer),
        }
    }
}

/// An opaque, probe-session-local transfer capability. It is deliberately non-cloneable: a
/// continuation or cancellation consumes ownership of the admitted in-memory decoder state.
pub struct AttachmentTransfer {
    value: String,
}
impl fmt::Debug for AttachmentTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachmentTransfer(..)")
    }
}

#[derive(Debug)]
pub struct AttachmentChunk {
    pub bytes: Vec<u8>,
    pub decoded_offset: u64,
    pub complete: bool,
    pub continuation: Option<AttachmentTransfer>,
    pub total_decoded_bytes: Option<u64>,
    pub sha256: Option<[u8; 32]>,
    pub metrics: Metrics,
}

#[derive(Default)]
pub(super) struct TransferStore {
    entries: HashMap<String, TransferState>,
}
impl TransferStore {
    fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, state| state.expires > now);
    }
    fn remove(&mut self, token: AttachmentTransfer) -> Result<TransferState, Error> {
        self.prune();
        self.entries
            .remove(&token.value)
            .ok_or(Error::TransferExpired)
    }
    fn insert(&mut self, state: TransferState) -> Result<AttachmentTransfer, Error> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Transport)?;
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(value, "{byte:02x}");
        }
        if self.entries.insert(value.clone(), state).is_some() {
            return Err(Error::Transport);
        }
        Ok(AttachmentTransfer { value })
    }
}

struct TransferState {
    principal: [u8; 32],
    mailbox: String,
    uid: u32,
    uid_validity: u32,
    part: Part,
    encoding: TransferEncoding,
    wire_offset: usize,
    decoded_offset: usize,
    pending: Vec<u8>,
    base64: Vec<u8>,
    base64_padded: bool,
    quoted_printable: Vec<u8>,
    eof: bool,
    expires: Instant,
    digest: Sha256,
    wire_bytes: usize,
    decoded_bytes: usize,
    decode_steps: usize,
    max_state_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferEncoding {
    Identity,
    Base64,
    QuotedPrintable,
}

#[derive(Clone)]
struct AttachmentDefinition {
    part: Part,
    filename: Option<String>,
    media_type: String,
    declared_size: Option<u64>,
    encoding: Option<TransferEncoding>,
}

const REPRESENTATION: &str = "mailctl-body-1/mail-parser-0.11.8/html2text-0.17.1";

impl ImapProbe {
    /// Reads one selected body under an exclusive connection lease, checking the
    /// expected UIDVALIDITY before fetching. Cancellation disposes the connection.
    /// Each continuation refetches within the same finite bounds.
    pub async fn read_body(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: BodyRequest,
    ) -> Result<BodyPage, Error> {
        self.metrics = Metrics::default();
        credentials(username, password)?;
        mailbox(name)?;
        if request.uid == 0 || request.uid_validity == 0 {
            return Err(Error::InvalidInput);
        }
        let limits = self.limits.clone();
        let mut context = Sha256::new();
        for value in [self.host.as_str(), username, name, REPRESENTATION] {
            context.update(value.len().to_be_bytes());
            context.update(value.as_bytes());
        }
        context.update(self.port.to_be_bytes());
        context.update(request.uid.to_be_bytes());
        context.update(request.uid_validity.to_be_bytes());
        context.update(format!("{limits:?}").as_bytes());
        tokio::time::timeout(limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            if conn.examine(name).await? != request.uid_validity {
                return Err(Error::UnsafeSelection);
            }
            let metadata = Fetch::Metadata { uid: request.uid };
            let fields = metadata.execute(&mut conn).await?;
            let (size, structure) = metadata.metadata(&fields)?;
            // Validate every MIME node, including excluded attachment subtrees.
            let mut related_ids = HashMap::new();
            let needed_headers = representation::related_multipart_headers(structure, &limits)?;
            let mut header_bytes = 0;
            let root_headers = headers(
                &mut conn,
                request.uid,
                Section::Header(None),
                &limits,
                &mut header_bytes,
            )
            .await?;
            representation::validate_headers(&root_headers, None, &limits)?;
            for path in needed_headers {
                let raw = headers(
                    &mut conn,
                    request.uid,
                    Section::Mime(path.clone()),
                    &limits,
                    &mut header_bytes,
                )
                .await?;
                if let Some(id) = representation::validate_headers(&raw, None, &limits)? {
                    related_ids.insert(path, id);
                }
            }
            let selected = representation::select(structure, &limits, &related_ids)?;
            let rendered = if let Some(selected) = &selected {
                if selected.wire_size > limits.max_body_wire_bytes {
                    return Err(Error::Limit);
                }
                let single = matches!(structure, BodyStructure::Single { .. });
                if single {
                    representation::validate_headers(&root_headers, Some(selected), &limits)?;
                }
                let (raw, body_offset) = if single && size as usize <= limits.max_body_wire_bytes {
                    let whole = bytes(
                        &mut conn,
                        request.uid,
                        None,
                        Some(size as usize),
                        limits.max_body_wire_bytes,
                        &limits,
                    )
                    .await?;
                    if !whole.starts_with(&root_headers)
                        || whole.len() - root_headers.len() > selected.wire_size
                    {
                        return Err(Error::Protocol);
                    }
                    (whole, root_headers.len())
                } else {
                    (
                        bytes(
                            &mut conn,
                            request.uid,
                            Some(Section::Part(selected.part.clone())),
                            Some(selected.wire_size),
                            limits.max_body_wire_bytes,
                            &limits,
                        )
                        .await?,
                        0,
                    )
                };
                let body = &raw[body_offset..];
                context.update(body);
                tokio::task::yield_now().await;
                Some(representation::render(selected, body, &limits)?)
            } else {
                None
            };
            conn.drive(ImapLogout::new()).await?;
            let mut metrics = conn.metrics();
            drop(conn);
            let (text, converted, replacements) = if let Some(rendered) = rendered {
                metrics.decode_steps = rendered.work;
                metrics.decoded_bytes = rendered.text.len();
                (rendered.text, rendered.converted, rendered.replacements)
            } else {
                (String::new(), false, false)
            };
            self.metrics = metrics;
            let selected_part = selected.as_ref().map(|selected| {
                let name = part_name(&selected.part);
                context.update(name.as_bytes());
                context.update(selected.media_type.as_bytes());
                context.update(selected.charset.as_bytes());
                context.update(selected.transfer_encoding.as_bytes());
                name
            });
            context.update(text.as_bytes());
            let fingerprint = context.finalize().into();
            let offset = match request.continuation {
                Some(cursor)
                    if cursor.fingerprint == fingerprint
                        && text.is_char_boundary(cursor.offset)
                        && cursor.offset < text.len() =>
                {
                    cursor.offset
                }
                Some(_) => return Err(Error::StaleCursor),
                None => 0,
            };
            let mut end = text.len().min(offset + limits.max_text_bytes);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            let continuation = (end < text.len()).then_some(BodyCursor {
                fingerprint,
                offset: end,
            });
            Ok(BodyPage {
                text: if offset == 0 && end == text.len() {
                    text
                } else {
                    text[offset..end].to_owned()
                },
                selected_part,
                source_media_type: selected.map(|s| s.media_type),
                representation_version: REPRESENTATION,
                converted,
                replacements,
                truncated: continuation.is_some(),
                continuation,
                metrics,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    /// Lists attachment metadata from BODYSTRUCTURE only. It never requests an attachment
    /// section, so a large payload cannot affect this route's allocation or wire budget.
    pub async fn list_attachments(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: AttachmentListRequest,
    ) -> Result<AttachmentList, Error> {
        self.metrics = Metrics::default();
        self.transfers.prune();
        credentials(username, password)?;
        mailbox(name)?;
        if request.uid == 0 || request.uid_validity == 0 {
            return Err(Error::InvalidInput);
        }
        let limits = self.limits.clone();
        let active = self.transfers.entries.len();
        tokio::time::timeout(limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            if conn.examine(name).await? != request.uid_validity {
                return Err(Error::UnsafeSelection);
            }
            let fetch = Fetch::Metadata { uid: request.uid };
            let fields = fetch.execute(&mut conn).await?;
            let (_, structure) = fetch.metadata(&fields)?;
            let attachments = attachments(structure, &limits)?
                .into_iter()
                .map(|attachment| AttachmentMetadata {
                    part: part_name(&attachment.part),
                    filename: attachment.filename,
                    media_type: attachment.media_type,
                    declared_size: attachment.declared_size,
                    available: attachment.encoding.is_some(),
                })
                .collect();
            conn.drive(ImapLogout::new()).await?;
            let mut metrics = conn.metrics();
            metrics.active_transfers = active;
            self.metrics = metrics;
            Ok(AttachmentList {
                attachments,
                metrics,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    /// Fetches and decodes at most one bounded wire slice. EOF is proved by a short PEEK
    /// response rather than trusted BODYSTRUCTURE sizes, so each continuation rechecks mailbox
    /// incarnation before it can advance its decoder.
    pub async fn read_attachment(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: AttachmentRequest,
    ) -> Result<AttachmentChunk, Error> {
        self.metrics = Metrics::default();
        self.transfers.prune();
        credentials(username, password)?;
        mailbox(name)?;
        let limits = self.limits.clone();
        let mut state = match (request.start, request.transfer) {
            (Some(_), Some(_)) | (None, None) => return Err(Error::InvalidInput),
            (None, Some(token)) => self.transfers.remove(token)?,
            (Some((uid, uid_validity, part)), None) => {
                if uid == 0 || uid_validity == 0 {
                    return Err(Error::InvalidInput);
                }
                if self.transfers.entries.len() >= limits.max_transfers {
                    return Err(Error::Limit);
                }
                let part = parse_part(&part, &limits)?;
                TransferState::new(
                    username,
                    name,
                    uid,
                    uid_validity,
                    part,
                    TransferEncoding::Identity,
                    &limits,
                )
            }
        };
        if state.mailbox != name || state.principal != principal(username) {
            return Err(Error::TransferExpired);
        }
        tokio::time::timeout(limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            if conn.examine(name).await? != state.uid_validity {
                return Err(Error::UnsafeSelection);
            }
            // A new transfer validates that its requested part is an attachment without fetching
            // any payload. Resumed transfers use the state admitted by that same check.
            if state.wire_offset == 0 && state.decoded_offset == 0 && !state.eof {
                let metadata = Fetch::Metadata { uid: state.uid };
                let fields = metadata.execute(&mut conn).await?;
                let (_, structure) = metadata.metadata(&fields)?;
                let definition = attachments(structure, &limits)?
                    .into_iter()
                    .find(|definition| definition.part == state.part)
                    .ok_or(Error::InvalidInput)?;
                state.encoding = definition.encoding.ok_or(Error::Unsupported)?;
            }
            let decoded_offset = state.decoded_offset as u64;
            let bytes = attachment_bytes(&mut conn, &mut state, &limits).await?;
            conn.drive(ImapLogout::new()).await?;
            let mut metrics = conn.metrics();
            metrics.transfer_wire_bytes = state.wire_bytes;
            metrics.transfer_decoded_bytes = state.decoded_bytes;
            metrics.transfer_decode_steps = state.decode_steps;
            metrics.max_transfer_state_bytes = state.max_state_bytes;
            let complete = state.eof && state.pending.is_empty();
            let (continuation, total_decoded_bytes, sha256) = if complete {
                (
                    None,
                    Some(state.decoded_bytes as u64),
                    Some(state.digest.clone().finalize().into()),
                )
            } else {
                let continuation = self.transfers.insert(state)?;
                (Some(continuation), None, None)
            };
            metrics.active_transfers = self.transfers.entries.len();
            self.metrics = metrics;
            Ok(AttachmentChunk {
                bytes,
                decoded_offset,
                complete,
                continuation,
                total_decoded_bytes,
                sha256,
                metrics,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    /// Cancels an admitted transfer and releases its bounded decoder state immediately.
    pub fn cancel_attachment(&mut self, transfer: AttachmentTransfer) -> Result<(), Error> {
        self.transfers.remove(transfer)?;
        self.metrics.active_transfers = self.transfers.entries.len();
        Ok(())
    }
}

impl TransferState {
    fn new(
        username: &str,
        mailbox: &str,
        uid: u32,
        uid_validity: u32,
        part: Part,
        encoding: TransferEncoding,
        limits: &Limits,
    ) -> Self {
        Self {
            principal: principal(username),
            mailbox: mailbox.to_owned(),
            uid,
            uid_validity,
            part,
            encoding,
            wire_offset: 0,
            decoded_offset: 0,
            pending: Vec::new(),
            base64: Vec::with_capacity(4),
            base64_padded: false,
            quoted_printable: Vec::with_capacity(2),
            eof: false,
            expires: Instant::now() + limits.max_transfer_lifetime,
            digest: Sha256::new(),
            wire_bytes: 0,
            decoded_bytes: 0,
            decode_steps: 0,
            max_state_bytes: 0,
        }
    }
    fn account_state(&mut self) {
        self.max_state_bytes = self.max_state_bytes.max(
            self.pending
                .len()
                .saturating_add(self.base64.len())
                .saturating_add(self.quoted_printable.len())
                .saturating_add(128),
        );
    }
}

async fn attachment_bytes(
    conn: &mut Connection<'_>,
    state: &mut TransferState,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let chunk = limits.max_attachment_chunk_bytes;
    // A resume may have enough retained decoded bytes to complete a chunk. It still owns a fresh
    // EXAMINE lease (the caller did that before this function), but need not fetch redundant wire.
    if state.pending.len() < chunk && !state.eof {
        let remaining = limits
            .max_attachment_wire_bytes
            .checked_sub(state.wire_bytes)
            .ok_or(Error::Limit)?;
        let count = (16 * 1024)
            .min(limits.max_literal_bytes)
            .min(limits.max_response_bytes / 2)
            .min(remaining.saturating_add(1));
        if count == 0 {
            return Err(Error::InvalidInput);
        }
        let fetch = Fetch::Bytes {
            uid: state.uid,
            section: Some(Section::Part(state.part.clone())),
            offset: u32::try_from(state.wire_offset).map_err(|_| Error::Limit)?,
            count: u32::try_from(count).map_err(|_| Error::Limit)?,
        };
        let fields = fetch.execute(conn).await?;
        let wire = fetch.data(&fields)?;
        if wire.len() > remaining {
            return Err(Error::Limit);
        }
        state.wire_offset = state
            .wire_offset
            .checked_add(wire.len())
            .ok_or(Error::Limit)?;
        state.wire_bytes = state
            .wire_bytes
            .checked_add(wire.len())
            .ok_or(Error::Limit)?;
        decode_attachment(state, wire, limits)?;
        if wire.len() < count {
            state.eof = true;
            finish_attachment_decoder(state)?;
        }
    }
    let take = chunk.min(state.pending.len());
    let bytes: Vec<_> = state.pending.drain(..take).collect();
    state.digest.update(&bytes);
    state.decoded_offset = state
        .decoded_offset
        .checked_add(bytes.len())
        .ok_or(Error::Limit)?;
    state.decoded_bytes = state.decoded_offset;
    state.account_state();
    Ok(bytes)
}

fn decode_attachment(state: &mut TransferState, wire: &[u8], limits: &Limits) -> Result<(), Error> {
    state.decode_steps = state
        .decode_steps
        .checked_add(wire.len())
        .ok_or(Error::Limit)?;
    if state.decode_steps > limits.max_decode_steps {
        return Err(Error::Limit);
    }
    match state.encoding {
        TransferEncoding::Identity => append_decoded(state, wire, limits),
        TransferEncoding::Base64 => {
            for byte in wire.iter().copied() {
                if byte.is_ascii_whitespace() {
                    continue;
                }
                if state.base64_padded
                    || !(base64_value(byte).is_some() || byte == b'=')
                    || state.base64.len() == 4
                {
                    return Err(Error::Protocol);
                }
                state.base64.push(byte);
                if state.base64.len() == 4 {
                    let quartet: [u8; 4] = state
                        .base64
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Protocol)?;
                    let padded = quartet[2] == b'=' || quartet[3] == b'=';
                    append_base64_quartet(state, quartet, limits)?;
                    state.base64_padded = padded;
                    state.base64.clear();
                }
            }
            Ok(())
        }
        TransferEncoding::QuotedPrintable => {
            let mut input = std::mem::take(&mut state.quoted_printable);
            input.extend_from_slice(wire);
            let mut index = 0;
            while index < input.len() {
                if input[index] != b'=' {
                    append_decoded(state, &input[index..index + 1], limits)?;
                    index += 1;
                    continue;
                }
                if input.len() - index < 3 {
                    break;
                }
                let first = input[index + 1];
                let second = input[index + 2];
                if first == b'\r' && second == b'\n' {
                    index += 3;
                } else if let (Some(first), Some(second)) = (hex(first), hex(second)) {
                    append_decoded(state, &[first << 4 | second], limits)?;
                    index += 3;
                } else {
                    return Err(Error::Protocol);
                }
            }
            state.quoted_printable.extend_from_slice(&input[index..]);
            if state.quoted_printable.len() > 2 {
                return Err(Error::Protocol);
            }
            Ok(())
        }
    }
}

fn finish_attachment_decoder(state: &mut TransferState) -> Result<(), Error> {
    match state.encoding {
        TransferEncoding::Identity => Ok(()),
        TransferEncoding::Base64 if state.base64.is_empty() => Ok(()),
        TransferEncoding::QuotedPrintable if state.quoted_printable.is_empty() => Ok(()),
        _ => Err(Error::Protocol),
    }
}

fn append_decoded(state: &mut TransferState, bytes: &[u8], limits: &Limits) -> Result<(), Error> {
    if bytes.len() > limits_remaining(state, limits.max_attachment_decoded_bytes)
        || bytes.len()
            > (16_usize * 1024)
                .saturating_add(limits.max_attachment_chunk_bytes)
                .saturating_sub(state.pending.len())
    {
        return Err(Error::Limit);
    }
    state.pending.extend_from_slice(bytes);
    state.account_state();
    Ok(())
}

fn limits_remaining(state: &TransferState, max: usize) -> usize {
    max.saturating_sub(state.decoded_offset.saturating_add(state.pending.len()))
}

fn append_base64_quartet(
    state: &mut TransferState,
    quartet: [u8; 4],
    limits: &Limits,
) -> Result<(), Error> {
    let values = [
        base64_value(quartet[0]).ok_or(Error::Protocol)?,
        base64_value(quartet[1]).ok_or(Error::Protocol)?,
    ];
    let mut decoded = [0; 3];
    decoded[0] = (values[0] << 2) | (values[1] >> 4);
    let length = match (quartet[2], quartet[3]) {
        (b'=', b'=') if values[1] & 0b1111 == 0 => 1,
        (third, b'=') => {
            let third = base64_value(third).ok_or(Error::Protocol)?;
            if third & 0b11 != 0 {
                return Err(Error::Protocol);
            }
            decoded[1] = (values[1] << 4) | (third >> 2);
            2
        }
        (third, fourth) => {
            let third = base64_value(third).ok_or(Error::Protocol)?;
            let fourth = base64_value(fourth).ok_or(Error::Protocol)?;
            decoded[1] = (values[1] << 4) | (third >> 2);
            decoded[2] = (third << 6) | fourth;
            3
        }
    };
    append_decoded(state, &decoded[..length], limits)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_part(part: &str, limits: &Limits) -> Result<Part, Error> {
    if part.is_empty() || part.len() > limits.max_nesting.saturating_mul(11) {
        return Err(Error::InvalidInput);
    }
    let mut values = Vec::new();
    for value in part.split('.') {
        if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Error::InvalidInput);
        }
        let value = value.parse::<u32>().map_err(|_| Error::InvalidInput)?;
        values.push(NonZeroU32::new(value).ok_or(Error::InvalidInput)?);
        if values.len() > limits.max_nesting {
            return Err(Error::Limit);
        }
    }
    Ok(Part(values.try_into().map_err(|_| Error::InvalidInput)?))
}

fn attachments(
    structure: &BodyStructure<'_>,
    limits: &Limits,
) -> Result<Vec<AttachmentDefinition>, Error> {
    fn visit(
        structure: &BodyStructure<'_>,
        path: Option<&Part>,
        depth: usize,
        parts: &mut usize,
        output: &mut Vec<AttachmentDefinition>,
        limits: &Limits,
    ) -> Result<(), Error> {
        *parts = parts.checked_add(1).ok_or(Error::Limit)?;
        if *parts > limits.max_mime_parts || depth > limits.max_nesting {
            return Err(Error::Limit);
        }
        match structure {
            BodyStructure::Single {
                body,
                extension_data,
            } => {
                let part = path
                    .cloned()
                    .unwrap_or_else(|| Part(NonZeroU32::MIN.into()));
                if is_attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                    output.push(attachment_definition(
                        part.clone(),
                        body,
                        extension_data.as_ref().and_then(|data| data.tail.as_ref()),
                    )?);
                }
                // An attached message is transferred as its enclosing RFC822 part. Traversing its
                // embedded body would fabricate duplicate/ambiguous IMAP section locators.
            }
            BodyStructure::Multi { bodies, .. } => {
                for (index, child) in bodies.as_ref().iter().enumerate() {
                    let path = child_part(path, index + 1)?;
                    visit(child, Some(&path), depth + 1, parts, output, limits)?;
                }
            }
        }
        Ok(())
    }
    validate_attachment_structure(structure, limits)?;
    let mut output = Vec::new();
    visit(structure, None, 1, &mut 0, &mut output, limits)?;
    Ok(output)
}

/// Selection stops at an attached RFC822 message because its outer section is the only stable
/// attachment locator. Validation still visits that embedded structure so hostile nesting cannot
/// hide behind an excluded attachment subtree.
fn validate_attachment_structure(
    structure: &BodyStructure<'_>,
    limits: &Limits,
) -> Result<(), Error> {
    fn visit(
        structure: &BodyStructure<'_>,
        depth: usize,
        parts: &mut usize,
        limits: &Limits,
    ) -> Result<(), Error> {
        *parts = parts.checked_add(1).ok_or(Error::Limit)?;
        if *parts > limits.max_mime_parts || depth > limits.max_nesting {
            return Err(Error::Limit);
        }
        match structure {
            BodyStructure::Single { body, .. } => {
                if let SpecificFields::Message { body_structure, .. } = &body.specific {
                    visit(body_structure, depth + 1, parts, limits)?;
                }
            }
            BodyStructure::Multi { bodies, .. } => {
                for child in bodies.as_ref() {
                    visit(child, depth + 1, parts, limits)?;
                }
            }
        }
        Ok(())
    }
    visit(structure, 1, &mut 0, limits)
}

fn child_part(parent: Option<&Part>, child: usize) -> Result<Part, Error> {
    let child =
        NonZeroU32::new(u32::try_from(child).map_err(|_| Error::Limit)?).ok_or(Error::Limit)?;
    let mut values = parent.map_or_else(Vec::new, |parent| parent.0.as_ref().to_vec());
    values.push(child);
    Ok(Part(values.try_into().map_err(|_| Error::Limit)?))
}

fn attachment_definition(
    part: Part,
    body: &Body<'_>,
    disposition: Option<&Disposition<'_>>,
) -> Result<AttachmentDefinition, Error> {
    let (kind, subtype) = match &body.specific {
        SpecificFields::Basic { r#type, subtype } => (imap_string(r#type)?, imap_string(subtype)?),
        SpecificFields::Text { subtype, .. } => ("text", imap_string(subtype)?),
        SpecificFields::Message { .. } => ("message", "rfc822"),
    };
    let filename = disposition
        .and_then(|value| value.disposition.as_ref())
        .and_then(|(_, parameters)| {
            parameters.iter().find(|(name, _)| {
                imap_string(name).is_ok_and(|name| name.eq_ignore_ascii_case("filename"))
            })
        })
        .and_then(|(_, value)| imap_string(value).ok())
        .and_then(safe_filename);
    let encoding = match imap_string(&body.basic.content_transfer_encoding)?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "7bit" | "8bit" => Some(TransferEncoding::Identity),
        "base64" => Some(TransferEncoding::Base64),
        "quoted-printable" => Some(TransferEncoding::QuotedPrintable),
        _ => None,
    };
    Ok(AttachmentDefinition {
        part,
        filename,
        media_type: format!(
            "{}/{}",
            kind.to_ascii_lowercase(),
            subtype.to_ascii_lowercase()
        ),
        declared_size: Some(body.basic.size as u64),
        encoding,
    })
}

fn is_attachment(disposition: Option<&Disposition<'_>>) -> bool {
    disposition
        .and_then(|value| value.disposition.as_ref())
        .is_some_and(|(kind, _)| {
            imap_string(kind).is_ok_and(|kind| kind.eq_ignore_ascii_case("attachment"))
        })
}

fn imap_string<'a>(value: &'a io_imap::types::core::IString<'a>) -> Result<&'a str, Error> {
    std::str::from_utf8(value.as_ref()).map_err(|_| Error::Protocol)
}

fn safe_filename(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().take(257).count() > 256
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn principal(username: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(username.as_bytes());
    digest.finalize().into()
}

fn part_name(part: &Part) -> String {
    let mut name = String::new();
    for (index, number) in part.0.as_ref().iter().enumerate() {
        if index != 0 {
            name.push('.');
        }
        let _ = write!(name, "{number}");
    }
    name
}

async fn headers(
    conn: &mut Connection<'_>,
    uid: u32,
    section: Section<'static>,
    limits: &Limits,
    used: &mut usize,
) -> Result<Vec<u8>, Error> {
    let remaining = limits
        .max_header_bytes
        .checked_sub(*used)
        .ok_or(Error::Limit)?;
    let mut value = bytes(conn, uid, Some(section), None, remaining, limits).await?;
    *used += value.len();
    if !value.ends_with(b"\r\n") {
        return Err(Error::Protocol);
    }
    // GreenMail omits the empty separator from complete HEADER/MIME sections.
    // The short partial response has already established EOF; normalize only
    // that missing separator, within the shared header budget.
    if !value.ends_with(b"\r\n\r\n") && value != b"\r\n" {
        if *used + 2 > limits.max_header_bytes {
            return Err(Error::Limit);
        }
        value.extend_from_slice(b"\r\n");
        *used += 2;
    }
    Ok(value)
}

async fn bytes(
    conn: &mut Connection<'_>,
    uid: u32,
    section: Option<Section<'static>>,
    expected: Option<usize>,
    budget: usize,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let ceiling = expected.unwrap_or(budget);
    if ceiling > budget {
        return Err(Error::Limit);
    }
    let chunk = (16 * 1024)
        .min(limits.max_literal_bytes)
        .min(limits.max_response_bytes / 2);
    if chunk == 0 {
        return Err(Error::InvalidInput);
    }
    let mut result = Vec::new();
    loop {
        let count = chunk.min(ceiling + 1 - result.len());
        let fetch = Fetch::Bytes {
            uid,
            section: section.clone(),
            offset: result.len() as u32,
            count: count as u32,
        };
        let items = fetch.execute(conn).await?;
        let value = fetch.data(&items)?;
        if value.len() > budget.saturating_sub(result.len()) {
            return Err(Error::Limit);
        }
        result.extend_from_slice(value);
        if result.len() > ceiling {
            return Err(Error::Protocol);
        }
        if value.len() < count {
            // BODYSTRUCTURE size is an admission hint: some servers include
            // MIME headers in it. A short partial response establishes EOF.
            return Ok(result);
        }
    }
}

/// Request and response validation stay together; the wire driver applies this
/// contract before the backend can accumulate or merge FETCH rows.
#[derive(Clone, Debug)]
pub(super) enum Fetch {
    Metadata {
        uid: u32,
    },
    Bytes {
        uid: u32,
        section: Option<Section<'static>>,
        offset: u32,
        count: u32,
    },
}
impl Fetch {
    /// GreenMail 2.1.13 emits `<offset>{length}` for partial numeric/MIME
    /// sections. Repair only that separator in the exact requested field, before
    /// the first literal. Typed response validation still checks the entire row.
    pub(super) fn repair_partial_separator(
        &self,
        frame: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Self::Bytes {
            section, offset, ..
        } = self
        else {
            return Ok(None);
        };
        let section = match section {
            None => String::new(),
            Some(Section::Header(None)) => "HEADER".to_owned(),
            Some(Section::Part(part)) => part_name(part),
            Some(Section::Mime(part)) => format!("{}.MIME", part_name(part)),
            _ => return Ok(None),
        };
        let prefix = format!("BODY[{section}]<{offset}>");
        let Some(end) = frame.windows(2).position(|bytes| bytes == b"\r\n") else {
            return Ok(None);
        };
        let line = &frame[..end];
        let mut quoted = false;
        let mut escaped = false;
        for (index, byte) in line.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if quoted && *byte == b'\\' {
                escaped = true;
                continue;
            }
            if *byte == b'"' {
                quoted = !quoted;
                continue;
            }
            if quoted || index == 0 || !matches!(line[index - 1], b' ' | b'(') {
                continue;
            }
            let Some(field) = line.get(index..index + prefix.len()) else {
                continue;
            };
            if !field.eq_ignore_ascii_case(prefix.as_bytes()) {
                continue;
            }
            let insertion = index + prefix.len();
            let tail = &line[insertion..];
            if tail.len() < 3
                || tail[0] != b'{'
                || tail.last() != Some(&b'}')
                || !tail[1..tail.len() - 1].iter().all(u8::is_ascii_digit)
            {
                continue;
            }
            if frame.len() >= max_bytes {
                return Err(Error::Limit);
            }
            let mut repaired = Vec::with_capacity(frame.len() + 1);
            repaired.extend_from_slice(&frame[..insertion]);
            repaired.push(b' ');
            repaired.extend_from_slice(&frame[insertion..]);
            return Ok(Some(repaired));
        }
        Ok(None)
    }
    fn uid(&self) -> u32 {
        match self {
            Self::Metadata { uid } | Self::Bytes { uid, .. } => *uid,
        }
    }
    fn request(&self) -> MacroOrMessageDataItemNames<'static> {
        let mut names = vec![MessageDataItemName::Uid];
        match self {
            Self::Metadata { .. } => names.extend([
                MessageDataItemName::Rfc822Size,
                MessageDataItemName::BodyStructure,
            ]),
            Self::Bytes {
                section,
                offset,
                count,
                ..
            } => names.push(MessageDataItemName::BodyExt {
                section: section.clone(),
                partial: Some((
                    *offset,
                    NonZeroU32::new(*count).expect("nonzero bounded chunk"),
                )),
                peek: true,
            }),
        }
        names.into()
    }
    pub(super) fn from_command(body: &CommandBody<'_>) -> Option<Self> {
        let CommandBody::Fetch {
            sequence_set,
            macro_or_item_names: MacroOrMessageDataItemNames::MessageDataItemNames(names),
            uid: true,
            modifiers,
        } = body
        else {
            return None;
        };
        if !modifiers.is_empty() {
            return None;
        }
        let [Sequence::Single(SeqOrUid::Value(uid))] = sequence_set.0.as_ref() else {
            return None;
        };
        let uid = uid.get();
        match names.as_slice() {
            [
                MessageDataItemName::Uid,
                MessageDataItemName::Rfc822Size,
                MessageDataItemName::BodyStructure,
            ] => Some(Self::Metadata { uid }),
            [
                MessageDataItemName::Uid,
                MessageDataItemName::BodyExt {
                    section,
                    partial: Some((offset, count)),
                    peek: true,
                },
            ] => {
                let section = match section {
                    None => None,
                    Some(Section::Header(None)) => Some(Section::Header(None)),
                    Some(Section::Mime(part)) => Some(Section::Mime(part.clone())),
                    Some(Section::Part(part)) => Some(Section::Part(part.clone())),
                    _ => return None,
                };
                Some(Self::Bytes {
                    uid,
                    section,
                    offset: *offset,
                    count: count.get(),
                })
            }
            _ => None,
        }
    }
    pub(super) fn literal_limit(&self) -> Option<usize> {
        match self {
            Self::Bytes { count, .. } => Some(*count as usize),
            _ => None,
        }
    }
    pub(super) fn validate(&self, items: &[MessageDataItem<'_>]) -> Result<(), Error> {
        let mut uid = None;
        for item in items {
            if let MessageDataItem::Uid(value) = item
                && uid.replace(value.get()).is_some()
            {
                return Err(Error::Protocol);
            }
        }
        if uid != Some(self.uid()) {
            return Err(Error::Protocol);
        }
        match self {
            Self::Metadata { .. } => {
                self.metadata(items)?;
            }
            Self::Bytes { .. } => {
                self.data(items)?;
            }
        }
        Ok(())
    }
    fn metadata<'a, 'b>(
        &self,
        items: &'a [MessageDataItem<'b>],
    ) -> Result<(u32, &'a BodyStructure<'b>), Error> {
        if items.len() != 3 {
            return Err(Error::Protocol);
        }
        let mut size = None;
        let mut structure = None;
        for item in items {
            match item {
                MessageDataItem::Uid(_) => {}
                MessageDataItem::Rfc822Size(value) if size.is_none() => size = Some(*value),
                MessageDataItem::BodyStructure(value) if structure.is_none() => {
                    structure = Some(value)
                }
                _ => return Err(Error::Protocol),
            }
        }
        Ok((
            size.ok_or(Error::Protocol)?,
            structure.ok_or(Error::Protocol)?,
        ))
    }
    fn data<'a>(&self, items: &'a [MessageDataItem<'_>]) -> Result<&'a [u8], Error> {
        let Self::Bytes {
            section,
            offset,
            count,
            ..
        } = self
        else {
            return Err(Error::Protocol);
        };
        if items.len() != 2 {
            return Err(Error::Protocol);
        }
        let mut value = None;
        for item in items {
            match item {
                MessageDataItem::Uid(_) => {}
                MessageDataItem::BodyExt {
                    section: actual,
                    origin,
                    data,
                } if actual == section && *origin == Some(*offset) && value.is_none() => {
                    value = Some(data.0.as_ref().ok_or(Error::Protocol)?.as_ref())
                }
                _ => return Err(Error::Protocol),
            }
        }
        let value = value.ok_or(Error::Protocol)?;
        if value.len() > *count as usize {
            return Err(Error::Limit);
        }
        Ok(value)
    }
    async fn execute(
        &self,
        conn: &mut Connection<'_>,
    ) -> Result<Vec<MessageDataItem<'static>>, Error> {
        let uid = NonZeroU32::new(self.uid()).ok_or(Error::InvalidInput)?;
        let mut rows = conn
            .drive(ImapMessageFetch::new(
                SequenceSet::from(SeqOrUid::from(uid)),
                self.request(),
                ImapMessageFetchOptions {
                    uid: true,
                    ..Default::default()
                },
            ))
            .await?;
        if rows.len() != 1 {
            return Err(Error::Protocol);
        }
        let items = rows.pop_first().ok_or(Error::Protocol)?.1.into_inner();
        self.validate(&items)?;
        Ok(items)
    }
}
