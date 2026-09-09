//! Bounded attachment transfer ownership and verified IMAP retrieval.
mod decoder;
use super::{
    Error, ImapProbe, Limits, Metrics, credentials,
    fetch::Fetch,
    mailbox,
    mime::{
        attachment as is_attachment, child_path as child_part, imap_text as imap_string, part_name,
        validate_structure,
    },
    wire::Connection,
};
use decoder::{Decoder, TransferEncoding, WIRE_SLICE_BYTES};
use io_imap::{
    rfc3501::logout::ImapLogout,
    types::{
        body::{Body, BodyStructure, Disposition, SpecificFields},
        fetch::{Part, Section},
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt::{self, Write},
    num::NonZeroU32,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Instant,
};

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
    kind: RequestKind,
}
#[derive(Debug)]
enum RequestKind {
    Start {
        uid: u32,
        uid_validity: u32,
        part: String,
    },
    Resume(AttachmentTransfer),
}
impl AttachmentRequest {
    pub fn new(uid: u32, uid_validity: u32, part: impl Into<String>) -> Self {
        Self {
            kind: RequestKind::Start {
                uid,
                uid_validity,
                part: part.into(),
            },
        }
    }
    pub fn resume(transfer: AttachmentTransfer) -> Self {
        Self {
            kind: RequestKind::Resume(transfer),
        }
    }
}

/// An opaque continuation owned by one probe session. Resume or cancellation consumes it.
///
/// ```compile_fail
/// use mailctl::imap::AttachmentTransfer;
/// fn copy(transfer: AttachmentTransfer) { let _ = transfer.clone(); }
/// ```
///
/// ```compile_fail
/// use mailctl::imap::AttachmentTransfer;
/// let transfer = AttachmentTransfer { value: String::from("invented") };
/// ```
///
/// ```compile_fail
/// use mailctl::imap::{AttachmentTransfer, AttachmentRequest};
/// fn reuse(transfer: AttachmentTransfer) {
///     let first = AttachmentRequest::resume(transfer);
///     let second = AttachmentRequest::resume(transfer);
/// }
/// ```
pub struct AttachmentTransfer {
    value: String,
    owner: Weak<Mutex<HashMap<String, TransferState>>>,
}
impl fmt::Debug for AttachmentTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachmentTransfer(..)")
    }
}
impl Drop for AttachmentTransfer {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            owner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&self.value);
        }
    }
}

#[derive(Debug)]
pub struct AttachmentChunk {
    pub bytes: Vec<u8>,
    pub decoded_offset: u64,
    pub progress: AttachmentProgress,
    pub metrics: Metrics,
}

/// A chunk either continues a transfer or carries its final integrity result.
#[derive(Debug)]
pub enum AttachmentProgress {
    Continue(AttachmentTransfer),
    Complete(AttachmentIntegrity),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentIntegrity {
    pub total_decoded_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Default)]
pub(super) struct TransferStore {
    entries: Arc<Mutex<HashMap<String, TransferState>>>,
}
impl TransferStore {
    fn entries(&self) -> MutexGuard<'_, HashMap<String, TransferState>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    pub(super) fn active_count(&self) -> usize {
        let now = Instant::now();
        self.entries()
            .values()
            .filter(|state| state.expires > now)
            .count()
    }
    fn prune(&mut self) {
        let now = Instant::now();
        self.entries().retain(|_, state| state.expires > now);
    }
    fn remove(&mut self, token: AttachmentTransfer) -> Result<TransferState, Error> {
        self.prune();
        if !Weak::ptr_eq(&Arc::downgrade(&self.entries), &token.owner) {
            return Err(Error::TransferExpired);
        }
        // Release the registry lock before the consumed token's Drop runs.
        let state = self.entries().remove(&token.value);
        state.ok_or(Error::TransferExpired)
    }
    fn insert(&mut self, state: TransferState) -> Result<AttachmentTransfer, Error> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Transport)?;
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(value, "{byte:02x}");
        }
        if self.entries().insert(value.clone(), state).is_some() {
            return Err(Error::Transport);
        }
        Ok(AttachmentTransfer {
            value,
            owner: Arc::downgrade(&self.entries),
        })
    }
}

struct TransferState {
    principal: [u8; 32],
    mailbox: String,
    uid: u32,
    uid_validity: u32,
    part: Part,
    decoder: Decoder,
    wire_bytes: usize,
    eof: bool,
    expires: Instant,
}

#[derive(Clone)]
struct AttachmentDefinition {
    part: Part,
    filename: Option<String>,
    media_type: String,
    declared_size: Option<u64>,
    encoding: Option<TransferEncoding>,
}

impl ImapProbe {
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
            metrics.active_transfers = self.transfers.active_count();
            self.metrics = metrics;
            Ok(AttachmentList {
                attachments,
                metrics,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    /// Fills a decoded chunk through bounded PEEK requests on one exclusive lease.
    /// EOF comes from a short response; every continuation rechecks UIDVALIDITY.
    pub async fn read_attachment(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: AttachmentRequest,
    ) -> Result<AttachmentChunk, Error> {
        self.metrics = Metrics::default();
        self.transfers.prune();
        let limits = self.limits.clone();
        let starting = matches!(request.kind, RequestKind::Start { .. });
        // A moved continuation relinquishes its retained state even when later validation fails.
        let mut state = match request.kind {
            RequestKind::Resume(token) => self.transfers.remove(token)?,
            RequestKind::Start {
                uid,
                uid_validity,
                part,
            } => {
                credentials(username, password)?;
                mailbox(name)?;
                if uid == 0 || uid_validity == 0 {
                    return Err(Error::InvalidInput);
                }
                if self.transfers.active_count() >= limits.max_transfers {
                    return Err(Error::Limit);
                }
                TransferState::new(
                    username,
                    name,
                    uid,
                    uid_validity,
                    parse_part(&part, &limits)?,
                    &limits,
                )
            }
        };
        state.publish(&mut self.metrics);
        credentials(username, password)?;
        mailbox(name)?;
        if state.mailbox != name || state.principal != principal(username) {
            return Err(Error::TransferExpired);
        }
        let operation_deadline = Instant::now() + limits.operation_timeout;
        let deadline = operation_deadline.min(state.expires);
        let expired_error = if state.expires <= operation_deadline {
            Error::TransferExpired
        } else {
            Error::Timeout
        };
        let bytes = tokio::time::timeout_at(deadline.into(), async {
            let mut conn = self.authenticate(username, password).await?;
            if conn.examine(name).await? != state.uid_validity {
                return Err(Error::UnsafeSelection);
            }
            if starting {
                let metadata = Fetch::Metadata { uid: state.uid };
                let fields = metadata.execute(&mut conn).await?;
                let (_, structure) = metadata.metadata(&fields)?;
                let definition = attachments(structure, &limits)?
                    .into_iter()
                    .find(|definition| definition.part == state.part)
                    .ok_or(Error::InvalidInput)?;
                state.decoder = Decoder::new(definition.encoding.ok_or(Error::Unsupported)?);
            }
            let bytes = attachment_bytes(&mut conn, &mut state, &limits).await?;
            conn.drive(ImapLogout::new()).await?;
            Ok(bytes)
        })
        .await
        .map_err(|_| expired_error)??;
        // Synchronous decoding and finalization also obey the absolute transfer deadline.
        if Instant::now() >= deadline {
            return Err(expired_error);
        }
        let decoded_offset = state.decoder.decoded_offset() - bytes.len();
        let complete = state.eof && state.decoder.pending_len() == 0;
        let progress = if complete {
            let (total_decoded_bytes, sha256) = state.decoder.integrity();
            AttachmentProgress::Complete(AttachmentIntegrity {
                total_decoded_bytes,
                sha256,
            })
        } else {
            AttachmentProgress::Continue(self.transfers.insert(state)?)
        };
        self.metrics.active_transfers = self.transfers.active_count();
        Ok(AttachmentChunk {
            bytes,
            decoded_offset: decoded_offset as u64,
            progress,
            metrics: self.metrics,
        })
    }

    /// Cancels an admitted transfer and releases its bounded decoder state immediately.
    pub fn cancel_attachment(&mut self, transfer: AttachmentTransfer) -> Result<(), Error> {
        self.transfers.remove(transfer)?;
        self.metrics.active_transfers = self.transfers.active_count();
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
        limits: &Limits,
    ) -> Self {
        Self {
            principal: principal(username),
            mailbox: mailbox.to_owned(),
            uid,
            uid_validity,
            part,
            decoder: Decoder::new(TransferEncoding::Identity),
            wire_bytes: 0,
            eof: false,
            expires: Instant::now() + limits.max_transfer_lifetime,
        }
    }
    fn publish(&self, metrics: &mut Metrics) {
        let decoder = self.decoder.snapshot();
        metrics.transfer_wire_bytes = self.wire_bytes;
        metrics.transfer_decoded_bytes = decoder.decoded_bytes;
        metrics.transfer_decode_steps = decoder.decode_steps;
        metrics.max_transfer_state_bytes = decoder.max_state_bytes;
    }
}

async fn attachment_bytes(
    conn: &mut Connection<'_>,
    state: &mut TransferState,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let mut fetched = false;
    while state.decoder.pending_len() < limits.max_attachment_chunk_bytes && !state.eof {
        // Return the available prefix at a clean command boundary when another maximum
        // response pair would approach the operation budget. Every call can attempt a slice.
        if fetched
            && limits
                .max_operation_bytes
                .saturating_sub(conn.metrics().wire_bytes)
                < limits.max_response_bytes.saturating_mul(2)
        {
            break;
        }
        if Instant::now() >= state.expires {
            return Err(Error::TransferExpired);
        }
        let remaining = limits
            .max_attachment_wire_bytes
            .checked_sub(state.wire_bytes)
            .ok_or(Error::Limit)?;
        let count = WIRE_SLICE_BYTES
            .min(limits.max_literal_bytes)
            .min(limits.max_response_bytes / 2)
            .min(remaining.saturating_add(1));
        if count == 0 {
            return Err(Error::InvalidInput);
        }
        let fetch = Fetch::Bytes {
            uid: state.uid,
            section: Some(Section::Part(state.part.clone())),
            offset: u32::try_from(state.wire_bytes).map_err(|_| Error::Limit)?,
            count: count as u32,
        };
        let fields = fetch.execute(conn).await?;
        let wire = fetch.data(&fields)?;
        state.wire_bytes = state
            .wire_bytes
            .checked_add(wire.len())
            .ok_or(Error::Limit)?;
        state.publish(conn.metrics_mut());
        if wire.len() > remaining {
            return Err(Error::Limit);
        }
        let decoded = state.decoder.push(wire, limits);
        state.publish(conn.metrics_mut());
        decoded?;
        if wire.len() < count {
            state.eof = true;
            let finished = state.decoder.finish(limits);
            state.publish(conn.metrics_mut());
            finished?;
        }
        fetched = true;
        tokio::task::yield_now().await;
    }
    let bytes = state.decoder.take_chunk(limits.max_attachment_chunk_bytes);
    state.publish(conn.metrics_mut());
    Ok(bytes)
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
        output: &mut Vec<AttachmentDefinition>,
    ) -> Result<(), Error> {
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
                    visit(child, Some(&path), output)?;
                }
            }
        }
        Ok(())
    }
    validate_structure(structure, limits)?;
    let mut output = Vec::new();
    visit(structure, None, &mut output)?;
    Ok(output)
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
