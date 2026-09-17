//! Bounded attachment transfer ownership and verified IMAP retrieval.
mod decoder;
use super::{
    Error, Limits, Metrics,
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
use std::num::NonZeroU32;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentIntegrity {
    pub total_decoded_bytes: u64,
    pub sha256: [u8; 32],
}

struct TransferState {
    identity: Option<[u8; 32]>,
    mailbox: String,
    uid: u32,
    uid_validity: u32,
    part: Part,
    decoder: Decoder,
    wire_bytes: usize,
    eof: bool,
}

struct AttachmentDefinition {
    part: Part,
    filename: Option<String>,
    media_type: String,
    declared_size: Option<u64>,
    encoding: Option<TransferEncoding>,
}

impl TransferState {
    async fn read_selected(
        &mut self,
        conn: &mut Connection<'_>,
        limits: &Limits,
    ) -> Result<Vec<u8>, Error> {
        if self.wire_bytes == 0 && !self.eof {
            let definition = attachment_definitions(conn, self.uid, limits)
                .await?
                .into_iter()
                .find(|entry| entry.part == self.part)
                .ok_or(Error::StaleReference)?;
            self.decoder = Decoder::new(definition.encoding.ok_or(Error::Unsupported)?);
        }
        let mut fetched = false;
        while self.decoder.pending_len() < limits.max_attachment_chunk_bytes && !self.eof {
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
            let remaining = limits
                .max_attachment_wire_bytes
                .checked_sub(self.wire_bytes)
                .ok_or(Error::Limit)?;
            let count = WIRE_SLICE_BYTES
                .min(limits.max_literal_bytes)
                .min(limits.max_response_bytes / 2)
                .min(remaining.saturating_add(1));
            if count == 0 {
                return Err(Error::InvalidInput);
            }
            let fetch = Fetch::Bytes {
                uid: self.uid,
                section: Some(Section::Part(self.part.clone())),
                offset: u32::try_from(self.wire_bytes).map_err(|_| Error::Limit)?,
                count: count as u32,
            };
            let fields = fetch.execute(conn).await?;
            let wire = fetch.data(&fields)?;
            self.wire_bytes = self
                .wire_bytes
                .checked_add(wire.len())
                .ok_or(Error::Limit)?;
            self.publish(conn.metrics_mut());
            if wire.len() > remaining {
                return Err(Error::Limit);
            }
            let decoded = self.decoder.push(wire, limits);
            self.publish(conn.metrics_mut());
            decoded?;
            if wire.len() < count {
                self.eof = true;
                let finished = self.decoder.finish(limits);
                self.publish(conn.metrics_mut());
                finished?;
            }
            fetched = true;
            tokio::task::yield_now().await;
        }
        let bytes = self.decoder.take_chunk(limits.max_attachment_chunk_bytes);
        self.publish(conn.metrics_mut());
        conn.drive(ImapLogout::new()).await?;
        Ok(bytes)
    }

    fn publish(&self, metrics: &mut Metrics) {
        let decoder = self.decoder.snapshot();
        metrics.transfer_wire_bytes = self.wire_bytes;
        metrics.transfer_decoded_bytes = decoder.decoded_bytes;
        metrics.transfer_decode_steps = decoder.decode_steps;
        metrics.max_transfer_state_bytes = decoder.max_state_bytes;
    }
}

fn parse_part(part: &str, limits: &Limits) -> Result<Part, Error> {
    if part.is_empty() || part.len() > limits.max_nesting.saturating_mul(11) {
        return Err(Error::InvalidInput);
    }
    let mut values = Vec::<NonZeroU32>::new();
    for value in part.split('.') {
        if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Error::InvalidInput);
        }
        values.push(value.parse().map_err(|_| Error::InvalidInput)?);
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
                let disposition = extension_data.as_ref().and_then(|data| data.tail.as_ref());
                if is_attachment(disposition) {
                    output.push(attachment_definition(
                        path.cloned()
                            .unwrap_or_else(|| Part(NonZeroU32::MIN.into())),
                        body,
                        disposition,
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
    let encoding = imap_string(&body.basic.content_transfer_encoding)?.trim();
    let encoding = if encoding.eq_ignore_ascii_case("7bit") || encoding.eq_ignore_ascii_case("8bit")
    {
        Some(TransferEncoding::Identity)
    } else if encoding.eq_ignore_ascii_case("base64") {
        Some(TransferEncoding::Base64)
    } else if encoding.eq_ignore_ascii_case("quoted-printable") {
        Some(TransferEncoding::QuotedPrintable)
    } else {
        None
    };
    let mut media_type = format!("{kind}/{subtype}");
    media_type.make_ascii_lowercase();
    Ok(AttachmentDefinition {
        part,
        filename,
        media_type,
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

impl super::AuthenticatedConnection {
    pub async fn list_attachments(
        self,
        name: &str,
        request: AttachmentListRequest,
        limits: &Limits,
        metrics: &mut Metrics,
    ) -> Result<Vec<AttachmentMetadata>, Error> {
        limits.validate()?;
        let mut conn = self.session.resume(metrics);
        conn.limit_body(limits);
        mailbox(name)?;
        if request.uid == 0 || request.uid_validity == 0 {
            return Err(Error::InvalidInput);
        }
        if conn.examine(name).await? != request.uid_validity {
            return Err(Error::StaleReference);
        }
        let result = attachment_definitions(&mut conn, request.uid, limits)
            .await?
            .into_iter()
            .map(AttachmentDefinition::into_metadata)
            .collect();
        conn.drive(ImapLogout::new()).await?;
        Ok(result)
    }
}
impl Limits {
    pub(crate) fn attachment(limits: &crate::config::Limits) -> Self {
        Self {
            max_header_bytes: limits.header_bytes,
            max_nesting: limits.mime_depth,
            max_mime_parts: limits.mime_parts,
            max_attachment_wire_bytes: limits.attachment_wire_bytes,
            max_attachment_decoded_bytes: limits.attachment_decoded_bytes,
            max_attachment_chunk_bytes: limits.attachment_chunk_bytes,
            max_operation_bytes: limits.wire_fetch_bytes,
            ..Self::default()
        }
    }
}

/// One decoded page. Only a completed page carries its final byte count and digest.
#[derive(Debug)]
pub struct AttachmentData {
    pub bytes: Vec<u8>,
    pub decoded_offset: u64,
    pub integrity: Option<AttachmentIntegrity>,
}

/// Incremental decoding state, bound to its mailbox, UIDVALIDITY, UID, and part.
/// The first read binds the authenticated endpoint and username. Completion, a read
/// failure, or cancellation during retrieval invalidates the state. The application
/// owns deadlines, quotas, and continuation-token authorization.
///
/// State cannot be cloned or replaced by callers:
/// ```compile_fail
/// use mailctl::imap::AttachmentDecoder;
/// fn duplicate(decoder: AttachmentDecoder) { let _ = decoder.clone(); }
/// ```
/// ```compile_fail
/// use mailctl::imap::AttachmentDecoder;
/// fn reset(decoder: &mut AttachmentDecoder) { decoder.0 = None; }
/// ```
pub struct AttachmentDecoder(Option<TransferState>);
impl AttachmentDecoder {
    pub fn new(
        mailbox: &str,
        uid: u32,
        validity: u32,
        part: &str,
        limits: &Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        super::mailbox(mailbox)?;
        if uid == 0 || validity == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(Some(TransferState {
            identity: None,
            mailbox: mailbox.to_owned(),
            uid,
            uid_validity: validity,
            part: parse_part(part, limits)?,
            decoder: Decoder::new(TransferEncoding::Identity),
            wire_bytes: 0,
            eof: false,
        })))
    }
}
impl super::AuthenticatedConnection {
    pub async fn read_attachment(
        self,
        decoder: &mut AttachmentDecoder,
        limits: &Limits,
        metrics: &mut Metrics,
    ) -> Result<AttachmentData, Error> {
        let mut state = decoder.0.take().ok_or(Error::TransferExpired)?;
        limits.validate()?;
        if state
            .identity
            .is_some_and(|identity| identity != self.identity)
        {
            return Err(Error::TransferExpired);
        }
        state.identity = Some(self.identity);
        let mut conn = self.session.resume(metrics);
        conn.limit_body(limits);
        if conn.examine(&state.mailbox).await? != state.uid_validity {
            return Err(Error::StaleReference);
        }
        let bytes = state.read_selected(&mut conn, limits).await?;
        let decoded_offset = (state.decoder.decoded_offset() - bytes.len()) as u64;
        let integrity = if state.eof && state.decoder.pending_len() == 0 {
            let (total_decoded_bytes, sha256) = state.decoder.integrity();
            Some(AttachmentIntegrity {
                total_decoded_bytes,
                sha256,
            })
        } else {
            decoder.0 = Some(state);
            None
        };
        Ok(AttachmentData {
            bytes,
            decoded_offset,
            integrity,
        })
    }
}

async fn attachment_definitions(
    conn: &mut Connection<'_>,
    uid: u32,
    limits: &Limits,
) -> Result<Vec<AttachmentDefinition>, Error> {
    let fetch = Fetch::Metadata { uid };
    let fields = fetch.execute(conn).await?;
    let (_, structure) = Fetch::metadata(&fields)?;
    attachments(structure, limits)
}
impl AttachmentDefinition {
    fn into_metadata(self) -> AttachmentMetadata {
        AttachmentMetadata {
            part: part_name(&self.part),
            filename: self.filename,
            media_type: self.media_type,
            declared_size: self.declared_size,
            available: self.encoding.is_some(),
        }
    }
}
