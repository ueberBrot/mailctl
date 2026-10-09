//! Bounded attachment transfer ownership and verified IMAP retrieval.
mod decoder;
use super::{
    Error, Limits, Metrics,
    fetch::Fetch,
    mailbox,
    mime::{attachment, imap_text, part_name, validate_structure},
    wire::Connection,
};
use decoder::{Decoder, TransferEncoding};
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
            let definition = attachment_definitions(conn, self.uid, limits, Some(&self.part))
                .await?
                .into_iter()
                .next()
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
            let count = limits.fetch_chunk_bytes()?.min(remaining.saturating_add(1));
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
    wanted: Option<&Part>,
) -> Result<Vec<AttachmentDefinition>, Error> {
    fn visit(
        structure: &BodyStructure<'_>,
        path: &mut Vec<NonZeroU32>,
        output: &mut Vec<AttachmentDefinition>,
        wanted: Option<&Part>,
    ) -> Result<(), Error> {
        match structure {
            BodyStructure::Single {
                body,
                extension_data,
            } => {
                let disposition = extension_data.as_ref().and_then(|data| data.tail.as_ref());
                if attachment(disposition)
                    && let Some(definition) =
                        attachment_definition(path, body, disposition, wanted)?
                {
                    output.push(definition);
                }
                // An attached message is transferred as its enclosing RFC822 part. Traversing its
                // embedded body would fabricate duplicate/ambiguous IMAP section locators.
            }
            BodyStructure::Multi { bodies, .. } => {
                for (index, child) in bodies.as_ref().iter().enumerate() {
                    let number =
                        NonZeroU32::new(u32::try_from(index + 1).map_err(|_| Error::Limit)?)
                            .ok_or(Error::Limit)?;
                    path.push(number);
                    visit(child, path, output, wanted)?;
                    path.pop();
                }
            }
        }
        Ok(())
    }
    validate_structure(structure, limits)?;
    let mut output = Vec::new();
    visit(structure, &mut Vec::new(), &mut output, wanted)?;
    Ok(output)
}

fn attachment_definition(
    path: &[NonZeroU32],
    body: &Body<'_>,
    disposition: Option<&Disposition<'_>>,
    wanted: Option<&Part>,
) -> Result<Option<AttachmentDefinition>, Error> {
    let (kind, subtype) = match &body.specific {
        SpecificFields::Basic { r#type, subtype } => (imap_text(r#type)?, imap_text(subtype)?),
        SpecificFields::Text { subtype, .. } => ("text", imap_text(subtype)?),
        SpecificFields::Message { .. } => ("message", "rfc822"),
    };
    let encoding = imap_text(&body.basic.content_transfer_encoding)?.trim();
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
    // First reads retain one attachment, but every eligible sibling still validates
    // its fallible fields before metadata and its owned section path are filtered.
    let path = if path.is_empty() {
        &[NonZeroU32::MIN]
    } else {
        path
    };
    if wanted.is_some_and(|wanted| wanted.0.as_ref() != path) {
        return Ok(None);
    }
    let filename = disposition
        .and_then(|value| value.disposition.as_ref())
        .and_then(|(_, parameters)| {
            parameters.iter().find(|(name, _)| {
                imap_text(name).is_ok_and(|name| name.eq_ignore_ascii_case("filename"))
            })
        })
        .and_then(|(_, value)| imap_text(value).ok())
        .and_then(safe_filename);
    let mut media_type = format!("{kind}/{subtype}");
    media_type.make_ascii_lowercase();
    Ok(Some(AttachmentDefinition {
        part: Part(path.to_vec().try_into().expect("path is nonempty")),
        filename,
        media_type,
        declared_size: Some(body.basic.size as u64),
        encoding,
    }))
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
        let result = attachment_definitions(&mut conn, request.uid, limits, None)
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
    wanted: Option<&Part>,
) -> Result<Vec<AttachmentDefinition>, Error> {
    let fetch = Fetch::Metadata { uid };
    let fields = fetch.execute(conn).await?;
    let (_, structure) = Fetch::metadata(&fields)?;
    attachments(structure, limits, wanted)
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

#[cfg(test)]
mod traversal_tests {
    use super::*;
    use io_imap::types::{
        body::{BasicFields, SinglePartExtensionData},
        core::NString,
        envelope::Envelope,
    };

    fn leaf(attached: bool) -> BodyStructure<'static> {
        BodyStructure::Single {
            body: Body {
                basic: BasicFields {
                    parameter_list: vec![],
                    id: NString::NIL,
                    description: NString::NIL,
                    content_transfer_encoding: "7BIT".try_into().unwrap(),
                    size: 5,
                },
                specific: SpecificFields::Basic {
                    r#type: "APPLICATION".try_into().unwrap(),
                    subtype: "OCTET-STREAM".try_into().unwrap(),
                },
            },
            extension_data: attached.then(|| SinglePartExtensionData {
                md5: NString::NIL,
                tail: Some(Disposition {
                    disposition: Some(("ATTACHMENT".try_into().unwrap(), vec![])),
                    tail: None,
                }),
            }),
        }
    }

    fn multipart(children: Vec<BodyStructure<'static>>) -> BodyStructure<'static> {
        BodyStructure::Multi {
            bodies: children.try_into().unwrap(),
            subtype: "MIXED".try_into().unwrap(),
            extension_data: None,
        }
    }

    fn attached_message(embedded: BodyStructure<'static>) -> BodyStructure<'static> {
        let mut structure = leaf(true);
        let BodyStructure::Single { body, .. } = &mut structure else {
            unreachable!();
        };
        body.specific = SpecificFields::Message {
            envelope: Box::new(Envelope {
                date: NString::NIL,
                subject: NString::NIL,
                from: vec![],
                sender: vec![],
                reply_to: vec![],
                to: vec![],
                cc: vec![],
                bcc: vec![],
                in_reply_to: NString::NIL,
                message_id: NString::NIL,
            }),
            body_structure: Box::new(embedded),
            number_of_lines: 1,
        };
        structure
    }

    #[test]
    fn root_single_attachment_has_part_one() {
        let definitions = attachments(&leaf(true), &Limits::default(), None).unwrap();
        assert_eq!(definitions.len(), 1);
        assert_eq!(part_name(&definitions[0].part), "1");
        assert_eq!(definitions[0].media_type, "application/octet-stream");
    }

    #[test]
    fn nested_attachment_paths_preserve_sibling_numbering() {
        let structure = multipart(vec![
            leaf(false),
            multipart(vec![leaf(true), leaf(true)]),
            leaf(true),
        ]);
        let definitions = attachments(&structure, &Limits::default(), None).unwrap();
        let parts = definitions
            .iter()
            .map(|entry| part_name(&entry.part))
            .collect::<Vec<_>>();
        assert_eq!(parts, ["2.1", "2.2", "3"]);
    }

    #[test]
    fn attached_message_uses_its_enclosing_part_and_counts_its_embedded_structure() {
        let structure = multipart(vec![
            leaf(false),
            attached_message(multipart(vec![leaf(true), leaf(true)])),
        ]);
        let limits = Limits {
            max_mime_parts: 6,
            ..Limits::default()
        };
        let definitions = attachments(&structure, &limits, None).unwrap();
        assert_eq!(definitions.len(), 1);
        assert_eq!(part_name(&definitions[0].part), "2");
        assert_eq!(definitions[0].media_type, "message/rfc822");
        assert!(matches!(
            attachments(
                &structure,
                &Limits {
                    max_mime_parts: 5,
                    ..limits
                },
                None,
            ),
            Err(Error::Limit)
        ));
    }

    #[test]
    fn excluded_leaves_do_not_allocate_individual_part_paths() {
        for (depth, parts) in [(2, 1_000), (40, 1_000)] {
            let mut structure = multipart(vec![leaf(false); parts - depth + 1]);
            for _ in 2..depth {
                structure = multipart(vec![structure]);
            }
            let limits = Limits {
                max_nesting: depth,
                max_mime_parts: parts,
                ..Limits::default()
            };
            let measured = allocation_counter::measure(|| {
                assert!(attachments(&structure, &limits, None).unwrap().is_empty());
            });
            assert!(
                measured.count_total < 16 && measured.bytes_total < 16 * 1_024,
                "attachment discovery must reuse its path for excluded leaves: {measured:?}"
            );
        }
    }

    #[test]
    fn selecting_one_attachment_only_materializes_its_metadata() {
        for (depth, parts) in [(2, 1_000), (40, 1_000)] {
            let mut entry = leaf(true);
            let BodyStructure::Single { extension_data, .. } = &mut entry else {
                unreachable!();
            };
            extension_data
                .as_mut()
                .unwrap()
                .tail
                .as_mut()
                .unwrap()
                .disposition
                .as_mut()
                .unwrap()
                .1
                .push((
                    "FILENAME".try_into().unwrap(),
                    "report.txt".try_into().unwrap(),
                ));
            let leaves = parts - depth + 1;
            let mut structure = multipart(vec![entry; leaves]);
            for _ in 2..depth {
                structure = multipart(vec![structure]);
            }
            let mut path = vec![NonZeroU32::MIN; depth - 2];
            path.push(NonZeroU32::new(leaves as u32).unwrap());
            let wanted = Part(path.try_into().unwrap());
            let limits = Limits {
                max_nesting: depth,
                max_mime_parts: parts,
                ..Limits::default()
            };
            let measured = allocation_counter::measure(|| {
                let mut selected = attachments(&structure, &limits, Some(&wanted)).unwrap();
                assert_eq!(selected.len(), 1);
                let selected = selected.pop().unwrap();
                assert_eq!(selected.part, wanted);
                assert_eq!(selected.filename.as_deref(), Some("report.txt"));
                assert_eq!(selected.media_type, "application/octet-stream");
                assert_eq!(selected.encoding, Some(TransferEncoding::Identity));
            });
            eprintln!(
                "selected attachment depth={depth} parts={parts} leaves={leaves} allocations={} total={} peak={}",
                measured.count_total, measured.bytes_total, measured.bytes_max
            );
            assert!(
                measured.count_total < 20 && measured.bytes_total < 8 * 1_024,
                "choosing one attachment must not own every sibling's metadata: {measured:?}"
            );
        }
    }

    #[test]
    fn selecting_one_attachment_still_validates_other_attachment_fields() {
        for field in ["type", "subtype", "encoding"] {
            let mut malformed = leaf(true);
            let BodyStructure::Single { body, .. } = &mut malformed else {
                unreachable!();
            };
            match field {
                "type" | "subtype" => {
                    let SpecificFields::Basic { r#type, subtype } = &mut body.specific else {
                        unreachable!();
                    };
                    let value = if field == "type" { r#type } else { subtype };
                    *value = b"\xff".as_slice().try_into().unwrap();
                }
                "encoding" => {
                    body.basic.content_transfer_encoding = b"\xff".as_slice().try_into().unwrap();
                }
                _ => unreachable!(),
            }
            for malformed_first in [false, true] {
                let (children, wanted) = if malformed_first {
                    (vec![malformed.clone(), leaf(true)], 2)
                } else {
                    (vec![leaf(true), malformed.clone()], 1)
                };
                let wanted = Part(NonZeroU32::new(wanted).unwrap().into());
                let selected = attachments(&multipart(children), &Limits::default(), Some(&wanted));
                assert!(
                    matches!(selected, Err(Error::Protocol)),
                    "malformed {field}, malformed_first={malformed_first}"
                );
            }
        }
    }

    #[test]
    fn selected_root_attachment_preserves_unsupported_and_missing_outcomes() {
        let wanted = Part(NonZeroU32::MIN.into());
        let missing = Part(NonZeroU32::new(2).unwrap().into());
        for (encoding, expected) in [
            ("7BIT", Some(TransferEncoding::Identity)),
            ("X-UNKNOWN", None),
        ] {
            let mut structure = leaf(true);
            let BodyStructure::Single { body, .. } = &mut structure else {
                unreachable!();
            };
            body.basic.content_transfer_encoding = encoding.try_into().unwrap();
            let mut selected = attachments(&structure, &Limits::default(), Some(&wanted)).unwrap();
            assert_eq!(selected.len(), 1);
            let selected = selected.pop().unwrap();
            assert_eq!(selected.part, wanted);
            assert_eq!(selected.encoding, expected);
            assert!(
                attachments(&structure, &Limits::default(), Some(&missing))
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
