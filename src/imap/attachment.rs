//! Bounded attachment transfer ownership and verified IMAP retrieval.
mod decoder;
use super::{
    Error, Limits, Metrics,
    fetch::{Fetch, Section},
    mailbox,
    mime::{Part, attachment, common, encoding_name, part_name, single, validate_structure},
    wire::Connection,
};
use decoder::{Decoder, TransferEncoding};
use imap_proto::BodyStructure;
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
            // response pair would approach the operation budget. Zero-output transfer prefixes
            // keep reading until they produce a page, finish, or reach the ordinary resource limit.
            if fetched
                && self.decoder.pending_len() != 0
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
            let wire = fetch.data(Fetch::items(&fields)?)?;
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
        conn.logout().await?;
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
    Ok(values)
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
            BodyStructure::Multipart { bodies, .. } => {
                for (index, child) in bodies.iter().enumerate() {
                    let number =
                        NonZeroU32::new(u32::try_from(index + 1).map_err(|_| Error::Limit)?)
                            .ok_or(Error::Limit)?;
                    path.push(number);
                    visit(child, path, output, wanted)?;
                    path.pop();
                }
            }
            _ => {
                if attachment(common(structure).disposition.as_ref())
                    && let Some(definition) = attachment_definition(path, structure, wanted)?
                {
                    output.push(definition);
                }
                // Attached messages use their enclosing RFC822 section. Their embedded bodies
                // cannot be traversed as ordinary multipart children.
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
    structure: &BodyStructure<'_>,
    wanted: Option<&Part>,
) -> Result<Option<AttachmentDefinition>, Error> {
    let fields = common(structure);
    let body = single(structure).ok_or(Error::Protocol)?;
    let encoding = encoding_name(&body.transfer_encoding).trim();
    let encoding = if encoding.eq_ignore_ascii_case("7bit")
        || encoding.eq_ignore_ascii_case("8bit")
        || encoding.eq_ignore_ascii_case("binary")
    {
        Some(TransferEncoding::Identity)
    } else if encoding.eq_ignore_ascii_case("base64") {
        Some(TransferEncoding::Base64)
    } else if encoding.eq_ignore_ascii_case("quoted-printable") {
        Some(TransferEncoding::QuotedPrintable)
    } else {
        None
    };
    let path = if path.is_empty() {
        &[NonZeroU32::MIN]
    } else {
        path
    };
    if wanted.is_some_and(|wanted| wanted.as_slice() != path) {
        return Ok(None);
    }
    let filename = fields
        .disposition
        .as_ref()
        .and_then(|disposition| disposition.params.as_ref())
        .and_then(|parameters| {
            parameters
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("filename"))
        })
        .and_then(|(_, value)| safe_filename(value));
    let mut media_type = format!("{}/{}", fields.ty.ty, fields.ty.subtype);
    media_type.make_ascii_lowercase();
    Ok(Some(AttachmentDefinition {
        part: path.to_vec(),
        filename,
        media_type,
        declared_size: Some(body.octets as u64),
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
        conn.logout().await?;
        Ok(result)
    }
}
impl Limits {
    pub(crate) fn attachment(limits: &crate::config::Limits) -> Self {
        let defaults = Self::default();
        let max_response_bytes = defaults.max_response_bytes.min(limits.wire_fetch_bytes);
        Self {
            max_response_bytes,
            max_literal_bytes: defaults.max_literal_bytes.min(max_response_bytes),
            max_header_bytes: limits.header_bytes,
            max_nesting: limits.mime_depth,
            max_mime_parts: limits.mime_parts,
            max_attachment_wire_bytes: limits.attachment_wire_bytes,
            max_attachment_decoded_bytes: limits.attachment_decoded_bytes,
            max_attachment_chunk_bytes: limits.attachment_chunk_bytes,
            max_operation_bytes: limits.wire_fetch_bytes,
            ..defaults
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
    let (_, structure) = Fetch::metadata(Fetch::items(&fields)?)?;
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
    use imap_proto::{
        BodyContentCommon, BodyContentSinglePart, ContentDisposition, ContentEncoding, ContentType,
        Envelope,
    };

    fn leaf(attached: bool) -> BodyStructure<'static> {
        BodyStructure::Basic {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: "APPLICATION".into(),
                    subtype: "OCTET-STREAM".into(),
                    params: None,
                },
                disposition: attached.then(|| ContentDisposition {
                    ty: "ATTACHMENT".into(),
                    params: None,
                }),
                language: None,
                location: None,
            },
            other: BodyContentSinglePart {
                id: None,
                description: None,
                md5: None,
                transfer_encoding: ContentEncoding::SevenBit,
                octets: 5,
            },
            extension: None,
        }
    }

    fn multipart(bodies: Vec<BodyStructure<'static>>) -> BodyStructure<'static> {
        BodyStructure::Multipart {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: "MULTIPART".into(),
                    subtype: "MIXED".into(),
                    params: None,
                },
                disposition: None,
                language: None,
                location: None,
            },
            bodies,
            extension: None,
        }
    }

    fn attached_message(embedded: BodyStructure<'static>) -> BodyStructure<'static> {
        let BodyStructure::Basic {
            mut common,
            other,
            extension,
        } = leaf(true)
        else {
            unreachable!();
        };
        common.ty.ty = "MESSAGE".into();
        common.ty.subtype = "RFC822".into();
        BodyStructure::Message {
            common,
            other,
            extension,
            envelope: Envelope {
                date: None,
                subject: None,
                from: None,
                sender: None,
                reply_to: None,
                to: None,
                cc: None,
                bcc: None,
                in_reply_to: None,
                message_id: None,
            },
            body: Box::new(embedded),
            lines: 1,
        }
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
            let mut structure = multipart((0..parts - depth + 1).map(|_| leaf(false)).collect());
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
            let leaves = parts - depth + 1;
            let mut structure = multipart(
                (0..leaves)
                    .map(|_| {
                        let mut entry = leaf(true);
                        let BodyStructure::Basic { common, .. } = &mut entry else {
                            unreachable!();
                        };
                        common.disposition.as_mut().unwrap().params =
                            Some(vec![("FILENAME".into(), "report.txt".into())]);
                        entry
                    })
                    .collect(),
            );
            for _ in 2..depth {
                structure = multipart(vec![structure]);
            }
            let mut path = vec![NonZeroU32::MIN; depth - 2];
            path.push(NonZeroU32::new(leaves as u32).unwrap());
            let wanted = path;
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
    fn selecting_one_attachment_keeps_each_siblings_encoding_and_filename() {
        let mut first = leaf(true);
        let BodyStructure::Basic { common, other, .. } = &mut first else {
            unreachable!();
        };
        common.disposition.as_mut().unwrap().params =
            Some(vec![("FILENAME".into(), "quoted\"name\\file.txt".into())]);
        other.transfer_encoding = ContentEncoding::Other("X-UNKNOWN".into());
        let structure = multipart(vec![first, leaf(true)]);
        for (number, encoding, filename) in [
            (1, None, Some("quoted\"name\\file.txt")),
            (2, Some(TransferEncoding::Identity), None),
        ] {
            let wanted = vec![NonZeroU32::new(number).unwrap()];
            let selected = attachments(&structure, &Limits::default(), Some(&wanted)).unwrap();
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].part, wanted);
            assert_eq!(selected[0].encoding, encoding);
            assert_eq!(selected[0].filename.as_deref(), filename);
        }
    }

    #[test]
    fn selected_root_attachment_preserves_unsupported_and_missing_outcomes() {
        let wanted = vec![NonZeroU32::MIN];
        let missing = vec![NonZeroU32::new(2).unwrap()];
        for (encoding, expected) in [
            ("7BIT", Some(TransferEncoding::Identity)),
            ("BINARY", Some(TransferEncoding::Identity)),
            ("X-UNKNOWN", None),
        ] {
            let mut structure = leaf(true);
            let BodyStructure::Basic { other, .. } = &mut structure else {
                unreachable!();
            };
            other.transfer_encoding = imap_proto::ContentEncoding::Other(encoding.into());
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
