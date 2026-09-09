//! A bounded body read owns selection, byte retrieval, representation, and continuation.
mod representation;

use super::{Error, ImapProbe, Limits, Metrics, credentials, mailbox, wire::Connection};
use io_imap::{
    rfc3501::{
        fetch::{ImapMessageFetch, ImapMessageFetchOptions},
        logout::ImapLogout,
    },
    types::{
        body::BodyStructure,
        command::CommandBody,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Part, Section},
        sequence::{SeqOrUid, Sequence, SequenceSet},
    },
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, num::NonZeroU32};

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
            let mut related_ids = BTreeMap::new();
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
                    Section::Mime(part(&path)?),
                    &limits,
                    &mut header_bytes,
                )
                .await?;
                if let Some(id) = representation::validate_headers(&raw, None, &limits)? {
                    related_ids.insert(path, id);
                }
            }
            let selected = representation::select(structure, &limits, &related_ids)?;
            let mut raw = Vec::new();
            let rendered = if let Some(selected) = &selected {
                if selected.wire_size > limits.max_body_wire_bytes {
                    return Err(Error::Limit);
                }
                let single = matches!(structure, BodyStructure::Single { .. });
                if single {
                    representation::validate_headers(&root_headers, Some(selected), &limits)?;
                }
                if single && size as usize <= limits.max_body_wire_bytes {
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
                    raw.extend_from_slice(&whole[root_headers.len()..]);
                } else {
                    raw = bytes(
                        &mut conn,
                        request.uid,
                        Some(Section::Part(part(&selected.part)?)),
                        Some(selected.wire_size),
                        limits.max_body_wire_bytes,
                        &limits,
                    )
                    .await?;
                }
                tokio::task::yield_now().await;
                Some(representation::render(selected, &raw, &limits)?)
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
            context.update(&raw);
            if let Some(selected) = &selected {
                context.update(selected.part.as_bytes());
                context.update(selected.media_type.as_bytes());
                context.update(selected.charset.as_bytes());
                context.update(selected.transfer_encoding.as_bytes());
            }
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
                text: text[offset..end].to_owned(),
                selected_part: selected.as_ref().map(|s| s.part.clone()),
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
}

fn part(path: &str) -> Result<Part, Error> {
    let parts = path
        .split('.')
        .map(|value| value.parse::<NonZeroU32>().map_err(|_| Error::Protocol))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Part(parts.try_into().map_err(|_| Error::Protocol)?))
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
        let part_name = |part: &Part| {
            part.0
                .as_ref()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(".")
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
