//! Typed bounded FETCH requests and response validation, shared by body and attachment reads.
use super::{Error, mime::part_name, wire::Connection};
use io_imap::{
    rfc3501::fetch::{ImapMessageFetch, ImapMessageFetchOptions},
    types::{
        body::BodyStructure,
        command::CommandBody,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Section},
        sequence::{SeqOrUid, Sequence, SequenceSet},
    },
};
use std::num::NonZeroU32;

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
        let Some(end) = frame.windows(2).position(|bytes| bytes == b"\r\n") else {
            return Ok(None);
        };
        let line = &frame[..end];
        if !line.windows(2).any(|bytes| bytes == b">{") {
            return Ok(None);
        }
        let section = match section {
            None => String::new(),
            Some(Section::Header(None)) => "HEADER".to_owned(),
            Some(Section::Part(part)) => part_name(part),
            Some(Section::Mime(part)) => format!("{}.MIME", part_name(part)),
            _ => return Ok(None),
        };
        let prefix = format!("BODY[{section}]<{offset}>");
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
        let names = match self {
            Self::Metadata { .. } => vec![
                MessageDataItemName::Uid,
                MessageDataItemName::Rfc822Size,
                MessageDataItemName::BodyStructure,
            ],
            Self::Bytes {
                section,
                offset,
                count,
                ..
            } => vec![
                MessageDataItemName::Uid,
                MessageDataItemName::BodyExt {
                    section: section.clone(),
                    partial: Some((
                        *offset,
                        NonZeroU32::new(*count).expect("nonzero bounded chunk"),
                    )),
                    peek: true,
                },
            ],
        };
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
    pub(super) fn metadata<'a, 'b>(
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
    pub(super) fn data<'a>(&self, items: &'a [MessageDataItem<'_>]) -> Result<&'a [u8], Error> {
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
    pub(super) async fn execute(
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
        if rows.is_empty() {
            return Err(Error::MessageNotFound);
        }
        if rows.len() != 1 {
            return Err(Error::Protocol);
        }
        let items = rows.pop_first().ok_or(Error::Protocol)?.1.into_inner();
        self.validate(&items)?;
        Ok(items)
    }
}
