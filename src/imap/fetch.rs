//! Bounded FETCH requests and validation shared by body and attachment retrieval.
use super::{
    Error, Limits,
    admission::FrameContract,
    mime::part_name,
    wire::{Connection, Kind},
};
use imap_proto::{AttributeValue, BodyStructure, MessageSection, Response, SectionPath};
use std::num::NonZeroU32;

pub(super) const MAX_CHUNK_BYTES: usize = 16 * 1024;

impl Limits {
    pub(super) fn fetch_chunk_bytes(&self) -> Result<usize, Error> {
        match MAX_CHUNK_BYTES
            .min(self.max_literal_bytes)
            .min(self.max_response_bytes / 2)
        {
            0 => Err(Error::InvalidInput),
            count => Ok(count),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Section<'a> {
    Header,
    Mime(&'a [NonZeroU32]),
    Part(&'a [NonZeroU32]),
}
impl Section<'_> {
    fn name(&self) -> String {
        match self {
            Self::Header => "HEADER".into(),
            Self::Mime(part) => format!("{}.MIME", part_name(part)),
            Self::Part(part) => part_name(part),
        }
    }
    fn matches(&self, returned: &SectionPath) -> bool {
        match (self, returned) {
            (Self::Header, SectionPath::Full(MessageSection::Header)) => true,
            (Self::Mime(part), SectionPath::Part(path, Some(MessageSection::Mime)))
            | (Self::Part(part), SectionPath::Part(path, None)) => part
                .iter()
                .map(|number| number.get())
                .eq(path.iter().copied()),
            _ => false,
        }
    }
}

#[derive(Debug)]
pub(super) enum Fetch<'a> {
    Metadata {
        uid: u32,
    },
    Bytes {
        uid: u32,
        section: Option<Section<'a>>,
        offset: u32,
        count: u32,
    },
}
impl Fetch<'_> {
    pub(super) fn items<'a>(
        row: &'a Response<'static>,
    ) -> Result<&'a [AttributeValue<'static>], Error> {
        match row {
            Response::Fetch(sequence, items) if *sequence != 0 => Ok(items),
            _ => Err(Error::Protocol),
        }
    }
    fn uid(&self) -> u32 {
        match self {
            Self::Metadata { uid } | Self::Bytes { uid, .. } => *uid,
        }
    }
    pub(super) fn contract(&self) -> FrameContract {
        match self {
            Self::Metadata { .. } => FrameContract::Metadata,
            Self::Bytes {
                section,
                offset,
                count,
                ..
            } => FrameContract::Body {
                section: section.as_ref().map_or_else(String::new, Section::name),
                offset: *offset,
                count: *count as usize,
            },
        }
    }
    pub(super) fn validate(&self, items: &[AttributeValue<'_>]) -> Result<(), Error> {
        let mut uid = None;
        for item in items {
            if let AttributeValue::Uid(value) = item
                && uid.replace(*value).is_some()
            {
                return Err(Error::Protocol);
            }
        }
        if uid != Some(self.uid()) || self.uid() == 0 {
            return Err(Error::Protocol);
        }
        match self {
            Self::Metadata { .. } => {
                Self::metadata(items)?;
            }
            Self::Bytes { .. } => {
                self.data(items)?;
            }
        }
        Ok(())
    }
    pub(super) fn metadata<'a, 'b>(
        items: &'a [AttributeValue<'b>],
    ) -> Result<(u32, &'a BodyStructure<'b>), Error> {
        if items.len() != 3 {
            return Err(Error::Protocol);
        }
        let mut size = None;
        let mut structure = None;
        for item in items {
            match item {
                AttributeValue::Uid(_) => {}
                AttributeValue::Rfc822Size(value) if size.is_none() => size = Some(*value),
                AttributeValue::BodyStructure(value) if structure.is_none() => {
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
    pub(super) fn data<'a>(&self, items: &'a [AttributeValue<'_>]) -> Result<&'a [u8], Error> {
        let Self::Bytes {
            section,
            offset,
            count,
            ..
        } = self
        else {
            return Err(Error::InvalidInput);
        };
        if items.len() != 2 {
            return Err(Error::Protocol);
        }
        let mut data = None;
        for item in items {
            match item {
                AttributeValue::Uid(_) => {}
                AttributeValue::BodySection {
                    section: returned,
                    index,
                    data: Some(value),
                } if data.is_none()
                    && match (section, returned) {
                        (None, None) => true,
                        (Some(expected), Some(returned)) => expected.matches(returned),
                        _ => false,
                    }
                    && *index == Some(*offset)
                    && value.len() <= *count as usize =>
                {
                    data = Some(value.as_ref())
                }
                _ => return Err(Error::Protocol),
            }
        }
        data.ok_or(Error::Protocol)
    }
    pub(super) async fn execute(
        &self,
        connection: &mut Connection<'_>,
    ) -> Result<Response<'static>, Error> {
        if self.uid() == 0 {
            return Err(Error::InvalidInput);
        }
        let query = match self {
            Self::Metadata { .. } => "UID RFC822.SIZE BODYSTRUCTURE".to_owned(),
            Self::Bytes {
                section,
                offset,
                count,
                ..
            } => {
                if *count == 0 || *count as usize > connection.literal_limit() {
                    return Err(Error::Limit);
                }
                format!(
                    "UID BODY.PEEK[{}]<{offset}.{count}>",
                    section.as_ref().map_or_else(String::new, Section::name)
                )
            }
        };
        let mut rows = connection
            .request(
                &format!("UID FETCH {} ({query})", self.uid()),
                Kind::Body(self),
            )
            .await?;
        if rows.len() != 1 {
            return Err(Error::MessageNotFound);
        }
        Ok(rows.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn repeated_partial_fetch_validation_borrows_nested_section_paths() {
        let part = vec![NonZeroU32::new(3).unwrap(); 40];
        for (section, returned) in [
            (None, None),
            (
                Some(Section::Header),
                Some(SectionPath::Full(MessageSection::Header)),
            ),
            (
                Some(Section::Mime(&part)),
                Some(SectionPath::Part(vec![3; 40], Some(MessageSection::Mime))),
            ),
            (
                Some(Section::Part(&part)),
                Some(SectionPath::Part(vec![3; 40], None)),
            ),
        ] {
            let request = Fetch::Bytes {
                uid: 4,
                section,
                offset: 16_384,
                count: 16_384,
            };
            let mut fields = [
                AttributeValue::Uid(4),
                AttributeValue::BodySection {
                    section: returned,
                    index: Some(16_384),
                    data: Some(Cow::Borrowed(b"payload")),
                },
            ];
            let measured = allocation_counter::measure(|| {
                for _ in 0..64 {
                    request.validate(&fields).unwrap();
                    assert_eq!(request.data(&fields).unwrap(), b"payload");
                }
            });
            assert_eq!(measured.count_total, 0, "{measured:?}");
            let AttributeValue::BodySection { section, .. } = &mut fields[1] else {
                unreachable!();
            };
            *section = Some(SectionPath::Part(vec![3; 39], None));
            assert_eq!(request.validate(&fields), Err(Error::Protocol));
            let AttributeValue::BodySection { section, index, .. } = &mut fields[1] else {
                unreachable!();
            };
            *section = None;
            *index = Some(0);
            assert_eq!(request.validate(&fields), Err(Error::Protocol));
        }
    }
}
