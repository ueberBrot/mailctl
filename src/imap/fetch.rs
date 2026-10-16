//! Bounded FETCH requests and validation shared by body and attachment retrieval.
use super::{
    Error, Limits,
    admission::FrameContract,
    mime::{Part, part_name},
    wire::{Connection, Kind},
};
use imap_proto::{AttributeValue, BodyStructure, MessageSection, Response, SectionPath};

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

#[derive(Clone, Debug)]
pub(super) enum Section {
    Header,
    Mime(Part),
    Part(Part),
}
impl Section {
    fn name(&self) -> String {
        match self {
            Self::Header => "HEADER".into(),
            Self::Mime(part) => format!("{}.MIME", part_name(part)),
            Self::Part(part) => part_name(part),
        }
    }
    fn path(&self) -> SectionPath {
        match self {
            Self::Header => SectionPath::Full(MessageSection::Header),
            Self::Mime(part) => SectionPath::Part(
                part.iter().map(|v| v.get()).collect(),
                Some(MessageSection::Mime),
            ),
            Self::Part(part) => SectionPath::Part(part.iter().map(|v| v.get()).collect(), None),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum Fetch {
    Metadata {
        uid: u32,
    },
    Bytes {
        uid: u32,
        section: Option<Section>,
        offset: u32,
        count: u32,
    },
}
impl Fetch {
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
                    && *returned == section.as_ref().map(Section::path)
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
                Kind::Body(self.clone()),
            )
            .await?;
        if rows.len() != 1 {
            return Err(Error::MessageNotFound);
        }
        Ok(rows.remove(0))
    }
}
