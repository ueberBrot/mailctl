//! The envelope FETCH contract: requested fields, validation, and normalization.
use super::{Address, Envelope, Error};
use io_imap::types::{
    core::NString,
    datetime::DateTime,
    envelope::Envelope as WireEnvelope,
    fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
    flag::FlagFetch,
};
use std::num::NonZeroU32;

#[derive(Clone, Copy)]
enum Kind {
    Uid,
    Envelope,
    Flags,
    InternalDate,
    Size,
}
const FIELDS: [Kind; 5] = [
    Kind::Uid,
    Kind::Envelope,
    Kind::Flags,
    Kind::InternalDate,
    Kind::Size,
];
impl Kind {
    fn request(self) -> MessageDataItemName<'static> {
        match self {
            Self::Uid => MessageDataItemName::Uid,
            Self::Envelope => MessageDataItemName::Envelope,
            Self::Flags => MessageDataItemName::Flags,
            Self::InternalDate => MessageDataItemName::InternalDate,
            Self::Size => MessageDataItemName::Rfc822Size,
        }
    }
}

enum Field<'a, 'b> {
    Uid(NonZeroU32),
    Envelope(&'a WireEnvelope<'b>),
    Flags(&'a [FlagFetch<'b>]),
    InternalDate(&'a DateTime),
    Size(u32),
}
impl<'a, 'b> Field<'a, 'b> {
    fn classify(item: &'a MessageDataItem<'b>) -> Result<(Kind, Self), Error> {
        Ok(match item {
            MessageDataItem::Uid(uid) => (Kind::Uid, Self::Uid(*uid)),
            MessageDataItem::Envelope(envelope) => (Kind::Envelope, Self::Envelope(envelope)),
            MessageDataItem::Flags(flags) => (Kind::Flags, Self::Flags(flags)),
            MessageDataItem::InternalDate(date) => (Kind::InternalDate, Self::InternalDate(date)),
            MessageDataItem::Rfc822Size(size) => (Kind::Size, Self::Size(*size)),
            _ => return Err(Error::Unsupported),
        })
    }
    fn project(self, result: &mut Envelope) {
        match self {
            Self::Uid(uid) => result.uid = uid.get(),
            Self::Envelope(envelope) => {
                result.subject = string(&envelope.subject);
                result.from = addresses(&envelope.from);
                result.to = addresses(&envelope.to);
                result.cc = addresses(&envelope.cc);
                result.sent_date = string(&envelope.date);
                result.message_id = string(&envelope.message_id);
            }
            Self::Flags(flags) => {
                result.flags = flags
                    .iter()
                    .map(|flag| match flag {
                        FlagFetch::Flag(flag) => flag.to_string(),
                        FlagFetch::Recent => "\\Recent".to_owned(),
                    })
                    .collect();
            }
            Self::InternalDate(date) => result.received_date = Some(date.as_ref().to_rfc3339()),
            Self::Size(size) => result.size = Some(size),
        }
    }
}

pub(super) struct Projection<'a, 'b> {
    fields: [Option<Field<'a, 'b>>; FIELDS.len()],
}
impl<'a, 'b> Projection<'a, 'b> {
    pub fn request() -> MacroOrMessageDataItemNames<'static> {
        MacroOrMessageDataItemNames::MessageDataItemNames(FIELDS.map(Kind::request).to_vec())
    }
    /// Rejects unknown, duplicate, and missing fields before the backend can merge rows.
    pub fn parse(items: &'a [MessageDataItem<'b>]) -> Result<Self, Error> {
        let mut fields = [const { None }; FIELDS.len()];
        for item in items {
            let (kind, field) = Field::classify(item)?;
            if fields[kind as usize].replace(field).is_some() {
                return Err(Error::Protocol);
            }
        }
        if fields.iter().any(Option::is_none) {
            return Err(Error::Protocol);
        }
        Ok(Self { fields })
    }
    pub fn normalize(self) -> Envelope {
        let mut envelope = Envelope::default();
        for field in self.fields.into_iter().flatten() {
            field.project(&mut envelope);
        }
        envelope
    }
}
fn string(value: &NString<'_>) -> Option<String> {
    value
        .0
        .as_ref()
        .map(|s| String::from_utf8_lossy(s.as_ref()).into_owned())
}
fn addresses(values: &[io_imap::types::envelope::Address<'_>]) -> Vec<Address> {
    values
        .iter()
        .map(|address| Address {
            name: string(&address.name),
            mailbox: string(&address.mailbox),
            host: string(&address.host),
        })
        .collect()
}
