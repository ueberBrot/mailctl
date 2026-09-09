//! The envelope FETCH contract: requested fields, validation, and normalization.
use super::{Address, Envelope, Error};
use io_imap::types::{
    core::NString,
    datetime::DateTime,
    envelope::Envelope as WireEnvelope,
    fetch::{MessageDataItem, MessageDataItemName},
    flag::FlagFetch,
};
use std::num::NonZeroU32;

pub(super) struct Projection<'a, 'b> {
    uid: NonZeroU32,
    envelope: &'a WireEnvelope<'b>,
    flags: &'a [FlagFetch<'b>],
    internal_date: &'a DateTime,
    size: u32,
}
impl<'a, 'b> Projection<'a, 'b> {
    pub const FIELDS: [MessageDataItemName<'static>; 5] = [
        MessageDataItemName::Uid,
        MessageDataItemName::Envelope,
        MessageDataItemName::Flags,
        MessageDataItemName::InternalDate,
        MessageDataItemName::Rfc822Size,
    ];
    /// Rejects unknown, duplicate, and missing fields before the backend can merge rows.
    pub fn parse(items: &'a [MessageDataItem<'b>]) -> Result<Self, Error> {
        let mut uid = None;
        let mut envelope = None;
        let mut flags = None;
        let mut internal_date = None;
        let mut size = None;
        for item in items {
            let duplicate = match item {
                MessageDataItem::Uid(value) => uid.replace(*value).is_some(),
                MessageDataItem::Envelope(value) => envelope.replace(value).is_some(),
                MessageDataItem::Flags(value) => flags.replace(value.as_slice()).is_some(),
                MessageDataItem::InternalDate(value) => internal_date.replace(value).is_some(),
                MessageDataItem::Rfc822Size(value) => size.replace(*value).is_some(),
                _ => return Err(Error::Unsupported),
            };
            if duplicate {
                return Err(Error::Protocol);
            }
        }
        Ok(Self {
            uid: uid.ok_or(Error::Protocol)?,
            envelope: envelope.ok_or(Error::Protocol)?,
            flags: flags.ok_or(Error::Protocol)?,
            internal_date: internal_date.ok_or(Error::Protocol)?,
            size: size.ok_or(Error::Protocol)?,
        })
    }
    pub fn normalize(self) -> Envelope {
        Envelope {
            uid: self.uid.get(),
            subject: string(&self.envelope.subject),
            from: addresses(&self.envelope.from),
            to: addresses(&self.envelope.to),
            cc: addresses(&self.envelope.cc),
            received_date: Some(self.internal_date.as_ref().to_rfc3339()),
            sent_date: string(&self.envelope.date),
            flags: self
                .flags
                .iter()
                .map(|flag| match flag {
                    FlagFetch::Flag(flag) => flag.to_string(),
                    FlagFetch::Recent => "\\Recent".to_owned(),
                })
                .collect(),
            message_id: string(&self.envelope.message_id),
            size: Some(self.size),
        }
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
