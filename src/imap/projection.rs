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
    /// Bound source field octets before malformed/encoded metadata can shrink or grow.
    pub(super) fn check_header_bytes(&self, maximum: usize) -> Result<(), Error> {
        let mut remaining = maximum;
        let mut count = |value: &NString<'_>| {
            let length = value.0.as_ref().map_or(0, |value| value.as_ref().len());
            remaining = remaining.checked_sub(length).ok_or(Error::Limit)?;
            Ok::<_, Error>(())
        };
        for value in [
            &self.envelope.date,
            &self.envelope.subject,
            &self.envelope.in_reply_to,
            &self.envelope.message_id,
        ] {
            count(value)?;
        }
        for addresses in [
            &self.envelope.from,
            &self.envelope.sender,
            &self.envelope.reply_to,
            &self.envelope.to,
            &self.envelope.cc,
            &self.envelope.bcc,
        ] {
            for address in addresses {
                for value in [&address.name, &address.adl, &address.mailbox, &address.host] {
                    count(value)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn message(self) -> crate::search::LocatedMessage {
        use crate::domain::MessageMetadata;
        let mut flags = self
            .flags
            .iter()
            .map(|flag| match flag {
                FlagFetch::Flag(flag) => flag.to_string(),
                FlagFetch::Recent => "\\Recent".into(),
            })
            .collect::<Vec<_>>();
        flags.sort();
        flags.dedup();
        crate::search::LocatedMessage {
            uid: self.uid.get(),
            metadata: MessageMetadata {
                subject: metadata(&self.envelope.subject, header_text),
                from: parsed_addresses(&self.envelope.from),
                to: parsed_addresses(&self.envelope.to),
                cc: parsed_addresses(&self.envelope.cc),
                received_date: self.internal_date.as_ref().to_rfc3339(),
                sent_date: metadata(&self.envelope.date, |bytes| {
                    let value = std::str::from_utf8(bytes).ok()?;
                    let date = mail_parser::DateTime::parse_rfc822(value)?;
                    date.is_valid().then(|| date.to_rfc3339())
                }),
                flags,
                message_id: metadata(&self.envelope.message_id, message_id),
                size: self.size,
            },
        }
    }
}

fn metadata<T>(
    value: &NString<'_>,
    parse: impl FnOnce(&[u8]) -> Option<T>,
) -> crate::domain::Metadata<T> {
    use crate::domain::Metadata;
    match &value.0 {
        None => Metadata::Missing,
        Some(value) => parse(value.as_ref()).map_or(Metadata::Malformed, Metadata::Present),
    }
}
fn header_text(bytes: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?;
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t'))
    {
        return None;
    }
    // A literal is one header value; an embedded new header is malformed metadata.
    for (index, byte) in bytes.iter().enumerate() {
        if (*byte == b'\n' && !matches!(bytes.get(index + 1), Some(b' ' | b'\t')))
            || (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
        {
            return None;
        }
    }
    let mut line = bytes.to_vec();
    line.extend_from_slice(b"\r\n");
    let parsed = mail_parser::parsers::MessageStream::new(&line).parse_unstructured();
    match parsed {
        mail_parser::HeaderValue::Text(value) => Some(value.into_owned()),
        mail_parser::HeaderValue::Empty if bytes.iter().all(u8::is_ascii_whitespace) => {
            Some(String::new())
        }
        _ => None,
    }
}
fn parsed_addresses(
    values: &[io_imap::types::envelope::Address<'_>],
) -> crate::domain::Metadata<Vec<crate::domain::MessageAddress>> {
    use crate::domain::{MessageAddress, Metadata};
    if values.is_empty() {
        return Metadata::Missing;
    }
    let mut addresses = Vec::new();
    let mut group = false;
    for value in values {
        match (&value.mailbox.0, &value.host.0) {
            (Some(name), None) if !group => {
                if std::str::from_utf8(name.as_ref())
                    .ok()
                    .is_none_or(str::is_empty)
                {
                    return Metadata::Malformed;
                }
                group = true;
            }
            (None, None) if group => group = false,
            (Some(local), Some(host)) => {
                let (Ok(local), Ok(host)) = (
                    std::str::from_utf8(local.as_ref()),
                    std::str::from_utf8(host.as_ref()),
                ) else {
                    return Metadata::Malformed;
                };
                if local.is_empty() || local.chars().any(char::is_control) || !domain(host) {
                    return Metadata::Malformed;
                }
                let name = match metadata(&value.name, header_text) {
                    Metadata::Present(name) => Some(name),
                    Metadata::Missing => None,
                    Metadata::Malformed => return Metadata::Malformed,
                };
                let local = if dot_atom(local) {
                    local.to_owned()
                } else {
                    format!("\"{}\"", local.replace('\\', "\\\\").replace('"', "\\\""))
                };
                addresses.push(MessageAddress {
                    name,
                    address: format!("{local}@{host}"),
                });
            }
            _ => return Metadata::Malformed,
        }
    }
    if group {
        Metadata::Malformed
    } else {
        Metadata::Present(addresses)
    }
}
fn dot_atom(value: &str) -> bool {
    value.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b))
    })
}
fn domain(value: &str) -> bool {
    dot_atom(value)
        || value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(|literal| {
                !literal.is_empty()
                    && literal
                        .bytes()
                        .all(|b| (33..=126).contains(&b) && !b"[]\\".contains(&b))
            })
}
fn message_id(bytes: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = skip_comments(value)?.strip_prefix('<')?;
    let (identifier, tail) = value.rsplit_once('>')?;
    if !skip_comments(tail)?.is_empty() {
        return None;
    }
    let (local, host) = identifier.split_once('@')?;
    if !dot_atom(local) || !domain(host) {
        return None;
    }
    Some(format!("<{identifier}>"))
}
fn skip_comments(mut value: &str) -> Option<&str> {
    loop {
        value = value.trim_start_matches([' ', '\t', '\r', '\n']);
        if !value.starts_with('(') {
            return Some(value);
        }
        let mut depth = 0usize;
        let mut escaped = false;
        let mut end = None;
        for (index, byte) in value.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'(' => {
                    depth += 1;
                    if depth > 20 {
                        return None;
                    }
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        value = &value[end?..];
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
