//! The envelope FETCH contract: requested fields, validation, and normalization.
use super::Error;
use crate::domain::dot_atom;
use imap_proto::{AttributeValue, Envelope as WireEnvelope};
use std::{borrow::Cow, num::NonZeroU32};

pub(super) struct Projection<'a, 'b> {
    uid: NonZeroU32,
    envelope: &'a WireEnvelope<'b>,
    flags: &'a [Cow<'b, str>],
    internal_date: chrono::DateTime<chrono::FixedOffset>,
    size: u32,
}
impl<'a, 'b> Projection<'a, 'b> {
    pub const FIELDS: &'static str = "UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE";
    /// Rejects unknown, duplicate, and missing fields before the backend can merge rows.
    pub fn parse(items: &'a [AttributeValue<'b>]) -> Result<Self, Error> {
        let mut uid = None;
        let mut envelope = None;
        let mut flags = None;
        let mut internal_date = None;
        let mut size = None;
        for item in items {
            let duplicate = match item {
                AttributeValue::Uid(value) => uid.replace(*value).is_some(),
                AttributeValue::Envelope(value) => envelope.replace(value).is_some(),
                AttributeValue::Flags(value) => flags.replace(value.as_slice()).is_some(),
                AttributeValue::InternalDate(value) => internal_date.replace(value).is_some(),
                AttributeValue::Rfc822Size(value) => size.replace(*value).is_some(),
                _ => return Err(Error::Unsupported),
            };
            if duplicate {
                return Err(Error::Protocol);
            }
        }
        Ok(Self {
            uid: NonZeroU32::new(uid.ok_or(Error::Protocol)?).ok_or(Error::Protocol)?,
            envelope: envelope.ok_or(Error::Protocol)?,
            flags: flags.ok_or(Error::Protocol)?,
            internal_date: chrono::DateTime::parse_from_str(
                internal_date.ok_or(Error::Protocol)?,
                "%d-%b-%Y %H:%M:%S %z",
            )
            .map_err(|_| Error::Protocol)?,
            size: size.ok_or(Error::Protocol)?,
        })
    }
    /// Bound source field octets before malformed/encoded metadata can shrink or grow.
    pub(super) fn check_header_bytes(&self, maximum: usize) -> Result<(), Error> {
        let mut remaining = maximum;
        let mut count = |value: &Option<Cow<'_, [u8]>>| {
            let length = value.as_ref().map_or(0, |value| value.as_ref().len());
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
            for address in addresses.iter().flatten() {
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
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        flags.sort_unstable();
        flags.dedup();
        crate::search::LocatedMessage {
            uid: self.uid.get(),
            metadata: MessageMetadata {
                subject: metadata(&self.envelope.subject, header_text),
                from: parsed_addresses(&self.envelope.from),
                to: parsed_addresses(&self.envelope.to),
                cc: parsed_addresses(&self.envelope.cc),
                received_date: self.internal_date.to_rfc3339(),
                sent_date: metadata(&self.envelope.date, |bytes| {
                    let value = std::str::from_utf8(bytes).ok()?;
                    let date = mail_parser::DateTime::parse_rfc822(value)?;
                    chrono::NaiveDate::from_ymd_opt(
                        date.year.into(),
                        date.month.into(),
                        date.day.into(),
                    )?;
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
    value: &Option<Cow<'_, [u8]>>,
    parse: impl FnOnce(&[u8]) -> Option<T>,
) -> crate::domain::Metadata<T> {
    use crate::domain::Metadata;
    match value {
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
    if !value.contains(['\r', '\n']) && !value.contains("=?") {
        // One unencoded line needs only the parser's outer ASCII whitespace trim.
        return Some(value.trim_matches([' ', '\t']).to_owned());
    }
    // A literal is one header value; an embedded new header is malformed metadata.
    for (index, byte) in bytes.iter().enumerate() {
        if (*byte == b'\n' && !matches!(bytes.get(index + 1), Some(b' ' | b'\t')))
            || (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
        {
            return None;
        }
    }
    let mut line = Vec::with_capacity(bytes.len() + 2);
    line.extend_from_slice(bytes);
    line.extend_from_slice(b"\r\n");
    if !encoded_word_work_is_bounded(&line) {
        return None;
    }
    let parsed = mail_parser::parsers::MessageStream::new(&line).parse_unstructured();
    match parsed {
        mail_parser::HeaderValue::Text(value) => Some(value.into_owned()),
        mail_parser::HeaderValue::Empty if bytes.iter().all(u8::is_ascii_whitespace) => {
            Some(String::new())
        }
        _ => None,
    }
}

// The pinned parser restores its position after a failed encoded word. Repeated
// malformed prefixes can otherwise decode and allocate each remaining suffix.
// Admit the same candidate attempts with a linear aggregate work allowance;
// cap each decoder's input before it can allocate that suffix.
fn encoded_word_work_is_bounded(bytes: &[u8]) -> bool {
    let mut remaining = bytes.len().saturating_mul(8);
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"=?") {
            let start = index + 1;
            let available = bytes.len() - start;
            let admitted = remaining.min(available);
            let mut stream =
                mail_parser::parsers::MessageStream::new(&bytes[start..start + admitted]);
            let decoded = stream.decode_rfc2047();
            let consumed = stream.offset();
            remaining -= consumed;
            if admitted < available && consumed == admitted {
                return false;
            }
            if decoded.is_some() {
                index = start + consumed;
                continue;
            }
        }
        index += 1;
    }
    true
}

fn parsed_addresses(
    values: &Option<Vec<imap_proto::Address<'_>>>,
) -> crate::domain::Metadata<Vec<crate::domain::MessageAddress>> {
    use crate::domain::{MessageAddress, Metadata};
    let values = values.as_deref().unwrap_or_default();
    if values.is_empty() {
        return Metadata::Missing;
    }
    let mut addresses = Vec::new();
    let mut group = false;
    for value in values {
        match (&value.mailbox, &value.host) {
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
                let address = if dot_atom(local) {
                    format!("{local}@{host}")
                } else {
                    let escapes = local
                        .bytes()
                        .filter(|byte| matches!(byte, b'"' | b'\\'))
                        .count();
                    let mut address = String::with_capacity(local.len() + escapes + host.len() + 3);
                    address.push('"');
                    for character in local.chars() {
                        if matches!(character, '"' | '\\') {
                            address.push('\\');
                        }
                        address.push(character);
                    }
                    address.push_str("\"@");
                    address.push_str(host);
                    address
                };
                addresses.push(MessageAddress { name, address });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{MessageAddress, Metadata};
    use imap_proto::Address;

    fn fields(local: &str) -> Vec<AttributeValue<'_>> {
        vec![
            AttributeValue::Uid(1),
            AttributeValue::Envelope(Box::new(WireEnvelope {
                date: None,
                subject: None,
                from: Some(vec![Address {
                    name: None,
                    adl: None,
                    mailbox: Some(Cow::Borrowed(local.as_bytes())),
                    host: Some(Cow::Borrowed(b"example.test")),
                }]),
                sender: None,
                reply_to: None,
                to: None,
                cc: None,
                bcc: None,
                in_reply_to: None,
                message_id: None,
            })),
            AttributeValue::Flags(vec![]),
            AttributeValue::InternalDate(Cow::Borrowed("01-Mar-2024 00:30:00 +1400")),
            AttributeValue::Rfc822Size(100),
        ]
    }

    #[test]
    fn projection_rejects_zero_duplicate_and_missing_uids() {
        let mut zero = fields("sender");
        zero[0] = AttributeValue::Uid(0);
        assert!(matches!(Projection::parse(&zero), Err(Error::Protocol)));
        let mut duplicate = fields("sender");
        duplicate.push(AttributeValue::Uid(1));
        assert!(matches!(
            Projection::parse(&duplicate),
            Err(Error::Protocol)
        ));
        let mut missing = fields("sender");
        missing.remove(0);
        assert!(matches!(Projection::parse(&missing), Err(Error::Protocol)));
    }

    #[test]
    fn internal_dates_validate_calendar_values_before_projection() {
        for raw in [
            "31-Feb-2024 12:00:00 +0000",
            "01-Mar-2024 24:00:00 +0000",
            "invalid",
        ] {
            let mut fields = fields("sender");
            fields[3] = AttributeValue::InternalDate(raw.into());
            assert!(
                matches!(Projection::parse(&fields), Err(Error::Protocol)),
                "{raw}"
            );
        }
        let mut fields = fields("sender");
        fields[3] = AttributeValue::InternalDate(" 1-Mar-2024 00:30:00 +1400".into());
        assert_eq!(
            Projection::parse(&fields)
                .unwrap()
                .message()
                .metadata
                .received_date,
            "2024-03-01T00:30:00+14:00"
        );
    }

    #[test]
    fn envelope_addresses_preserve_quoted_local_parts_and_dot_atoms() {
        for (local, expected) in [
            ("first.last+tag", "first.last+tag@example.test"),
            ("two words", "\"two words\"@example.test"),
            ("say\"hi\\there", "\"say\\\"hi\\\\there\"@example.test"),
            ("grüß", "\"grüß\"@example.test"),
        ] {
            let fields = fields(local);
            let message = Projection::parse(&fields).unwrap().message();
            assert_eq!(
                message.metadata.from,
                Metadata::Present(vec![MessageAddress {
                    name: None,
                    address: expected.into(),
                }]),
                "{local:?}"
            );
        }
    }

    #[test]
    fn envelope_sent_dates_require_valid_calendar_days_and_preserve_offsets() {
        for (raw, expected) in [
            ("31 Feb 2024 12:00:00 +0000", None),
            ("29 Feb 2023 12:00:00 +0000", None),
            ("29 Feb 1900 12:00:00 +0000", None),
            ("31 Apr 2024 12:00:00 +0000", None),
            ("29 Feb 2024 24:00:00 +0000", None),
            ("01 Jan 3001 12:00:00 +0000", None),
            (
                "29 Feb 2024 23:30:00 -1200",
                Some("2024-02-29T23:30:00-12:00"),
            ),
            (
                "29 Feb 2000 00:30:00 +1400",
                Some("2000-02-29T00:30:00+14:00"),
            ),
            ("28 Feb 1900 12:00:00 +0000", Some("1900-02-28T12:00:00Z")),
            ("30 Apr 2024 12:00:00 +0000", Some("2024-04-30T12:00:00Z")),
        ] {
            let mut fields = fields("sender");
            let AttributeValue::Envelope(envelope) = &mut fields[1] else {
                unreachable!();
            };
            envelope.date = Some(Cow::Borrowed(raw.as_bytes()));
            let message = Projection::parse(&fields).unwrap().message();
            assert_eq!(
                message.metadata.sent_date,
                expected.map_or(Metadata::Malformed, |value| Metadata::Present(value.into())),
                "{raw}"
            );
        }
    }

    #[test]
    fn plain_envelope_headers_allocate_only_the_returned_text() {
        for expected in [
            "Ordinary title  \twith spaces.".repeat(2048),
            "Ordinary café 🦀 Ελληνικά 日本語  \twith spaces.".repeat(1024),
        ] {
            let source = format!("\t  {expected} \t");
            let mut fields = fields("sender");
            let AttributeValue::Envelope(envelope) = &mut fields[1] else {
                unreachable!();
            };
            envelope.subject = Some(Cow::Borrowed(source.as_bytes()));
            envelope.from.as_mut().unwrap()[0].name = Some(Cow::Borrowed(source.as_bytes()));
            let measured = allocation_counter::measure(|| {
                let projection = Projection::parse(&fields).unwrap();
                projection.check_header_bytes(256 * 1024).unwrap();
                let message = projection.message();
                assert_eq!(message.metadata.subject.value(), Some(&expected));
                let Metadata::Present(addresses) = message.metadata.from else {
                    panic!("valid envelope sender");
                };
                assert_eq!(addresses[0].name.as_ref(), Some(&expected));
            });
            assert!(
                measured.bytes_total <= (2 * expected.len()) as u64 + 1024,
                "plain headers must not retain CRLF-terminated parsing copies: {measured:?}"
            );
        }
    }

    #[test]
    fn envelope_headers_preserve_whitespace_encoding_and_malformed_metadata() {
        for (raw, expected) in [
            (b"".as_slice(), Some("")),
            (b" \t ".as_slice(), Some("")),
            (
                b"\t Leading  \tand trailing \t ".as_slice(),
                Some("Leading  \tand trailing"),
            ),
            (
                "\u{a0}café 🦀 Ελληνικά 日本語\u{a0}".as_bytes(),
                Some("\u{a0}café 🦀 Ελληνικά 日本語\u{a0}"),
            ),
            (b"First \r\n\t second".as_slice(), Some("First second")),
            (
                b"=?UTF-8?Q?Gr=C3=BC?= \t =?UTF-8?Q?=C3=9Fe?=".as_slice(),
                Some("Grüße"),
            ),
            (
                b"Before =?utf-8?Q?caf=C3=A9?= after".as_slice(),
                Some("Before café after"),
            ),
            (b"How =? works".as_slice(), Some("How =? works")),
            (b"First\rbare".as_slice(), None),
            (b"First\nInjected: header".as_slice(), None),
            (b"First\r\nInjected: header".as_slice(), None),
            (b"Control\x1b".as_slice(), None),
            (b"Invalid\xff".as_slice(), None),
        ] {
            let mut fields = fields("sender");
            let AttributeValue::Envelope(envelope) = &mut fields[1] else {
                unreachable!();
            };
            envelope.subject = Some(Cow::Borrowed(raw));
            envelope.from.as_mut().unwrap()[0].name = Some(Cow::Borrowed(raw));
            let message = Projection::parse(&fields).unwrap().message();
            match expected {
                Some(expected) => {
                    assert_eq!(
                        message.metadata.subject.value().map(String::as_str),
                        Some(expected),
                        "{raw:?}",
                    );
                    let Metadata::Present(addresses) = message.metadata.from else {
                        panic!("valid envelope sender for {raw:?}");
                    };
                    assert_eq!(addresses[0].name.as_deref(), Some(expected), "{raw:?}");
                }
                None => {
                    assert_eq!(message.metadata.subject, Metadata::Malformed, "{raw:?}");
                    assert_eq!(message.metadata.from, Metadata::Malformed, "{raw:?}");
                }
            }
        }
    }

    #[test]
    fn quoted_envelope_addresses_do_not_allocate_intermediate_escaped_copies() {
        let local = "a\"\\é ".repeat(512);
        let expected = format!("\"{}\"@example.test", "a\\\"\\\\é ".repeat(512));
        let fields = fields(&local);
        let measured = allocation_counter::measure(|| {
            let message = Projection::parse(&fields).unwrap().message();
            let Metadata::Present(addresses) = message.metadata.from else {
                panic!("valid envelope address");
            };
            assert_eq!(addresses[0].address, expected);
        });
        assert!(
            measured.bytes_total <= expected.len() as u64 + 1024,
            "normalizing one address must not materialize full escaped copies: {measured:?}"
        );
    }
}
