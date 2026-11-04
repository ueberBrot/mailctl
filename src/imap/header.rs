//! Borrow header fields without normalizing unrelated message metadata.

use mail_parser::HeaderName;

/// Yield raw values, including folded lines, from an already bounded header block.
/// Header names follow the dependency's strict RFC 5322 name validation.
pub(super) fn fields(mut raw: &[u8]) -> impl Iterator<Item = (HeaderName<'_>, &[u8])> {
    std::iter::from_fn(move || {
        while !raw.is_empty() {
            let first_end = raw
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(raw.len(), |at| at + 1);
            let first = &raw[..first_end];
            if first == b"\r\n" || first == b"\n" {
                raw = &[];
                return None;
            }
            let mut end = first_end;
            while matches!(raw.get(end), Some(b' ' | b'\t')) {
                end += raw[end..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(raw.len() - end, |at| at + 1);
            }
            let field = &raw[..end];
            raw = &raw[end..];
            let Some(colon) = first.iter().position(|byte| *byte == b':') else {
                continue;
            };
            let name_end = first[..colon]
                .iter()
                .rposition(|byte| !matches!(byte, b' ' | b'\t'))
                .map_or(0, |at| at + 1);
            let Ok(name) = std::str::from_utf8(&first[..name_end]) else {
                continue;
            };
            if let Some(name) = HeaderName::parse(name) {
                return Some((name, &field[colon + 1..]));
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_identity_fields_preserve_folding_duplicates_and_body_boundary() {
        let raw = b"Subject: =?AB?q?ignored\r\nMessage-ID: <first@example.test>\r\nMessage-ID \t: <second@\r\n example.test>\r\n\r\nMessage-ID: <body@example.test>";
        let ids: Vec<_> = fields(raw)
            .filter(|(name, _)| *name == HeaderName::MessageId)
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            ids,
            [
                b" <first@example.test>\r\n".as_slice(),
                b" <second@\r\n example.test>\r\n"
            ]
        );
    }

    #[test]
    fn malformed_names_cannot_become_identity_fields() {
        let raw = b"Content -ID: <wrong>\r\n:Content-ID: <wrong>\r\nContent-ID\r: <wrong>\r\nContent-ID: <right>\n\n";
        let ids: Vec<_> = fields(raw)
            .filter(|(name, _)| *name == HeaderName::ContentId)
            .map(|(_, value)| value)
            .collect();
        assert_eq!(ids, [b" <right>\n"]);
    }
}
