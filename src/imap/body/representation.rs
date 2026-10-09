//! Deterministic MIME body selection and bounded text rendering.

use super::super::{
    Error, Limits,
    mime::{attachment, imap_text, validate_structure},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use io_imap::types::{
    body::{Body, BodyStructure, SpecificFields},
    core::IString,
    fetch::Part,
};
use mail_parser::{GetHeader, MessageParser, MimeHeaders};
use std::{borrow::Cow, collections::HashMap, io::Cursor, num::NonZeroU32};

const HTML_TABLE_SPAN_LIMIT: usize = 8;
const HTML_TABLE_CELL_LIMIT: usize = 128;
const HTML_RENDER_WIDTH: usize = 80;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Selected {
    pub(super) part: Part,
    pub(super) media_type: String,
    pub(super) charset: String,
    pub(super) transfer_encoding: String,
    pub(super) wire_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Rendered {
    pub(super) text: String,
    pub(super) converted: bool,
    pub(super) replacements: bool,
    pub(super) work: usize,
}

/// Select a body without fetching its siblings. `content_ids` maps direct multipart/related
/// child paths to the value from their MIME headers.
pub(super) fn select(
    structure: &BodyStructure<'_>,
    limits: &Limits,
    content_ids: &HashMap<Vec<NonZeroU32>, String>,
) -> Result<Option<Selected>, Error> {
    validate_structure(structure, limits)?;
    // The selected body owns metadata; excluded candidates need only borrowed
    // fields while validation and selection traverse the complete structure.
    select_part(structure, &mut Vec::new(), content_ids).map(|candidate| {
        candidate.map(|mut candidate| {
            candidate.path.reverse();
            if candidate.path.is_empty() {
                candidate.path.push(NonZeroU32::MIN);
            }
            Selected {
                part: Part(
                    candidate
                        .path
                        .try_into()
                        .expect("selected path is nonempty"),
                ),
                media_type: candidate.media_type.to_owned(),
                charset: candidate.charset.to_owned(),
                transfer_encoding: candidate.transfer_encoding.to_ascii_lowercase(),
                wire_size: candidate.wire_size,
            }
        })
    })
}

/// Return only the direct children whose MIME headers can establish a related root.
pub(super) fn related_multipart_headers(
    structure: &BodyStructure<'_>,
    limits: &Limits,
) -> Result<Vec<Part>, Error> {
    validate_structure(structure, limits)?;
    let mut paths = Vec::new();
    related_headers(structure, &mut Vec::new(), &mut paths)?;
    Ok(paths)
}

/// Validate a bounded MIME header block and return its normalized Content-ID, if present.
/// When a selection is supplied, the fetched MIME header must agree with the structure used to
/// choose it.
pub(super) fn validate_headers(
    raw: &[u8],
    selected: Option<&Selected>,
    limits: &Limits,
) -> Result<Option<String>, Error> {
    if raw.is_empty() || raw.len() > limits.max_header_bytes || !complete_headers(raw) {
        return Err(Error::Limit);
    }
    if raw == b"\r\n" {
        if let Some(selected) = selected
            && (selected.media_type != "text/plain"
                || !selected.charset.eq_ignore_ascii_case("us-ascii")
                || !selected.transfer_encoding.eq_ignore_ascii_case("7bit"))
        {
            return Err(Error::Protocol);
        }
        return Ok(None);
    }
    // Body selection does not need Subject, addresses, or descriptive fields.
    // Their encoded-word normalization can retry malformed suffixes; skip them
    // rather than spending the body-read budget on unrelated metadata.
    let parser = MessageParser::new()
        .default_header_ignore()
        .header_id(mail_parser::HeaderName::ContentId);
    // MIME identity needs only the media type, charset and disposition type.
    // Keep offsets for these fields so irrelevant canonical parameters can be
    // omitted before the pinned parser joins continuation fragments.
    let parser = if selected.is_some() {
        parser
            .ignore_header(mail_parser::HeaderName::ContentType)
            .ignore_header(mail_parser::HeaderName::ContentDisposition)
            .header_raw(mail_parser::HeaderName::ContentTransferEncoding)
    } else {
        parser
    };
    let message = parser.parse_headers(raw).ok_or(Error::Protocol)?;
    let headers = message.parts.first().ok_or(Error::Protocol)?;
    let content_id = headers
        .headers
        .header_value(&mail_parser::HeaderName::ContentId)
        .and_then(|value| value.as_text())
        .map(normalize_content_id)
        .transpose()?
        .map(ToOwned::to_owned);

    if let Some(selected) = selected {
        let content_type = identity_header_value(
            raw,
            headers.headers.header(mail_parser::HeaderName::ContentType),
            Some("charset"),
        )?;
        let content_type =
            mail_parser::parsers::MessageStream::new(content_type.as_ref()).parse_content_type();
        let disposition = identity_header_value(
            raw,
            headers
                .headers
                .header(mail_parser::HeaderName::ContentDisposition),
            None,
        )?;
        let disposition =
            mail_parser::parsers::MessageStream::new(disposition.as_ref()).parse_content_type();
        let (media_type, charset) = content_type.as_content_type().map_or_else(
            || ("text/plain".to_owned(), "us-ascii"),
            |content_type| {
                let subtype = content_type.c_subtype.as_deref().unwrap_or("plain");
                let mut media_type = format!("{}/{subtype}", content_type.c_type);
                media_type.make_ascii_lowercase();
                (
                    media_type,
                    content_type.attribute("charset").unwrap_or("us-ascii"),
                )
            },
        );
        if media_type != selected.media_type
            || !charset.trim().eq_ignore_ascii_case(&selected.charset)
            || !headers
                .content_transfer_encoding()
                .unwrap_or("7bit")
                .trim()
                .eq_ignore_ascii_case(&selected.transfer_encoding)
            || disposition
                .as_content_type()
                .is_some_and(|value| value.c_type.eq_ignore_ascii_case("attachment"))
        {
            return Err(Error::Protocol);
        }
    }
    Ok(content_id)
}

fn identity_header_value<'a>(
    raw: &'a [u8],
    header: Option<&mail_parser::Header<'_>>,
    wanted: Option<&str>,
) -> Result<Cow<'a, [u8]>, Error> {
    let Some(header) = header else {
        return Ok(Cow::Borrowed(&[]));
    };
    let value = raw
        .get(header.offset_start as usize..header.offset_end as usize)
        .ok_or(Error::Protocol)?;
    Ok(projected_mime_value(value, wanted))
}

// Projection is limited to canonical ASCII tokens, quoted empty scalars and nonempty continuations.
// Any uncertain segment keeps the entire original field: removing later text
// can otherwise change the dependency's permissive recovery from earlier text.
fn projected_mime_value<'a>(raw: &'a [u8], wanted: Option<&str>) -> Cow<'a, [u8]> {
    fn token(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii() && byte > b' ' && !b"()<>@,;:\\\"/[]?=".contains(&byte))
    }
    fn encoded_parameter(value: &str, position: u32) -> bool {
        let payload = if position == 0 {
            let Some((charset, rest)) = value.split_once('\'') else {
                return false;
            };
            let Some((language, payload)) = rest.split_once('\'') else {
                return false;
            };
            if !token(charset)
                || !language
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return false;
            }
            payload
        } else {
            value
        };
        if payload.is_empty() {
            return false;
        }
        let mut bytes = payload.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                    || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                {
                    return false;
                }
            } else if matches!(byte, b'\'' | b'*') {
                return false;
            }
        }
        true
    }
    fn parameter_base(segment: &str) -> Option<&str> {
        let (name, value) = segment.trim_ascii().split_once('=')?;
        let name = name.trim_matches([' ', '\t']);
        let value = value.trim_matches([' ', '\t']);
        if !token(name) {
            return None;
        }
        // Empty quoted scalars do not leave continuation state in the pinned
        // parser. Starred empties can affect recovery of the next parameter.
        if value == "\"\"" && !name.contains('*') {
            return Some(name);
        }
        // Quoted tokens follow the same simple parser path as unquoted ones.
        // Other empty values, escapes, folds and more complex quotes retain the full
        // original field, including the pinned parser's recovery behavior.
        let value = if let Some(value) = value.strip_prefix('"') {
            value.strip_suffix('"')?
        } else {
            value
        };
        if !token(value) {
            return None;
        }
        let Some((base, suffix)) = name.split_once('*') else {
            return Some(name);
        };
        if base.is_empty() {
            return None;
        }
        if suffix.is_empty() {
            return encoded_parameter(value, 0).then_some(base);
        }
        let (suffix, encoded) = suffix
            .strip_suffix('*')
            .map_or((suffix, false), |suffix| (suffix, true));
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let position = suffix.parse::<u32>().ok()?;
        if encoded && !encoded_parameter(value, position) {
            return None;
        }
        Some(base)
    }
    fn keep_segment(segment: &str, first: bool, wanted: Option<&str>) -> Option<bool> {
        if first {
            let mut pieces = segment.trim_ascii().split('/');
            let first = pieces.next()?;
            if !token(first)
                || pieces.next().is_some_and(|piece| !token(piece))
                || pieces.next().is_some()
            {
                return None;
            }
            return Some(true);
        }
        let name = parameter_base(segment)?;
        Some(wanted.is_some_and(|wanted| {
            name.eq_ignore_ascii_case(wanted)
                || name.len() == wanted.len() + "-language".len()
                    && name[..wanted.len()].eq_ignore_ascii_case(wanted)
                    && name[wanted.len()..].eq_ignore_ascii_case("-language")
        }))
    }
    let Ok(value) = std::str::from_utf8(raw) else {
        return Cow::Borrowed(raw);
    };
    if value.contains("=?")
        || value.bytes().any(|byte| {
            !byte.is_ascii() || byte.is_ascii_control() && !matches!(byte, b'\t' | b'\r' | b'\n')
        })
    {
        return Cow::Borrowed(raw);
    }
    let value = value.trim_ascii();
    let mut result = String::with_capacity(value.len().min(128) + 2);
    for (index, segment) in value.split(';').enumerate() {
        let Some(keep) = keep_segment(segment, index == 0, wanted) else {
            return Cow::Borrowed(raw);
        };
        if keep {
            if index != 0 {
                result.push(';');
            }
            result.push_str(segment);
        }
    }
    result.push_str("\r\n");
    Cow::Owned(result.into_bytes())
}

pub(super) fn render(selected: &Selected, wire: &[u8], limits: &Limits) -> Result<Rendered, Error> {
    if wire.len() > limits.max_body_wire_bytes || selected.wire_size > limits.max_body_wire_bytes {
        return Err(Error::Limit);
    }
    let mut work = wire.len();
    require_work(work, limits)?;
    // Base64 and quoted-printable validation scan the input before calling the
    // decoder. A malformed input can add a scan and a prefix decode, so admit
    // all bounded passes before invoking dependency code.
    if wire.len() > limits.max_decoded_bytes {
        return Err(Error::Limit);
    }
    let transfer_work = wire.len().checked_mul(4).ok_or(Error::Limit)?;
    work = add_work(work, transfer_work, limits)?;
    let (decoded, mut replacements) = decode_transfer(wire, &selected.transfer_encoding);
    if decoded.len() > limits.max_decoded_bytes {
        return Err(Error::Limit);
    }
    work = add_work(work, decoded.len(), limits)?;

    // A charset can expand a byte to at most three UTF-8 bytes. Admit input before the decoder
    // allocates its output. `max_text_bytes` is a page limit; the full representation has its
    // own decoded limit so it can be continued at UTF-8 boundaries.
    if decoded.len() > limits.max_decoded_bytes / 3 {
        return Err(Error::Limit);
    }
    require_work(
        work.checked_add(decoded.len() * 3).ok_or(Error::Limit)?,
        limits,
    )?;
    let (text, charset_replacements) = decode_charset(&decoded, &selected.charset);
    replacements |= charset_replacements;
    let mut text = if replacements {
        match text {
            Cow::Borrowed(text) => {
                let mut marked = String::with_capacity(text.len() + '\u{fffd}'.len_utf8());
                marked.push('\u{fffd}');
                marked.push_str(text);
                marked
            }
            Cow::Owned(mut text) => {
                // Charset conversions may already have spare output capacity.
                // Preserve it; otherwise reserve only the marker before shifting.
                text.reserve_exact('\u{fffd}'.len_utf8());
                text.insert(0, '\u{fffd}');
                text
            }
        }
    } else {
        text.into_owned()
    };
    work = add_work(work, text.len(), limits)?;

    let converted = selected.media_type == "text/html";
    if converted {
        text = render_html(&text, limits, &mut work)?;
    }
    if text.len() > limits.max_decoded_bytes {
        return Err(Error::Limit);
    }
    Ok(Rendered {
        text,
        converted,
        replacements,
        work,
    })
}

struct Candidate<'a> {
    // A child contributes its number only if its candidate remains selected.
    // Ancestors append their numbers, and select() reverses the final path.
    path: Vec<NonZeroU32>,
    media_type: &'static str,
    charset: &'a str,
    transfer_encoding: &'a str,
    wire_size: usize,
}

fn select_part<'a>(
    structure: &'a BodyStructure<'_>,
    path: &mut Vec<NonZeroU32>,
    content_ids: &HashMap<Vec<NonZeroU32>, String>,
) -> Result<Option<Candidate<'a>>, Error> {
    match structure {
        BodyStructure::Single {
            body,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(None);
            }
            leaf(body)
        }
        BodyStructure::Multi {
            bodies,
            subtype,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(None);
            }
            let subtype = imap_text(subtype)?;
            let children = bodies.as_ref();
            let alternative = subtype.eq_ignore_ascii_case("alternative");
            let root = if subtype.eq_ignore_ascii_case("related") {
                parameter(
                    extension_data
                        .as_ref()
                        .map_or(&[][..], |data| data.parameter_list.as_slice()),
                    "start",
                )?
                .map(normalize_content_id)
                .transpose()?
            } else {
                None
            };
            let mut selected: Option<Candidate<'a>> = None;
            let mut related_root = None;
            let mut root_matched = false;
            for (index, child) in children.iter().enumerate() {
                let number = NonZeroU32::new(u32::try_from(index + 1).map_err(|_| Error::Limit)?)
                    .ok_or(Error::Limit)?;
                path.push(number);
                // Continue through every child even after a definite choice so
                // malformed candidate fields keep their existing error outcome.
                let mut candidate = select_part(child, path, content_ids)?;
                if let Some(root) = root
                    && !root_matched
                {
                    let content_id = content_ids
                        .get(path.as_slice())
                        .map(|value| normalize_content_id(value))
                        .transpose()?
                        .or(structure_content_id(child)?);
                    if content_id == Some(root) {
                        root_matched = true;
                        if let Some(mut candidate) = candidate.take() {
                            candidate.path.push(number);
                            related_root = Some(candidate);
                        }
                    }
                }
                path.pop();
                if let Some(mut candidate) = candidate
                    && (selected.is_none()
                        || alternative
                            && candidate.media_type == "text/plain"
                            && selected
                                .as_ref()
                                .is_some_and(|selected| selected.media_type != "text/plain"))
                {
                    candidate.path.push(number);
                    selected = Some(candidate);
                }
            }
            Ok(related_root.or(selected))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Plain,
    Html,
}

fn related_headers(
    structure: &BodyStructure<'_>,
    path: &mut Vec<NonZeroU32>,
    paths: &mut Vec<Part>,
) -> Result<Option<BodyKind>, Error> {
    match structure {
        BodyStructure::Single {
            body,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(None);
            }
            let SpecificFields::Text { subtype, .. } = &body.specific else {
                return Ok(None);
            };
            let subtype = imap_text(subtype)?;
            Ok(if subtype.eq_ignore_ascii_case("plain") {
                Some(BodyKind::Plain)
            } else if subtype.eq_ignore_ascii_case("html") {
                Some(BodyKind::Html)
            } else {
                None
            })
        }
        BodyStructure::Multi {
            bodies,
            subtype,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(None);
            }
            let subtype = imap_text(subtype)?;
            let root = if subtype.eq_ignore_ascii_case("related") {
                parameter(
                    extension_data
                        .as_ref()
                        .map_or(&[][..], |data| data.parameter_list.as_slice()),
                    "start",
                )?
                .map(normalize_content_id)
                .transpose()?
            } else {
                None
            };
            let alternative = subtype.eq_ignore_ascii_case("alternative");
            let first_wins = !alternative && root.is_none();
            let mut selected = None;
            let mut matched_root = false;
            for (index, child) in bodies.as_ref().iter().enumerate() {
                let number = NonZeroU32::new(u32::try_from(index + 1).map_err(|_| Error::Limit)?)
                    .ok_or(Error::Limit)?;
                path.push(number);
                let before = paths.len();
                if root.is_some() && matches!(child, BodyStructure::Multi { .. }) {
                    paths.push(Part(
                        path.clone()
                            .try_into()
                            .expect("child makes the path nonempty"),
                    ));
                }
                let candidate = related_headers(child, path, paths)?;
                path.pop();
                // Eligibility is stable without Content-IDs: a related child
                // falls back to its first readable candidate. Return its type
                // from this traversal so ancestors need no repeated selection.
                if selected.is_none() || alternative && candidate == Some(BodyKind::Plain) {
                    selected = candidate;
                }
                if root.is_some() && !matched_root && structure_content_id(child)? == root {
                    matched_root = true;
                    // A matching unreadable root uses the first readable
                    // fallback, exactly like selection after headers arrive.
                    selected = candidate.or(selected);
                }
                if (first_wins || matched_root) && selected.is_some()
                    || alternative && paths.len() == before && candidate == Some(BodyKind::Plain)
                {
                    break;
                }
            }
            Ok(selected)
        }
    }
}

fn leaf<'a>(body: &'a Body<'_>) -> Result<Option<Candidate<'a>>, Error> {
    let SpecificFields::Text { subtype, .. } = &body.specific else {
        return Ok(None);
    };
    let subtype = imap_text(subtype)?;
    let media_type = if subtype.eq_ignore_ascii_case("plain") {
        "text/plain"
    } else if subtype.eq_ignore_ascii_case("html") {
        "text/html"
    } else {
        return Ok(None);
    };
    Ok(Some(Candidate {
        path: Vec::new(),
        media_type,
        charset: parameter(&body.basic.parameter_list, "charset")?.unwrap_or("us-ascii"),
        transfer_encoding: imap_text(&body.basic.content_transfer_encoding)?,
        wire_size: body.basic.size as usize,
    }))
}

fn structure_content_id<'a>(structure: &'a BodyStructure<'_>) -> Result<Option<&'a str>, Error> {
    let BodyStructure::Single { body, .. } = structure else {
        return Ok(None);
    };
    body.basic
        .id
        .0
        .as_ref()
        .map(imap_text)
        .transpose()?
        .map(normalize_content_id)
        .transpose()
}

fn parameter<'a>(
    parameters: &'a [(IString<'_>, IString<'_>)],
    wanted: &str,
) -> Result<Option<&'a str>, Error> {
    for (name, value) in parameters {
        if imap_text(name)?.eq_ignore_ascii_case(wanted) {
            return Ok(Some(imap_text(value)?));
        }
    }
    Ok(None)
}

fn complete_headers(raw: &[u8]) -> bool {
    raw == b"\r\n" || raw.ends_with(b"\r\n\r\n") || raw.ends_with(b"\n\n")
}

fn normalize_content_id(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    let value = value
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(value);
    if value.is_empty() || value.len() > 998 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(Error::Protocol);
    }
    Ok(value)
}

fn decode_transfer<'a>(wire: &'a [u8], transfer_encoding: &str) -> (Cow<'a, [u8]>, bool) {
    let (decoded, replacements) = match transfer_encoding.trim() {
        "7bit" | "8bit" | "binary" => return (Cow::Borrowed(wire), false),
        "base64" => decode_base64(wire),
        "quoted-printable" => decode_quoted_printable(wire),
        _ => return (Cow::Borrowed(wire), true),
    };
    (Cow::Owned(decoded), replacements)
}

fn decode_base64(wire: &[u8]) -> (Vec<u8>, bool) {
    let (complete, well_formed) = scan_base64(wire);
    if let Some(decoded) = mail_parser::decoders::base64::base64_decode(wire) {
        return (decoded, !well_formed);
    }

    // The pinned decoder rejects an invalid byte wholesale. Keep the complete MIME quanta before
    // that byte, which are independently decodable, and make the loss visible to the caller.
    let recovered =
        mail_parser::decoders::base64::base64_decode(&wire[..complete]).unwrap_or_default();
    (recovered, true)
}

/// Validate the whole input and retain the end of its independently decodable prefix.
fn scan_base64(wire: &[u8]) -> (usize, bool) {
    let mut complete = 0;
    let mut quartet = [0; 4];
    let mut len = 0;
    let mut padded = false;
    for (index, byte) in wire.iter().copied().enumerate() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if padded || !(base64_alphabet(byte) || byte == b'=') {
            return (complete, false);
        }
        quartet[len] = byte;
        len += 1;
        if len == quartet.len() {
            // Alphabet-only quartets are valid; padding still needs strict checks.
            if quartet.contains(&b'=') && STANDARD.decode_slice(quartet, &mut [0; 3]).is_err() {
                return (complete, false);
            }
            complete = index + 1;
            padded = quartet[2] == b'=' || quartet[3] == b'=';
            len = 0;
        }
    }
    (complete, len == 0)
}

fn base64_alphabet(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn decode_quoted_printable(wire: &[u8]) -> (Vec<u8>, bool) {
    let prefix = quoted_printable_prefix_len(wire);
    let malformed = prefix != wire.len();
    if let Some(decoded) = mail_parser::decoders::quoted_printable::quoted_printable_decode(wire) {
        return (decoded, malformed);
    }

    let recovered =
        mail_parser::decoders::quoted_printable::quoted_printable_decode(&wire[..prefix])
            .unwrap_or_default();
    (recovered, true)
}

fn quoted_printable_prefix_len(wire: &[u8]) -> usize {
    let mut index = 0;
    while let Some(&byte) = wire.get(index) {
        if byte != b'=' {
            if byte == b'\r' && wire.get(index + 1) == Some(&b'\n') {
                index += 2;
            } else if matches!(byte, b'\t' | b' '..=b'~') {
                index += 1;
            } else {
                break;
            }
            continue;
        }
        let Some(&next) = wire.get(index + 1) else {
            break;
        };
        if next == b'\r' && wire.get(index + 2) == Some(&b'\n') {
            index += 3;
        } else if let Some(&last) = wire.get(index + 2) {
            if next.is_ascii_hexdigit() && last.is_ascii_hexdigit() {
                index += 3;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    index
}

fn decode_charset<'a>(bytes: &'a [u8], charset: &str) -> (Cow<'a, str>, bool) {
    encoding_rs::Encoding::for_label(charset.trim().as_bytes()).map_or_else(
        || (String::from_utf8_lossy(bytes), true),
        |encoding| encoding.decode_without_bom_handling(bytes),
    )
}

fn render_html(text: &str, limits: &Limits, work: &mut usize) -> Result<String, Error> {
    let source_limit = (limits.max_decoded_bytes / 16).min(64 * 1024);
    if source_limit == 0 || text.len() > source_limit {
        return Err(Error::Limit);
    }
    // Reserve for parser tree repair before html5ever runs. Counting every '<'
    // overestimates markup in text and attributes, keeping this admission finite.
    let markup = text.bytes().filter(|byte| *byte == b'<').count();
    let parser_work = text.len().checked_mul(markup + 1).ok_or(Error::Limit)?;
    *work = add_work(*work, parser_work, limits)?;
    let config = html2text::config::plain().raw_mode(true);
    let dom = config
        .parse_html(Cursor::new(text.as_bytes()))
        .map_err(|_| Error::Protocol)?;
    let nodes = preflight_html(&dom.document, limits, work)?;
    let render_bound = text
        .len()
        .checked_mul(limits.max_nesting)
        .and_then(|bytes| bytes.checked_add(nodes * HTML_RENDER_WIDTH))
        .and_then(|bytes| {
            bytes.checked_add(HTML_TABLE_CELL_LIMIT * HTML_TABLE_SPAN_LIMIT * HTML_RENDER_WIDTH)
        })
        .ok_or(Error::Limit)?;
    if render_bound > limits.max_decoded_bytes {
        return Err(Error::Limit);
    }
    *work = add_work(*work, render_bound, limits)?;
    let tree = config
        .dom_to_render_tree(&dom)
        .map_err(|_| Error::Protocol)?;
    let text = config
        .render_to_string(tree, HTML_RENDER_WIDTH)
        .map_err(|_| Error::Protocol)?;
    *work = add_work(*work, text.len(), limits)?;
    Ok(text)
}

fn preflight_html(
    root: &html2text::Handle,
    limits: &Limits,
    work: &mut usize,
) -> Result<usize, Error> {
    let node_limit = (limits.max_decode_steps / 32).clamp(1, 4096);
    let mut nodes = 0usize;
    let mut attributes = 0usize;
    let mut table_cells = 0usize;
    let mut stack = vec![(root.clone(), 1usize)];
    while let Some((node, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or(Error::Limit)?;
        if nodes > node_limit || depth > limits.max_nesting {
            return Err(Error::Limit);
        }
        *work = add_work(*work, 1, limits)?;
        if let html2text::Element { name, attrs, .. } = &node.data {
            let local = name.local.as_ref();
            let mut attrs = attrs.borrow_mut();
            attributes = attributes.checked_add(attrs.len()).ok_or(Error::Limit)?;
            if attributes > node_limit.saturating_mul(4) {
                return Err(Error::Limit);
            }
            if local == "td" || local == "th" {
                table_cells = table_cells.checked_add(1).ok_or(Error::Limit)?;
                if table_cells > HTML_TABLE_CELL_LIMIT {
                    return Err(Error::Limit);
                }
                for attribute in attrs.iter_mut() {
                    if attribute.name.local.as_ref() == "colspan"
                        || attribute.name.local.as_ref() == "rowspan"
                    {
                        let parsed = attribute
                            .value
                            .parse::<usize>()
                            .unwrap_or(1)
                            .clamp(1, HTML_TABLE_SPAN_LIMIT);
                        attribute.value = parsed.to_string().into();
                    }
                }
            }
        }
        let children = node.children.borrow();
        for child in children.iter() {
            stack.push((child.clone(), depth + 1));
        }
    }
    Ok(nodes)
}

fn require_work(work: usize, limits: &Limits) -> Result<(), Error> {
    if work > limits.max_decode_steps {
        Err(Error::Limit)
    } else {
        Ok(())
    }
}

fn add_work(work: usize, additional: usize, limits: &Limits) -> Result<usize, Error> {
    let work = work.checked_add(additional).ok_or(Error::Limit)?;
    require_work(work, limits)?;
    Ok(work)
}

#[cfg(test)]
mod planner_performance_tests {
    use super::*;
    use io_imap::types::{body::BasicFields, core::NString};

    #[test]
    fn base64_scan_preserves_padding_validation_and_complete_prefixes() {
        for (wire, expected) in [
            (b"Zm9v".as_slice(), (4, true)),
            (b"////".as_slice(), (4, true)),
            (b"Z m\t9\r\nv".as_slice(), (8, true)),
            (b"Zg==".as_slice(), (4, true)),
            (b"Zm8=".as_slice(), (4, true)),
            (b"Zh==".as_slice(), (0, false)),
            (b"Zm9=".as_slice(), (0, false)),
            (b"=AAA".as_slice(), (0, false)),
            (b"A=AA".as_slice(), (0, false)),
            (b"Zg===".as_slice(), (4, false)),
            (b"Zg==Zm9v".as_slice(), (4, false)),
            (b"Zm9v$ignored".as_slice(), (4, false)),
            (b"Zm9vZg".as_slice(), (4, false)),
        ] {
            assert_eq!(scan_base64(wire), expected, "{wire:?}");
        }
    }

    #[test]
    fn empty_scalar_mime_parameters_preserve_bounded_continuation_allocation() {
        for fragments in [128, 512, 2048] {
            let mut field = format!("text/plain; x*0={}", "a".repeat(32 * 1024));
            for index in 1..fragments {
                field.push_str(&format!("; x*{index}=b"));
            }
            for tail in ["; charset=utf-8", "; unused=\"\"; charset=utf-8"] {
                let selected = Selected {
                    part: Part(NonZeroU32::MIN.into()),
                    media_type: "text/plain".into(),
                    charset: "utf-8".into(),
                    transfer_encoding: "7bit".into(),
                    wire_size: 5,
                };
                let raw = format!("Content-Type: {field}{tail}\r\n\r\n");
                let started = std::time::Instant::now();
                let measured = allocation_counter::measure(|| {
                    assert_eq!(
                        validate_headers(raw.as_bytes(), Some(&selected), &Limits::default()),
                        Ok(None)
                    );
                });
                eprintln!(
                    "mime fallback fragments={fragments} source={} tail={tail:?} elapsed={:?} {measured:?}",
                    raw.len(),
                    started.elapsed()
                );
                assert!(
                    measured.bytes_total < 64 * 1024 + raw.len() as u64 * 4,
                    "an empty scalar must not force unused continuation materialization: {measured:?}"
                );
            }
        }
    }

    #[test]
    fn replacement_markers_do_not_grow_an_already_owned_body_copy() {
        let mut measurements = Vec::new();
        for size in [64 * 1_024, 256 * 1_024, 2 * 1_024 * 1_024] {
            let wire = vec![b'x'; size];
            for charset in ["UTF-8", "x-unknown-fixture"] {
                let selected = Selected {
                    part: Part(NonZeroU32::MIN.into()),
                    media_type: "text/plain".into(),
                    charset: charset.into(),
                    transfer_encoding: "7bit".into(),
                    wire_size: size,
                };
                let replacement = charset == "x-unknown-fixture";
                let measured = allocation_counter::measure(|| {
                    let rendered = render(&selected, &wire, &Limits::default()).unwrap();
                    assert_eq!(rendered.replacements, replacement);
                    assert!(!rendered.converted);
                    assert_eq!(rendered.text.len(), size + usize::from(replacement) * 3);
                    assert_eq!(rendered.work, size * 7 + usize::from(replacement) * 3);
                    let payload = if replacement {
                        rendered.text.strip_prefix('\u{fffd}').unwrap()
                    } else {
                        &rendered.text
                    };
                    assert_eq!(payload.as_bytes(), wire);
                });
                eprintln!(
                    "body replacement size={size} charset={charset} allocations={} total={} peak={}",
                    measured.count_total, measured.bytes_total, measured.bytes_max
                );
                measurements.push((size, measured));
            }
        }
        for (size, measured) in measurements {
            assert!(
                measured.bytes_total < size as u64 * 2 + 32 * 1_024,
                "a replacement marker must not geometrically grow a complete body copy: {measured:?}"
            );
        }
    }

    #[test]
    fn owned_charset_results_keep_their_existing_output_allocation() {
        const SIZE: usize = 64 * 1_024;
        let wire = vec![0xe9; SIZE];
        for transfer_encoding in ["7bit", "x-unknown-fixture"] {
            let selected = Selected {
                part: Part(NonZeroU32::MIN.into()),
                media_type: "text/plain".into(),
                charset: "iso-8859-1".into(),
                transfer_encoding: transfer_encoding.into(),
                wire_size: SIZE,
            };
            let replacement = transfer_encoding == "x-unknown-fixture";
            let measured = allocation_counter::measure(|| {
                let rendered = render(&selected, &wire, &Limits::default()).unwrap();
                assert_eq!(rendered.replacements, replacement);
                let payload = if replacement {
                    rendered.text.strip_prefix('\u{fffd}').unwrap()
                } else {
                    &rendered.text
                };
                assert_eq!(payload.len(), SIZE * 2);
                assert!(payload.chars().all(|character| character == 'é'));
            });
            eprintln!(
                "owned charset size={SIZE} transfer={transfer_encoding} allocations={} total={} peak={}",
                measured.count_total, measured.bytes_total, measured.bytes_max
            );
            assert_eq!(
                measured.count_total, 1,
                "an owned charset conversion with spare capacity must not copy into another output buffer: {measured:?}"
            );
        }
    }

    fn deep_structure(depth: usize, parts: usize) -> BodyStructure<'static> {
        let leaf = BodyStructure::Single {
            body: Body {
                basic: BasicFields {
                    parameter_list: vec![],
                    id: NString::NIL,
                    description: NString::NIL,
                    content_transfer_encoding: "7BIT".try_into().unwrap(),
                    size: 5,
                },
                specific: SpecificFields::Text {
                    subtype: "PLAIN".try_into().unwrap(),
                    number_of_lines: 1,
                },
            },
            extension_data: None,
        };
        let mut structure = BodyStructure::Multi {
            bodies: vec![leaf; parts - depth + 1].try_into().unwrap(),
            subtype: "MIXED".try_into().unwrap(),
            extension_data: None,
        };
        for _ in 2..depth {
            structure = BodyStructure::Multi {
                bodies: vec![structure].try_into().unwrap(),
                subtype: "MIXED".try_into().unwrap(),
                extension_data: None,
            };
        }
        structure
    }

    #[test]
    fn related_header_planning_does_not_allocate_unneeded_part_paths() {
        let mut measurements = Vec::new();
        for (depth, parts, subtype) in [
            (2, 1_000, "ALTERNATIVE"),
            (20, 200, "MIXED"),
            (40, 1_000, "MIXED"),
        ] {
            let mut structure = deep_structure(depth, parts);
            let BodyStructure::Multi {
                subtype: root_subtype,
                ..
            } = &mut structure
            else {
                unreachable!();
            };
            *root_subtype = subtype.try_into().unwrap();
            let limits = Limits {
                max_nesting: depth,
                max_mime_parts: parts,
                ..Limits::default()
            };
            let measured = allocation_counter::measure(|| {
                assert!(
                    related_multipart_headers(&structure, &limits)
                        .unwrap()
                        .is_empty()
                );
            });
            eprintln!(
                "related planner depth={depth} parts={parts} allocations={} total={} peak={}",
                measured.count_total, measured.bytes_total, measured.bytes_max
            );
            measurements.push(measured);
        }
        for measured in measurements {
            assert!(
                measured.count_total < 16 && measured.bytes_total < 16 * 1_024,
                "header planning must reuse its traversal path when no headers are needed: {measured:?}"
            );
        }
    }

    #[test]
    fn body_selection_does_not_materialize_every_excluded_leaf() {
        let mut measurements = Vec::new();
        for (depth, parts) in [(2, 1_000), (40, 1_000)] {
            let structure = deep_structure(depth, parts);
            let limits = Limits {
                max_nesting: depth,
                max_mime_parts: parts,
                ..Limits::default()
            };
            let measured = allocation_counter::measure(|| {
                let selected = select(&structure, &limits, &HashMap::new())
                    .unwrap()
                    .unwrap();
                assert_eq!(selected.media_type, "text/plain");
                assert_eq!(selected.charset, "us-ascii");
                assert_eq!(selected.transfer_encoding, "7bit");
                assert_eq!(selected.part.0.as_ref().len(), depth - 1);
                assert!(selected.part.0.as_ref().iter().all(|part| part.get() == 1));
            });
            eprintln!(
                "body selection depth={depth} parts={parts} allocations={} total={} peak={}",
                measured.count_total, measured.bytes_total, measured.bytes_max
            );
            measurements.push(measured);
        }
        for measured in measurements {
            assert!(
                measured.count_total < 128 && measured.bytes_total < 16 * 1024,
                "selection must allocate for the chosen part rather than every readable sibling: {measured:?}"
            );
        }
    }

    #[test]
    fn body_selection_still_validates_readable_siblings_after_its_first_choice() {
        let mut structure = deep_structure(2, 3);
        let BodyStructure::Multi { bodies, .. } = &structure else {
            unreachable!();
        };
        let mut children = bodies.clone().into_inner();
        let BodyStructure::Single { body, .. } = &mut children[1] else {
            unreachable!();
        };
        body.basic.parameter_list.push((
            "CHARSET".try_into().unwrap(),
            vec![0xff].try_into().unwrap(),
        ));
        let BodyStructure::Multi { bodies, .. } = &mut structure else {
            unreachable!();
        };
        *bodies = children.try_into().unwrap();
        assert_eq!(
            select(&structure, &Limits::default(), &HashMap::new()),
            Err(Error::Protocol)
        );
    }

    #[test]
    fn mime_header_parameter_continuations_have_linear_allocation() {
        let mut measurements = Vec::new();
        for fragments in [128, 512] {
            let mut headers = "Content-Type: text/plain; charset=us-ascii".to_owned();
            for index in 0..fragments {
                headers.push_str(&format!(";\r\n x*{index}={}", "a".repeat(32)));
            }
            headers.push_str("\r\n\r\n");
            let measured = allocation_counter::measure(|| {
                assert_eq!(
                    validate_headers(headers.as_bytes(), None, &Limits::default()),
                    Ok(None)
                );
            });
            eprintln!(
                "MIME continuations fragments={fragments} source={} allocations={} total={} peak={}",
                headers.len(),
                measured.count_total,
                measured.bytes_total,
                measured.bytes_max
            );
            measurements.push((headers.len(), measured));
        }
        for (bytes, measured) in measurements {
            assert!(
                measured.bytes_total < 64 * 1_024 + bytes as u64 * 32,
                "ignored MIME parameter fragments must not repeatedly copy their combined value: {measured:?}"
            );
        }
    }

    #[test]
    fn selected_mime_headers_still_validate_charset_encoding_and_disposition() {
        let selected = Selected {
            part: Part(NonZeroU32::MIN.into()),
            media_type: "text/plain".into(),
            charset: "UTF-8".into(),
            transfer_encoding: "7bit".into(),
            wire_size: 5,
        };
        let valid = b"Content-Type: text/plain; charset*0=utf; charset*1=-8\r\nContent-Disposition: inline; filename*0=first; filename*1=last\r\n\r\n";
        assert_eq!(
            validate_headers(valid, Some(&selected), &Limits::default()),
            Ok(None)
        );
        for invalid in [
            "Content-Type: text/html; charset=utf-8\r\n\r\n",
            "Content-Type: text/plain; charset=iso-8859-1\r\n\r\n",
            "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
            "Content-Type: text/plain; charset=utf-8\r\nContent-Disposition: attachment\r\n\r\n",
        ] {
            assert_eq!(
                validate_headers(invalid.as_bytes(), Some(&selected), &Limits::default()),
                Err(Error::Protocol)
            );
        }
    }

    #[test]
    fn selected_mime_headers_skip_unused_parameter_continuation_decoding() {
        let selected = Selected {
            part: Part(NonZeroU32::MIN.into()),
            media_type: "text/plain".into(),
            charset: "us-ascii".into(),
            transfer_encoding: "7bit".into(),
            wire_size: 5,
        };
        let mut measurements = Vec::new();
        for (fragments, quoted) in [(128, false), (512, false), (512, true)] {
            let charset = if quoted { "\"us-ascii\"" } else { "us-ascii" };
            let mut headers = format!("Content-Type: text/plain; charset={charset}");
            for index in 0..fragments {
                headers.push_str(&format!(";\r\n x*{index}={}", "a".repeat(32)));
            }
            headers.push_str("\r\n\r\n");
            let measured = allocation_counter::measure(|| {
                assert_eq!(
                    validate_headers(headers.as_bytes(), Some(&selected), &Limits::default()),
                    Ok(None)
                );
            });
            eprintln!(
                "selected MIME continuations fragments={fragments} quoted={quoted} source={} allocations={} total={} peak={}",
                headers.len(),
                measured.count_total,
                measured.bytes_total,
                measured.bytes_max
            );
            measurements.push((headers.len(), measured));
        }
        for (bytes, measured) in measurements {
            assert!(
                measured.bytes_total < 64 * 1_024 + bytes as u64 * 32,
                "selected MIME identity must not repeatedly copy unrelated continued parameter values: {measured:?}"
            );
        }
    }

    #[test]
    fn selected_mime_headers_skip_canonical_encoded_unused_continuations() {
        let selected = Selected {
            part: Part(NonZeroU32::MIN.into()),
            media_type: "text/plain".into(),
            charset: "us-ascii".into(),
            transfer_encoding: "7bit".into(),
            wire_size: 5,
        };
        let mut measurements = Vec::new();
        for fragments in [128, 512] {
            for initial in [
                "Content-Type: text/plain; charset=us-ascii",
                "Content-Disposition: inline",
            ] {
                let mut headers = initial.to_owned();
                for index in 0..fragments {
                    let prefix = if index == 0 { "utf-8'en'" } else { "" };
                    headers.push_str(&format!(
                        ";\r\n unused*{index}*={prefix}{}",
                        "%61".repeat(32)
                    ));
                }
                headers.push_str("\r\n\r\n");
                assert!(headers.len() < Limits::default().max_header_bytes);
                let measured = allocation_counter::measure(|| {
                    assert_eq!(
                        validate_headers(headers.as_bytes(), Some(&selected), &Limits::default()),
                        Ok(None)
                    );
                });
                eprintln!(
                    "selected encoded MIME continuations fragments={fragments} field={initial:?} source={} allocations={} total={} peak={}",
                    headers.len(),
                    measured.count_total,
                    measured.bytes_total,
                    measured.bytes_max
                );
                measurements.push((headers.len(), measured));
            }
        }
        for (bytes, measured) in measurements {
            assert!(
                measured.bytes_total < 64 * 1_024 + bytes as u64 * 32,
                "canonical encoded unused values must not repeatedly copy their combined value: {measured:?}"
            );
        }
    }

    #[test]
    fn uncertain_encoded_mime_parameters_keep_the_entire_pinned_parser_input() {
        for value in [
            "text/plain; unused=; charset=utf-8\r\n",
            "text/plain; x*=\"\"; charset=utf-8\r\n",
            "text/plain; x*0=\"\"; charset=utf-8\r\n",
            "text/plain; x*0*=\"\"; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%QZ; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'%61; x*1*=extra'apostrophe; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'; charset=utf-8\r\n",
            "text/plain; x*0*=''value; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'bad language'value; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'%61; x*4294967296*=%62; charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%62(comment); charset=utf-8\r\n",
            "text/plain; x*0*=utf-8'en'%61; x*1*=\"%62\\\"quote\"; charset=utf-8\r\n",
        ] {
            assert!(
                matches!(
                    projected_mime_value(value.as_bytes(), Some("charset")),
                    Cow::Borrowed(bytes) if bytes == value.as_bytes()
                ),
                "uncertain MIME syntax must preserve full-field parser recovery: {value:?}"
            );
        }
    }

    #[test]
    fn mime_identity_projection_matches_the_full_pinned_parser() {
        let values = [
            "text/plain; unused=\"\"; charset=utf-8",
            "text/plain; unused=\"\"; x*0=first; x*1=last; charset=utf-8",
            "text/plain; x*0=first; unused=\"\"; x*1=last; charset=utf-8",
            "text/plain; x*0=first; x*1=last; unused=\"\"; charset=utf-8",
            "text/plain; charset=us-ascii; unused=\"\"; charset=utf-8",
            "text/plain; charset=us-ascii; charset=\"\"; unused=\"\"",
            "text/plain; charset*0=utf; unused=\"\"; charset*1=-8",
            "text/plain; charset*0*=utf-8'en'utf; unused=\"\"; charset*1*=%2D8",
            "text/plain; charset-language=en; unused=\"\"; charset*=utf-8'en'utf-8",
            "text/plain; charset-language=\"\"; unused=\"\"; charset*=utf-8'en'utf-8",
            "inline; filename*0=first; unused=\"\"; filename*1=last",
            "attachment; unused=\"\"; filename*0*=utf-8'en'%61; filename*1*=%62",
            "text/plain; charset=UTF-8",
            "text/plain; x*0=first; charset=\"us-ascii\"; x*1=last",
            "text/plain; x*0=\"first\"; charset=\"utf-8\"; x*1=\"last\"",
            "TEXT/PLAIN (comment); unused=ignored; charset=\"utf-8\"",
            "text/plain; unused=\"semi; charset=wrong\"; charset=utf-8",
            "text/plain; unused=\"escaped\\\"; charset=wrong\"; charset=utf-8",
            "text/plain; charset*0=utf; charset*1=-8; x*0=first; x*1=last",
            "text/plain; charset*0*=utf-8''utf; charset*1*=%2D8",
            "text/plain; charset=us-ascii; charset*0=utf; charset*1=-8",
            "text/plain; x=first\r\n charset=utf-8",
            "text/plain; charset (comment)=utf-8; x*0=first; x*1=last",
            "text/plain; unused (nested(comment))=ignored; charset=utf-8",
            "text/plain; unused=a\\; charset=wrong; charset=utf-8",
            "text/plain; unused=\"open; charset=utf-8",
            "text/plain; unused=(open; charset=utf-8",
            "text/plain; unused=first); charset=utf-8",
            "text/plain; charset=utf-8; unused=backslash\\",
            "text/plain\r\n charset=utf-8",
            "inline; filename*0*=utf-8'en'%E2; filename*1*=%82%AC",
            "attachment; filename=\"name; charset=wrong\"",
            "text/plain; x=\"hello\" charset=utf-8",
            "text/plain; unused=\"x\"charset=utf-8",
            "inline; filename=\"hello\" attachment",
            "text/plain; charset=iso-8859-1; x*2=; charset=utf-8",
            "text/plain; charset=iso-8859-1; x*2=\"\"; charset=utf-8",
            "text/plain; x*=utf-8''; charset=utf-8",
            "text/plain; x*0*=utf-8''; charset=utf-8",
            "text/plain; charset-language=en; charset*=utf-8'en'utf-8",
            "text/plain; CHARSET-LANGUAGE=en; charset*=utf-8'en'utf-8",
            "text/plain; x=\"=?utf-8?Q?a?=\"; charset=utf-8",
            "text/plain; unused=\"(parentheses)\"; charset=utf-8",
            "text/plain; unused=a,b; charset=utf-8",
            "text/plain; unused=a=b; charset=utf-8",
            "text/plain; unused=a:b; charset=utf-8",
            "text/plain; unused=a\\;charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%62; charset=utf-8",
            "text/plain; x*0*=UTF-8''%E2; x*1*=%82; x*2*=%AC; charset=utf-8",
            "text/plain; x*2*=%AC; x*0*=utf-8'en'%E2; charset=utf-8; x*1*=%82",
            "text/plain; x*0*=utf-8'en'%61; charset=utf-8; x*1*=%62; x*1*=%63",
            "text/plain; x*0*=utf-8'en'%61; x*0*=utf-8'en'%62; charset=utf-8",
            "text/plain; x*=utf-8'en'%61; charset=utf-8",
            "text/plain; x*=unknown-charset''%E2%82%AC; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1=last; charset=utf-8",
            "text/plain; x*0=first; x*1*=%62; charset=utf-8",
            "text/plain; charset*0*=utf-8'en'utf; x*=utf-8'en'%61; charset*1*=%2D8",
            "text/plain; charset-language=en; x*=utf-8'en'%61; charset*=utf-8'en'utf-8",
            "text/plain; charset-language*=utf-8'en'%64%65; x*=utf-8''%61; charset*=utf-8'en'utf-8",
            "inline; filename*2*=%AC; filename*0*=utf-8'en'%E2; filename*1*=%82",
            "inline; filename*0*=\"utf-8'en'%61\"; filename*1*=\"%62\"",
            "text/plain; x*0*=utf-8''%00; x*1*=%FF; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*01*=%62; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*4294967295*=%62; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*4294967296*=%62; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*2*=%62; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=extra'apostrophe; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%QZ; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%6; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%; charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%62(comment); charset=utf-8",
            "text/plain; x*0*=utf-8'en'%61; x*1*=%62; x*2*=; charset=utf-8",
            "text/plain; x*0*=utf-8'en'; charset=utf-8",
            "text/plain; x*0*=''value; charset=utf-8",
            "text/plain; x*0*=utf-8'bad language'value; charset=utf-8",
            "text/plain; x*0*=utf-8'en'first; x*1*=last; charset=utf-8",
        ];
        for value in values {
            for (header, wanted) in [
                (mail_parser::HeaderName::ContentType, Some("charset")),
                (mail_parser::HeaderName::ContentDisposition, None),
            ] {
                let raw = format!("{header}: {value}\r\n\r\n");
                let reference = MessageParser::new()
                    .default_header_ignore()
                    .header_content_type(header.clone())
                    .parse_headers(raw.as_bytes())
                    .unwrap();
                let reference = reference.parts[0].headers.header_value(&header).unwrap();
                let parsed = MessageParser::new()
                    .default_header_ignore()
                    .ignore_header(header.clone())
                    .parse_headers(raw.as_bytes())
                    .unwrap();
                let value = parsed.parts[0].headers.header(header.clone()).unwrap();
                let value = &raw.as_bytes()[value.offset_start as usize..value.offset_end as usize];
                let projected = projected_mime_value(value, wanted);
                let projected = mail_parser::parsers::MessageStream::new(projected.as_ref())
                    .parse_content_type();
                let identity = |value: &mail_parser::HeaderValue<'_>| {
                    value.as_content_type().map(|value| {
                        (
                            value.c_type.to_string(),
                            value.c_subtype.as_deref().map(str::to_owned),
                            wanted
                                .and_then(|wanted| value.attribute(wanted))
                                .map(str::to_owned),
                        )
                    })
                };
                assert_eq!(identity(reference), identity(&projected), "{raw:?}");
            }
        }
    }

    #[test]
    fn mime_identity_projection_matches_deterministic_syntax_mutations() {
        fn compare(value: &[u8]) {
            for (header, wanted) in [
                (mail_parser::HeaderName::ContentType, Some("charset")),
                (mail_parser::HeaderName::ContentDisposition, None),
            ] {
                let mut raw = format!("{header}: ").into_bytes();
                raw.extend_from_slice(value);
                raw.extend_from_slice(b"\r\n\r\n");
                let reference = MessageParser::new()
                    .default_header_ignore()
                    .header_content_type(header.clone())
                    .parse_headers(&raw)
                    .unwrap();
                let empty = mail_parser::HeaderValue::Empty;
                let reference = reference.parts[0]
                    .headers
                    .header_value(&header)
                    .unwrap_or(&empty);
                let parsed = MessageParser::new()
                    .default_header_ignore()
                    .ignore_header(header.clone())
                    .parse_headers(&raw)
                    .unwrap();
                let projected = parsed.parts[0]
                    .headers
                    .header(header.clone())
                    .map(|value| &raw[value.offset_start as usize..value.offset_end as usize])
                    .map(|value| projected_mime_value(value, wanted));
                let projected = projected.as_ref().map_or_else(
                    || mail_parser::HeaderValue::Empty,
                    |projected| {
                        mail_parser::parsers::MessageStream::new(projected.as_ref())
                            .parse_content_type()
                    },
                );
                let identity = |value: &mail_parser::HeaderValue<'_>| {
                    value.as_content_type().map(|value| {
                        (
                            value.c_type.to_string(),
                            value.c_subtype.as_deref().map(str::to_owned),
                            wanted
                                .and_then(|wanted| value.attribute(wanted))
                                .map(str::to_owned),
                        )
                    })
                };
                assert_eq!(identity(reference), identity(&projected), "{raw:?}");
            }
        }
        let bases: &[&[u8]] = &[
            b"text/plain; x*0=first; x*1=last; charset=utf-8",
            b"text/plain; x*0=first; unused=\"\"; x*1=last; charset=utf-8",
            b"text/plain; x*0=first; x*1=last; charset=\"us-ascii\"",
            b"text/plain; x*0=\"first\"; x*1=\"last\"; charset=\"utf-8\"",
            b"text/plain; charset*0=utf; charset*1=-8; charset=iso-8859-1",
            b"text/plain; unused=\"semi; escaped\\\"quote\"; charset=\"utf-8\"",
            b"attachment; filename*0=first; filename*1=last; charset*0=utf; charset*1=-8",
            b"text/plain; x*0*=utf-8'en'%61; x*1*=%62; charset=utf-8",
            b"text/plain; charset*0*=utf-8'en'utf; x*=utf-8'en'%61; charset*1*=%2D8",
            b"inline; filename*2*=%AC; filename*0*=utf-8'en'%E2; filename*1*=%82; charset=utf-8",
        ];
        let additions: &[&[u8]] = &[
            b"; unused=\"\"",
            b"\r\n ",
            b"\r\n\t",
            b"\xff\xfe",
            b"\xc3\x28",
            b"; charset=latin1",
            b"; charset*0=utf; charset*1=-8",
            b"; charset*0*=utf-8'en'utf; charset*1*=%2D8",
            b"; charset*1=-8; charset*0=utf",
            b"; charset-language=en; charset*=utf-8'en'utf-8",
            b"; CHARSET-LANGUAGE=en; charset*=utf-8'en'utf-8",
            b"; unused=\"x\"charset=utf-8",
            b"; x*2=; charset=utf-8",
            b"; x*2=\"\"; charset=utf-8",
            b"; x*=utf-8''; charset=utf-8",
            b"; unused=\"=?utf-8?Q?a?=\"; charset=utf-8",
            b"; x*=utf-8'en'%61",
            b"; x*0*=utf-8''%E2; x*1*=%82; x*2*=%AC",
            b"; x*1*=%61; x*0*=utf-8'en'%62",
            b"; x*1*=%61; x*1*=%62",
            b"; x*0*=utf-8''%61; x*2*=%62",
            b"; x*0*=utf-8'en'",
            b"; x*0*=''value",
            b"; x*0*=utf-8'bad language'value",
            b"; x*1*=extra'apostrophe",
            b"; x*1*=%QZ",
            b"; x*1*=%6",
            b"; x*1*=%",
            b"; x*4294967296*=%61",
            b"; charset-language*=utf-8'en'%64%65; charset*=utf-8'en'utf-8",
        ];
        for base in bases {
            let mut positions = vec![0, base.len()];
            // Include token interiors as well as separators; malformed unused
            // values can influence the pinned parser's later recovery.
            positions.extend(0..base.len());
            for index in positions {
                for byte in 0..=127u8 {
                    let mut value = base.to_vec();
                    value.insert(index, byte);
                    compare(&value);
                    if index != base.len() {
                        let mut value = base.to_vec();
                        value[index] = byte;
                        compare(&value);
                    }
                }
                for addition in additions {
                    let mut value = base[..index].to_vec();
                    value.extend_from_slice(addition);
                    value.extend_from_slice(&base[index..]);
                    compare(&value);
                }
            }
        }
    }
}
