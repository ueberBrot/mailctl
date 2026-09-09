//! Deterministic MIME body selection and bounded text rendering.

use super::super::{
    Error, Limits,
    mime::{attachment, child_path, imap_text, validate_structure},
};
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
    content_ids: &HashMap<Part, String>,
) -> Result<Option<Selected>, Error> {
    validate_structure(structure, limits)?;
    select_part(structure, None, content_ids)
}

/// Return only the direct children whose MIME headers can establish a related root.
pub(super) fn related_multipart_headers(
    structure: &BodyStructure<'_>,
    limits: &Limits,
) -> Result<Vec<Part>, Error> {
    validate_structure(structure, limits)?;
    let mut paths = Vec::new();
    related_headers(structure, None, &mut paths)?;
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
    let message = MessageParser::default()
        .parse_headers(raw)
        .ok_or(Error::Protocol)?;
    let headers = message.parts.first().ok_or(Error::Protocol)?;
    let content_id = headers
        .headers
        .header_value(&mail_parser::HeaderName::ContentId)
        .and_then(|value| value.as_text())
        .map(normalize_content_id)
        .transpose()?
        .map(ToOwned::to_owned);

    if let Some(selected) = selected {
        let (media_type, charset) = headers.content_type().map_or_else(
            || ("text/plain".to_owned(), "us-ascii"),
            |content_type| {
                let subtype = content_type.c_subtype.as_deref().unwrap_or("plain");
                (
                    format!(
                        "{}/{}",
                        content_type.c_type.to_ascii_lowercase(),
                        subtype.to_ascii_lowercase()
                    ),
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
            || headers
                .content_disposition()
                .is_some_and(|value| value.c_type.eq_ignore_ascii_case("attachment"))
        {
            return Err(Error::Protocol);
        }
    }
    Ok(content_id)
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
    let (mut text, charset_replacements) = decode_charset(&decoded, &selected.charset);
    replacements |= charset_replacements;
    if replacements {
        text.insert(0, '\u{fffd}');
    }
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

fn select_part(
    structure: &BodyStructure<'_>,
    path: Option<&Part>,
    content_ids: &HashMap<Part, String>,
) -> Result<Option<Selected>, Error> {
    match structure {
        BodyStructure::Single {
            body,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(None);
            }
            leaf(
                body,
                path.cloned()
                    .unwrap_or_else(|| Part(NonZeroU32::MIN.into())),
            )
        }
        BodyStructure::Multi {
            bodies,
            subtype,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(None);
            }
            let subtype = imap_text(subtype)?.to_ascii_lowercase();
            let children = bodies.as_ref();
            let mut selected = Vec::with_capacity(children.len());
            for (index, child) in children.iter().enumerate() {
                let child_path = child_path(path, index + 1)?;
                let candidate = select_part(child, Some(&child_path), content_ids)?;
                selected.push((child_path, candidate));
            }
            Ok(match subtype.as_str() {
                "alternative" => first_type(&mut selected, "text/plain")
                    .or_else(|| first_type(&mut selected, "text/html")),
                "related" => {
                    let parameters = extension_data
                        .as_ref()
                        .map_or(&[][..], |data| data.parameter_list.as_slice());
                    let root = parameter(parameters, "start")?
                        .map(normalize_content_id)
                        .transpose()?;
                    let related_root = if let Some(root) = root {
                        let mut related_root = None;
                        for (child, (path, candidate)) in children.iter().zip(&mut selected) {
                            let content_id = content_ids
                                .get(path)
                                .map(|value| normalize_content_id(value))
                                .transpose()?
                                .or(structure_content_id(child)?);
                            if content_id == Some(root) {
                                related_root = candidate.take();
                                break;
                            }
                        }
                        related_root
                    } else {
                        None
                    };
                    related_root.or_else(|| first(&mut selected))
                }
                _ => first(&mut selected),
            })
        }
    }
}

fn related_headers(
    structure: &BodyStructure<'_>,
    path: Option<&Part>,
    paths: &mut Vec<Part>,
) -> Result<(), Error> {
    match structure {
        BodyStructure::Single { .. } => Ok(()),
        BodyStructure::Multi {
            bodies,
            subtype,
            extension_data,
        } => {
            if attachment(extension_data.as_ref().and_then(|data| data.tail.as_ref())) {
                return Ok(());
            }
            let related = imap_text(subtype)?.eq_ignore_ascii_case("related")
                && parameter(
                    extension_data
                        .as_ref()
                        .map_or(&[][..], |data| data.parameter_list.as_slice()),
                    "start",
                )?
                .is_some();
            for (index, child) in bodies.as_ref().iter().enumerate() {
                let child_path = child_path(path, index + 1)?;
                if related && matches!(child, BodyStructure::Multi { .. }) {
                    paths.push(child_path.clone());
                }
                related_headers(child, Some(&child_path), paths)?;
            }
            Ok(())
        }
    }
}

fn leaf(body: &Body<'_>, part: Part) -> Result<Option<Selected>, Error> {
    let SpecificFields::Text { subtype, .. } = &body.specific else {
        return Ok(None);
    };
    let subtype = imap_text(subtype)?.to_ascii_lowercase();
    if subtype != "plain" && subtype != "html" {
        return Ok(None);
    }
    Ok(Some(Selected {
        part,
        media_type: format!("text/{subtype}"),
        charset: parameter(&body.basic.parameter_list, "charset")?
            .unwrap_or("us-ascii")
            .to_owned(),
        transfer_encoding: imap_text(&body.basic.content_transfer_encoding)?.to_ascii_lowercase(),
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

fn first(candidates: &mut [(Part, Option<Selected>)]) -> Option<Selected> {
    candidates
        .iter_mut()
        .find_map(|(_, candidate)| candidate.take())
}

fn first_type(candidates: &mut [(Part, Option<Selected>)], media_type: &str) -> Option<Selected> {
    candidates.iter_mut().find_map(|(_, candidate)| {
        candidate.take_if(|candidate| candidate.media_type == media_type)
    })
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
            if !valid_base64_quartet(quartet) {
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

fn valid_base64_quartet(quartet: [u8; 4]) -> bool {
    (quartet.iter().all(|byte| base64_alphabet(*byte)))
        || (base64_alphabet(quartet[0])
            && base64_alphabet(quartet[1])
            && base64_alphabet(quartet[2])
            && quartet[3] == b'='
            && base64_value(quartet[2]).is_some_and(|value| value & 0b11 == 0))
        || (base64_alphabet(quartet[0])
            && base64_alphabet(quartet[1])
            && quartet[2] == b'='
            && quartet[3] == b'='
            && base64_value(quartet[1]).is_some_and(|value| value & 0b1111 == 0))
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
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

fn decode_charset(bytes: &[u8], charset: &str) -> (String, bool) {
    encoding_rs::Encoding::for_label(charset.trim().as_bytes()).map_or_else(
        || (String::from_utf8_lossy(bytes).into_owned(), true),
        |encoding| {
            let (text, replacements) = encoding.decode_without_bom_handling(bytes);
            (text.into_owned(), replacements)
        },
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
