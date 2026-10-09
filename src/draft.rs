//! Draft composition and verification types shared by provider adapters and the journal.
use crate::domain::dot_atom;
use mail_builder::MessageBuilder;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(crate) const ENCODER_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Limit,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "Invalid draft composition",
            Self::Limit => "Draft composition exceeds its limit",
        })
    }
}
impl std::error::Error for Error {}
impl From<Error> for crate::domain::Error {
    fn from(error: Error) -> Self {
        Self::new(match error {
            Error::InvalidInput => crate::domain::ErrorCode::InvalidRequest,
            Error::Limit => crate::domain::ErrorCode::ResponseTooLarge,
        })
    }
}
fn recipients(
    values: Vec<crate::domain::DraftAddress>,
) -> Vec<mail_builder::headers::address::Address<'static>> {
    values
        .into_iter()
        .map(|address| {
            mail_builder::headers::address::Address::new_address(address.name, address.address)
        })
        .collect()
}
/// Deterministic plain-text draft composition. Addresses use ASCII addr-spec syntax.
/// Message-ID and reply identifiers use ASCII dot-atoms on both sides of `@`,
/// without angle brackets. Quoted identifiers and domain literals remain unsupported.
#[derive(Clone, Default)]
pub struct DraftInput {
    pub from: String,
    pub to: Vec<crate::domain::DraftAddress>,
    pub cc: Vec<crate::domain::DraftAddress>,
    pub bcc: Vec<crate::domain::DraftAddress>,
    pub subject: String,
    pub body: String,
    /// Message-ID without angle brackets; frozen by the draft operation owner.
    pub message_id: String,
    pub date_unix: i64,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

/// Frozen bounded MIME; composition never contacts a provider.
pub struct PreparedDraft {
    bytes: Vec<u8>,
    sha256: [u8; 32],
    header_bytes: usize,
}
impl PreparedDraft {
    pub fn compose(input: DraftInput, max_mime_bytes: usize) -> Result<Self, Error> {
        if max_mime_bytes == 0 || max_mime_bytes > 8 * 1024 * 1024 {
            return Err(Error::InvalidInput);
        }
        if input
            .to
            .len()
            .saturating_add(input.cc.len())
            .saturating_add(input.bcc.len())
            > 100
            || input.subject.len() > 8 * 1024
            || input.body.len() > max_mime_bytes
            || input.references.len() > 50
        {
            return Err(Error::Limit);
        }
        address(&input.from)?;
        for value in input.to.iter().chain(&input.cc).chain(&input.bcc) {
            address(&value.address)?;
            if value
                .name
                .as_ref()
                .is_some_and(|name| name.len() > 1024 || name.chars().any(char::is_control))
            {
                return Err(Error::InvalidInput);
            }
        }
        identifier(&input.message_id)?;
        for value in input.in_reply_to.iter().chain(&input.references) {
            identifier(value)?;
        }
        if input.subject.chars().any(char::is_control)
            || !(0..=253_402_300_799).contains(&input.date_unix)
            || input.body.contains('\0')
        {
            return Err(Error::InvalidInput);
        }
        let body = normalize_body(input.body);
        let header_input_bytes = input.to.iter().chain(&input.cc).chain(&input.bcc).fold(
            input.subject.len() + input.from.len() + input.message_id.len(),
            |bytes, address| {
                bytes + address.address.len() + address.name.as_ref().map_or(0, String::len)
            },
        ) + input.in_reply_to.as_ref().map_or(0, String::len)
            + input.references.iter().map(String::len).sum::<usize>();
        // Reserve for this body and bounded header expansion. This is only a
        // storage hint: the pinned encoder and writer retain byte admission.
        let capacity = header_input_bytes
            .saturating_mul(3)
            .saturating_add(body_capacity_hint(&body))
            .saturating_add(4096)
            .min(max_mime_bytes);
        let mut builder = MessageBuilder::new()
            .from(input.from)
            .subject(input.subject)
            .message_id(input.message_id)
            .date(input.date_unix)
            .text_body(body);
        if !input.to.is_empty() {
            builder = builder.to(recipients(input.to));
        }
        if !input.cc.is_empty() {
            builder = builder.cc(recipients(input.cc));
        }
        if !input.bcc.is_empty() {
            builder = builder.bcc(recipients(input.bcc));
        }
        if let Some(value) = input.in_reply_to {
            builder = builder.in_reply_to(value);
        }
        if !input.references.is_empty() {
            builder = builder.references(input.references);
        }
        let mut output = MimeOutput {
            bytes: Vec::with_capacity(capacity),
            maximum: max_mime_bytes,
        };
        builder.write_to(&mut output).map_err(|_| Error::Limit)?;
        let bytes = output.bytes;
        let header_bytes = bytes
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or(Error::InvalidInput)?
            + 4;
        if header_bytes > 256 * 1024 {
            return Err(Error::Limit);
        }
        let sha256 = Sha256::digest(&bytes).into();
        Ok(Self {
            bytes,
            sha256,
            header_bytes,
        })
    }
    pub fn header_bytes(&self) -> usize {
        self.header_bytes
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

fn body_capacity_hint(body: &str) -> usize {
    let encoded = body.len().div_ceil(3).saturating_mul(4);
    // The encoder compares pre-fold quoted-printable size with base64. Allow
    // three-byte soft breaks after 74 columns even when quoted-printable wins
    // narrowly; this also covers base64's two-byte folds after 76 columns.
    let encoding_bound = encoded.saturating_add(encoded.div_ceil(74).saturating_mul(3));
    if !body.is_ascii() {
        return encoding_bound;
    }
    // Reduce bounded chunks as bytes, then widen, so large bodies can use cheap
    // narrow reductions. Each chunk count is at most 64 and cannot overflow.
    let (chunks, tail) = body.as_bytes().as_chunks::<64>();
    let breaks = chunks
        .iter()
        .map(|chunk| {
            usize::from(
                chunk
                    .iter()
                    .map(|byte| u8::from(*byte == b'\n'))
                    .sum::<u8>(),
            )
        })
        .sum::<usize>()
        + tail
            .iter()
            .map(|byte| usize::from(*byte == b'\n'))
            .sum::<usize>();
    let plain = body.len().saturating_add(breaks);
    // Rust's ASCII classification includes DEL, which this encoder escapes.
    // Equals alone may leave the body in 7bit, so retain its plain LF floor.
    if body.contains('=')
        || body.contains('\u{7f}')
        || body.ends_with([' ', '\t'])
        || body.contains(" \n")
        || body.contains("\t\n")
    {
        return encoding_bound.max(plain);
    }
    plain
        .saturating_add(plain.div_ceil(74).saturating_mul(3))
        .min(encoding_bound)
        .max(plain)
}

struct MimeOutput {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for MimeOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::other("MIME exceeds its byte limit"))?;
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.maximum);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn normalize_body(body: String) -> String {
    if !body.contains('\r') {
        return body;
    }
    let mut normalized = String::with_capacity(body.len());
    let mut remaining = body.as_str();
    while let Some((line, rest)) = remaining.split_once('\r') {
        normalized.push_str(line);
        normalized.push('\n');
        remaining = rest.strip_prefix('\n').unwrap_or(rest);
    }
    normalized.push_str(remaining);
    normalized
}

fn address(value: &str) -> Result<(), Error> {
    if value.len() > 254 {
        return Err(Error::Limit);
    }
    let Some((local, domain)) = value.split_once('@') else {
        return Err(Error::InvalidInput);
    };
    if local.len() > 64
        || !dot_atom(local)
        || domain.is_empty()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn identifier(value: &str) -> Result<(), Error> {
    if value.len() > 998 {
        return Err(Error::Limit);
    }
    let Some((left, right)) = value.split_once('@') else {
        return Err(Error::InvalidInput);
    };
    if !dot_atom(left) || !dot_atom(right) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// A message UID within the verified incarnation of its original Drafts mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DraftMessageIdentity {
    pub uid_validity: u32,
    pub uid: u32,
}

/// Frozen evidence required to identify an uncertain draft without composing it again.
pub struct DraftVerification {
    pub uid_validity: u32,
    pub message_id: String,
    pub content_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftEvidence {
    Verified(DraftMessageIdentity),
    Absent,
    Ambiguous,
    ContentMismatch,
}
