//! Bounded deterministic MIME shared by draft preparation and the IMAP adapter.
use crate::domain::dot_atom;
use mail_builder::MessageBuilder;
use sha2::{Digest, Sha256};

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
        let mut builder = MessageBuilder::new()
            .from(input.from)
            .subject(input.subject)
            .message_id(input.message_id)
            .date(input.date_unix)
            .text_body(normalize_body(input.body));
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
        let mut bytes = vec![0; max_mime_bytes];
        let mut output = bytes.as_mut_slice();
        builder.write_to(&mut output).map_err(|_| Error::Limit)?;
        let written = max_mime_bytes - output.len();
        bytes.truncate(written);
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

pub(crate) fn normalize_body(body: String) -> String {
    if body.contains('\r') {
        body.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        body
    }
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
