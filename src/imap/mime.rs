//! MIME structure limits and part identity shared by message readers.
use super::{Error, Limits};
use imap_proto::{
    BodyContentCommon, BodyContentSinglePart, BodyStructure, ContentDisposition, ContentEncoding,
};
use std::{fmt::Write, num::NonZeroU32};

pub(super) type Part = Vec<NonZeroU32>;

/// Count every server-provided node, including ineligible attached-message subtrees.
pub(super) fn validate_structure(
    structure: &BodyStructure<'_>,
    limits: &Limits,
) -> Result<(), Error> {
    fn visit(
        structure: &BodyStructure<'_>,
        limits: &Limits,
        parts: &mut usize,
        depth: usize,
    ) -> Result<(), Error> {
        *parts = parts.checked_add(1).ok_or(Error::Limit)?;
        if *parts > limits.max_mime_parts || depth > limits.max_nesting {
            return Err(Error::Limit);
        }
        match structure {
            BodyStructure::Message { body, .. } => visit(body, limits, parts, depth + 1)?,
            BodyStructure::Multipart { bodies, .. } => {
                for body in bodies {
                    visit(body, limits, parts, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(structure, limits, &mut 0, 1)
}

pub(super) fn common<'a, 'b>(structure: &'a BodyStructure<'b>) -> &'a BodyContentCommon<'b> {
    match structure {
        BodyStructure::Basic { common, .. }
        | BodyStructure::Text { common, .. }
        | BodyStructure::Message { common, .. }
        | BodyStructure::Multipart { common, .. } => common,
    }
}

pub(super) fn single<'a, 'b>(
    structure: &'a BodyStructure<'b>,
) -> Option<&'a BodyContentSinglePart<'b>> {
    match structure {
        BodyStructure::Basic { other, .. }
        | BodyStructure::Text { other, .. }
        | BodyStructure::Message { other, .. } => Some(other),
        BodyStructure::Multipart { .. } => None,
    }
}

pub(super) fn attachment(disposition: Option<&ContentDisposition<'_>>) -> bool {
    disposition.is_some_and(|disposition| disposition.ty.eq_ignore_ascii_case("attachment"))
}

pub(super) fn encoding_name<'a>(encoding: &'a ContentEncoding<'_>) -> &'a str {
    match encoding {
        ContentEncoding::SevenBit => "7bit",
        ContentEncoding::EightBit => "8bit",
        ContentEncoding::Binary => "binary",
        ContentEncoding::Base64 => "base64",
        ContentEncoding::QuotedPrintable => "quoted-printable",
        ContentEncoding::Other(value) => value,
    }
}

pub(super) fn part_name(part: &[NonZeroU32]) -> String {
    let mut name = String::new();
    for (index, number) in part.iter().enumerate() {
        if index != 0 {
            name.push('.');
        }
        let _ = write!(name, "{number}");
    }
    name
}
