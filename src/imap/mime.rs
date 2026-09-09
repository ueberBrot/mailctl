//! MIME structure limits and part identity shared by message readers.
use super::{Error, Limits};
use io_imap::types::{
    body::{BodyStructure, Disposition, SpecificFields},
    core::IString,
    fetch::Part,
};
use std::{fmt::Write, num::NonZeroU32};

/// Count the complete server-provided structure before selection cuts off attached-message and
/// attachment subtrees. Those subtrees are ineligible for rendering, but still consume the MIME
/// structure budget.
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
            BodyStructure::Single { body, .. } => {
                if let SpecificFields::Message { body_structure, .. } = &body.specific {
                    visit(body_structure, limits, parts, depth + 1)?;
                }
            }
            BodyStructure::Multi { bodies, .. } => {
                for body in bodies.as_ref() {
                    visit(body, limits, parts, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    let mut parts = 0;
    visit(structure, limits, &mut parts, 1)
}

pub(super) fn attachment(disposition: Option<&Disposition<'_>>) -> bool {
    disposition
        .and_then(|disposition| disposition.disposition.as_ref())
        .is_some_and(|(kind, _)| kind.as_ref().eq_ignore_ascii_case(b"attachment"))
}

pub(super) fn imap_text<'a>(value: &'a IString<'_>) -> Result<&'a str, Error> {
    std::str::from_utf8(value.as_ref()).map_err(|_| Error::Protocol)
}

pub(super) fn child_path(parent: Option<&Part>, child: usize) -> Result<Part, Error> {
    let child =
        NonZeroU32::new(u32::try_from(child).map_err(|_| Error::Limit)?).ok_or(Error::Limit)?;
    let mut parts = parent.map_or_else(Vec::new, |parent| parent.0.as_ref().to_vec());
    parts.push(child);
    Ok(Part(
        parts.try_into().expect("child makes the path nonempty"),
    ))
}

pub(super) fn part_name(part: &Part) -> String {
    let mut name = String::new();
    for (index, number) in part.0.as_ref().iter().enumerate() {
        if index != 0 {
            name.push('.');
        }
        let _ = write!(name, "{number}");
    }
    name
}
