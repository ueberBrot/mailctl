//! Shared allocation bounds for JSON parsing and serialization.
use crate::domain::{Error, ErrorCode};
use serde::Serialize;
use std::io::{self, Write};

pub(crate) fn request_buffer_bytes(length: usize) -> usize {
    let owned_strings = length.min(256 * 1024 + 2 * 64 + 256 + 16);
    let descriptors = (length / 3).min(256).next_power_of_two() * std::mem::size_of::<String>();
    // The input and JSON escape scratch coexist with bounded owned fields.
    length * 2 + owned_strings + descriptors
}

pub(crate) struct OutputBudget {
    remaining: usize,
}
impl OutputBudget {
    pub(crate) fn new(remaining: usize) -> Self {
        Self { remaining }
    }
    pub(crate) fn reserve(&mut self, bytes: usize) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| Error::new(ErrorCode::ResponseTooLarge))?;
        Ok(())
    }
    pub(crate) fn count(&mut self, value: &impl Serialize) -> Result<(), Error> {
        serde_json::to_writer(self, value).map_err(|_| Error::new(ErrorCode::ResponseTooLarge))
    }
}
impl Write for OutputBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.reserve(bytes.len()).map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialized_size<T: Serialize>(value: &T, maximum: usize) -> Result<usize, Error> {
    let mut budget = OutputBudget::new(maximum);
    budget.count(value)?;
    Ok(maximum - budget.remaining)
}

pub(crate) fn serialize_bounded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, Error> {
    let length = serialized_size(value, maximum)?;
    let mut bytes = vec![0; length];
    // A slice writer cannot grow, even if a serializer emits more on its second pass.
    let mut output = bytes.as_mut_slice();
    serde_json::to_writer(&mut output, value)
        .map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
    let written = length - output.len();
    bytes.truncate(written);
    Ok(bytes)
}

/// Bound nesting and structural nodes before the JSON decoder allocates values.
#[cfg(any(feature = "cli", feature = "mcp", target_os = "macos"))]
pub(crate) fn validate_json_bounds(
    bytes: &[u8],
    maximum_depth: usize,
    maximum_nodes: usize,
) -> Result<(), Error> {
    let mut depth = 0usize;
    let mut nodes = 1usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match *byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > maximum_depth {
                        return Err(Error::new(ErrorCode::InvalidRequest));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if matches!(byte, b'{' | b'[' | b',' | b':') {
                nodes += 1;
                if nodes > maximum_nodes {
                    return Err(Error::new(ErrorCode::InvalidRequest));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[cfg(any(feature = "cli", feature = "mcp", target_os = "macos"))]
    fn json_bounds_ignore_structure_inside_escaped_strings() {
        let bytes = serde_json::to_vec(&json!({"value": "\\\"[{,:}]"})).unwrap();
        validate_json_bounds(&bytes, 1, 3).unwrap();
        assert_eq!(
            validate_json_bounds(&bytes, 0, 3).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            validate_json_bounds(&bytes, 1, 2).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    #[cfg(any(feature = "cli", feature = "mcp", target_os = "macos"))]
    fn json_bounds_enforce_depth_and_nodes_independently() {
        let bytes = br#"{"values":[{},[]]}"#;
        validate_json_bounds(bytes, 3, 7).unwrap();
        assert!(validate_json_bounds(bytes, 2, usize::MAX).is_err());
        assert!(validate_json_bounds(bytes, 3, 6).is_err());
        validate_json_bounds(b"[[],[]]", 2, usize::MAX).unwrap();
    }

    #[test]
    fn response_serialization_stops_at_the_frame_ceiling() {
        assert_eq!(
            serialize_bounded(&json!({"ok": true}), 11).unwrap(),
            br#"{"ok":true}"#
        );
        assert_eq!(
            serialize_bounded(&json!({"ok": true}), 10)
                .unwrap_err()
                .code,
            ErrorCode::ResponseTooLarge
        );
    }
}
