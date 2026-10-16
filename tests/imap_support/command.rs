//! Fixture-only lexical checks for the small outgoing command set exercised here.
//! This does not parse responses or participate in production admission.

#[derive(Debug, Eq, PartialEq)]
pub enum Token {
    Value(Vec<u8>),
    Open,
    Close,
}

#[derive(Debug)]
pub struct Command {
    pub tag: String,
    pub body: Vec<Token>,
}

impl Command {
    pub fn is(&self, body: &str) -> bool {
        self.body
            == parse(format!("expected {body}\r\n").as_bytes())
                .unwrap()
                .body
    }

    pub fn bounded_peek(&self, uid: u32) -> (String, usize, usize) {
        let [
            Token::Value(prefix),
            Token::Value(fetch),
            Token::Value(actual_uid),
            Token::Open,
            Token::Value(uid_attribute),
            Token::Value(peek),
            Token::Close,
        ] = self.body.as_slice()
        else {
            panic!(
                "only UID FETCH with UID and one bounded PEEK is allowed: {:?}",
                self.body
            );
        };
        assert_eq!(prefix, b"UID");
        assert_eq!(fetch, b"FETCH");
        assert_eq!(actual_uid, uid.to_string().as_bytes());
        assert_eq!(uid_attribute, b"UID");
        let peek = std::str::from_utf8(peek).unwrap();
        let (section, partial) = peek
            .strip_prefix("BODY.PEEK[")
            .unwrap()
            .split_once("]<")
            .unwrap();
        let (offset, count) = partial.strip_suffix('>').unwrap().split_once('.').unwrap();
        (
            section.to_owned(),
            offset.parse().unwrap(),
            count.parse().unwrap(),
        )
    }
}

// Only known UID-set positions are normalized. Intervals stay intervals even at
// u32::MAX, so fixture checks cannot accidentally expand a huge provider range.
fn normalize_uid_set(body: &mut [Token]) {
    let value = |index: usize| match body.get(index) {
        Some(Token::Value(value)) => Some(value.as_slice()),
        _ => None,
    };
    if value(0) != Some(b"UID") {
        return;
    }
    let index = match value(1) {
        Some(b"FETCH") => 2,
        Some(b"SEARCH") if value(2) == Some(b"UID") => 3,
        Some(b"SEARCH") if value(2) == Some(b"CHARSET") && value(4) == Some(b"UID") => 5,
        _ => return,
    };
    let Some(Token::Value(value)) = body.get_mut(index) else {
        return;
    };
    if let Some(normalized) = finite_uid_set(value) {
        *value = normalized;
    }
}

fn finite_uid_set(value: &[u8]) -> Option<Vec<u8>> {
    let number = |value: &[u8]| {
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let value: u32 = std::str::from_utf8(value).ok()?.parse().ok()?;
        (value != 0).then_some(value)
    };
    let mut ranges = Vec::new();
    for item in value.split(|byte| *byte == b',') {
        let (first, last) = if let Some(colon) = item.iter().position(|byte| *byte == b':') {
            (number(&item[..colon])?, number(&item[colon + 1..])?)
        } else {
            let value = number(item)?;
            (value, value)
        };
        ranges.push((first.min(last), first.max(last)));
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::new();
    for (first, last) in ranges {
        if let Some((_, previous_last)) = merged.last_mut()
            && first <= previous_last.saturating_add(1)
        {
            *previous_last = (*previous_last).max(last);
        } else {
            merged.push((first, last));
        }
    }
    Some(
        merged
            .into_iter()
            .map(|(first, last)| {
                if first == last {
                    first.to_string()
                } else {
                    format!("{first}:{last}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
            .into_bytes(),
    )
}

#[derive(Debug)]
pub enum DecodeError {
    Incomplete,
    Literal { boundary: usize },
    Malformed,
}

pub fn parse(input: &[u8]) -> Result<Command, DecodeError> {
    use DecodeError::{Incomplete, Malformed};
    let mut tokens = Vec::new();
    let mut index = 0;
    loop {
        let byte = *input.get(index).ok_or(Incomplete)?;
        match byte {
            b' ' => index += 1,
            b'\r' => {
                if input.get(index + 1) != Some(&b'\n') {
                    return if index + 1 == input.len() {
                        Err(Incomplete)
                    } else {
                        Err(Malformed)
                    };
                }
                if index + 2 != input.len() {
                    return Err(Malformed);
                }
                let Some(Token::Value(tag)) = tokens.first() else {
                    return Err(Malformed);
                };
                let tag = String::from_utf8(tag.clone()).map_err(|_| Malformed)?;
                if tag.is_empty()
                    || !tag
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                {
                    return Err(Malformed);
                }
                tokens.remove(0);
                normalize_uid_set(&mut tokens);
                return Ok(Command { tag, body: tokens });
            }
            b'(' | b')' => {
                tokens.push(if byte == b'(' {
                    Token::Open
                } else {
                    Token::Close
                });
                index += 1;
            }
            b'"' => {
                index += 1;
                let mut value = Vec::new();
                loop {
                    let byte = *input.get(index).ok_or(Incomplete)?;
                    index += 1;
                    match byte {
                        b'"' => break,
                        b'\\' => {
                            let escaped = *input.get(index).ok_or(Incomplete)?;
                            if !matches!(escaped, b'"' | b'\\') {
                                return Err(Malformed);
                            }
                            value.push(escaped);
                            index += 1;
                        }
                        b'\r' | b'\n' | 0 => return Err(Malformed),
                        byte => value.push(byte),
                    }
                }
                tokens.push(Token::Value(value));
            }
            b'{' => {
                let start = index + 1;
                let Some(relative_end) = input[start..].iter().position(|b| *b == b'}') else {
                    return Err(Incomplete);
                };
                let end = start + relative_end;
                let number = input[start..end]
                    .strip_suffix(b"+")
                    .unwrap_or(&input[start..end]);
                if number.is_empty() || !number.iter().all(u8::is_ascii_digit) {
                    return Err(Malformed);
                }
                let length: usize = std::str::from_utf8(number)
                    .map_err(|_| Malformed)?
                    .parse()
                    .map_err(|_| Malformed)?;
                if length > 16 * 1024 {
                    return Err(Malformed);
                }
                let boundary = end.checked_add(3).ok_or(Malformed)?;
                if input.len() < boundary {
                    return Err(Incomplete);
                }
                if &input[end + 1..boundary] != b"\r\n" {
                    return Err(Malformed);
                }
                let payload_end = boundary.checked_add(length).ok_or(Malformed)?;
                if input.len() < payload_end {
                    return Err(DecodeError::Literal { boundary });
                }
                tokens.push(Token::Value(input[boundary..payload_end].to_vec()));
                index = payload_end;
            }
            b'\n' | 0 => return Err(Malformed),
            _ => {
                let start = index;
                while input.get(index).is_some_and(|b| !b" ()\r\n".contains(b)) {
                    index += 1;
                }
                if index == input.len() {
                    return Err(Incomplete);
                }
                tokens.push(Token::Value(input[start..index].to_vec()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_and_literal_values_preserve_exact_bytes() {
        let quoted = parse(b"A1 LIST \"\" \"a\\\\b\\\"c\"\r\n").unwrap();
        let literal = parse(b"M2 LIST {0}\r\n {5}\r\na\\b\"c\r\n").unwrap();
        assert_eq!(quoted.body, literal.body);
        assert!(!quoted.is("LIST \"\" \"ab\\\"c\""));
    }

    #[test]
    fn bounded_peek_checks_the_entire_command() {
        let command = parse(b"A1 UID FETCH 4 (UID BODY.PEEK[1.2]<3.1024>)\r\n").unwrap();
        assert_eq!(command.bounded_peek(4), ("1.2".to_owned(), 3, 1024));
    }
    #[test]
    fn finite_uid_sets_compare_exactly_without_expanding_ranges() {
        let command = parse(b"A1 UID FETCH 3,1,2,9 (UID)\r\n").unwrap();
        assert!(command.is("UID FETCH 1:3,9 (UID)"));
        assert!(!command.is("UID FETCH 1:4,9 (UID)"));
        assert!(!command.is("UID FETCH 1,3,9 (UID)"));
        assert_eq!(finite_uid_set(b"1:4294967295").unwrap(), b"1:4294967295");
        assert!(finite_uid_set(b"1:*").is_none());
        let command = parse(b"A1 UID SEARCH UID 1:1\r\n").unwrap();
        assert!(command.is("UID SEARCH UID 1"));
    }
}
