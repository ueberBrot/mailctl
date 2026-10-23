//! Plain-text extraction policy; visibility is limited to explicit inline hints.

use std::borrow::Cow;

pub(super) fn apply(root: &html2text::Handle) {
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        if let html2text::Element { attrs, .. } = &node.data {
            attrs.borrow_mut().retain(|attribute| {
                attribute.name.local.as_ref() != "href"
                    || allowed_link_destination(&attribute.value)
            });
        }
        let mut children = node.children.borrow_mut();
        children.retain(|child| match &child.data {
            html2text::Comment { .. } => false,
            html2text::Element { name, attrs, .. } => {
                !matches!(
                    name.local.as_ref(),
                    "head"
                        | "script"
                        | "style"
                        | "template"
                        | "noscript"
                        | "iframe"
                        | "object"
                        | "embed"
                        | "svg"
                        | "math"
                        | "canvas"
                        | "audio"
                        | "video"
                ) && !attrs.borrow().iter().any(|attribute| {
                    attribute.name.local.as_ref() == "hidden"
                        || attribute.name.local.as_ref() == "style"
                            && inline_style_hides(&attribute.value)
                })
            }
            _ => true,
        });
        stack.extend(children.iter().cloned());
    }
}

fn allowed_link_destination(value: &str) -> bool {
    if value.chars().any(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(character, '\\' | '\u{061c}' | '\u{200e}' | '\u{200f}'
                | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) {
        return false;
    }
    let Some((scheme, destination)) = value.split_once(':') else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        destination.strip_prefix("//").is_some_and(|destination| {
            !destination
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .is_empty()
        })
    } else {
        scheme.eq_ignore_ascii_case("mailto")
            && !destination.is_empty()
            && !destination.starts_with(['/', '?', '#'])
    }
}

fn inline_style_hides(style: &str) -> bool {
    let mut remaining = style;
    while let Some((property, value)) = css_declaration(&mut remaining) {
        let property = inline_css_text(property);
        let property = property.trim();
        let value = inline_css_text(value);
        let value = value.as_ref();
        let value = match value.rsplit_once('!') {
            Some((value, priority)) if priority.trim().eq_ignore_ascii_case("important") => value,
            _ => value,
        }
        .trim();
        if property.eq_ignore_ascii_case("display") && value.eq_ignore_ascii_case("none")
            || property.eq_ignore_ascii_case("visibility")
                && (value.eq_ignore_ascii_case("hidden") || value.eq_ignore_ascii_case("collapse"))
            || property.eq_ignore_ascii_case("mso-hide") && value.eq_ignore_ascii_case("all")
            || property.eq_ignore_ascii_case("opacity") && zero_opacity(value)
        {
            return true;
        }
    }
    false
}

fn zero_opacity(value: &str) -> bool {
    let number = value.strip_suffix('%').unwrap_or(value);
    let number = number.strip_prefix(['+', '-']).unwrap_or(number);
    let mantissa = match number.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => {
            let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
            if exponent.is_empty() || !exponent.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            mantissa
        }
        None => number,
    };
    match mantissa.split_once('.') {
        Some((integer, fraction)) => {
            !fraction.is_empty()
                && integer.bytes().all(|byte| byte == b'0')
                && fraction.bytes().all(|byte| byte == b'0')
        }
        None => !mantissa.is_empty() && mantissa.bytes().all(|byte| byte == b'0'),
    }
}

// This recognizes explicit inline hiding hints, not the CSS cascade. Delimiters
// inside strings, comments and functions cannot introduce declarations.
fn css_declaration<'a>(remaining: &mut &'a str) -> Option<(&'a str, &'a str)> {
    if remaining.is_empty() {
        return None;
    }
    let source = *remaining;
    let mut characters = source.char_indices().peekable();
    let mut quote = None;
    let mut depth = 0usize;
    let mut start = 0;
    let mut separator = None;
    while let Some((offset, character)) = characters.next() {
        if character == '\\' {
            characters.next();
        } else if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            }
        } else if character == '/' && characters.next_if(|&(_, next)| next == '*').is_some() {
            while let Some((_, character)) = characters.next() {
                if character == '*' && characters.next_if(|&(_, next)| next == '/').is_some() {
                    break;
                }
            }
        } else {
            match character {
                '\'' | '"' => quote = Some(character),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ':' if depth == 0 && separator.is_none() => separator = Some(offset),
                ';' if depth == 0 => {
                    if let Some(separator) = separator {
                        *remaining = &source[offset + 1..];
                        return Some((&source[start..separator], &source[separator + 1..offset]));
                    }
                    start = offset + 1;
                }
                _ => {}
            }
        }
    }
    *remaining = "";
    separator.map(|separator| (&source[start..separator], &source[separator + 1..]))
}

fn inline_css_text(text: &str) -> Cow<'_, str> {
    if !text.contains(['\\', '/']) {
        return Cow::Borrowed(text);
    }
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '/' && characters.next_if_eq(&'*').is_some() {
            while let Some(character) = characters.next() {
                if character == '*' && characters.next_if_eq(&'/').is_some() {
                    break;
                }
            }
            output.push(' ');
        } else if character == '\\' {
            let mut value = 0;
            let mut digits = 0;
            while digits < 6 {
                let Some(digit) = characters
                    .peek()
                    .and_then(|character| character.to_digit(16))
                else {
                    break;
                };
                characters.next();
                value = value * 16 + digit;
                digits += 1;
            }
            if digits > 0 {
                if characters
                    .next_if(|character| matches!(character, ' ' | '\t' | '\r' | '\n' | '\u{000c}'))
                    .is_some_and(|character| character == '\r')
                {
                    characters.next_if_eq(&'\n');
                }
                output.push(
                    char::from_u32(value)
                        .filter(|&character| character != '\0')
                        .unwrap_or('\u{fffd}'),
                );
            } else {
                output.push(characters.next().unwrap_or('\u{fffd}'));
            }
        } else {
            output.push(character);
        }
    }
    Cow::Owned(output)
}
