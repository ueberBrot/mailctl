//! Terminal presentation of semantic operation results.
use crate::domain::OperationResult;
use std::fmt::Write;

pub(super) fn human(result: &OperationResult) -> Result<String, serde_json::Error> {
    let mut metadata = serde_json::to_value(result)?;
    let body = if let OperationResult::Message(message) = result {
        metadata["body"]
            .as_object_mut()
            .expect("body metadata")
            .remove("text");
        Some(message.body.text.as_str())
    } else {
        None
    };
    let mut output = metadata_text(serde_json::to_string_pretty(&metadata)?);
    if let Some(body) = body {
        output.push_str("\n\nBody:\n");
        append_body(&mut output, body);
    }
    Ok(output)
}

fn unsafe_character(character: char) -> bool {
    character.is_control()
        || matches!(character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' |
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn metadata_text(text: String) -> String {
    // Literal newlines belong to JSON layout; string newlines are already escaped.
    let Some(start) = text.find(|character| character != '\n' && unsafe_character(character))
    else {
        return text;
    };
    let mut output = String::with_capacity(text.len());
    output.push_str(&text[..start]);
    for character in text[start..].chars() {
        if character != '\n' && unsafe_character(character) {
            let _ = write!(output, "\\u{{{:04x}}}", character as u32);
        } else {
            output.push(character);
        }
    }
    output
}

fn append_body(output: &mut String, text: &str) {
    output.reserve(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                characters.next_if_eq(&'\n');
                output.push('\n');
            }
            '\n' => output.push('\n'),
            '\t' => output.push_str("    "),
            '\u{1b}' => match characters.peek().copied() {
                Some('[') => {
                    characters.next();
                    skip_csi(&mut characters);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    let osc = characters.next() == Some(']');
                    skip_string(&mut characters, osc);
                }
                _ => output.push_str("\\u{001b}"),
            },
            '\u{009b}' => skip_csi(&mut characters),
            '\u{009d}' => skip_string(&mut characters, true),
            '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}' => {
                skip_string(&mut characters, false)
            }
            character if unsafe_character(character) => {
                let _ = write!(output, "\\u{{{:04x}}}", character as u32);
            }
            _ => output.push(character),
        }
    }
}

fn skip_csi(characters: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    // Consume through the final byte; incomplete sequences end at the page boundary.
    for character in characters.by_ref() {
        if ('@'..='~').contains(&character) {
            break;
        }
    }
}

fn skip_string(characters: &mut std::iter::Peekable<std::str::Chars<'_>>, osc: bool) {
    while let Some(character) = characters.next() {
        if character == '\u{009c}' || (osc && character == '\u{7}') {
            break;
        }
        if character == '\u{1b}' && characters.next_if_eq(&'\\').is_some() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BodyText, MessageBody};

    fn message(text: &str) -> OperationResult {
        OperationResult::Message(MessageBody {
            account_id: "account".into(),
            generation: 1,
            message_reference: "message".into(),
            body: BodyText {
                text: text.into(),
                selected_part: Some("1".into()),
                source_media_type: Some("text/plain".into()),
                representation_version: "1".into(),
                converted: false,
                replacements: false,
                truncated: false,
                empty_reason: None,
                continuation_available: false,
                next_cursor: None,
            },
        })
    }

    #[test]
    fn labels_and_incomplete_sequences_stay_inert() {
        let mut result = message("");
        if let OperationResult::Message(message) = &mut result {
            message.account_id = "name\n\t\r\u{1b}\u{009b}\u{202e}é".into();
        }
        let rendered = human(&result).unwrap();
        assert!(
            !rendered.contains('\u{1b}')
                && !rendered.contains('\u{009b}')
                && !rendered.contains('\u{202e}')
        );
        assert!(rendered.contains("é"));
        for sequence in [
            "\u{1b}]8;;url",
            "\u{1b}Ppayload",
            "\u{009d}payload",
            "\u{1b}[31",
        ] {
            assert!(
                human(&message(&format!("before{sequence}")))
                    .unwrap()
                    .ends_with("Body:\nbefore")
            );
        }
        assert!(
            human(&message(
                "a\u{1b}]8;;url\u{1b}\\b\u{009b}31mc\u{009d}title\u{009c}d"
            ))
            .unwrap()
            .ends_with("Body:\nabcd")
        );
    }

    #[test]
    fn human_body_preserves_paragraphs_and_neutralizes_terminal_controls() {
        let result = message(
            "First café\r\n\r\nSecond\tcolumn\rThird\u{1b}]52;c;clipboard\u{7}safe\u{1b}[31mred\u{1b}[0m\u{202e}\u{0}",
        );
        let rendered = human(&result).unwrap();
        assert!(
            rendered.contains("First café\n\nSecond    column\nThirdsafered\\u{202e}\\u{0000}"),
            "{rendered}"
        );
        assert!(!rendered.contains("clipboard"));
        assert!(!rendered.contains('\u{1b}'));
        let semantic = serde_json::to_value(&result).unwrap();
        assert!(
            semantic["body"]["text"]
                .as_str()
                .unwrap()
                .contains("\u{1b}]52;c;clipboard")
        );
    }
}
