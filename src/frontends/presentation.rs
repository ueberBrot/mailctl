//! Terminal presentation of semantic operation results.
use crate::domain::{Error, OperationResult};
use std::{borrow::Cow, fmt::Write};

pub(super) fn human(result: &OperationResult) -> Result<String, serde_json::Error> {
    let mut output = String::new();
    match result {
        OperationResult::Accounts(page) => {
            for account in &page.accounts {
                let _ = writeln!(
                    output,
                    "{}  {}  generation {}  {}",
                    label(&account.alias),
                    label(&account.account_id),
                    account.generation,
                    serde_json::to_value(account.availability)?
                        .as_str()
                        .expect("availability")
                );
            }
            if page.accounts.is_empty() {
                output.push_str("No authorized email accounts.\n");
            }
            if !page.complete {
                output.push_str(
                    "Account listing is incomplete; request a larger authorized limit.\n",
                );
            }
        }
        OperationResult::Mailboxes(page) => {
            let _ = writeln!(
                output,
                "Account: {} (generation {})",
                label(&page.account_id),
                page.generation
            );
            for mailbox in &page.mailboxes {
                let selectable = if mailbox.metadata.selectable {
                    ""
                } else {
                    " (not selectable)"
                };
                let _ = writeln!(
                    output,
                    "{}{}\n  reference: {}",
                    label(&mailbox.display_label),
                    selectable,
                    label(&mailbox.reference)
                );
            }
            if page.mailboxes.is_empty() {
                output.push_str("No approved mailboxes found.\n");
            }
            continuation(&mut output, page.complete, page.next_cursor.as_deref());
        }
        OperationResult::Messages(page) => {
            let _ = writeln!(output, "{} messages", page.messages.len());
            for message in &page.messages {
                let subject = match &message.metadata.subject {
                    crate::domain::Metadata::Present(value) if value.is_empty() => {
                        "(empty subject)".into()
                    }
                    crate::domain::Metadata::Present(value) => label(value),
                    crate::domain::Metadata::Missing => "(missing subject)".into(),
                    crate::domain::Metadata::Malformed => "(malformed subject)".into(),
                };
                let _ = write!(output, "{}  ", label(&message.metadata.received_date));
                match &message.metadata.from {
                    crate::domain::Metadata::Present(addresses) => append_labels(
                        &mut output,
                        addresses.iter().map(|address| address.address.as_str()),
                    ),
                    crate::domain::Metadata::Missing => output.push_str("(missing sender)"),
                    crate::domain::Metadata::Malformed => output.push_str("(malformed sender)"),
                }
                let _ = writeln!(
                    output,
                    "  {}\n  reference: {}",
                    subject,
                    label(&message.reference)
                );
            }
            continuation(&mut output, page.complete, page.next_cursor.as_deref());
        }
        OperationResult::Message(message) => {
            let _ = write!(output, "Message: {}", label(&message.message_reference));
            if message.body.converted {
                let _ = write!(
                    output,
                    "\nText converted from {}.",
                    label(
                        message
                            .body
                            .source_media_type
                            .as_deref()
                            .unwrap_or("the selected body")
                    )
                );
            }
            if message.body.replacements {
                output.push_str("\nSome text required replacement characters.");
            }
            if message.body.empty_reason.is_some() {
                output.push_str("\nNo supported text body.");
            }
            output.push_str("\n\nBody:\n");
            append_body(&mut output, &message.body.text);
            if let Some(cursor) = &message.body.next_cursor {
                let _ = write!(
                    output,
                    "\n\nMore text available.\nCursor: {}",
                    label(cursor)
                );
            } else if message.body.truncated {
                output.push_str("\n\nText is truncated; no continuation is available.");
            }
        }
        OperationResult::Capabilities(capabilities) => {
            let _ = writeln!(
                output,
                "Grant: {}\nStatus: {}",
                label(&capabilities.health.grant),
                label(&capabilities.health.status)
            );
            output.push_str("Operations: ");
            append_labels(
                &mut output,
                capabilities.operations.iter().map(String::as_str),
            );
            output.push('\n');
            let _ = writeln!(
                output,
                "Permissions: {}",
                serde_json::to_string(&capabilities.permissions)?
            );
            let limits = &capabilities.limits;
            let _ = writeln!(
                output,
                "Page limits: {} accounts, {} mailboxes, {} messages",
                limits.accounts, limits.mailbox_page, limits.search_page
            );
            let _ = writeln!(
                output,
                "Text: {} bytes by default; maximum {} bytes per page",
                limits.default_text_page_bytes, limits.text_page_bytes
            );
            let _ = writeln!(
                output,
                "Attachments: {} bytes per file, {} bytes per chunk, {}s transfer lifetime",
                limits.attachment_decoded_bytes,
                limits.attachment_chunk_bytes,
                limits.transfer_seconds
            );
            let _ = writeln!(output, "Draft MIME: {} bytes", limits.draft_mime_bytes);
            let capacity = &capabilities.capacity.per_process;
            let _ = writeln!(
                output,
                "Process capacity: {} active requests, {} queued, {} buffered bytes",
                capacity.active_requests, capacity.queued_requests, capacity.buffered_bytes
            );
            if let Some(isolation) = &capabilities.capacity.isolation {
                let _ = writeln!(
                    output,
                    "Isolation capacity: {}",
                    serde_json::to_string(isolation)?
                );
            }
            for account in &capabilities.health.accounts {
                let _ = writeln!(
                    output,
                    "Account: {} (generation {}), {}",
                    label(&account.account_id),
                    account.generation,
                    serde_json::to_value(account.availability)?
                        .as_str()
                        .expect("availability")
                );
            }
            if let Some(availability) = capabilities.health.draft_creation {
                let _ = writeln!(
                    output,
                    "Draft creation: {}",
                    serde_json::to_value(availability)?
                        .as_str()
                        .expect("availability")
                );
            }
            if let Some(availability) = capabilities.health.draft_journal {
                let _ = writeln!(
                    output,
                    "Draft history: {}",
                    serde_json::to_value(availability)?
                        .as_str()
                        .expect("availability")
                );
            }
        }
        _ => return serde_json::to_string_pretty(result).map(metadata_text),
    }
    output.truncate(output.trim_end_matches('\n').len());
    Ok(output)
}

fn continuation(output: &mut String, complete: bool, cursor: Option<&str>) {
    if let Some(cursor) = cursor {
        let _ = writeln!(output, "More results available.\nCursor: {}", label(cursor));
    } else if !complete {
        output.push_str("Listing is incomplete; no continuation is available.\n");
    }
}

pub(super) fn human_error(error: &Error) -> Result<String, serde_json::Error> {
    let code = serde_json::to_value(error.code)?;
    let mut output = format!(
        "Error ({}): {}",
        code.as_str().expect("error code"),
        label(&error.message)
    );
    if let Some(operation) = &error.draft_operation {
        let _ = write!(
            output,
            "\nDraft operation: {}\nAccount: {} (generation {})\nMailbox: {}",
            operation.identity.operation_id,
            operation.identity.account_id,
            operation.identity.account_generation,
            label(&operation.mailbox)
        );
    }
    Ok(output)
}

fn label(text: &str) -> Cow<'_, str> {
    escape_characters(text, unsafe_character)
}

fn append_labels<'a>(output: &mut String, values: impl IntoIterator<Item = &'a str>) {
    let mut values = values.into_iter();
    if let Some(first) = values.next() {
        output.push_str(&label(first));
        for value in values {
            output.push_str(", ");
            output.push_str(&label(value));
        }
    }
}

fn escape_characters(text: &str, unsafe_character: impl Fn(char) -> bool) -> Cow<'_, str> {
    let Some(start) = text.find(&unsafe_character) else {
        return Cow::Borrowed(text);
    };
    let mut output = String::with_capacity(text.len());
    output.push_str(&text[..start]);
    for character in text[start..].chars() {
        if unsafe_character(character) {
            let _ = write!(output, "\\u{{{:04x}}}", character as u32);
        } else {
            output.push(character);
        }
    }
    Cow::Owned(output)
}

fn unsafe_character(character: char) -> bool {
    character.is_control()
        || matches!(character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' |
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn metadata_text(text: String) -> String {
    // Literal newlines belong to JSON layout; string newlines are already escaped.
    match escape_characters(&text, |character| {
        character != '\n' && unsafe_character(character)
    }) {
        Cow::Borrowed(_) => text,
        Cow::Owned(output) => output,
    }
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
            message.message_reference = "name\n\t\r\u{1b}\u{009b}\u{202e}é".into();
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

    #[test]
    fn human_message_pages_retain_only_one_complete_rendered_copy() {
        let mut excessive_allocation = Vec::new();
        for size in [64 * 1024, 256 * 1024, 2 * 1024 * 1024] {
            let body = format!("{}\n\n", "x".repeat(size));
            let result = message(&body);
            let mut rendered = None;
            let allocation = allocation_counter::measure(|| {
                rendered = Some(human(&result).unwrap());
            });
            let rendered = rendered.unwrap();
            assert_eq!(
                rendered,
                format!("Message: message\n\nBody:\n{}", "x".repeat(size))
            );
            eprintln!("human page bytes={size}, {allocation:?}");
            if allocation.bytes_total > size as u64 + 4096
                || allocation.bytes_max > size as u64 + 4096
            {
                excessive_allocation.push((size, allocation));
            }
        }
        assert!(
            excessive_allocation.is_empty(),
            "human presentation must retain only its completed output, beyond small formatting overhead: {excessive_allocation:?}"
        );
    }
}
