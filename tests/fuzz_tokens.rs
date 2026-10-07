mod fuzz_support;
mod support;

use mailctl::{
    config::Config,
    domain::{BodyText, ErrorCode, MailboxMetadata, MessageMetadata, Operation},
    service::{
        MemoryAttachments, MemoryBodies, MemoryMailboxes, MemoryMessage, MemoryMessages, Service,
    },
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

struct Tokens {
    service: Service,
    cases: Vec<TokenCase>,
}

struct TokenCase {
    name: &'static str,
    request: Value,
    field: &'static str,
    value: String,
    expected: ErrorCode,
}

impl TokenCase {
    fn new(name: &'static str, request: Value, field: &'static str, expected: ErrorCode) -> Self {
        let value = request["input"][field].as_str().unwrap().to_owned();
        Self {
            name,
            request,
            field,
            value,
            expected,
        }
    }
}

impl Tokens {
    async fn new() -> Self {
        let installation = support::Installation::two_accounts();
        let mut config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        for account in &mut config.accounts {
            account.credential = mailctl::config::CredentialSource::Session {};
        }
        config.limits.text_page_bytes = 4;
        config.limits.attachment_chunk_bytes = 2;
        for grant in &mut config.grants {
            grant.limits = config.limits.clone();
            if grant.name == "all" {
                grant.mailboxes.push("Drafts".into());
            }
        }
        let mailboxes = Arc::new(MemoryMailboxes::default());
        mailboxes.set(
            "work",
            ["INBOX", "Drafts"]
                .into_iter()
                .map(|name| MailboxMetadata {
                    name: name.into(),
                    selectable: true,
                    special_use: vec![],
                })
                .collect(),
        );
        let messages = Arc::new(MemoryMessages::default());
        messages.set(
            "work",
            "INBOX",
            77,
            (1..=2)
                .map(|uid| MemoryMessage {
                    uid,
                    metadata: MessageMetadata {
                        received_date: "2024-02-29T12:00:00+00:00".into(),
                        ..Default::default()
                    },
                    bcc: vec![],
                    text: String::new(),
                })
                .collect(),
        );
        let bodies = Arc::new(MemoryBodies::default());
        bodies.set(
            "work",
            "INBOX",
            77,
            2,
            BodyText {
                text: "a🦀éxyz".into(),
                selected_part: Some("1".into()),
                source_media_type: Some("text/plain".into()),
                representation_version: "fixture-1".into(),
                converted: false,
                replacements: false,
                truncated: false,
                empty_reason: None,
                continuation_available: false,
                next_cursor: None,
            },
        );
        let attachments = Arc::new(MemoryAttachments::default());
        attachments.set(
            "work",
            "INBOX",
            77,
            2,
            vec![(
                mailctl::imap::AttachmentMetadata {
                    part: "2".into(),
                    filename: Some("synthetic.bin".into()),
                    media_type: "application/octet-stream".into(),
                    declared_size: Some(6),
                    available: true,
                },
                b"abcdef".to_vec(),
            )],
        );
        let service = Service::in_memory(config)
            .unwrap()
            .with_mailbox_backend(mailboxes)
            .with_search_backend(messages)
            .with_body_backend(bodies)
            .with_attachment_backend(attachments);
        let inventory = execute(
            &service,
            json!({"operation":"list_mailboxes","input":{"account":"work"}}),
        )
        .await;
        let mailbox = inventory["mailboxes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mailbox| mailbox["metadata"]["name"] == "INBOX")
            .unwrap()["reference"]
            .clone();
        let page = execute(
            &service,
            json!({"operation":"search_messages","input":{"mailbox":mailbox,"limit":1}}),
        )
        .await;
        let message = page["messages"][0]["reference"].clone();
        let body = execute(
            &service,
            json!({"operation":"get_message","input":{"message":message}}),
        )
        .await;
        let list = execute(
            &service,
            json!({"operation":"list_attachments","input":{"message":message}}),
        )
        .await;
        let attachment = list["attachments"][0]["reference"].clone();
        let chunk = execute(
            &service,
            json!({"operation":"get_attachment","input":{"attachment":attachment}}),
        )
        .await;
        let mailbox_page = execute(
            &service,
            json!({"operation":"list_mailboxes","input":{"account":"work","limit":1}}),
        )
        .await;
        let cases = vec![
            TokenCase::new(
                "mailbox-reference",
                json!({"operation":"list_mailboxes","input":{"reference":mailbox}}),
                "reference",
                ErrorCode::StaleReference,
            ),
            TokenCase::new(
                "mailbox-cursor",
                json!({"operation":"list_mailboxes","input":{"account":"work","limit":1,"cursor":mailbox_page["next_cursor"]}}),
                "cursor",
                ErrorCode::StaleCursor,
            ),
            TokenCase::new(
                "search-cursor",
                json!({"operation":"search_messages","input":{"mailbox":mailbox,"limit":1,"cursor":page["next_cursor"]}}),
                "cursor",
                ErrorCode::StaleCursor,
            ),
            TokenCase::new(
                "message-reference",
                json!({"operation":"get_message","input":{"message":message}}),
                "message",
                ErrorCode::StaleReference,
            ),
            TokenCase::new(
                "body-cursor",
                json!({"operation":"get_message","input":{"message":message,"cursor":body["body"]["next_cursor"]}}),
                "cursor",
                ErrorCode::StaleCursor,
            ),
            TokenCase::new(
                "attachment-reference",
                json!({"operation":"get_attachment","input":{"attachment":attachment}}),
                "attachment",
                ErrorCode::StaleReference,
            ),
            TokenCase::new(
                "transfer-token",
                json!({"operation":"get_attachment","input":{"token":chunk["progress"]["next_token"]}}),
                "token",
                ErrorCode::TransferExpired,
            ),
        ];
        Self { service, cases }
    }

    async fn reject(&self, case: &TokenCase, input: &[u8]) {
        let value = String::from_utf8_lossy(input);
        // Some mutations are no-ops. Genuine references remain valid and are exercised during setup.
        if value == case.value {
            return;
        }
        let mut request = case.request.clone();
        request["input"][case.field] = json!(value);
        let Ok(operation) = serde_json::from_value::<Operation>(request) else {
            return;
        };
        let context = self.service.context("all", &Default::default()).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            self.service.execute(&context, operation),
        )
        .await
        .expect("token decoding exceeded its deadline")
        .expect_err("altered token was accepted");
        assert_eq!(error.code, case.expected, "token case {}", case.name);
        assert!(error.message.len() < 256);
        assert!(!error.retryable);
        assert!(error.draft_operation.is_none());
    }
}

async fn execute(service: &Service, request: Value) -> Value {
    let context = service.context("all", &Default::default()).unwrap();
    serde_json::to_value(
        service
            .execute(&context, serde_json::from_value(request).unwrap())
            .await
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn retained_token_regressions_reject_every_resource_and_continuation_kind() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tokens = runtime.block_on(Tokens::new());
    for input in [
        include_bytes!("fuzz_corpus/tokens/truncated-signature.token").as_slice(),
        include_bytes!("fuzz_corpus/tokens/extra-separator.token").as_slice(),
        include_bytes!("fuzz_corpus/tokens/noncanonical-base64.token").as_slice(),
    ] {
        for case in &tokens.cases {
            let allocation =
                allocation_counter::measure(|| runtime.block_on(tokens.reject(case, input)));
            assert!(
                allocation.bytes_max < 1024 * 1024,
                "token decoding exceeded its allocation ceiling"
            );
            assert!(allocation.bytes_total < 2 * 1024 * 1024);
        }
    }
    // Alter each authenticated part independently, including the kind, payload, and signature.
    for case in &tokens.cases {
        let token = &case.value;
        for position in [0, token.find('.').unwrap() + 1, token.len() - 1] {
            let mut altered = token.as_bytes().to_vec();
            altered[position] = if altered[position] == b'A' {
                b'B'
            } else {
                b'A'
            };
            runtime.block_on(tokens.reject(case, &altered));
        }
    }
}

#[test]
#[ignore = "explicit bounded fuzz campaign; retained regressions run in ordinary CI"]
fn fuzz_tokens() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tokens = runtime.block_on(Tokens::new());
    let seeds: Vec<_> = tokens
        .cases
        .iter()
        .map(|case| case.value.as_bytes())
        .collect();
    let campaign = fuzz_support::Campaign::from_env("tokens");
    for (index, input) in campaign.cases(&seeds) {
        let allocation = allocation_counter::measure(|| {
            runtime.block_on(tokens.reject(&tokens.cases[index % seeds.len()], &input))
        });
        assert!(
            allocation.bytes_max < 1024 * 1024,
            "token case {index} exceeded its allocation ceiling"
        );
        assert!(allocation.bytes_total < 2 * 1024 * 1024);
    }
    campaign.finish();
}
