use mailctl::{
    config::{Config, MailboxScope},
    domain::{BodyText, ErrorCode, MailboxMetadata, MessageMetadata, Operation, OperationResult},
    service::{
        MemoryAttachments, MemoryBodies, MemoryMailboxes, MemoryMessage, MemoryMessages, Service,
    },
};
use serde_json::json;
use std::sync::Arc;

fn config() -> Config {
    Config::parse(&format!(
        r#"version = 1
default_grant = "reader"
state_dir = {state}
[[accounts]]
key = "work"
alias = "work"
server = "imap.example.test"
username = "synthetic@example.test"
from_identities = ["work"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["work"]
"#,
        state =
            serde_json::to_string(&std::env::temp_dir().join("mailctl-scope-contract")).unwrap()
    ))
    .unwrap()
}

fn metadata(name: &str) -> MailboxMetadata {
    MailboxMetadata {
        name: name.into(),
        selectable: true,
        special_use: vec![],
    }
}

fn operation(name: &str, input: serde_json::Value) -> Operation {
    serde_json::from_value(json!({"operation":name,"input":input})).unwrap()
}

#[tokio::test]
async fn malformed_unapproved_inventory_rows_fail_before_wildcard_filtering() {
    let mut conflicting = metadata("Hidden");
    conflicting.selectable = false;
    for invalid in [
        vec![metadata("")],
        vec![metadata("bad\nname")],
        vec![metadata(&"x".repeat(1025))],
        vec![metadata("Hidden"), conflicting],
    ] {
        let mut configuration = config();
        configuration.grants[0].mailboxes = vec!["Literal*".into()].into();
        let memory = Arc::new(MemoryMailboxes::default());
        let mut rows = vec![metadata("Literal*")];
        rows.extend(invalid);
        memory.set("work", rows);
        let service = Service::in_memory(configuration)
            .unwrap()
            .with_mailbox_backend(memory);
        let context = service.context("reader", &Default::default()).unwrap();
        assert_eq!(
            service
                .execute(&context, Operation::ListMailboxes(Default::default()))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ProviderUnavailable
        );
    }
}

#[tokio::test]
async fn wildcard_restrictions_count_full_inventory_while_ordinary_exact_scopes_do_not() {
    for (name, expected) in [
        ("Projects*2026", Some(ErrorCode::ResponseTooLarge)),
        ("Projects", None),
    ] {
        let mut configuration = config();
        configuration.limits.mailbox_inventory = 2;
        configuration.limits.mailbox_page = 2;
        configuration.grants[0].limits = configuration.limits.clone();
        configuration.grants[0].mailboxes = vec![name.into()].into();
        let memory = Arc::new(MemoryMailboxes::default());
        memory.set("work", vec![metadata(name), metadata("Unrelated")]);
        let service = Service::in_memory(configuration)
            .unwrap()
            .with_mailbox_backend(memory.clone());
        let context = service.context("reader", &Default::default()).unwrap();
        let OperationResult::Mailboxes(page) = service
            .execute(&context, Operation::ListMailboxes(Default::default()))
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(page.mailboxes.len(), 1);
        assert_eq!(page.mailboxes[0].metadata.name, name);
        memory.set(
            "work",
            vec![metadata(name), metadata("Unrelated"), metadata("INBOX")],
        );
        let result = service
            .execute(&context, Operation::ListMailboxes(Default::default()))
            .await;
        if let Some(code) = expected {
            assert_eq!(result.unwrap_err().code, code);
        } else {
            let OperationResult::Mailboxes(page) = result.unwrap() else {
                panic!()
            };
            assert_eq!(page.mailboxes.len(), 1);
        }
    }
}

#[test]
fn oversized_memory_inventory_is_refused_before_allocating_an_output_copy() {
    let mut configuration = config();
    configuration.limits.mailbox_inventory = 2;
    configuration.limits.mailbox_page = 2;
    configuration.grants[0].limits = configuration.limits.clone();
    let memory = Arc::new(MemoryMailboxes::default());
    memory.set(
        "work",
        (0..1000)
            .map(|index| metadata(&format!("Mailbox{index:04}{}", "x".repeat(900))))
            .collect(),
    );
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory);
    let context = service.context("reader", &Default::default()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let allocation = allocation_counter::measure(|| {
        assert_eq!(
            runtime
                .block_on(service.execute(&context, Operation::ListMailboxes(Default::default())))
                .unwrap_err()
                .code,
            ErrorCode::ResponseTooLarge
        );
    });
    assert!(
        allocation.bytes_total < 64 * 1024,
        "oversized inventories must be rejected before cloning: {allocation:?}"
    );
}

#[tokio::test]
async fn namespace_roots_are_omitted_but_count_toward_the_inventory_ceiling() {
    let mut configuration = config();
    configuration.limits.mailbox_inventory = 2;
    configuration.limits.mailbox_page = 2;
    configuration.grants[0].limits = configuration.limits.clone();
    let memory = Arc::new(MemoryMailboxes::default());
    let root = MailboxMetadata {
        name: String::new(),
        selectable: false,
        special_use: vec![],
    };
    memory.set("work", vec![root.clone(), metadata("INBOX")]);
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory.clone());
    let context = service.context("reader", &Default::default()).unwrap();
    let OperationResult::Mailboxes(page) = service
        .execute(&context, Operation::ListMailboxes(Default::default()))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(page.mailboxes.len(), 1);
    assert_eq!(page.mailboxes[0].metadata.name, "INBOX");
    assert!(page.complete);
    memory.set("work", vec![root.clone(), root, metadata("INBOX")]);
    assert_eq!(
        service
            .execute(&context, Operation::ListMailboxes(Default::default()))
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResponseTooLarge
    );
}

#[tokio::test]
async fn account_and_grant_scopes_intersect_including_an_empty_intersection() {
    for (account, grant, expected) in [
        (
            MailboxScope::All,
            MailboxScope::All,
            vec!["Archive", "INBOX", "Projects"],
        ),
        (
            MailboxScope::All,
            vec!["inbox".into()].into(),
            vec!["INBOX"],
        ),
        (
            vec!["Projects".into()].into(),
            MailboxScope::All,
            vec!["Projects"],
        ),
        (
            vec!["Archive".into(), "INBOX".into()].into(),
            vec!["inbox".into(), "Projects".into()].into(),
            vec!["INBOX"],
        ),
        (
            vec!["Archive".into()].into(),
            vec!["Projects".into()].into(),
            vec![],
        ),
    ] {
        let mut configuration = config();
        configuration.accounts[0].mailboxes = account;
        configuration.grants[0].mailboxes = grant;
        let memory = Arc::new(MemoryMailboxes::default());
        memory.set(
            "work",
            ["Projects", "INBOX", "Archive"].map(metadata).to_vec(),
        );
        let service = Service::in_memory(configuration)
            .unwrap()
            .with_mailbox_backend(memory);
        let context = service.context("reader", &Default::default()).unwrap();
        let OperationResult::Mailboxes(page) = service
            .execute(&context, Operation::ListMailboxes(Default::default()))
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            page.mailboxes
                .iter()
                .map(|mailbox| mailbox.metadata.name.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(page.complete);
        assert!(page.next_cursor.is_none());
    }
}

#[tokio::test]
async fn all_folder_reads_work_and_resources_cannot_widen_a_restricted_grant() {
    let mut configuration = config();
    configuration.grants[0].limits.text_page_bytes = 4;
    configuration.grants[0].limits.attachment_chunk_bytes = 2;
    let mut restricted = configuration.grants[0].clone();
    restricted.name = "restricted".into();
    restricted.mailboxes = vec!["INBOX".into()].into();
    configuration.grants.push(restricted);

    let mailboxes = Arc::new(MemoryMailboxes::default());
    mailboxes.set("work", vec![metadata("Projects*2026")]);
    let messages = Arc::new(MemoryMessages::default());
    messages.set(
        "work",
        "Projects*2026",
        7,
        (1..=2)
            .map(|uid| MemoryMessage {
                uid,
                metadata: MessageMetadata::default(),
                bcc: vec![],
                text: "fixture".into(),
            })
            .collect(),
    );
    let bodies = Arc::new(MemoryBodies::default());
    bodies.set(
        "work",
        "Projects*2026",
        7,
        2,
        BodyText {
            text: "abcdefgh".into(),
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
        "Projects*2026",
        7,
        2,
        vec![(
            mailctl::imap::AttachmentMetadata {
                part: "2".into(),
                filename: Some("fixture.txt".into()),
                media_type: "text/plain".into(),
                declared_size: Some(4),
                available: true,
            },
            b"data".to_vec(),
        )],
    );
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(mailboxes)
        .with_search_backend(messages)
        .with_body_backend(bodies)
        .with_attachment_backend(attachments);
    let context = service.context("reader", &Default::default()).unwrap();
    let denied = service.context("restricted", &Default::default()).unwrap();
    let OperationResult::Mailboxes(page) = service
        .execute(&context, Operation::ListMailboxes(Default::default()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let mailbox = &page.mailboxes[0].reference;
    let OperationResult::Messages(search) = service
        .execute(
            &context,
            operation("search_messages", json!({"mailbox":mailbox,"limit":1})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let message = &search.messages[0].reference;
    let OperationResult::Message(body) = service
        .execute(
            &context,
            operation("get_message", json!({"message":message})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(body.body.text, "abcd");
    let OperationResult::Attachments(parts) = service
        .execute(
            &context,
            operation("list_attachments", json!({"message":message})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let attachment = &parts.attachments[0].reference;
    let OperationResult::Attachment(chunk) = service
        .execute(
            &context,
            operation("get_attachment", json!({"attachment":attachment})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(chunk.bytes_base64, "ZGE=");
    let mailctl::domain::AttachmentProgress::Continue { next_token } = chunk.progress else {
        panic!()
    };

    for request in [
        operation("list_mailboxes", json!({"reference":mailbox})),
        operation("search_messages", json!({"mailbox":mailbox})),
        operation(
            "search_messages",
            json!({"mailbox":mailbox,"cursor":search.next_cursor}),
        ),
        operation("get_message", json!({"message":message})),
        operation(
            "get_message",
            json!({"message":message,"cursor":body.body.next_cursor}),
        ),
        operation("list_attachments", json!({"message":message})),
        operation("get_attachment", json!({"attachment":attachment})),
    ] {
        assert_eq!(
            service.execute(&denied, request).await.unwrap_err().code,
            ErrorCode::MailboxNotAllowed
        );
    }
    assert_eq!(
        service
            .execute(
                &denied,
                operation("get_attachment", json!({"token":next_token}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::TransferExpired
    );
    let OperationResult::Message(last) = service
        .execute(
            &context,
            operation(
                "get_message",
                json!({"message":message,"cursor":body.body.next_cursor}),
            ),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(last.body.text, "efgh");
    let OperationResult::Attachment(last) = service
        .execute(
            &context,
            operation("get_attachment", json!({"token":next_token})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(last.bytes_base64, "dGE=");
}
