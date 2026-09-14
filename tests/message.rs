use mailctl::{
    domain::{BodyText, GetMessageInput, MessageMetadata, Operation, OperationResult},
    service::{MemoryBodies, MemoryMailboxes, MemoryMessage, MemoryMessages, Service},
};
use serde_json::json;
use std::sync::Arc;
#[allow(dead_code)]
mod imap_support;
fn config() -> mailctl::config::Config {
    mailctl::config::Config::parse(&format!(
        r#"
version = 1
default_grant = "reader"
state_dir = {state}
[[accounts]]
key = "work"
alias = "work"
server = "imap.example.test"
username = "synthetic@example.test"
mailboxes = ["INBOX"]
from_identities = ["work"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["work"]
mailboxes = ["INBOX"]
"#,
        state =
            serde_json::to_string(&std::env::temp_dir().join("mailctl-search-contract")).unwrap()
    ))
    .unwrap()
}

async fn setup(
    config: mailctl::config::Config,
    backend: Arc<dyn mailctl::service::BodyBackend>,
) -> (Service, String) {
    setup_with_state(config, backend, false).await
}
async fn setup_with_state(
    config: mailctl::config::Config,
    backend: Arc<dyn mailctl::service::BodyBackend>,
    persistent: bool,
) -> (Service, String) {
    let name = config.accounts[0].mailboxes[0].clone();
    let inventory = Arc::new(MemoryMailboxes::default());
    inventory.set(
        "work",
        vec![mailctl::domain::MailboxMetadata {
            name: name.clone(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let messages = Arc::new(MemoryMessages::default());
    messages.set(
        "work",
        &name,
        77,
        vec![MemoryMessage {
            uid: 4,
            metadata: MessageMetadata {
                received_date: "2024-02-29T12:00:00+00:00".into(),
                ..Default::default()
            },
            bcc: vec![],
            text: "".into(),
        }],
    );
    let service = setup_service(config, persistent)
        .unwrap()
        .with_mailbox_backend(inventory)
        .with_search_backend(messages)
        .with_body_backend(backend);
    let context = service.context("reader", &Default::default()).unwrap();
    let OperationResult::Mailboxes(page) = service
        .execute(&context, Operation::ListMailboxes(Default::default()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let operation = serde_json::from_value(
        json!({"operation":"search_messages","input":{"mailbox":page.mailboxes[0].reference}}),
    )
    .unwrap();
    let OperationResult::Messages(page) = service.execute(&context, operation).await.unwrap()
    else {
        panic!()
    };
    (service, page.messages[0].reference.clone())
}
fn setup_service(
    config: mailctl::config::Config,
    persistent: bool,
) -> Result<Service, mailctl::domain::Error> {
    if persistent {
        Service::setup(config.clone())?;
        Service::open(config)
    } else {
        Service::in_memory(config)
    }
}
fn get(reference: &str) -> Operation {
    Operation::GetMessage(GetMessageInput {
        message: reference.into(),
        cursor: None,
    })
}
fn body(text: &str) -> BodyText {
    BodyText {
        text: text.into(),
        selected_part: Some("1".into()),
        source_media_type: Some("text/plain".into()),
        representation_version: "fixture-1".into(),
        converted: false,
        replacements: false,
        truncated: false,
        empty_reason: None,
        continuation_available: false,
        next_cursor: None,
    }
}
#[tokio::test]
async fn body_reads_preserve_identity_bound_text_and_reauthorize_references() {
    let bodies = Arc::new(MemoryBodies::default());
    bodies.set("work", "INBOX", 77, 4, body("a🦀éxyz"));
    let mut config = config();
    config.limits.text_page_bytes = 4;
    config.grants[0].limits.text_page_bytes = 4;
    let (service, reference) = setup(config, bodies.clone()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let OperationResult::Message(result) =
        service.execute(&context, get(&reference)).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(result.message_reference, reference);
    assert_eq!(result.generation, 1);
    assert_eq!(result.body.text, "a");
    assert!(result.body.truncated);
    assert!(result.body.continuation_available);
    let denied = service
        .context(
            "reader",
            &mailctl::policy::Narrowing {
                accounts: Some(vec![]),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        service
            .execute(&denied, get(&reference))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::AccountNotAllowed
    );
    bodies.set("work", "INBOX", 78, 4, body("recreated mailbox"));
    assert_eq!(
        service
            .execute(&context, get(&reference))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::StaleReference
    );
    assert_eq!(
        service
            .execute(&context, get("invalid"))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::StaleReference
    );
    assert_eq!(
        service
            .execute(&context, get(&(reference + "x")))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::StaleReference
    );
}

struct SyntheticSource;
impl mailctl::credentials::SecretSource for SyntheticSource {
    fn availability(&self, _: uuid::Uuid) -> mailctl::credentials::Availability {
        mailctl::credentials::Availability::Available
    }
    fn resolve(
        &self,
        _: uuid::Uuid,
    ) -> Result<mailctl::credentials::Secret, mailctl::credentials::SourceError> {
        mailctl::credentials::Secret::new(b"disposable-password".to_vec())
    }
}
async fn live(
    fixture: &imap_support::Fixture,
    mut config: mailctl::config::Config,
) -> (Service, String) {
    config.accounts[0].server = "127.0.0.1".into();
    config.accounts[0].port = fixture.port;
    config.accounts[0].username = "fixture".into();
    let runtime = Arc::new(
        mailctl::authentication::Runtime::new(config.limits.clone(), fixture.roots.clone())
            .unwrap(),
    );
    let sources = std::collections::BTreeMap::from([(
        "work".into(),
        Arc::new(SyntheticSource) as Arc<dyn mailctl::credentials::SecretSource>,
    )]);
    setup(
        config,
        Arc::new(mailctl::service::ImapBackend::new(runtime, sources)),
    )
    .await
}
#[tokio::test]
async fn application_reads_short_body_without_fetching_large_attachment() {
    use imap_support::*;
    for (name, wire_name) in [("INBOX", "INBOX"), ("Entwürfe", "Entw&APw-rfe")] {
        let fixture = fixture(mailctl::imap::TlsMode::Implicit, Default::default(), move |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        let tag = expect(&mut wire, &format!("EXAMINE {wire_name}")).await;
        write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 77] valid\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
        let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"large.bin\")) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
        literal_bytes(&mut wire, "HEADER", 0, 16384, b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n").await;
        literal_bytes(&mut wire, "1", 0, 14, b"Short body.\r\n").await;
        logout(&mut wire).await;
    })).await;
        let mut configuration = config();
        configuration.accounts[0].mailboxes = vec![name.into()];
        configuration.grants[0].mailboxes = vec![name.into()];
        let (service, reference) = live(&fixture, configuration).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let OperationResult::Message(result) =
            service.execute(&context, get(&reference)).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(result.body.text, "Short body.\r\n");
        assert_eq!(result.body.selected_part.as_deref(), Some("1"));
        assert!(
            result
                .body
                .representation_version
                .contains("html2text-0.17.1")
        );
        assert!(!result.body.truncated);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn application_checks_uidvalidity_on_the_fetch_lease() {
    use imap_support::*;
    let fixture = fixture(mailctl::imap::TlsMode::Implicit, Default::default(), |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        let tag = expect(&mut wire, "EXAMINE INBOX").await;
        write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 78] recreated\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
        dropped(&mut wire).await;
    })).await;
    let (service, reference) = live(&fixture, config()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(&context, get(&reference))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::StaleReference
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn application_distinguishes_missing_messages_from_unsupported_bodies() {
    use imap_support::*;
    for missing in [true, false] {
        let fixture = fixture(mailctl::imap::TlsMode::Implicit, Default::default(), move |mut wire| Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            if missing {
                write(&mut wire, &format!("{tag} OK absent\r\n")).await;
                dropped(&mut wire).await;
            } else {
                write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000000 BODYSTRUCTURE (\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" NIL) NIL NIL))\r\n{tag} OK fetched\r\n")).await;
                literal_bytes(&mut wire, "HEADER", 0, 16384, b"Content-Type: application/octet-stream\r\n\r\n").await;
                logout(&mut wire).await;
            }
        })).await;
        let (service, reference) = live(&fixture, config()).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let result = service.execute(&context, get(&reference)).await;
        if missing {
            assert_eq!(
                result.unwrap_err().code,
                mailctl::domain::ErrorCode::MessageNotFound
            );
        } else {
            let OperationResult::Message(result) = result.unwrap() else {
                panic!()
            };
            assert!(result.body.text.is_empty());
            assert!(result.body.selected_part.is_none());
            assert!(result.body.source_media_type.is_none());
            assert!(matches!(
                result.body.empty_reason,
                Some(mailctl::domain::EmptyBodyReason::NoSupportedBody)
            ));
            assert!(!result.body.truncated);
        }
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn application_propagates_independent_body_and_structure_limits() {
    use imap_support::*;
    for limit in ["wire", "headers", "parts", "depth"] {
        let fixture = fixture(mailctl::imap::TlsMode::Implicit, Default::default(), move |mut wire| Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" NIL) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
            match limit {
                "wire" => literal_bytes(&mut wire, "HEADER", 0, 16384, b"Content-Type: multipart/mixed; boundary=fixture\r\n\r\n").await,
                "headers" => literal_bytes(&mut wire, "HEADER", 0, 9, b"123456789").await,
                _ => {}
            }
            dropped(&mut wire).await;
        })).await;
        let mut configuration = config();
        let limits = &mut configuration.grants[0].limits;
        match limit {
            "wire" => limits.wire_fetch_bytes = 8,
            "headers" => limits.header_bytes = 8,
            "parts" => limits.mime_parts = 1,
            "depth" => limits.mime_depth = 1,
            _ => unreachable!(),
        }
        let (service, reference) = live(&fixture, configuration).await;
        let context = service.context("reader", &Default::default()).unwrap();
        assert_eq!(
            service
                .execute(&context, get(&reference))
                .await
                .unwrap_err()
                .code,
            mailctl::domain::ErrorCode::ResponseTooLarge,
            "{limit}"
        );
        fixture.task.await.unwrap();
    }
}

#[test]
fn message_input_rejects_unknown_fields_and_oversized_references() {
    for input in [
        json!({}),
        json!({"message":null}),
        json!({"message":""}),
        json!({"message":"é".repeat(4097)}),
        json!({"message":"valid", "unknown":"not supported"}),
        json!({"message":"valid", "cursor":""}),
        json!({"message":"valid", "cursor":"é".repeat(4097)}),
    ] {
        assert!(serde_json::from_value::<GetMessageInput>(input).is_err());
    }
    assert!(serde_json::from_value::<GetMessageInput>(json!({"message":"é".repeat(4096)})).is_ok());
}

#[tokio::test]
async fn authenticated_text_pages_reconstruct_the_available_representation() {
    let bodies = Arc::new(MemoryBodies::default());
    bodies.set("work", "INBOX", 77, 4, body("a🦀éxyz"));
    let mut configuration = config();
    configuration.grants[0].limits.text_page_bytes = 4;
    let (service, reference) = setup(configuration, bodies).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let mut cursor = None;
    let mut text = String::new();
    for expected in ["a", "🦀", "éxy", "z"] {
        let input = GetMessageInput {
            message: reference.clone(),
            cursor,
        };
        let OperationResult::Message(result) = service
            .execute(&context, Operation::GetMessage(input))
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(result.body.text, expected);
        cursor = result.body.next_cursor;
        assert_eq!(result.body.truncated, cursor.is_some());
        assert_eq!(result.body.continuation_available, cursor.is_some());
        text.push_str(&result.body.text);
    }
    assert_eq!(text, "a🦀éxyz");
    assert!(cursor.is_none());
}

#[tokio::test]
async fn text_cursors_reject_tampering_and_changes_after_fresh_authorization() {
    use mailctl::domain::ErrorCode;
    let bodies = Arc::new(MemoryBodies::default());
    let original = body("a🦀éxyz");
    bodies.set("work", "INBOX", 77, 4, original.clone());
    let mut configuration = config();
    configuration.grants[0].limits.text_page_bytes = 4;
    let mut narrower = configuration.grants[0].clone();
    narrower.name = "narrower".into();
    narrower.limits.text_page_bytes = 5;
    configuration.grants.push(narrower);
    let (service, reference) = setup(configuration, bodies.clone()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let OperationResult::Message(first) = service.execute(&context, get(&reference)).await.unwrap()
    else {
        panic!()
    };
    let cursor = first.body.next_cursor.unwrap();
    let resume = |message: &str, cursor: &str| {
        Operation::GetMessage(GetMessageInput {
            message: message.into(),
            cursor: Some(cursor.into()),
        })
    };
    let denied = service
        .context(
            "reader",
            &mailctl::policy::Narrowing {
                accounts: Some(vec![]),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        service
            .execute(&denied, resume(&reference, &cursor))
            .await
            .unwrap_err()
            .code,
        ErrorCode::AccountNotAllowed
    );
    let narrower = service.context("narrower", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(&narrower, resume(&reference, &cursor))
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleCursor
    );
    for invalid in ["invalid".to_owned(), format!("{cursor}x")] {
        assert_eq!(
            service
                .execute(&context, resume(&reference, &invalid))
                .await
                .unwrap_err()
                .code,
            ErrorCode::StaleCursor
        );
    }
    assert_eq!(
        service
            .execute(&context, resume("invalid", &cursor))
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleCursor
    );
    for change in ["content", "version", "part", "media", "validity", "missing"] {
        let mut changed = original.clone();
        match change {
            "content" => changed.text = "b🦀éxyz".into(),
            "version" => changed.representation_version = "fixture-2".into(),
            "part" => changed.selected_part = Some("2".into()),
            "media" => changed.source_media_type = Some("text/html".into()),
            _ => {}
        }
        bodies.set(
            "work",
            "INBOX",
            if change == "validity" { 78 } else { 77 },
            if change == "missing" { 5 } else { 4 },
            changed,
        );
        assert_eq!(
            service
                .execute(&context, resume(&reference, &cursor))
                .await
                .unwrap_err()
                .code,
            ErrorCode::StaleCursor,
            "{change}"
        );
    }
}

#[tokio::test]
async fn whole_and_partial_body_pages_decode_malformed_html_with_finite_work() {
    use imap_support::*;
    let raw = b"<p>a\xf0\x9f\xa6\x80\xffxyz</p>";
    for whole in [true, false] {
        let fixture = repeating_fixture(Default::default(), 5, move |mut wire| Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            let part = format!("(\"TEXT\" \"HTML\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" {} 1 NIL NIL NIL NIL)", raw.len());
            let header = if whole { b"Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n".as_slice() } else { b"Content-Type: multipart/mixed; boundary=fixture\r\n\r\n".as_slice() };
            let (structure, size) = if whole { (part, header.len() + raw.len()) } else { (format!("({part}(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" NIL) NIL NIL) \"MIXED\" NIL NIL NIL NIL)"), 3000300) };
            write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE {size} BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
            literal_bytes(&mut wire, "HEADER", 0, 16384, header).await;
            if whole {
                let mut message = header.to_vec(); message.extend_from_slice(raw);
                literal_bytes(&mut wire, "", 0, message.len() + 1, &message).await;
            } else {
                literal_bytes(&mut wire, "1", 0, raw.len() + 1, raw).await;
            }
            logout(&mut wire).await;
        })).await;
        let mut configuration = config();
        configuration.grants[0].limits.text_page_bytes = 4;
        let (service, reference) = live(&fixture, configuration).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let mut cursor = None;
        let mut text = String::new();
        for _ in 0..5 {
            let input = GetMessageInput {
                message: reference.clone(),
                cursor,
            };
            let OperationResult::Message(page) = service
                .execute(&context, Operation::GetMessage(input))
                .await
                .unwrap()
            else {
                panic!()
            };
            assert!(page.body.converted);
            assert!(page.body.replacements);
            assert!(page.body.text.len() <= 4);
            text.push_str(&page.body.text);
            cursor = page.body.next_cursor;
        }
        assert_eq!(text, "�\n\na🦀�xyz\n");
        assert!(cursor.is_none());
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn restarted_installations_resume_under_new_grants_and_enforce_output_limits() {
    let directory = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("mailctl-text-{}", uuid::Uuid::new_v4()));
    let mut configuration = config();
    configuration.state_dir = directory.clone();
    configuration.grants[0].limits.text_page_bytes = 4;
    let mut second = configuration.grants[0].clone();
    second.name = "second".into();
    configuration.grants.push(second);
    let bodies = Arc::new(MemoryBodies::default());
    bodies.set("work", "INBOX", 77, 4, body("a🦀éxyz"));
    let (first, reference) = setup_with_state(configuration.clone(), bodies.clone(), true).await;
    let context = first.context("reader", &Default::default()).unwrap();
    let OperationResult::Message(page) = first.execute(&context, get(&reference)).await.unwrap()
    else {
        panic!()
    };
    let cursor = page.body.next_cursor.unwrap();
    drop(first);
    let service = Service::open(configuration.clone())
        .unwrap()
        .with_body_backend(bodies.clone());
    let context = service.context("second", &Default::default()).unwrap();
    let resume = || {
        Operation::GetMessage(GetMessageInput {
            message: reference.clone(),
            cursor: Some(cursor.clone()),
        })
    };
    for _ in 0..2 {
        let OperationResult::Message(page) = service.execute(&context, resume()).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(page.body.text, "🦀");
        assert!(page.body.next_cursor.is_some());
    }
    let bounded = service
        .context("second", &Default::default())
        .unwrap()
        .with_response_limit(1);
    assert_eq!(
        service.execute(&bounded, resume()).await.unwrap_err().code,
        mailctl::domain::ErrorCode::ResponseTooLarge
    );
    drop(service);
    configuration.state_dir = directory.join("independent");
    let independent = setup_service(configuration, true)
        .unwrap()
        .with_body_backend(bodies);
    let context = independent.context("second", &Default::default()).unwrap();
    assert_eq!(
        independent
            .execute(&context, resume())
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::StaleCursor
    );
    drop(independent);
    std::fs::remove_dir_all(directory).unwrap();
}
