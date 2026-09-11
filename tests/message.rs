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
    let service = Service::in_memory(config)
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
fn get(reference: &str) -> Operation {
    Operation::GetMessage(GetMessageInput {
        message: reference.into(),
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
    assert!(!result.body.continuation_available);
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
        json!({"message":"valid", "cursor":"not supported"}),
    ] {
        assert!(serde_json::from_value::<GetMessageInput>(input).is_err());
    }
    assert!(serde_json::from_value::<GetMessageInput>(json!({"message":"é".repeat(4096)})).is_ok());
}
