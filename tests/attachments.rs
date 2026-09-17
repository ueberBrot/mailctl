mod host_support;
use mailctl::service::Service;
use serde_json::json;
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

#[tokio::test]
async fn attachment_operations_reject_untrusted_references_before_credentials() {
    let service = Service::in_memory(config()).unwrap();
    let context = service.context("reader", &Default::default()).unwrap();
    for (operation, input) in [
        ("list_attachments", json!({"message":"forged"})),
        ("get_attachment", json!({"attachment":"forged"})),
    ] {
        let operation = serde_json::from_value(json!({"operation":operation,"input":input}))
            .expect("published attachment operation");
        assert_eq!(
            service.execute(&context, operation).await.unwrap_err().code,
            mailctl::domain::ErrorCode::StaleReference
        );
    }
}

use mailctl::{
    domain::{MessageMetadata, Operation, OperationResult},
    service::{MemoryMailboxes, MemoryMessage, MemoryMessages},
};
use std::sync::Arc;
async fn setup(
    config: mailctl::config::Config,
    backend: Arc<dyn mailctl::service::AttachmentBackend>,
) -> (Service, String) {
    let name = config.accounts[0].mailboxes[0].clone();
    setup_service(
        name,
        Service::in_memory(config)
            .unwrap()
            .with_attachment_backend(backend),
    )
    .await
}
async fn setup_service(name: String, service: Service) -> (Service, String) {
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
    let service = service
        .with_mailbox_backend(inventory)
        .with_search_backend(messages);
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
async fn live(
    fixture: &imap_support::Fixture,
    mut config: mailctl::config::Config,
) -> (Service, String) {
    config.accounts[0].server = "127.0.0.1".into();
    config.accounts[0].port = fixture.port;
    config.accounts[0].username = "fixture".into();
    let name = config.accounts[0].mailboxes[0].clone();
    let service = Service::in_memory(config)
        .unwrap()
        .with_environment(host_support::Host::new(
            fixture.roots.clone(),
            b"disposable-password",
        ));
    setup_service(name, service).await
}

#[tokio::test]
async fn metadata_lists_reusable_part_references_without_payload_reads() {
    use imap_support::*;
    let fixture = fixture(mailctl::imap::TlsMode::Implicit, Default::default(), |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        let tag = expect(&mut wire, "EXAMINE INBOX").await;
        write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 77] valid\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
        let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"large.bin\")) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
        logout(&mut wire).await;
    })).await;
    let (service, reference) = live(&fixture, config()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let result = service
        .execute(
            &context,
            serde_json::from_value(
                json!({"operation":"list_attachments","input":{"message":reference}}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let OperationResult::Attachments(list) = result else {
        panic!()
    };
    assert_eq!(list.message_reference, reference);
    assert_eq!(list.attachments.len(), 1);
    assert_eq!(
        list.attachments[0].display_name.as_deref(),
        Some("large.bin")
    );
    assert_eq!(list.attachments[0].media_type, "application/octet-stream");
    assert!(list.attachments[0].reference.starts_with("at1."));
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn transfers_preserve_bytes_and_bind_tokens_to_scope_session_and_offset() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use mailctl::{domain::AttachmentProgress, service::MemoryAttachments};
    let backend = Arc::new(MemoryAttachments::default());
    backend.set(
        "work",
        "INBOX",
        77,
        4,
        vec![(
            mailctl::imap::AttachmentMetadata {
                part: "2".into(),
                filename: Some("fixture.bin".into()),
                media_type: "application/octet-stream".into(),
                declared_size: Some(6),
                available: true,
            },
            b"abcdef".to_vec(),
        )],
    );
    let mut configuration = config();
    configuration.limits.attachment_chunk_bytes = 2;
    configuration.grants[0].limits.attachment_chunk_bytes = 2;
    let (service, message) = setup(configuration.clone(), backend.clone()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let OperationResult::Attachments(list) = service
        .execute(
            &context,
            serde_json::from_value(
                json!({"operation":"list_attachments","input":{"message":message}}),
            )
            .unwrap(),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let get = |input| {
        serde_json::from_value(json!({"operation":"get_attachment","input":input})).unwrap()
    };
    let OperationResult::Attachment(first) = service
        .execute(
            &context,
            get(json!({"attachment":list.attachments[0].reference})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(STANDARD.decode(&first.bytes_base64).unwrap(), b"ab");
    assert_eq!(first.decoded_offset, 0);
    let AttachmentProgress::Continue { next_token } = first.progress else {
        panic!()
    };
    let (other, _) = setup(configuration, backend).await;
    let other_context = other.context("reader", &Default::default()).unwrap();
    assert_eq!(
        other
            .execute(&other_context, get(json!({"token":next_token})))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::TransferExpired
    );
    let OperationResult::Attachment(second) = service
        .execute(&context, get(json!({"token":next_token})))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(STANDARD.decode(&second.bytes_base64).unwrap(), b"cd");
    assert_eq!(second.decoded_offset, 2);
    assert_eq!(
        service
            .execute(&context, get(json!({"token":next_token})))
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::TransferExpired
    );
    let AttachmentProgress::Continue { next_token } = second.progress else {
        panic!()
    };
    let OperationResult::Attachment(last) = service
        .execute(&context, get(json!({"token":next_token})))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(STANDARD.decode(&last.bytes_base64).unwrap(), b"ef");
    assert_eq!(last.decoded_offset, 4);
    let AttachmentProgress::Complete {
        total_decoded_bytes,
        sha256,
    } = last.progress
    else {
        panic!()
    };
    assert_eq!(total_decoded_bytes, 6);
    assert_eq!(
        sha256,
        "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    );
}

fn memory() -> Arc<mailctl::service::MemoryAttachments> {
    let backend = Arc::new(mailctl::service::MemoryAttachments::default());
    backend.set(
        "work",
        "INBOX",
        77,
        4,
        vec![(
            mailctl::imap::AttachmentMetadata {
                part: "2".into(),
                filename: None,
                media_type: "application/octet-stream".into(),
                declared_size: Some(6),
                available: true,
            },
            b"abcdef".to_vec(),
        )],
    );
    backend
}
fn operation(name: &str, input: serde_json::Value) -> Operation {
    serde_json::from_value(json!({"operation":name,"input":input})).unwrap()
}
async fn attachment_reference(
    service: &Service,
    context: &mailctl::policy::RequestContext,
    message: &str,
) -> String {
    let OperationResult::Attachments(list) = service
        .execute(
            context,
            operation("list_attachments", json!({"message":message})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    list.attachments[0].reference.clone()
}
async fn start(
    service: &Service,
    context: &mailctl::policy::RequestContext,
    reference: &str,
) -> String {
    let OperationResult::Attachment(chunk) = service
        .execute(
            context,
            operation("get_attachment", json!({"attachment":reference})),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let mailctl::domain::AttachmentProgress::Continue { next_token } = chunk.progress else {
        panic!()
    };
    next_token
}
fn small_config() -> mailctl::config::Config {
    let mut config = config();
    config.limits.attachment_chunk_bytes = 2;
    config.grants[0].limits.attachment_chunk_bytes = 2;
    config.limits.transfers_per_account = 1;
    config.grants[0].limits.transfers_per_account = 1;
    config
}
#[tokio::test]
async fn scope_session_replay_expiry_and_session_drop_preserve_account_quota() {
    use mailctl::domain::ErrorCode;
    let mut configuration = small_config();
    configuration.limits.transfer_seconds = 1;
    configuration.grants[0].limits.transfer_seconds = 1;
    let (service, message) = setup(configuration, memory()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let reference = attachment_reference(&service, &context, &message).await;
    let token = start(&service, &context, &reference).await;
    let resume = |token: &str| operation("get_attachment", json!({"token":token}));
    let other = service.context("reader", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(&other, resume(&token))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TransferExpired
    );
    assert_eq!(
        service
            .execute(&context.clone().with_response_limit(8192), resume(&token))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TransferExpired
    );
    let mut altered = token.clone().into_bytes();
    altered[10] = if altered[10] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        service
            .execute(&context, resume(std::str::from_utf8(&altered).unwrap()))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TransferExpired
    );
    assert_eq!(
        service
            .execute(
                &other,
                operation("get_attachment", json!({"attachment":reference}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::RateLimited
    );
    drop(context);
    // Releasing the session removes its decoder even while the application remains live.
    let token = start(&service, &other, &reference).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        service
            .execute(&other, resume(&token))
            .await
            .unwrap_err()
            .code,
        ErrorCode::TransferExpired
    );
    let _token = start(&service, &other, &reference).await;
}
#[tokio::test]
async fn reconnect_rechecks_mailbox_incarnation_and_releases_failed_transfer() {
    use mailctl::domain::ErrorCode;
    let backend = memory();
    let (service, message) = setup(small_config(), backend.clone()).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let reference = attachment_reference(&service, &context, &message).await;
    let token = start(&service, &context, &reference).await;
    backend.set("work", "INBOX", 78, 4, vec![]);
    assert_eq!(
        service
            .execute(
                &context,
                operation("get_attachment", json!({"token":token}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleReference
    );
    assert_eq!(
        service
            .execute(
                &context,
                operation("get_attachment", json!({"token":token}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::TransferExpired
    );
    assert_eq!(
        service
            .execute(
                &context,
                operation("get_attachment", json!({"attachment":reference}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleReference
    );
}
#[tokio::test]
async fn denied_attachment_reads_and_invalid_inputs_do_not_reveal_resources() {
    let mut configuration = config();
    let mut writer = configuration.grants[0].clone();
    writer.name = "writer".into();
    writer.profile = mailctl::policy::Profile::DraftsOnly;
    configuration.grants.push(writer);
    configuration.accounts[0].drafts_mailbox = Some("INBOX".into());
    let service = Service::in_memory(configuration).unwrap();
    let context = service.context("writer", &Default::default()).unwrap();
    for input in [json!({"attachment":"forged"}), json!({"token":"forged"})] {
        assert_eq!(
            service
                .execute(&context, operation("get_attachment", input))
                .await
                .unwrap_err()
                .code,
            mailctl::domain::ErrorCode::PermissionDenied
        );
    }
    assert_eq!(
        service
            .execute(
                &context,
                operation("list_attachments", json!({"message":"forged"}))
            )
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::PermissionDenied
    );
    for input in [
        json!({}),
        json!({"attachment":"a","token":"b"}),
        json!({"attachment":""}),
        json!({"attachment":null}),
        json!({"token":null}),
        json!({"token":"x".repeat(8193)}),
        json!({"attachment":"x","grant":"reader"}),
    ] {
        assert!(serde_json::from_value::<mailctl::domain::GetAttachmentInput>(input).is_err());
    }
}

struct PausedBackend {
    memory: Arc<mailctl::service::MemoryAttachments>,
    paused: Arc<std::sync::atomic::AtomicBool>,
}
impl mailctl::service::AttachmentBackend for PausedBackend {
    fn list<'a>(
        &'a self,
        target: mailctl::service::MailboxTarget<'a>,
        mailbox: &'a str,
        request: mailctl::imap::AttachmentListRequest,
        limits: &'a mailctl::config::Limits,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<mailctl::imap::AttachmentMetadata>, mailctl::domain::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.memory.list(target, mailbox, request, limits)
    }
    fn start(
        &self,
        target: mailctl::service::MailboxTarget<'_>,
        mailbox: &str,
        uid: u32,
        validity: u32,
        part: &str,
        limits: &mailctl::config::Limits,
    ) -> Result<Box<dyn mailctl::service::AttachmentReader>, mailctl::domain::Error> {
        Ok(Box::new(PausedReader {
            inner: self
                .memory
                .start(target, mailbox, uid, validity, part, limits)?,
            paused: self.paused.clone(),
        }))
    }
}
struct PausedReader {
    inner: Box<dyn mailctl::service::AttachmentReader>,
    paused: Arc<std::sync::atomic::AtomicBool>,
}
impl mailctl::service::AttachmentReader for PausedReader {
    fn next<'a>(
        &'a mut self,
        limits: &'a mailctl::config::Limits,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<mailctl::imap::AttachmentData, mailctl::domain::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if self.paused.load(std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            self.inner.next(limits).await
        })
    }
}
#[tokio::test]
async fn cancellation_and_output_failure_release_in_flight_transfer_reservations() {
    let paused = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let backend = Arc::new(PausedBackend {
        memory: memory(),
        paused: paused.clone(),
    });
    let (service, message) = setup(small_config(), backend).await;
    let context = service.context("reader", &Default::default()).unwrap();
    let reference = attachment_reference(&service, &context, &message).await;
    let get = || operation("get_attachment", json!({"attachment":reference}));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            service.execute(&context, get())
        )
        .await
        .is_err()
    );
    paused.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        service
            .execute(&context.clone().with_response_limit(1024), get())
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::ResponseTooLarge
    );
    let token = start(&service, &context, &reference).await;
    paused.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            service.execute(
                &context,
                operation("get_attachment", json!({"token":token}))
            )
        )
        .await
        .is_err()
    );
    paused.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        service
            .execute(
                &context,
                operation("get_attachment", json!({"token":token}))
            )
            .await
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::TransferExpired
    );
    let _new_transfer = start(&service, &context, &reference).await;
}
#[tokio::test]
async fn narrowed_attachment_byte_limits_fail_without_retaining_a_transfer() {
    for wire in [false, true] {
        let mut configuration = small_config();
        if wire {
            configuration.grants[0].limits.attachment_wire_bytes = 5;
        } else {
            configuration.grants[0].limits.attachment_decoded_bytes = 5;
        }
        let (service, message) = setup(configuration, memory()).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let reference = attachment_reference(&service, &context, &message).await;
        for _ in 0..2 {
            assert_eq!(
                service
                    .execute(
                        &context,
                        operation("get_attachment", json!({"attachment":reference}))
                    )
                    .await
                    .unwrap_err()
                    .code,
                mailctl::domain::ErrorCode::AttachmentTooLarge
            );
        }
    }
}

mod attachment_support;
#[tokio::test]
async fn imap_continuations_reconnect_and_check_identity_before_returning_buffered_bytes() {
    use imap_support::*;
    for stale in [false, true] {
        let mut session = 0;
        let fixture = repeating_fixture(Default::default(), if stale { 3 } else { 4 }, move |mut wire| {
            let step = session; session += 1;
            Box::pin(async move {
                authenticate(&mut wire).await;
                if stale && step == 2 {
                    let tag = expect(&mut wire, "EXAMINE INBOX").await;
                    write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 78] recreated\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                    dropped(&mut wire).await;
                    return;
                }
                examine(&mut wire).await;
                if step <= 1 { attachment_support::metadata(&mut wire, &attachment_support::structure("BASE64", 8)).await; }
                if step == 1 { literal_bytes(&mut wire, "2", 0, 16384, b"YWJjZGVm").await; }
                logout(&mut wire).await;
            })
        }).await;
        let (service, message) = live(&fixture, small_config()).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let reference = attachment_reference(&service, &context, &message).await;
        let mut token = start(&service, &context, &reference).await;
        for (offset, expected) in [(2, "Y2Q="), (4, "ZWY=")] {
            let result = service
                .execute(
                    &context,
                    operation("get_attachment", json!({"token":token})),
                )
                .await;
            if stale {
                assert_eq!(
                    result.unwrap_err().code,
                    mailctl::domain::ErrorCode::StaleReference
                );
                break;
            }
            let OperationResult::Attachment(chunk) = result.unwrap() else {
                panic!()
            };
            assert_eq!(chunk.bytes_base64, expected);
            assert_eq!(chunk.decoded_offset, offset);
            match chunk.progress {
                mailctl::domain::AttachmentProgress::Continue { next_token } => token = next_token,
                mailctl::domain::AttachmentProgress::Complete {
                    total_decoded_bytes,
                    ..
                } => assert_eq!(total_decoded_bytes, 6),
            }
        }
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn transfer_deadlines_interrupt_imap_authentication_and_incomplete_fetches() {
    use imap_support::*;
    use mailctl::domain::ErrorCode::{Timeout, TransferExpired};
    for (during_fetch, operation_seconds, transfer_seconds, expected) in
        [false, true].into_iter().flat_map(|fetch| {
            [
                (30, 1, TransferExpired),
                (1, 1, TransferExpired),
                (1, 30, Timeout),
            ]
            .map(|(operation, transfer, error)| (fetch, operation, transfer, error))
        })
    {
        let mut session = 0;
        let fixture = repeating_fixture(Default::default(), 3, move |mut wire| {
            let step = session;
            session += 1;
            Box::pin(async move {
                if step == 1 && !during_fetch {
                    expect(&mut wire, "CAPABILITY").await;
                    dropped(&mut wire).await;
                    return;
                }
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                attachment_support::metadata(
                    &mut wire,
                    &attachment_support::structure("7BIT", 40_000),
                )
                .await;
                if step == 1 {
                    expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[2]<0.16384>)").await;
                    write(&mut wire, "* 1 FETCH (UID 4 BODY[2]<0> {16384}\r\npartial").await;
                    dropped(&mut wire).await;
                } else {
                    if step == 2 {
                        literal_bytes(&mut wire, "2", 0, 16384, b"abcdef").await;
                    }
                    logout(&mut wire).await;
                }
            })
        })
        .await;
        let mut configuration = small_config();
        for limits in [
            &mut configuration.limits,
            &mut configuration.grants[0].limits,
        ] {
            limits.operation_seconds = operation_seconds;
            limits.transfer_seconds = transfer_seconds;
            limits.connection_seconds = 1;
            limits.initialization_seconds = 1;
        }
        let (service, message) = live(&fixture, configuration).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let reference = attachment_reference(&service, &context, &message).await;
        assert_eq!(
            service
                .execute(
                    &context,
                    operation("get_attachment", json!({"attachment": reference}))
                )
                .await
                .unwrap_err()
                .code,
            expected,
            "fetch={during_fetch}, operation={operation_seconds}, transfer={transfer_seconds}"
        );
        // Either deadline must release the account's only transfer slot.
        let _token = start(&service, &context, &reference).await;
        fixture.task.await.unwrap();
    }
}
