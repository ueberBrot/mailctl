use mailctl::domain::Operation;
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

async fn mailbox(service: &mailctl::service::Service) -> String {
    let context = service.context("reader", &Default::default()).unwrap();
    let mailctl::domain::OperationResult::Mailboxes(page) = service
        .execute(&context, Operation::ListMailboxes(Default::default()))
        .await
        .unwrap()
    else {
        panic!("mailboxes")
    };
    page.mailboxes[0].reference.clone()
}

async fn search(
    service: &mailctl::service::Service,
    input: serde_json::Value,
) -> serde_json::Value {
    let context = service.context("reader", &Default::default()).unwrap();
    let operation =
        serde_json::from_value(json!({"operation":"search_messages","input":input})).unwrap();
    serde_json::to_value(service.execute(&context, operation).await.unwrap()).unwrap()
}

#[test]
fn search_normalizes_and_terms_without_turning_repeated_fields_into_or() {
    let operation: Operation = serde_json::from_value(json!({
        "operation": "search_messages",
        "input": {
            "mailbox": "mb1.fixture",
            "criteria": [
                {"field":"subject", "value":"second"},
                {"field":"received_after", "date":"2024-02-29"},
                {"field":"subject", "value":"first"}
            ]
        }
    }))
    .expect("typed search is an application operation");
    let value = serde_json::to_value(operation).unwrap();
    assert_eq!(
        value["input"]["criteria"],
        json!([
            {"field":"received_after", "date":"2024-02-29"},
            {"field":"subject", "value":"first"},
            {"field":"subject", "value":"second"}
        ])
    );
}

#[test]
fn contradictory_or_oversized_criteria_fail_before_application_work() {
    use mailctl::domain::SearchCriteria;
    for criteria in [
        json!([{"field":"required_flag","flag":"seen"}, {"field":"forbidden_flag","flag":"seen"}]),
        json!([{"field":"received_after","date":"2024-03-01"}, {"field":"received_before","date":"2024-03-01"}]),
        json!([{"field":"sent_after","date":"2024-03-02"}, {"field":"sent_before","date":"2024-03-01"}]),
        json!([{"field":"subject","value":"x".repeat(4097)}]),
        json!([{"field":"text","value":"é".repeat(2049)}]),
        json!([{"field":"text","value":"a\u{0}b"}]),
        json!([{"field":"sent_after","date":"2023-02-29"}]),
        json!([{"field":"regex","value":".*"}]),
        json!([{"field":"subject","value":"x","or":true}]),
        json!(vec![json!({"field":"subject","value":"x"}); 33]),
    ] {
        assert!(
            serde_json::from_value::<SearchCriteria>(criteria.clone()).is_err(),
            "{criteria}"
        );
    }
    let criteria: SearchCriteria = serde_json::from_value(json!(vec![
        json!({"field":"text","value":"é".repeat(2048)});
        32
    ]))
    .unwrap();
    assert_eq!(criteria.predicates().len(), 32);
    assert!(
        serde_json::from_value::<SearchCriteria>(json!([
            {"field":"received_after","date":"2024-03-01"},
            {"field":"sent_before","date":"2024-03-01"},
            {"field":"subject","value":"  literal spaces  "}
        ]))
        .is_ok()
    );
}

#[tokio::test]
async fn descending_pages_preserve_remaining_matches_and_exclude_new_arrivals() {
    use mailctl::{
        domain::{MessageMetadata, Metadata},
        service::{MemoryMailboxes, MemoryMessage, MemoryMessages, Service},
    };
    let inventory = Arc::new(MemoryMailboxes::default());
    inventory.set(
        "work",
        vec![mailctl::domain::MailboxMetadata {
            name: "INBOX".into(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let messages = Arc::new(MemoryMessages::default());
    let message = |uid| MemoryMessage {
        uid,
        metadata: MessageMetadata {
            subject: Metadata::Present(format!("message {uid}")),
            received_date: "2024-02-29T12:00:00+00:00".into(),
            size: 100,
            ..Default::default()
        },
        bcc: vec![],
        text: "synthetic".into(),
    };
    messages.set("work", "INBOX", 7, (1..=5).map(message).collect());
    let service = Service::in_memory(config())
        .unwrap()
        .with_mailbox_backend(inventory)
        .with_search_backend(messages.clone());
    let reference = mailbox(&service).await;
    let first = search(&service, json!({"mailbox":reference,"limit":2})).await;
    assert_eq!(first["messages"][0]["subject"]["value"], "message 5");
    assert_eq!(first["messages"][1]["subject"]["value"], "message 4");
    assert_eq!(first["complete"], false);
    // Message 3 disappears and message 6 arrives between requests.
    messages.set(
        "work",
        "INBOX",
        7,
        [1, 2, 4, 5, 6].into_iter().map(message).collect(),
    );
    let second = search(
        &service,
        json!({"mailbox":reference,"limit":2,"cursor":first["next_cursor"]}),
    )
    .await;
    assert_eq!(second["messages"].as_array().unwrap().len(), 2);
    assert_eq!(second["messages"][0]["subject"]["value"], "message 2");
    assert_eq!(second["messages"][1]["subject"]["value"], "message 1");
    assert_eq!(second["complete"], true);
    assert!(second["next_cursor"].is_null());
    assert_ne!(
        first["messages"][0]["reference"],
        first["messages"][1]["reference"]
    );
}

#[tokio::test]
async fn empty_work_limited_pages_continue_and_recheck_live_flags() {
    use mailctl::{
        domain::{MailboxMetadata, MessageMetadata},
        service::{MemoryMailboxes, MemoryMessage, MemoryMessages, Service},
    };
    let inventory = Arc::new(MemoryMailboxes::default());
    inventory.set(
        "work",
        vec![MailboxMetadata {
            name: "INBOX".into(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let memory = Arc::new(MemoryMessages::default());
    let message = |uid, seen| MemoryMessage {
        uid,
        metadata: MessageMetadata {
            received_date: "2024-02-29T12:00:00+00:00".into(),
            flags: if seen { vec!["\\Seen".into()] } else { vec![] },
            size: 100,
            ..Default::default()
        },
        bcc: vec![],
        text: "synthetic".into(),
    };
    memory.set(
        "work",
        "INBOX",
        7,
        vec![message(1, false), message(3, true), message(5, true)],
    );
    let mut config = config();
    config.grants[0].limits.search_uid_window = 2;
    config.grants[0].limits.search_windows = 1;
    let service = Service::in_memory(config)
        .unwrap()
        .with_mailbox_backend(inventory)
        .with_search_backend(memory.clone());
    let reference = mailbox(&service).await;
    let criteria = json!([{"field":"forbidden_flag", "flag":"seen"}]);
    let first = search(&service, json!({"mailbox":reference,"criteria":criteria})).await;
    assert_eq!(first["messages"], json!([]));
    assert_eq!(first["complete"], false);
    assert!(first["next_cursor"].is_string());
    memory.set(
        "work",
        "INBOX",
        7,
        vec![message(1, false), message(3, false), message(5, true)],
    );
    let second = search(
        &service,
        json!({"mailbox":reference,"criteria":criteria,"cursor":first["next_cursor"]}),
    )
    .await;
    assert_eq!(second["messages"].as_array().unwrap().len(), 1);
    assert_eq!(second["complete"], false);
    let last = search(
        &service,
        json!({"mailbox":reference,"criteria":criteria,"cursor":second["next_cursor"]}),
    )
    .await;
    assert_eq!(last["messages"].as_array().unwrap().len(), 1);
    assert_eq!(last["complete"], true);
}

async fn memory_fixture(
    configuration: mailctl::config::Config,
    rows: Vec<mailctl::service::MemoryMessage>,
) -> (
    mailctl::service::Service,
    Arc<mailctl::service::MemoryMessages>,
    String,
) {
    use mailctl::{
        domain::MailboxMetadata,
        service::{MemoryMailboxes, MemoryMessages, Service},
    };
    let inventory = Arc::new(MemoryMailboxes::default());
    inventory.set(
        "work",
        vec![MailboxMetadata {
            name: "INBOX".into(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let memory = Arc::new(MemoryMessages::default());
    memory.set("work", "INBOX", 7, rows);
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(inventory)
        .with_search_backend(memory.clone());
    let reference = mailbox(&service).await;
    (service, memory, reference)
}

#[tokio::test]
async fn every_predicate_uses_and_substrings_and_the_named_calendar_date() {
    use mailctl::{
        domain::{MessageAddress, MessageMetadata, Metadata::Present},
        service::MemoryMessage,
    };
    let row = MemoryMessage {
        uid: 9,
        metadata: MessageMetadata {
            subject: Present("Blue annual report".into()),
            from: Present(vec![MessageAddress {
                name: Some("Sender Name".into()),
                address: "sender@example.test".into(),
            }]),
            to: Present(vec![MessageAddress {
                name: None,
                address: "reader@example.test".into(),
            }]),
            cc: Present(vec![MessageAddress {
                name: None,
                address: "copy@example.test".into(),
            }]),
            received_date: "2024-03-01T00:30:00+14:00".into(),
            sent_date: Present("2024-02-28T23:30:00-12:00".into()),
            flags: vec![
                "\\Answered".into(),
                "\\Deleted".into(),
                "\\Draft".into(),
                "\\Flagged".into(),
                "\\Recent".into(),
                "\\Seen".into(),
            ],
            size: 100,
            ..Default::default()
        },
        bcc: vec!["hidden@example.test".into()],
        text: "Blue annual report\r\nA synthetic body".into(),
    };
    let (service, _, reference) = memory_fixture(config(), vec![row]).await;
    for (predicate, matches) in [
        (json!({"field":"received_after","date":"2024-03-01"}), true),
        (
            json!({"field":"received_before","date":"2024-03-01"}),
            false,
        ),
        (json!({"field":"sent_after","date":"2024-02-29"}), false),
        (json!({"field":"sent_before","date":"2024-02-29"}), true),
        (json!({"field":"from","value":"SENDER@"}), true),
        (json!({"field":"to","value":"reader@"}), true),
        (json!({"field":"cc","value":"copy@"}), true),
        (json!({"field":"bcc","value":"hidden@"}), true),
        (json!({"field":"subject","value":"ANNUAL"}), true),
        (json!({"field":"subject","value":"absent"}), false),
        (json!({"field":"text","value":"synthetic BODY"}), true),
    ] {
        let page = search(
            &service,
            json!({"mailbox":reference,"criteria":[predicate.clone()]}),
        )
        .await;
        assert_eq!(
            page["messages"].as_array().unwrap().len(),
            usize::from(matches),
            "{predicate}"
        );
    }
    let page = search(
        &service,
        json!({"mailbox":reference,"criteria":[
            {"field":"subject","value":"annual"}, {"field":"subject","value":"absent"}
        ]}),
    )
    .await;
    assert_eq!(page["messages"], json!([]));
    for flag in ["answered", "deleted", "draft", "flagged", "recent", "seen"] {
        for (field, expected) in [("required_flag", 1), ("forbidden_flag", 0)] {
            let page = search(
                &service,
                json!({"mailbox":reference,"criteria":[{"field":field,"flag":flag}]}),
            )
            .await;
            assert_eq!(page["messages"].as_array().unwrap().len(), expected);
        }
    }
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
async fn imap_service(fixture: &imap_support::Fixture) -> (mailctl::service::Service, String) {
    use mailctl::{
        authentication::Runtime,
        domain::MailboxMetadata,
        service::{ImapMessages, MemoryMailboxes, Service},
    };
    let mut configuration = config();
    configuration.accounts[0].server = "127.0.0.1".into();
    configuration.accounts[0].port = fixture.port;
    configuration.accounts[0].username = "fixture".into();
    let runtime =
        Arc::new(Runtime::new(configuration.limits.clone(), fixture.roots.clone()).unwrap());
    let sources = std::collections::BTreeMap::from([(
        "work".into(),
        Arc::new(SyntheticSource) as Arc<dyn mailctl::credentials::SecretSource>,
    )]);
    let inventory = Arc::new(MemoryMailboxes::default());
    inventory.set(
        "work",
        vec![MailboxMetadata {
            name: "INBOX".into(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(inventory)
        .with_search_backend(Arc::new(ImapMessages::new(runtime, sources)));
    let reference = mailbox(&service).await;
    (service, reference)
}

async fn fetched(wire: &mut imap_support::Wire, uid: u32) {
    imap_support::write(wire, &format!("* {uid} FETCH (UID {uid} ENVELOPE (NIL \"message {uid}\" NIL NIL NIL NIL NIL NIL NIL NIL) FLAGS () INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 100)\r\n")).await;
}

#[tokio::test]
async fn imap_pages_use_one_read_only_selection_and_fetch_only_the_requested_page() {
    use imap_support::*;
    let mut page = 0;
    let fixture = repeating_fixture(mailctl::imap::Limits::default(), 2, move |mut wire| {
        page += 1;
        let first = page == 1;
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            if first {
                let tag = expect(&mut wire, "UID SEARCH UID *").await;
                write(
                    &mut wire,
                    &format!("* SEARCH 5\r\n{tag} OK upper boundary\r\n"),
                )
                .await;
            }
            let tag = expect(
                &mut wire,
                if first {
                    "UID SEARCH UID 1:5"
                } else {
                    "UID SEARCH UID 1:3"
                },
            )
            .await;
            let matches = if first { "1 2 3 4 5" } else { "1 2" };
            write(
                &mut wire,
                &format!("* SEARCH {matches}\r\n{tag} OK searched\r\n"),
            )
            .await;
            let tag = expect(
                &mut wire,
                if first {
                    "UID FETCH 4:5 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)"
                } else {
                    "UID FETCH 1:2 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)"
                },
            )
            .await;
            for uid in if first { [4, 5] } else { [1, 2] } {
                fetched(&mut wire, uid).await;
            }
            write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
            logout(&mut wire).await;
        })
    })
    .await;
    let (service, reference) = imap_service(&fixture).await;
    let first = search(&service, json!({"mailbox":reference,"limit":2})).await;
    assert_eq!(first["messages"][0]["subject"]["value"], "message 5");
    assert_eq!(first["messages"][1]["subject"]["value"], "message 4");
    assert_eq!(first["complete"], false);
    let second = search(
        &service,
        json!({"mailbox":reference,"limit":2,"cursor":first["next_cursor"]}),
    )
    .await;
    assert_eq!(second["messages"][0]["subject"]["value"], "message 2");
    assert_eq!(second["messages"][1]["subject"]["value"], "message 1");
    assert_eq!(second["complete"], true);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn imap_predicates_use_typed_and_terms_and_synchronizing_utf8_literals() {
    use imap_support::*;
    let fixture = repeating_fixture(mailctl::imap::Limits::default(), 1, |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID SEARCH UID *").await;
        write(&mut wire, &format!("* SEARCH 9\r\n{tag} OK boundary\r\n")).await;
        let tag = expect(&mut wire, "UID SEARCH CHARSET UTF-8 UID 1:9 SINCE 29-Feb-2024 BEFORE 02-Mar-2024 SENTSINCE 28-Feb-2024 SENTBEFORE 01-Mar-2024 FROM sender TO reader CC copy BCC hidden SUBJECT {6}\r\nGrüß SUBJECT annual TEXT {7}\r\nline\r\nx ANSWERED OLD").await;
        write(&mut wire, &format!("* SEARCH 9\r\n{tag} OK matched\r\n")).await;
        let tag = expect(&mut wire, "UID FETCH 9 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)").await;
        fetched(&mut wire, 9).await;
        write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
        logout(&mut wire).await;
    })).await;
    let (service, reference) = imap_service(&fixture).await;
    let result = search(
        &service,
        json!({"mailbox":reference,"criteria":[
            {"field":"received_after","date":"2024-02-29"},
            {"field":"received_before","date":"2024-03-02"},
            {"field":"sent_after","date":"2024-02-28"},
            {"field":"sent_before","date":"2024-03-01"},
            {"field":"from","value":"sender"}, {"field":"to","value":"reader"},
            {"field":"cc","value":"copy"}, {"field":"bcc","value":"hidden"},
            {"field":"subject","value":"annual"}, {"field":"subject","value":"Grüß"},
            {"field":"text","value":"line\r\nx"},
            {"field":"required_flag","flag":"answered"}, {"field":"forbidden_flag","flag":"recent"}
        ]}),
    )
    .await;
    assert_eq!(result["messages"].as_array().unwrap().len(), 1);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn imap_normalizes_envelopes_and_marks_missing_or_malformed_optional_metadata() {
    use imap_support::*;
    use tokio::io::AsyncWriteExt;
    let fixture = repeating_fixture(mailctl::imap::Limits::default(), 1, |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID SEARCH UID *").await;
        write(&mut wire, &format!("* SEARCH 2\r\n{tag} OK boundary\r\n")).await;
        let tag = expect(&mut wire, "UID SEARCH UID 1:2").await;
        write(&mut wire, &format!("* SEARCH 1 2\r\n{tag} OK searched\r\n")).await;
        let tag = expect(&mut wire, "UID FETCH 1:2 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)").await;
        write(&mut wire, "* 1 FETCH (UID 1 ENVELOPE (\"Thu, 29 Feb 2024 23:30:00 -1200\" \"=?UTF-8?Q?Gr=C3=BC=C3=9Fe?=\" ((\"=?UTF-8?Q?Absender?=\" NIL \"sender\" \"example.test\")) NIL NIL ((NIL NIL \"Team\" NIL)(NIL NIL \"reader\" \"example.test\")(NIL NIL NIL NIL)) NIL NIL NIL \"<fixture@example.test>\") FLAGS (\\Seen \\Flagged) INTERNALDATE \"01-Mar-2024 00:30:00 +1400\" RFC822.SIZE 100)\r\n").await;
        write(&mut wire, "* 2 FETCH (UID 2 ENVELOPE (\"not a date\" {1}\r\n").await;
        wire.write_all(&[0xff]).await.unwrap();
        write(&mut wire, " ((NIL NIL \"broken\" NIL)) NIL NIL NIL NIL NIL NIL \"bad id\") FLAGS () INTERNALDATE \"01-Mar-2024 01:00:00 +1400\" RFC822.SIZE 101)\r\n").await;
        write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
        logout(&mut wire).await;
    })).await;
    let (service, reference) = imap_service(&fixture).await;
    let result = search(&service, json!({"mailbox":reference})).await;
    let bad = &result["messages"][0];
    for field in ["subject", "from", "sent_date", "message_id"] {
        assert_eq!(bad[field]["status"], "malformed", "{field}");
    }
    assert_eq!(bad["to"]["status"], "missing");
    let good = &result["messages"][1];
    assert_eq!(good["subject"]["value"], "Grüße");
    assert_eq!(good["from"]["value"][0]["name"], "Absender");
    assert_eq!(good["to"]["value"][0]["address"], "reader@example.test");
    assert_eq!(good["cc"]["status"], "missing");
    assert_eq!(good["sent_date"]["value"], "2024-02-29T23:30:00-12:00");
    assert_eq!(good["received_date"], "2024-03-01T00:30:00+14:00");
    assert_eq!(good["message_id"]["value"], "<fixture@example.test>");
    assert_eq!(good["size"], 100);
    assert_eq!(good["flags"], json!(["\\Flagged", "\\Seen"]));
    assert!(good["reference"].as_str().unwrap().starts_with("ms1."));
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn cursors_bind_query_grant_selection_and_authenticate_token_kinds() {
    use mailctl::{
        domain::{ErrorCode, MessageMetadata},
        service::MemoryMessage,
    };
    let mut configuration = config();
    let mut other = configuration.grants[0].clone();
    other.name = "other".into();
    configuration.grants.push(other);
    let rows = || {
        (1..=3)
            .map(|uid| MemoryMessage {
                uid,
                metadata: MessageMetadata::default(),
                bcc: vec![],
                text: String::new(),
            })
            .collect()
    };
    let (service, memory, reference) = memory_fixture(configuration, rows()).await;
    let first = search(&service, json!({"mailbox":reference,"limit":1})).await;
    let request = |input| {
        serde_json::from_value(json!({"operation":"search_messages","input":input})).unwrap()
    };
    let context = service.context("reader", &Default::default()).unwrap();
    for input in [
        json!({"mailbox":reference,"cursor":first["next_cursor"],"criteria":[{"field":"subject","value":"changed"}]}),
        json!({"mailbox":reference,"cursor":reference}),
        json!({"mailbox":reference,"cursor":format!("{}x",first["next_cursor"].as_str().unwrap())}),
    ] {
        assert_eq!(
            service
                .execute(&context, request(input))
                .await
                .unwrap_err()
                .code,
            ErrorCode::StaleCursor
        );
    }
    for token in [
        first["messages"][0]["reference"].clone(),
        first["next_cursor"].clone(),
        json!(format!("{reference}x")),
    ] {
        assert_eq!(
            service
                .execute(&context, request(json!({"mailbox":token})))
                .await
                .unwrap_err()
                .code,
            ErrorCode::StaleReference
        );
    }
    let other = service.context("other", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(
                &other,
                request(json!({"mailbox":reference,"cursor":first["next_cursor"]}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleCursor
    );
    // Resource references carry no grant; a separately authorized grant can start a search.
    assert!(
        service
            .execute(&other, request(json!({"mailbox":reference})))
            .await
            .is_ok()
    );
    for limit in [0, 51] {
        assert_eq!(
            service
                .execute(
                    &context,
                    Operation::SearchMessages(mailctl::domain::SearchMessagesInput {
                        mailbox: reference.clone(),
                        criteria: Default::default(),
                        limit: Some(limit),
                        cursor: None
                    })
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
    }
    memory.set("work", "INBOX", 8, rows());
    assert_eq!(
        service
            .execute(
                &context,
                request(json!({"mailbox":reference,"cursor":first["next_cursor"]}))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleCursor
    );
}

#[tokio::test]
async fn empty_mailbox_finishes_without_a_cursor() {
    let (service, _, reference) = memory_fixture(config(), vec![]).await;
    let page = search(&service, json!({"mailbox":reference})).await;
    assert_eq!(page["messages"], json!([]));
    assert_eq!(page["complete"], true);
    assert!(page["next_cursor"].is_null());
}

#[tokio::test]
async fn search_rejects_duplicate_out_of_window_and_multiple_search_responses() {
    use imap_support::*;
    for response in [
        "* SEARCH 1 1\r\n",
        "* SEARCH 6\r\n",
        "* SEARCH 1\r\n* SEARCH 2\r\n",
        "* OK [UIDVALIDITY 8] changed\r\n* SEARCH 1\r\n",
    ] {
        let fixture = fixture(
            mailctl::imap::TlsMode::Implicit,
            mailctl::imap::Limits::default(),
            move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    examine(&mut wire).await;
                    let tag = expect(&mut wire, "UID SEARCH UID *").await;
                    write(&mut wire, &format!("* SEARCH 5\r\n{tag} OK boundary\r\n")).await;
                    let tag = expect(&mut wire, "UID SEARCH UID 1:5").await;
                    write(&mut wire, &format!("{response}{tag} OK searched\r\n")).await;
                    use tokio::io::AsyncReadExt;
                    assert_eq!(
                        wire.read_u8().await.unwrap_err().kind(),
                        std::io::ErrorKind::UnexpectedEof
                    );
                })
            },
        )
        .await;
        let (service, reference) = imap_service(&fixture).await;
        let context = service.context("reader", &Default::default()).unwrap();
        let operation = serde_json::from_value(
            json!({"operation":"search_messages","input":{"mailbox":reference}}),
        )
        .unwrap();
        assert!(service.execute(&context, operation).await.is_err());
        fixture.task.await.unwrap();
    }
}

#[allow(dead_code)]
mod support;

#[tokio::test]
async fn persistent_search_cursors_resume_and_reauthorize_after_configuration_changes() {
    use mailctl::{
        domain::{ErrorCode, MailboxMetadata, MessageMetadata},
        service::{MemoryMailboxes, MemoryMessage, MemoryMessages, Service},
    };
    let installation = support::Installation::empty();
    let mut configuration = config();
    configuration.state_dir = installation.config().parent().unwrap().join("state");
    let inventory = Arc::new(MemoryMailboxes::default());
    inventory.set(
        "work",
        vec![MailboxMetadata {
            name: "INBOX".into(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let memory = Arc::new(MemoryMessages::default());
    memory.set(
        "work",
        "INBOX",
        7,
        (1..=2)
            .map(|uid| MemoryMessage {
                uid,
                metadata: MessageMetadata::default(),
                bcc: vec![],
                text: String::new(),
            })
            .collect(),
    );
    Service::setup(configuration.clone()).unwrap();
    let open = |configuration| {
        Service::open(configuration)
            .unwrap()
            .with_mailbox_backend(inventory.clone())
            .with_search_backend(memory.clone())
    };
    let service = open(configuration.clone());
    let reference = mailbox(&service).await;
    let first = search(&service, json!({"mailbox":reference,"limit":1})).await;
    drop(service);
    let service = open(configuration.clone());
    assert_eq!(
        search(
            &service,
            json!({"mailbox":reference,"cursor":first["next_cursor"]})
        )
        .await["complete"],
        true
    );
    drop(service);
    configuration.accounts[0].alias = "renamed".into();
    let service = open(configuration.clone());
    let context = service.context("reader", &Default::default()).unwrap();
    let request = |cursor| {
        serde_json::from_value(
            json!({"operation":"search_messages","input":{"mailbox":reference,"cursor":cursor}}),
        )
        .unwrap()
    };
    assert_eq!(
        service
            .execute(&context, request(first["next_cursor"].clone()))
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleCursor
    );
    assert!(
        service
            .execute(&context, request(serde_json::Value::Null))
            .await
            .is_ok()
    );
    drop(service);
    configuration.grants[0].mailboxes = vec!["Archive".into()];
    let service = open(configuration.clone());
    let context = service.context("reader", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(&context, request(serde_json::Value::Null))
            .await
            .unwrap_err()
            .code,
        ErrorCode::MailboxNotAllowed
    );
    drop(service);
    configuration.grants[0].mailboxes = vec!["INBOX".into()];
    configuration.accounts[0].server = "changed.example.test".into();
    let service = open(configuration);
    let context = service.context("reader", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(&context, request(serde_json::Value::Null))
            .await
            .unwrap_err()
            .code,
        ErrorCode::StaleReference
    );
}
