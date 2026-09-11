#[allow(dead_code)]
mod imap_support;

use mailctl::{
    config::Config,
    domain::MailboxMetadata,
    domain::{ListMailboxesInput, Operation, OperationResult},
    policy::Narrowing,
    service::{MemoryMailboxes, Service},
};
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
mailboxes = ["INBOX", "Archive", "Folder", "Missing", "Hidden"]
from_identities = ["work"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["work"]
mailboxes = ["inbox", "Archive", "Folder", "Missing"]
"#,
        state =
            serde_json::to_string(&std::env::temp_dir().join("mailctl-mailbox-contract")).unwrap()
    ))
    .unwrap()
}

#[tokio::test]
async fn discovery_pages_only_real_approved_mailboxes_in_identity_order() {
    let memory = MemoryMailboxes::default();
    memory.set(
        "work",
        vec![
            MailboxMetadata {
                name: "INBOX".into(),
                selectable: true,
                special_use: vec![],
            },
            MailboxMetadata {
                name: "Archive".into(),
                selectable: true,
                special_use: vec!["\\Archive".into()],
            },
            MailboxMetadata {
                name: "Folder".into(),
                selectable: false,
                special_use: vec![],
            },
            MailboxMetadata {
                name: "Hidden".into(),
                selectable: true,
                special_use: vec![],
            },
        ],
    );
    let service = Service::in_memory(config())
        .unwrap()
        .with_mailbox_backend(Arc::new(memory));
    discovery_contract(service).await;
}

async fn discovery_contract(service: Service) {
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let OperationResult::Mailboxes(first) = service
        .execute(
            &context,
            Operation::ListMailboxes(ListMailboxesInput {
                limit: Some(2),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
    else {
        panic!("mailboxes")
    };
    assert_eq!(
        first
            .mailboxes
            .iter()
            .map(|m| m.metadata.name.as_str())
            .collect::<Vec<_>>(),
        ["Archive", "Folder"]
    );
    assert_eq!(first.mailboxes[0].metadata.special_use, ["\\Archive"]);
    assert!(!first.mailboxes[1].metadata.selectable);
    assert!(!first.complete);
    let OperationResult::Mailboxes(last) = service
        .execute(
            &context,
            Operation::ListMailboxes(ListMailboxesInput {
                cursor: first.next_cursor,
                limit: Some(2),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
    else {
        panic!("mailboxes")
    };
    assert_eq!(last.mailboxes.len(), 1);
    assert_eq!(last.mailboxes[0].metadata.name, "INBOX");
    assert!(last.mailboxes[0].metadata.special_use.is_empty());
    assert!(last.complete);
    assert!(last.next_cursor.is_none());
}

#[tokio::test]
async fn references_reauthorize_mailbox_scope_and_cannot_cross_installations() {
    use mailctl::domain::ErrorCode;
    let memory = Arc::new(MemoryMailboxes::default());
    memory.set(
        "work",
        vec![MailboxMetadata {
            name: "Archive".into(),
            selectable: true,
            special_use: vec![],
        }],
    );
    let mut configuration = config();
    let mut restricted = configuration.grants[0].clone();
    restricted.name = "restricted".into();
    restricted.mailboxes = vec!["INBOX".into()];
    configuration.grants.push(restricted);
    let service = Service::in_memory(configuration.clone())
        .unwrap()
        .with_mailbox_backend(memory.clone());
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let OperationResult::Mailboxes(page) = service
        .execute(
            &context,
            Operation::ListMailboxes(ListMailboxesInput::default()),
        )
        .await
        .unwrap()
    else {
        panic!("mailboxes")
    };
    let reference = page.mailboxes[0].reference.clone();
    let request = || {
        Operation::ListMailboxes(ListMailboxesInput {
            reference: Some(reference.clone()),
            ..Default::default()
        })
    };
    let OperationResult::Mailboxes(resolved) = service.execute(&context, request()).await.unwrap()
    else {
        panic!("mailboxes")
    };
    assert_eq!(resolved.mailboxes[0].metadata.name, "Archive");
    let denied = service
        .context("restricted", &Narrowing::default())
        .unwrap();
    assert_eq!(
        service.execute(&denied, request()).await.unwrap_err().code,
        ErrorCode::MailboxNotAllowed
    );
    let other = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory);
    let context = other.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        other.execute(&context, request()).await.unwrap_err().code,
        ErrorCode::StaleReference
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

fn imap_service(mut configuration: Config, fixture: &imap_support::Fixture) -> Service {
    configuration.accounts[0].server = "127.0.0.1".into();
    configuration.accounts[0].port = fixture.port;
    configuration.accounts[0].username = "fixture".into();
    let runtime = Arc::new(
        mailctl::authentication::Runtime::new(configuration.limits.clone(), fixture.roots.clone())
            .unwrap(),
    );
    let sources = std::collections::BTreeMap::from([(
        "work".into(),
        Arc::new(SyntheticSource) as Arc<dyn mailctl::credentials::SecretSource>,
    )]);
    Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(Arc::new(mailctl::service::ImapBackend::new(
            runtime, sources,
        )))
}

#[tokio::test]
async fn imap_runs_the_same_application_discovery_contract_with_exact_non_mutating_commands() {
    use imap_support::*;
    let fixture = repeating_fixture(mailctl::imap::Limits::default(), 2, |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            for (name, attributes) in [
                ("Archive", Some("\\Archive")),
                ("Folder", Some("\\Noselect")),
                ("INBOX", Some("")),
                ("Missing", None),
            ] {
                let tag = expect(&mut wire, &format!("LIST \"\" {name}")).await;
                if let Some(attributes) = attributes {
                    write(
                        &mut wire,
                        &format!("* LIST ({attributes}) \"/\" {name}\r\n"),
                    )
                    .await;
                }
                write(&mut wire, &format!("{tag} OK listed\r\n")).await;
            }
            logout(&mut wire).await;
        })
    })
    .await;
    discovery_contract(imap_service(config(), &fixture)).await;
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn imap_preserves_international_names_and_deduplicates_exact_server_identities() {
    use imap_support::*;
    for (name, wire_name) in [
        ("Projects & notes", "Projects &- notes"),
        ("Entwürfe", "Entw&APw-rfe"),
        ("台北/日本語", "&U,BTFw-/&ZeVnLIqe-"),
        ("📧 & Entwürfe", "&2D3c5w- &- Entw&APw-rfe"),
        ("e\u{301}", "e&AwE-"),
    ] {
        let fixture = repeating_fixture(mailctl::imap::Limits::default(), 1, move |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        let pattern = if wire_name.contains(' ') {
            format!("\"{wire_name}\"")
        } else {
            wire_name.into()
        };
        let tag = expect(&mut wire, &format!("LIST \"\" {pattern}")).await;
        write(&mut wire, &format!("* LIST (\\Archive) \"/\" \"{wire_name}\"\r\n* LIST (\\Archive) \"/\" \"{wire_name}\"\r\n{tag} OK listed\r\n")).await;
        logout(&mut wire).await;
    })).await;
        let mut configuration = config();
        configuration.accounts[0].mailboxes = vec![name.into()];
        configuration.grants[0].mailboxes = vec![name.into()];
        let service = imap_service(configuration, &fixture);
        let context = service.context("reader", &Narrowing::default()).unwrap();
        let OperationResult::Mailboxes(page) = service
            .execute(
                &context,
                Operation::ListMailboxes(ListMailboxesInput::default()),
            )
            .await
            .unwrap()
        else {
            panic!("mailboxes")
        };
        assert_eq!(page.mailboxes.len(), 1);
        assert_eq!(page.mailboxes[0].metadata.name, name);
        assert_eq!(page.mailboxes[0].display_label, name);
        assert_eq!(page.mailboxes[0].metadata.special_use, ["\\Archive"]);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn mailbox_input_rejects_schema_overflow_and_unknown_fields() {
    for input in [
        serde_json::json!({"limit":0}),
        serde_json::json!({"limit":1001}),
        serde_json::json!({"account":"x".repeat(1025)}),
        serde_json::json!({"reference":"x".repeat(8193)}),
        serde_json::json!({"cursor":"x".repeat(8193)}),
        serde_json::json!({"grant":"writer"}),
    ] {
        assert!(serde_json::from_value::<ListMailboxesInput>(input).is_err());
    }
    assert!(
        serde_json::from_value::<ListMailboxesInput>(
            serde_json::json!({"limit":1000,"reference":"x".repeat(8192)})
        )
        .is_ok()
    );
}

fn metadata(name: &str) -> MailboxMetadata {
    MailboxMetadata {
        name: name.into(),
        selectable: true,
        special_use: vec![],
    }
}
async fn list(
    service: &Service,
    grant: &str,
    input: ListMailboxesInput,
) -> Result<mailctl::domain::MailboxDiscovery, mailctl::domain::Error> {
    let context = service.context(grant, &Narrowing::default()).unwrap();
    match service
        .execute(&context, Operation::ListMailboxes(input))
        .await?
    {
        OperationResult::Mailboxes(page) => Ok(page),
        _ => panic!("mailbox result"),
    }
}

#[tokio::test]
async fn cursors_bind_inventory_grant_scope_and_token_kind() {
    use mailctl::domain::ErrorCode;
    let memory = Arc::new(MemoryMailboxes::default());
    memory.set("work", vec![metadata("INBOX"), metadata("Archive")]);
    let mut configuration = config();
    let mut second = configuration.grants[0].clone();
    second.name = "second-reader".into();
    configuration.grants.push(second);
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory.clone());
    let first = list(
        &service,
        "reader",
        ListMailboxesInput {
            limit: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cursor = first.next_cursor.unwrap();
    let reference = first.mailboxes[0].reference.clone();
    assert_eq!(
        list(
            &service,
            "second-reader",
            ListMailboxesInput {
                cursor: Some(cursor.clone()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StaleCursor
    );
    assert_eq!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                cursor: Some(reference.clone()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StaleCursor
    );
    assert_eq!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                reference: Some(cursor.clone()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StaleReference
    );
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    for (token, code, is_cursor) in [
        (&reference, ErrorCode::StaleReference, false),
        (&cursor, ErrorCode::StaleCursor, true),
    ] {
        let (signed, _) = token.rsplit_once('.').unwrap();
        for length in [0, 1, 31, 32, 33, 1024] {
            let tag = URL_SAFE_NO_PAD.encode(vec![0; length]);
            let token = format!("{signed}.{tag}");
            let input = if is_cursor {
                ListMailboxesInput {
                    cursor: Some(token),
                    ..Default::default()
                }
            } else {
                ListMailboxesInput {
                    reference: Some(token),
                    ..Default::default()
                }
            };
            assert_eq!(
                list(&service, "reader", input).await.unwrap_err().code,
                code
            );
        }
    }
    let mut tampered = reference.into_bytes();
    tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                reference: Some(String::from_utf8(tampered).unwrap()),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StaleReference
    );
    memory.set("work", vec![metadata("INBOX")]);
    assert_eq!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                cursor: Some(cursor),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StaleCursor
    );
}

mod support;

#[tokio::test]
async fn persistent_references_survive_restart_and_alias_rename_but_not_repointing_or_removal() {
    use mailctl::domain::ErrorCode;
    let installation = support::Installation::empty();
    let memory = Arc::new(MemoryMailboxes::default());
    memory.set("work", vec![metadata("INBOX"), metadata("Archive")]);
    let mut configuration = config();
    configuration.state_dir = installation.config().parent().unwrap().join("state");
    Service::setup(configuration.clone()).unwrap();
    let service = Service::open(configuration.clone())
        .unwrap()
        .with_mailbox_backend(memory.clone());
    let first = list(
        &service,
        "reader",
        ListMailboxesInput {
            limit: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let reference = first.mailboxes[0].reference.clone();
    let request = || ListMailboxesInput {
        reference: Some(reference.clone()),
        ..Default::default()
    };
    drop(service);
    let service = Service::open(configuration.clone())
        .unwrap()
        .with_mailbox_backend(memory.clone());
    assert_eq!(
        list(&service, "reader", request()).await.unwrap().mailboxes[0].reference,
        reference
    );
    assert!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                cursor: first.next_cursor.clone(),
                ..Default::default()
            }
        )
        .await
        .unwrap()
        .complete
    );
    drop(service);
    configuration.accounts[0].alias = "renamed".into();
    let service = Service::open(configuration.clone())
        .unwrap()
        .with_mailbox_backend(memory.clone());
    assert_eq!(
        list(&service, "reader", request()).await.unwrap().mailboxes[0].reference,
        reference
    );
    assert_eq!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                cursor: first.next_cursor,
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StaleCursor
    );
    drop(service);
    configuration.grants[0].mailboxes = vec!["INBOX".into()];
    let service = Service::open(configuration.clone())
        .unwrap()
        .with_mailbox_backend(memory.clone());
    assert_eq!(
        list(&service, "reader", request()).await.unwrap_err().code,
        ErrorCode::MailboxNotAllowed
    );
    drop(service);
    configuration.grants[0].mailboxes.push("Archive".into());
    configuration.accounts[0].server = "new.example.test".into();
    let service = Service::open(configuration)
        .unwrap()
        .with_mailbox_backend(memory);
    assert_eq!(
        list(&service, "reader", request()).await.unwrap_err().code,
        ErrorCode::StaleReference
    );
}

#[tokio::test]
async fn inbox_is_case_insensitive_while_other_mailboxes_keep_exact_identity() {
    let memory = Arc::new(MemoryMailboxes::default());
    memory.set(
        "work",
        vec![
            metadata("inbox"),
            metadata("INBOX"),
            metadata("Archive"),
            metadata("archive"),
        ],
    );
    let mut configuration = config();
    configuration.accounts[0].mailboxes.push("inbox".into());
    configuration.accounts[0].mailboxes.push("archive".into());
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory);
    let page = list(&service, "reader", ListMailboxesInput::default())
        .await
        .unwrap();
    assert_eq!(
        page.mailboxes
            .iter()
            .map(|mailbox| mailbox.metadata.name.as_str())
            .collect::<Vec<_>>(),
        ["Archive", "INBOX"]
    );
    let inbox = &page.mailboxes[1];
    let resolved = list(
        &service,
        "reader",
        ListMailboxesInput {
            reference: Some(inbox.reference.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resolved.mailboxes.len(), 1);
    assert_eq!(resolved.mailboxes[0].metadata.name, "INBOX");
}

#[tokio::test]
async fn mailbox_inventory_page_token_and_envelope_limits_fail_explicitly() {
    use mailctl::domain::ErrorCode;
    let memory = Arc::new(MemoryMailboxes::default());
    memory.set("work", vec![metadata("INBOX"), metadata("Archive")]);
    let mut configuration = config();
    configuration.grants[0].limits.mailbox_page = 1;
    configuration.grants[0].limits.token_bytes = 20;
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory.clone());
    assert_eq!(
        list(
            &service,
            "reader",
            ListMailboxesInput {
                limit: Some(2),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        list(&service, "reader", ListMailboxesInput::default())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResponseTooLarge
    );
    let service = Service::in_memory(config())
        .unwrap()
        .with_mailbox_backend(memory.clone());
    let context = service
        .context("reader", &Narrowing::default())
        .unwrap()
        .with_response_limit(600);
    assert_eq!(
        service
            .execute(
                &context,
                Operation::ListMailboxes(ListMailboxesInput::default())
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResponseTooLarge
    );
    memory.set("work", (0..1001).map(|_| metadata("INBOX")).collect());
    assert_eq!(
        list(&service, "reader", ListMailboxesInput::default())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResponseTooLarge
    );
    memory.set(
        "work",
        vec![
            metadata("INBOX"),
            MailboxMetadata {
                selectable: false,
                ..metadata("INBOX")
            },
        ],
    );
    assert_eq!(
        list(&service, "reader", ListMailboxesInput::default())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ProviderUnavailable
    );
}

#[tokio::test]
async fn imap_fails_explicitly_on_malformed_unrequested_conflicting_and_oversized_inventory() {
    use imap_support::*;
    use mailctl::domain::ErrorCode;
    for (response, expected) in [
        (
            "* LIST () \"/\" Private\r\n{tag} OK listed\r\n",
            ErrorCode::ProviderUnavailable,
        ),
        (
            "* LIST () \"/\" INBOX\r\n* LIST (\\Noselect) \"/\" INBOX\r\n{tag} OK listed\r\n",
            ErrorCode::ProviderUnavailable,
        ),
        ("* LIST malformed\r\n", ErrorCode::ProviderUnavailable),
        (
            "* LIST () \"/\" {33554432}\r\n",
            ErrorCode::ResponseTooLarge,
        ),
    ] {
        let fixture = repeating_fixture(mailctl::imap::Limits::default(), 1, move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "LIST \"\" INBOX").await;
                write(&mut wire, &response.replace("{tag}", &tag)).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let mut configuration = config();
        configuration.accounts[0].mailboxes = vec!["INBOX".into()];
        let service = imap_service(configuration, &fixture);
        assert_eq!(
            list(&service, "reader", ListMailboxesInput::default())
                .await
                .unwrap_err()
                .code,
            expected
        );
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn configured_inventory_ceiling_returns_all_thousand_mailboxes_without_false_completion() {
    let memory = Arc::new(MemoryMailboxes::default());
    let names = (0..1000)
        .map(|index| format!("Mailbox{index:04}"))
        .collect::<Vec<_>>();
    memory.set("work", names.iter().map(|name| metadata(name)).collect());
    let mut configuration = config();
    configuration.accounts[0].mailboxes = names.clone();
    configuration.grants[0].mailboxes = names.clone();
    configuration.grants[0].limits.mailbox_page = 1000;
    configuration.limits.mailbox_page = 1000;
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory);
    let page = list(
        &service,
        "reader",
        ListMailboxesInput {
            limit: Some(1000),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(page.complete);
    assert!(page.next_cursor.is_none());
    assert_eq!(
        page.mailboxes
            .iter()
            .map(|mailbox| mailbox.metadata.name.clone())
            .collect::<Vec<_>>(),
        names
    );
}

#[test]
fn a_small_response_budget_stops_large_page_assembly() {
    let memory = Arc::new(MemoryMailboxes::default());
    let names = (0..1000)
        .map(|index| format!("Mailbox{index:04}{}", "x".repeat(750)))
        .collect::<Vec<_>>();
    memory.set("work", names.iter().map(|name| metadata(name)).collect());
    let mut configuration = config();
    configuration.accounts[0].mailboxes = names.clone();
    configuration.grants[0].mailboxes = names;
    configuration.limits.mailbox_page = 1000;
    configuration.grants[0].limits.mailbox_page = 1000;
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(memory);
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let small = context.clone().with_response_limit(600);
    let restricted = allocation_counter::measure(|| {
        assert_eq!(
            runtime
                .block_on(service.execute(
                    &small,
                    Operation::ListMailboxes(ListMailboxesInput::default())
                ))
                .unwrap_err()
                .code,
            mailctl::domain::ErrorCode::ResponseTooLarge
        );
    });
    let complete = allocation_counter::measure(|| {
        assert!(
            runtime
                .block_on(service.execute(
                    &context,
                    Operation::ListMailboxes(ListMailboxesInput::default())
                ))
                .is_ok()
        );
    });
    assert!(
        restricted.bytes_total + 1024 * 1024 < complete.bytes_total,
        "a refused page must avoid allocating its mailbox references and labels: restricted={restricted:?}, complete={complete:?}"
    );
}

#[tokio::test]
async fn imap_runtime_inventory_ceiling_is_enforced_before_credential_work() {
    use mailctl::{
        authentication::Runtime,
        credentials::{Availability, Secret, SecretSource, SourceError},
        domain::ErrorCode,
    };
    struct Missing(std::sync::atomic::AtomicUsize);
    impl SecretSource for Missing {
        fn availability(&self, _: uuid::Uuid) -> Availability {
            Availability::Missing
        }
        fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(SourceError::Missing)
        }
    }
    let configuration = config();
    let mut runtime_limits = configuration.limits.clone();
    runtime_limits.mailbox_page = 1;
    runtime_limits.mailbox_inventory = 1;
    let runtime = Arc::new(
        Runtime::new(runtime_limits, tokio_rustls::rustls::RootCertStore::empty()).unwrap(),
    );
    let missing = Arc::new(Missing(std::sync::atomic::AtomicUsize::new(0)));
    let backend = mailctl::service::ImapBackend::new(
        runtime,
        std::collections::BTreeMap::from([(
            "work".into(),
            missing.clone() as Arc<dyn SecretSource>,
        )]),
    );
    let service = Service::in_memory(configuration)
        .unwrap()
        .with_mailbox_backend(Arc::new(backend));
    assert_eq!(
        list(&service, "reader", ListMailboxesInput::default())
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(missing.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_and_timed_out_discovery_release_the_connection_and_admission() {
    use imap_support::*;
    for cancel in [true, false] {
        let ready = Arc::new(tokio::sync::Notify::new());
        let mut first = true;
        let notify = ready.clone();
        let fixture = repeating_fixture(mailctl::imap::Limits::default(), 2, move |mut wire| {
            let stalled = first;
            first = false;
            let ready = notify.clone();
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "LIST \"\" INBOX").await;
                if stalled {
                    ready.notify_one();
                    dropped(&mut wire).await;
                } else {
                    write(
                        &mut wire,
                        &format!("* LIST () \"/\" INBOX\r\n{tag} OK listed\r\n"),
                    )
                    .await;
                    logout(&mut wire).await;
                }
            })
        })
        .await;
        let mut configuration = config();
        configuration.accounts[0].mailboxes = vec!["INBOX".into()];
        for limits in [
            &mut configuration.limits,
            &mut configuration.grants[0].limits,
        ] {
            limits.operation_seconds = 1;
            limits.connection_seconds = 1;
            limits.initialization_seconds = 1;
            limits.account_connections = 1;
        }
        let service = Arc::new(imap_service(configuration, &fixture));
        let running = service.clone();
        let task =
            tokio::spawn(
                async move { list(&running, "reader", ListMailboxesInput::default()).await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(3), ready.notified())
            .await
            .unwrap();
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                task.await.unwrap().unwrap_err().code,
                mailctl::domain::ErrorCode::Timeout
            );
        }
        assert!(
            list(&service, "reader", ListMailboxesInput::default())
                .await
                .unwrap()
                .complete
        );
        fixture.task.await.unwrap();
    }
}
