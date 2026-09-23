mod support;

use mailctl::{
    config::Config,
    domain::{ListAccountsInput, Operation, OperationResult},
    service::{MemoryDraftTargets, Service},
};
use serde_json::{Value, json};
use std::sync::Arc;

async fn account(service: &Service) -> Value {
    let context = service.context("writer", &Default::default()).unwrap();
    let OperationResult::Accounts(accounts) = service
        .execute(
            &context,
            Operation::ListAccounts(ListAccountsInput::default()),
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    serde_json::to_value(&accounts.accounts[0]).unwrap()
}
fn save(identity: &Value, operation: uuid::Uuid) -> Value {
    json!({"operation":"save_draft", "input": {
        "mailbox":"Drafts", "account_id":identity["account_id"], "account_generation":identity["generation"],
        "operation_id":operation, "draft":{"subject":"Synthetic draft", "body":"Private synthetic content"}
    }})
}
async fn execute(service: &Service, request: Value) -> Value {
    let context = service.context("writer", &Default::default()).unwrap();
    serde_json::to_value(
        service
            .execute(&context, serde_json::from_value(request).unwrap())
            .await
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn prepared_draft_survives_restart_and_status_never_contacts_provider() {
    let installation = support::Installation::two_accounts();
    let mut config =
        Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.accounts[0].from_identities = vec!["work@example.test".into()];
    Service::setup(config.clone()).unwrap();
    let provider = Arc::new(MemoryDraftTargets::default());
    provider.set("work", "Drafts", 77);
    let service = Service::open(config.clone())
        .unwrap()
        .with_draft_targets(provider);
    let identity = account(&service).await;
    let input = save(&identity, uuid::Uuid::new_v4());
    let result = execute(&service, input.clone()).await;
    assert_eq!(result["state"], "prepared");
    assert_eq!(result["dispatched"], false);
    assert_eq!(result["mailbox"], "Drafts");
    assert_eq!(result["uid_validity"], 77);
    drop(service);
    let service = Service::open(config).unwrap();
    let mut status = input.clone();
    status["operation"] = json!("draft_status");
    status["input"].as_object_mut().unwrap().remove("draft");
    assert_eq!(execute(&service, status).await, result);
    assert_eq!(execute(&service, input).await, result);
}

async fn fixture() -> (support::Installation, Config, Service, Value) {
    let installation = support::Installation::two_accounts();
    let mut config =
        Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.accounts[0].from_identities = vec!["work@example.test".into()];
    Service::setup(config.clone()).unwrap();
    let provider = Arc::new(MemoryDraftTargets::default());
    provider.set("work", "Drafts", 77);
    let service = Service::open(config.clone())
        .unwrap()
        .with_draft_targets(provider);
    let identity = account(&service).await;
    (installation, config, service, identity)
}
async fn failure(
    service: &Service,
    request: Value,
    grant: &str,
    read_only: bool,
) -> mailctl::domain::ErrorCode {
    let context = service
        .context(
            grant,
            &mailctl::policy::Narrowing {
                read_only,
                ..Default::default()
            },
        )
        .unwrap();
    service
        .execute(&context, serde_json::from_value(request).unwrap())
        .await
        .unwrap_err()
        .code
}
fn status(mut request: Value) -> Value {
    request["operation"] = json!("draft_status");
    request["input"].as_object_mut().unwrap().remove("draft");
    request
}
#[tokio::test]
async fn authorization_precedes_journal_existence_and_input_conflicts() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, _config, service, identity) = fixture().await;
    let request = save(&identity, uuid::Uuid::new_v4());
    for known in [false, true] {
        if known {
            execute(&service, request.clone()).await;
        }
        for grant in ["writer", "default"] {
            assert_eq!(
                failure(&service, status(request.clone()), grant, true).await,
                PermissionDenied
            );
            assert_eq!(
                failure(&service, request.clone(), grant, true).await,
                PermissionDenied
            );
        }
    }
    let mut conflicting = request.clone();
    conflicting["input"]["draft"]["body"] = json!("different");
    assert_eq!(
        failure(&service, conflicting.clone(), "writer", false).await,
        OperationConflict
    );
    conflicting["input"]["account_id"] = json!(uuid::Uuid::new_v4());
    assert_eq!(
        failure(&service, conflicting, "writer", false).await,
        AccountNotAllowed
    );
}
#[tokio::test]
async fn invalid_composition_fails_before_any_provider_connection() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, config, service, identity) = fixture().await;
    drop(service);
    let service = Service::open(config).unwrap();
    for draft in [
        json!({"from":"unapproved@example.test"}),
        json!({"subject":"injection\r\nBcc: victim@example.test"}),
        json!({"to":[{"address":"not-an-address"}]}),
        json!({"to":[{"address":"ok@example.test", "name":"injection\nname"}]}),
        json!({"in_reply_to":"bad\r\nid@example.test"}),
        json!({"references":["bad-id"]}),
        json!({"body":"zero\u{0000}byte"}),
    ] {
        let mut request = save(&identity, uuid::Uuid::new_v4());
        request["input"]["draft"] = draft;
        assert_eq!(
            failure(&service, request, "writer", false).await,
            InvalidRequest
        );
    }
}
#[tokio::test]
async fn canonical_input_preserves_recipient_order_and_normalizes_body_lines() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, _config, service, identity) = fixture().await;
    let mut request = save(&identity, uuid::Uuid::new_v4());
    request["input"]["draft"] = json!({"body":"one\r\ntwo\rthree", "to":[{"address":"first@example.test", "name":"First"},{"address":"second@example.test"}], "bcc":[{"address":"hidden@example.test"}], "in_reply_to":"original@example.test", "references":["first@example.test","second@example.test"]});
    let result = execute(&service, request.clone()).await;
    request["input"]["draft"]["body"] = json!("one\ntwo\nthree");
    assert_eq!(execute(&service, request.clone()).await, result);
    request["input"]["draft"]["to"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(
        failure(&service, request, "writer", false).await,
        OperationConflict
    );
}
#[tokio::test]
async fn journal_excludes_composition_and_missing_history_does_not_reinitialize() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, config, service, identity) = fixture().await;
    let request = save(&identity, uuid::Uuid::new_v4());
    execute(&service, request.clone()).await;
    for name in ["drafts.sqlite", "drafts.sqlite-wal"] {
        if let Ok(bytes) = std::fs::read(config.state_dir.join(name)) {
            let text = String::from_utf8_lossy(&bytes);
            for secret in [
                "work@example.test",
                "Synthetic draft",
                "Private synthetic content",
                "Content-Type:",
            ] {
                assert!(!text.contains(secret));
            }
        }
    }
    drop(service);
    std::fs::remove_file(config.state_dir.join("drafts.sqlite")).unwrap();
    let service = Service::open(config.clone()).unwrap();
    assert_eq!(
        failure(&service, status(request.clone()), "writer", false).await,
        JournalUnavailable
    );
    assert_eq!(
        failure(&service, request, "writer", false).await,
        JournalUnavailable
    );
    assert!(!config.state_dir.join("drafts.sqlite").exists());
    let context = service.context("default", &Default::default()).unwrap();
    service
        .execute(&context, Operation::ListAccounts(Default::default()))
        .await
        .unwrap();
}
#[tokio::test]
async fn changing_draft_routing_advances_generation_and_never_redirects_old_operations() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, mut config, service, identity) = fixture().await;
    let request = save(&identity, uuid::Uuid::new_v4());
    execute(&service, request.clone()).await;
    drop(service);
    config.accounts[0].mailboxes.push("New Drafts".into());
    config.accounts[0].drafts_mailbox = Some("New Drafts".into());
    config
        .grants
        .iter_mut()
        .find(|g| g.name == "writer")
        .unwrap()
        .mailboxes = vec!["New Drafts".into()];
    Service::setup(config.clone()).unwrap();
    let service = Service::open(config).unwrap();
    let current = account(&service).await;
    assert_eq!(current["account_id"], identity["account_id"]);
    assert_eq!(current["generation"], 2);
    assert_eq!(current["drafts_mailbox"], "New Drafts");
    for request in [request, save(&identity, uuid::Uuid::new_v4())] {
        for mailbox in ["Drafts", "New Drafts"] {
            let mut probe = request.clone();
            probe["input"]["mailbox"] = json!(mailbox);
            assert_eq!(
                failure(&service, probe.clone(), "writer", false).await,
                PermissionDenied
            );
            assert_eq!(
                failure(&service, status(probe), "writer", false).await,
                PermissionDenied
            );
        }
    }
}

#[tokio::test]
async fn schema_and_application_enforce_independent_composition_bounds() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, config, service, identity) = fixture().await;
    let base = save(&identity, uuid::Uuid::new_v4());
    for (field, value) in [
        ("subject", json!("x".repeat(8193))),
        ("references", json!(vec!["id@example.test"; 51])),
        ("in_reply_to", json!("a".repeat(999))),
        ("to", json!(vec![json!({"address":"to@example.test"}); 101])),
    ] {
        let mut request = base.clone();
        request["input"]["draft"][field] = value;
        assert!(serde_json::from_value::<Operation>(request).is_err());
    }
    let mut request = base.clone();
    request["input"]["draft"]["to"] = json!(vec![json!({"address":"to@example.test"}); 50]);
    request["input"]["draft"]["cc"] = json!(vec![json!({"address":"cc@example.test"}); 50]);
    let result = execute(&service, request.clone()).await;
    assert_eq!(result["state"], "prepared");
    request["input"]["operation_id"] = json!(uuid::Uuid::new_v4());
    request["input"]["draft"]["bcc"] = json!([{"address":"bcc@example.test"}]);
    assert_eq!(
        failure(&service, request, "writer", false).await,
        ResponseTooLarge
    );
    let mut direct: mailctl::domain::SaveDraftInput =
        serde_json::from_value(base["input"].clone()).unwrap();
    direct.draft.body = "x".repeat(config.limits.draft_mime_bytes + 1);
    let context = service.context("writer", &Default::default()).unwrap();
    assert_eq!(
        service
            .execute(&context, Operation::SaveDraft(direct))
            .await
            .unwrap_err()
            .code,
        ResponseTooLarge
    );
}
#[tokio::test]
async fn missing_target_is_not_created_and_no_journal_entry_is_prepared() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, _config, service, identity) = fixture().await;
    let service = service.with_draft_targets(Arc::new(MemoryDraftTargets::default()));
    let request = save(&identity, uuid::Uuid::new_v4());
    assert_eq!(
        failure(&service, request.clone(), "writer", false).await,
        DraftMailboxUnavailable
    );
    assert_eq!(
        failure(&service, status(request), "writer", false).await,
        OperationNotFound
    );
}
#[tokio::test]
async fn journal_quota_preserves_existing_status_and_read_only_health() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, mut config, service, identity) = fixture().await;
    drop(service);
    config.limits.journal_records = 1;
    for grant in &mut config.grants {
        grant.limits.journal_records = 1;
    }
    Service::setup(config.clone()).unwrap();
    let provider = Arc::new(MemoryDraftTargets::default());
    provider.set("work", "Drafts", 77);
    let service = Service::open(config.clone())
        .unwrap()
        .with_draft_targets(provider);
    let request = save(&identity, uuid::Uuid::new_v4());
    let expected = execute(&service, request.clone()).await;
    assert_eq!(
        failure(
            &service,
            save(&identity, uuid::Uuid::new_v4()),
            "writer",
            false
        )
        .await,
        JournalFull
    );
    assert_eq!(execute(&service, status(request.clone())).await, expected);
    drop(service);
    std::fs::write(config.state_dir.join("drafts.sqlite"), b"corrupt fixture").unwrap();
    let service = Service::open(config).unwrap();
    for grant in ["writer", "default"] {
        let context = service.context(grant, &Default::default()).unwrap();
        let health =
            serde_json::to_value(service.execute(&context, Operation::Health).await.unwrap())
                .unwrap();
        assert_eq!(
            health["status"],
            if grant == "writer" {
                "degraded"
            } else {
                "ready"
            }
        );
    }
    assert_eq!(
        failure(&service, status(request), "writer", false).await,
        JournalUnavailable
    );
}

#[tokio::test]
async fn original_mailbox_authorization_precedes_known_and_unknown_journal_lookup() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, mut config, service, identity) = fixture().await;
    let known = save(&identity, uuid::Uuid::new_v4());
    execute(&service, known.clone()).await;
    drop(service);
    config.accounts[0].mailboxes = vec!["INBOX".into(), "New Drafts".into()];
    config.accounts[0].drafts_mailbox = Some("New Drafts".into());
    config
        .grants
        .iter_mut()
        .find(|g| g.name == "writer")
        .unwrap()
        .mailboxes = vec!["New Drafts".into()];
    Service::setup(config.clone()).unwrap();
    let service = Service::open(config).unwrap();
    for request in [known, save(&identity, uuid::Uuid::new_v4())] {
        assert_eq!(
            failure(&service, request.clone(), "writer", false).await,
            PermissionDenied
        );
        assert_eq!(
            failure(&service, status(request), "writer", false).await,
            PermissionDenied
        );
    }
}

#[tokio::test]
async fn reply_metadata_accepts_schema_maxima_and_rejects_the_next_value() {
    let (_installation, _config, service, identity) = fixture().await;
    let id = format!("{}@example.test", "a".repeat(985));
    assert_eq!(id.len(), 998);
    let mut request = save(&identity, uuid::Uuid::new_v4());
    request["input"]["draft"]["in_reply_to"] = json!(id);
    request["input"]["draft"]["references"] = json!(vec![id.clone(); 50]);
    request["input"]["draft"]["subject"] = json!("s".repeat(8192));
    request["input"]["draft"]["to"] = json!([{"address":format!("{}@{}.{}.{}", "a".repeat(64),"b".repeat(63),"c".repeat(63),"d".repeat(61)), "name":"n".repeat(1024)}]);
    execute(&service, request.clone()).await;
    request["input"]["draft"]["references"]
        .as_array_mut()
        .unwrap()
        .push(json!(id));
    assert!(serde_json::from_value::<Operation>(request).is_err());
}

#[tokio::test]
async fn application_enforces_exact_frozen_mime_and_header_limits() {
    use mailctl::domain::ErrorCode::*;
    let (_installation, config, service, identity) = fixture().await;
    let request = save(&identity, uuid::Uuid::new_v4());
    let expected = execute(&service, request.clone()).await;
    let input: mailctl::domain::SaveDraftInput =
        serde_json::from_value(request["input"].clone()).unwrap();
    let record =
        mailctl::draft_journal::DraftJournal::open_existing(config.state_dir.join("drafts.sqlite"))
            .unwrap()
            .inspect(&input.identity())
            .unwrap()
            .unwrap();
    let frozen = record.operation.reconstruction.unwrap();
    let mime = mailctl::draft::PreparedDraft::compose(
        mailctl::draft::DraftInput {
            from: "work@example.test".into(),
            subject: input.draft.subject,
            body: input.draft.body,
            date_unix: frozen.date_unix,
            message_id: format!(
                "{}.{}.{}@mailctl.invalid",
                input.account_id, input.account_generation, input.operation_id
            ),
            ..Default::default()
        },
        config.limits.draft_mime_bytes,
    )
    .unwrap();
    drop(service);
    for (mime_limit, header_limit, passes) in [
        (mime.bytes().len(), mime.header_bytes(), true),
        (mime.bytes().len() - 1, mime.header_bytes(), false),
        (mime.bytes().len(), mime.header_bytes() - 1, false),
    ] {
        let mut config = config.clone();
        config.limits.draft_mime_bytes = mime_limit;
        config.limits.header_bytes = header_limit;
        for grant in &mut config.grants {
            grant.limits = config.limits.clone();
        }
        Service::setup(config.clone()).unwrap();
        let service = Service::open(config).unwrap();
        if passes {
            assert_eq!(execute(&service, request.clone()).await, expected);
        } else {
            assert_eq!(
                failure(&service, request.clone(), "writer", false).await,
                ResponseTooLarge
            );
        }
    }
}

#[tokio::test]
async fn sqlite_contention_never_blocks_the_async_executor_for_its_busy_timeout() {
    let (_installation, mut config, service, identity) = fixture().await;
    drop(service);
    config.limits.operation_seconds = 1;
    config.limits.connection_seconds = 1;
    config.limits.initialization_seconds = 1;
    for grant in &mut config.grants {
        grant.limits = config.limits.clone();
    }
    Service::setup(config.clone()).unwrap();
    let targets = Arc::new(MemoryDraftTargets::default());
    targets.set("work", "Drafts", 77);
    let service = Service::open(config.clone())
        .unwrap()
        .with_draft_targets(targets);
    let writer = rusqlite::Connection::open(config.state_dir.join("drafts.sqlite")).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        failure(
            &service,
            save(&identity, uuid::Uuid::new_v4()),
            "writer",
            false
        )
        .await,
        mailctl::domain::ErrorCode::JournalUnavailable
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "SQLite blocked the request executor"
    );
    writer.execute_batch("ROLLBACK").unwrap();
    execute(&service, save(&identity, uuid::Uuid::new_v4())).await;
}
