//! Durable history through the installed components and supported maintenance commands.

use super::{Caller, Fixture, assert_appended_content, server, support};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::fs;

pub(super) fn rows(fixture: &Fixture) -> Vec<Vec<SqlValue>> {
    let database = rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
    let mut statement = database
        .prepare(
            "SELECT operation_id, account_id, account_generation, mailbox_identity,
                    content_sha256, reconstruction, state, appended_uid_validity, appended_uid
             FROM draft_operations ORDER BY operation_id",
        )
        .unwrap();
    statement
        .query_map([], |row| (0..9).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn assert_error(response: &Value, code: &str) {
    assert_eq!(response["error"]["code"], code, "{response}");
}

async fn assert_read_only_health(fixture: &Fixture, executable: &str) {
    let reader = Caller::start(fixture, executable, "default", false).await;
    let health = reader.call(fixture, "email_capabilities", json!({})).await;
    assert_eq!(health["result"]["health"]["status"], "ready");
    assert!(health["result"]["health"].get("draft_creation").is_none());
    assert!(health["result"]["health"].get("draft_journal").is_none());
    reader.finish().await;
}

async fn snapshots_preserve_all_outcomes_and_suspend_missing_history(executable: &str) {
    let mut fixture = Fixture::new(executable);
    let mut retained = Vec::new();
    fixture.sql("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic dispatch failure'); END;");
    fixture.server.expect_draft_target(77);
    assert_error(&fixture.save(executable).await, "journal_unavailable");
    fixture.sql("DROP TRIGGER stop_dispatch");
    let prepared = fixture.status(executable, false).await;
    assert_eq!(prepared["result"]["state"], "prepared");
    retained.push((fixture.input.clone(), prepared));

    for (reply, state) in [
        (server::DraftReply::Disconnect, "outcome_unknown"),
        (server::DraftReply::Created(true), "created"),
        (server::DraftReply::Rejected, "rejected"),
        (server::DraftReply::Disconnect, "duplicate"),
    ] {
        fixture.new_operation();
        fixture.server.expect_append(reply);
        let mut outcome = fixture.save(executable).await;
        if matches!(state, "outcome_unknown" | "duplicate") {
            assert_error(&outcome, "outcome_unknown");
        }
        if state == "duplicate" {
            fixture.server.expect_reconciliation();
            outcome = fixture.status(executable, true).await;
        }
        if state != "outcome_unknown" {
            assert_eq!(outcome["result"]["state"], state, "{outcome}");
        } else {
            assert_eq!(outcome["error"]["reason"], "imap_connection_closed");
            outcome["error"].as_object_mut().unwrap().remove("reason");
        }
        retained.push((fixture.input.clone(), outcome));
    }
    let expected_rows = rows(&fixture);
    assert_eq!(expected_rows.len(), 5);
    let registry = fs::read(fixture.state().join("accounts.json")).unwrap();
    let verification = fixture.admin(executable, &["state", "verify"]);
    assert_eq!(verification["result"]["action"], "verify");
    assert_eq!(verification["result"]["draft_creation_suspended"], false);
    assert_eq!(rows(&fixture), expected_rows);
    let backup = fixture
        .installation
        .config()
        .parent()
        .unwrap()
        .join("history-backup");
    let backup_path = backup.to_str().unwrap();
    let backup_result = fixture.admin(
        executable,
        &["state", "backup", "--destination", backup_path],
    );
    assert_eq!(backup_result["result"]["action"], "backup");
    for name in [
        "accounts.json",
        "config.toml",
        "drafts.sqlite",
        "manifest.json",
    ] {
        assert!(backup.join(name).is_file(), "snapshot retains {name}");
    }

    // This remote side effect is newer than the snapshot. Restoring must not
    // turn its absent journal entry into authorization for another APPEND.
    fixture.new_operation();
    let later_input = fixture.input.clone();
    fixture
        .server
        .expect_append(server::DraftReply::Created(false));
    assert_eq!(
        fixture.save(executable).await["result"]["state"],
        "created_reference_unavailable"
    );
    let appends = fixture.server.drafts().len();
    let restore = fixture.admin(executable, &["state", "restore", "--source", backup_path]);
    assert_eq!(restore["result"]["action"], "restore");
    assert_eq!(restore["result"]["draft_creation_suspended"], true);
    assert_eq!(rows(&fixture), expected_rows);
    assert_eq!(
        fs::read(fixture.state().join("accounts.json")).unwrap(),
        registry
    );
    assert_eq!(
        fs::read(fixture.state().join("drafts.suspended")).unwrap(),
        b"suspended"
    );
    let connections = fixture.server.accepted();

    for (input, expected) in &retained {
        fixture.input = input.clone();
        let inspected = fixture.status(executable, false).await;
        assert_eq!(inspected["result"], expected["result"]);
        assert_eq!(inspected["error"], expected["error"]);
        let replay = fixture.save(executable).await;
        if expected["result"]["state"] == "prepared" {
            assert_error(&replay, "journal_unavailable");
        } else {
            assert_eq!(replay["result"], expected["result"]);
            assert_eq!(replay["error"], expected["error"]);
        }
    }
    fixture.input = later_input;
    assert_error(
        &fixture.status(executable, false).await,
        "journal_unavailable",
    );
    assert_error(&fixture.save(executable).await, "journal_unavailable");
    assert_eq!(fixture.server.accepted(), connections);
    assert_eq!(fixture.server.drafts().len(), appends);
    let health = fixture
        .call(executable, "email_capabilities", json!({}))
        .await;
    assert_eq!(health["result"]["health"]["status"], "degraded");
    assert_eq!(health["result"]["health"]["draft_creation"], "unavailable");
    assert!(
        fixture
            .call(executable, "email_list_accounts", json!({}))
            .await["result"]["accounts"]
            .as_array()
            .is_some_and(|accounts| !accounts.is_empty())
    );

    // Restore does permit read-only evidence to finish an already uncertain
    // operation. Its original target and checksum remain available.
    fixture.input = retained[1].0.clone();
    fixture
        .server
        .expect_reconciliation_bytes(fixture.server.drafts()[0].clone());
    let verified = fixture.status(executable, true).await;
    assert_eq!(verified["result"]["state"], "duplicate");
    assert_eq!(fixture.save(executable).await["result"], verified["result"]);
    assert_eq!(fixture.server.drafts().len(), appends);
    assert_eq!(fixture.server.accepted(), connections + 1);
    assert_read_only_health(&fixture, executable).await;
    fixture.server.finish();
}

async fn journal_loss_stays_suspended_after_file_replacement(executable: &str) {
    let mut fixture = Fixture::new(executable);
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let created = fixture.save(executable).await;
    assert_eq!(created["result"]["state"], "created");
    let journal = fixture.state().join("drafts.sqlite");
    let preserved = fixture.state().join("preserved.sqlite");
    fs::rename(&journal, &preserved).unwrap();
    assert_error(
        &fixture.status(executable, false).await,
        "journal_unavailable",
    );
    assert!(
        !journal.exists(),
        "missing history must not become an empty journal"
    );
    assert_eq!(
        fs::read(fixture.state().join("drafts.suspended")).unwrap(),
        b"suspended"
    );
    fs::rename(&preserved, &journal).unwrap();
    assert_eq!(
        fixture.status(executable, false).await["result"],
        created["result"]
    );
    assert_eq!(fixture.save(executable).await["result"], created["result"]);
    fixture.new_operation();
    assert_error(&fixture.save(executable).await, "journal_unavailable");
    assert_error(
        &fixture.status(executable, false).await,
        "journal_unavailable",
    );
    let health = fixture
        .call(executable, "email_capabilities", json!({}))
        .await;
    assert_eq!(health["result"]["health"]["draft_journal"], "available");
    assert_eq!(health["result"]["health"]["draft_creation"], "unavailable");
    assert_read_only_health(&fixture, executable).await;
    assert_eq!(fixture.server.accepted(), 1);
    assert_eq!(fixture.server.drafts().len(), 1);
    fixture.server.finish();
}

fn reconstruction(fixture: &Fixture) -> Value {
    let database = rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
    let value: String = database
        .query_row("SELECT reconstruction FROM draft_operations", [], |row| {
            row.get(0)
        })
        .unwrap();
    serde_json::from_str(&value).unwrap()
}

async fn previous_encoder_prepared_retry_preserves_frozen_facts(executable: &str) {
    let mut fixture = Fixture::new(executable);
    fixture.sql("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic dispatch failure'); END;");
    fixture.server.expect_draft_target(77);
    assert_error(&fixture.save(executable).await, "journal_unavailable");
    fixture.sql("DROP TRIGGER stop_dispatch");
    let current = reconstruction(&fixture);
    let mut previous = current.clone();
    previous["encoder"] = json!("mail-builder/0.5.0");
    {
        let database = rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
        // Represent an older encoder's retained hash without introducing that
        // obsolete dependency or a nonproduction executable into qualification.
        database
            .execute(
                "UPDATE draft_operations SET reconstruction = ?1, content_sha256 = ?2",
                rusqlite::params![previous.to_string(), [0x5a_u8; 32].as_slice()],
            )
            .unwrap();
    }
    let legacy = rows(&fixture);
    let verified = fixture.admin(executable, &["state", "verify"]);
    assert_eq!(verified["result"]["action"], "verify");
    assert_eq!(
        rows(&fixture),
        legacy,
        "verification never rewrites frozen work"
    );
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let created = fixture.save(executable).await;
    assert_eq!(created["result"]["state"], "created");
    assert_appended_content(&fixture, &created);
    assert_eq!(reconstruction(&fixture), current);
    assert_ne!(created["result"]["content_sha256"], "5a".repeat(32));
    let terminal = rows(&fixture);
    assert_eq!(fixture.save(executable).await["result"], created["result"]);
    assert_eq!(rows(&fixture), terminal);
    assert_eq!(fixture.server.accepted(), 2);
    assert_eq!(fixture.server.drafts().len(), 1);
    fixture.server.finish();
}

async fn historical_operations_keep_original_targets_and_permissions(executable: &str) {
    for state in [
        "prepared",
        "outcome_unknown",
        "created",
        "rejected",
        "duplicate",
    ] {
        let mut fixture = Fixture::new(executable);
        fixture.input["draft"]
            .as_object_mut()
            .unwrap()
            .remove("from");
        let mut original = if state == "prepared" {
            fixture.sql("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic dispatch failure'); END;");
            fixture.server.expect_draft_target(77);
            assert_error(&fixture.save(executable).await, "journal_unavailable");
            fixture.sql("DROP TRIGGER stop_dispatch");
            fixture.status(executable, false).await
        } else {
            fixture.server.expect_append(match state {
                "created" => server::DraftReply::Created(true),
                "rejected" => server::DraftReply::Rejected,
                _ => server::DraftReply::Disconnect,
            });
            fixture.save(executable).await
        };
        if state == "duplicate" {
            fixture.server.expect_reconciliation();
            original = fixture.status(executable, true).await;
        } else if state == "outcome_unknown" {
            assert_eq!(original["error"]["reason"], "imap_connection_closed");
            original["error"].as_object_mut().unwrap().remove("reason");
        }
        let original_rows = rows(&fixture);
        let frozen = reconstruction(&fixture);
        // A separate listening socket makes any accidental use of current
        // routing independently observable without reaching a real provider.
        let replacement = std::net::TcpListener::bind("localhost:0").unwrap();
        replacement.set_nonblocking(true).unwrap();
        let mut config = fixture.configuration();
        config.accounts[0].alias = "renamed".into();
        config.accounts[0].server = "localhost".into();
        config.accounts[0].port = replacement.local_addr().unwrap().port();
        config.accounts[0].mailboxes = vec!["INBOX".into(), "New Drafts".into()].into();
        config.accounts[0].drafts_mailbox = Some("New Drafts".into());
        config.accounts[0]
            .from_identities
            .insert(0, "replacement@example.test".into());
        for grant in &mut config.grants {
            if grant.name == "writer" || grant.name == "other-writer" {
                grant.mailboxes = vec!["New Drafts".into()].into();
                grant.historical_drafts = vec![mailctl::config::HistoricalDraftScope {
                    account_id: fixture.input["account_id"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap(),
                    account_generation: 1,
                    mailbox: "Drafts".into(),
                }];
            }
        }
        fixture.configure(&config);
        assert_eq!(rows(&fixture), original_rows);
        let status = fixture.status(executable, false).await;
        assert_eq!(status["result"], original["result"]);
        assert_eq!(status["error"], original["error"]);
        if state == "prepared" {
            fixture.server.expect_draft_target(88);
            assert_error(&fixture.save(executable).await, "draft_mailbox_unavailable");
            assert_eq!(rows(&fixture), original_rows);
            fixture
                .server
                .expect_append(server::DraftReply::Created(true));
            let created = fixture.save(executable).await;
            assert_eq!(created["result"]["state"], "created");
            assert_eq!(
                created["result"]["content_sha256"],
                original["result"]["content_sha256"]
            );
            assert_eq!(reconstruction(&fixture), frozen);
            assert_appended_content(&fixture, &created);
        } else {
            let replay = fixture.save(executable).await;
            assert_eq!(replay["result"], original["result"]);
            assert_eq!(replay["error"], original["error"]);
            if state == "outcome_unknown" {
                fixture.server.expect_reconciliation();
                let duplicate = fixture.status(executable, true).await;
                assert_eq!(duplicate["result"]["state"], "duplicate");
                assert_appended_content(&fixture, &duplicate);
            }
        }
        assert!(
            replacement
                .accept()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
            "historical work never connects to the current route"
        );
        let connections = fixture.server.accepted();
        for grant in &mut config.grants {
            grant.historical_drafts.clear();
        }
        fixture.configure(&config);
        let mut conflict = fixture.input.clone();
        conflict["draft"]["body"] = json!("Conflicting synthetic content");
        assert_error(
            &fixture.call(executable, "email_save_draft", conflict).await,
            "permission_denied",
        );
        assert_error(
            &fixture.status(executable, false).await,
            "permission_denied",
        );
        fixture.new_operation();
        assert_error(&fixture.save(executable).await, "permission_denied");
        assert_error(&fixture.status(executable, true).await, "permission_denied");
        assert_eq!(fixture.server.accepted(), connections);
        assert_eq!(fixture.server.drafts().len(), 1);
        fixture.server.finish();
    }
}

async fn revoked_from_and_unretained_routes_preserve_history_without_dispatch(executable: &str) {
    for fault in ["from", "routing"] {
        let mut fixture = Fixture::new(executable);
        fixture.input["draft"]
            .as_object_mut()
            .unwrap()
            .remove("from");
        fixture.sql("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic dispatch failure'); END;");
        fixture.server.expect_draft_target(77);
        assert_error(&fixture.save(executable).await, "journal_unavailable");
        fixture.sql("DROP TRIGGER stop_dispatch");
        let prepared_input = fixture.input.clone();
        let prepared = fixture.status(executable, false).await;
        assert_eq!(prepared["result"]["state"], "prepared");
        fixture.new_operation();
        fixture.server.expect_append(server::DraftReply::Disconnect);
        super::assert_uncertain(&fixture.save(executable).await, &fixture);
        let uncertain_input = fixture.input.clone();
        let original_rows = rows(&fixture);
        let replacement = std::net::TcpListener::bind("localhost:0").unwrap();
        replacement.set_nonblocking(true).unwrap();
        let mut config = fixture.configuration();
        config.accounts[0].alias = "renamed".into();
        config.accounts[0].server = "localhost".into();
        config.accounts[0].port = replacement.local_addr().unwrap().port();
        config.accounts[0].mailboxes = vec!["INBOX".into(), "New Drafts".into()].into();
        config.accounts[0].drafts_mailbox = Some("New Drafts".into());
        if fault == "from" {
            config.accounts[0].from_identities = vec!["replacement@example.test".into()];
        } else {
            config.accounts[0].retain_history = false;
        }
        for grant in &mut config.grants {
            if grant.name == "writer" || grant.name == "other-writer" {
                grant.mailboxes = vec!["New Drafts".into()].into();
                grant.historical_drafts = vec![mailctl::config::HistoricalDraftScope {
                    account_id: fixture.input["account_id"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap(),
                    account_generation: 1,
                    mailbox: "Drafts".into(),
                }];
            }
        }
        fixture.configure(&config);
        assert_eq!(rows(&fixture), original_rows);
        fixture.input = prepared_input;
        for reconcile in [false, true] {
            assert_eq!(
                fixture.status(executable, reconcile).await["result"],
                prepared["result"],
                "historical status remains authorized after {fault} removal"
            );
        }
        assert_error(
            &fixture.save(executable).await,
            if fault == "from" {
                "permission_denied"
            } else {
                "draft_mailbox_unavailable"
            },
        );
        assert_eq!(rows(&fixture), original_rows);
        fixture.input = uncertain_input;
        super::assert_uncertain(&fixture.save(executable).await, &fixture);
        super::assert_uncertain(&fixture.status(executable, false).await, &fixture);
        if fault == "routing" {
            let unknown = fixture.status(executable, true).await;
            super::assert_uncertain(&unknown, &fixture);
            assert_eq!(unknown["error"]["draft_operation"]["uid_validity"], 77);
            assert_eq!(rows(&fixture), original_rows);
        } else {
            // Revoking a sender prevents prepared dispatch, but does not erase
            // the retained route or forbid read-only proof of a past APPEND.
            fixture.server.expect_reconciliation();
            let verified = fixture.status(executable, true).await;
            assert_eq!(verified["result"]["state"], "duplicate");
            assert_appended_content(&fixture, &verified);
            let mut expected_rows = original_rows;
            for row in &mut expected_rows {
                if row[6] == SqlValue::Text("outcome_unknown".into()) {
                    row[6] = SqlValue::Text("duplicate".into());
                    row[7] = SqlValue::Integer(77);
                    row[8] = SqlValue::Integer(4);
                }
            }
            assert_eq!(rows(&fixture), expected_rows);
        }
        assert!(
            replacement
                .accept()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
            "historical work never connects to the replacement route"
        );
        assert_eq!(
            fixture.server.accepted(),
            if fault == "routing" { 2 } else { 3 }
        );
        assert_eq!(fixture.server.drafts().len(), 1);
        fixture.server.finish();
    }
}

async fn unusable_writer_preserves_status_and_provider_reads(executable: &str) {
    let mut fixture = Fixture::new(executable);
    let ordinary = super::read_only_message(&fixture, executable).await;
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let created = fixture.save(executable).await;
    assert_eq!(created["result"]["state"], "created");
    let writer = fixture.state().join(format!(
        "draft-{}.lock",
        fixture.input["account_id"].as_str().unwrap()
    ));
    fs::remove_file(&writer).unwrap();
    fs::create_dir(&writer).unwrap();
    assert_eq!(
        fixture.status(executable, false).await["result"],
        created["result"]
    );
    fixture.new_operation();
    assert_error(&fixture.save(executable).await, "journal_unavailable");
    let health = fixture
        .call(executable, "email_capabilities", json!({}))
        .await;
    assert_eq!(health["result"]["health"]["status"], "degraded");
    assert_eq!(health["result"]["health"]["draft_journal"], "available");
    assert_eq!(health["result"]["health"]["draft_creation"], "unavailable");
    assert!(
        fixture
            .call(executable, "email_list_accounts", json!({}))
            .await["result"]["accounts"]
            .as_array()
            .is_some_and(|accounts| !accounts.is_empty())
    );
    assert_eq!(
        super::read_only_message(&fixture, executable).await,
        ordinary
    );
    assert_eq!(fixture.server.accepted(), 7);
    assert_eq!(fixture.server.drafts().len(), 1);
    assert_read_only_health(&fixture, executable).await;
    fixture.server.finish();
}

async fn upgrade_verification_refuses_unknown_history_without_dispatch(executable: &str) {
    for fault in ["encoder", "schema"] {
        let mut fixture = Fixture::new(executable);
        fixture.sql("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic dispatch failure'); END;");
        fixture.server.expect_draft_target(77);
        assert_error(&fixture.save(executable).await, "journal_unavailable");
        fixture.sql("DROP TRIGGER stop_dispatch");
        let expected = if fault == "encoder" {
            let database =
                rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
            let original: String = database
                .query_row("SELECT reconstruction FROM draft_operations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let mut frozen: Value = serde_json::from_str(&original).unwrap();
            frozen["encoder"] = json!("unsupported encoder format");
            database
                .execute(
                    "UPDATE draft_operations SET reconstruction = ?1",
                    [frozen.to_string()],
                )
                .unwrap();
            "unsupported_capability"
        } else {
            fixture.sql("ALTER TABLE draft_operations ADD COLUMN incompatible TEXT");
            "journal_unavailable"
        };
        let before = rows(&fixture);
        assert_error(&fixture.admin(executable, &["state", "verify"]), expected);
        assert_error(&fixture.save(executable).await, expected);
        assert_eq!(rows(&fixture), before);
        assert_eq!(fixture.server.accepted(), 1);
        assert!(fixture.server.drafts().is_empty());
        fixture.server.finish();
    }
}

async fn corrupt_rows_suspend_creation_after_repair(executable: &str) {
    for offline_detection in [false, true] {
        let mut fixture = Fixture::new(executable);
        fixture
            .server
            .expect_append(server::DraftReply::Created(true));
        let created = fixture.save(executable).await;
        assert_eq!(created["result"]["state"], "created");
        let frozen = reconstruction(&fixture);
        fixture.sql("UPDATE draft_operations SET reconstruction = '{'");
        let detected = if offline_detection {
            fixture.admin(executable, &["state", "verify"])
        } else {
            fixture.status(executable, false).await
        };
        assert_error(&detected, "journal_unavailable");
        assert_eq!(
            fs::read(fixture.state().join("drafts.suspended")).unwrap(),
            b"suspended"
        );
        rusqlite::Connection::open(fixture.state().join("drafts.sqlite"))
            .unwrap()
            .execute(
                "UPDATE draft_operations SET reconstruction = ?1",
                [frozen.to_string()],
            )
            .unwrap();
        // Repairing a row is not proof of complete history. The detected loss
        // remains fenced through fresh processes while known status survives.
        assert_eq!(
            fixture.status(executable, false).await["result"],
            created["result"]
        );
        fixture.new_operation();
        assert_error(&fixture.save(executable).await, "journal_unavailable");
        assert_error(
            &fixture.status(executable, false).await,
            "journal_unavailable",
        );
        assert_read_only_health(&fixture, executable).await;
        assert_eq!(fixture.server.accepted(), 1);
        assert_eq!(fixture.server.drafts().len(), 1);
        fixture.server.finish();
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_corrupt_rows_keep_creation_suspended_after_repair() {
    corrupt_rows_suspend_creation_after_repair(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_corrupt_rows_keep_creation_suspended_after_repair() {
    corrupt_rows_suspend_creation_after_repair(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_snapshots_preserve_all_draft_outcomes_and_fence_post_backup_history() {
    snapshots_preserve_all_outcomes_and_suspend_missing_history(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_snapshots_preserve_all_draft_outcomes_and_fence_post_backup_history() {
    snapshots_preserve_all_outcomes_and_suspend_missing_history(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_journal_loss_stays_suspended_after_file_replacement() {
    journal_loss_stays_suspended_after_file_replacement(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_journal_loss_stays_suspended_after_file_replacement() {
    journal_loss_stays_suspended_after_file_replacement(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_unusable_writer_preserves_status_and_provider_reads() {
    unusable_writer_preserves_status_and_provider_reads(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_unusable_writer_preserves_status_and_provider_reads() {
    unusable_writer_preserves_status_and_provider_reads(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_upgrade_verification_refuses_unknown_history_without_dispatch() {
    upgrade_verification_refuses_unknown_history_without_dispatch(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_upgrade_verification_refuses_unknown_history_without_dispatch() {
    upgrade_verification_refuses_unknown_history_without_dispatch(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_previous_encoder_prepared_retry_preserves_frozen_facts() {
    previous_encoder_prepared_retry_preserves_frozen_facts(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_previous_encoder_prepared_retry_preserves_frozen_facts() {
    previous_encoder_prepared_retry_preserves_frozen_facts(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_historical_operations_keep_original_targets_and_permissions() {
    historical_operations_keep_original_targets_and_permissions(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_historical_operations_keep_original_targets_and_permissions() {
    historical_operations_keep_original_targets_and_permissions(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_revoked_from_and_unretained_routes_preserve_history_without_dispatch() {
    revoked_from_and_unretained_routes_preserve_history_without_dispatch(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_revoked_from_and_unretained_routes_preserve_history_without_dispatch() {
    revoked_from_and_unretained_routes_preserve_history_without_dispatch(support::MAILCTL_MCP)
        .await;
}
