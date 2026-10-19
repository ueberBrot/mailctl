//! Public response limits and actual SQLite contention precede side effects.
use super::*;

async fn authentication_and_sqlite_contention(executable: &str) {
    let mut fixture = Fixture::new(executable);
    fixture.server.reject_authentication(false);
    assert_eq!(
        fixture.save(executable).await["error"]["code"],
        "authentication_failed"
    );
    assert_eq!(
        fixture.status(executable, false).await["error"]["code"],
        "operation_not_found"
    );
    assert_eq!(fixture.server.interrupted(), 0);
    let database = rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
    database.execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE; UPDATE draft_operations SET state = state;").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        fixture.save(executable).await["error"]["code"],
        "rate_limited"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "SQLite contention has a finite initialization deadline"
    );
    assert_eq!(
        fixture.server.accepted(),
        1,
        "locked history never reaches the provider"
    );
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    assert_eq!(
        fixture.status(executable, false).await["error"]["code"],
        "operation_not_found"
    );
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let created = fixture.save(executable).await;
    assert_eq!(created["result"]["state"], "created");
    assert_appended_content(&fixture, &created);
    assert_eq!(fixture.server.interrupted(), 1);
    fixture.server.finish();
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_authentication_and_sqlite_lock_failures_precede_dispatch() {
    authentication_and_sqlite_contention(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_authentication_and_sqlite_lock_failures_precede_dispatch() {
    authentication_and_sqlite_contention(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_response_budget_admission_and_replay_preserve_side_effects() {
    let mut fixture = Fixture::new(support::MAILCTL);
    let mailbox = "x".repeat(400);
    let mut config = fixture.configuration();
    config.accounts[0].mailboxes = vec!["INBOX".into(), mailbox.clone()].into();
    config.accounts[0].drafts_mailbox = Some(mailbox.clone());
    for grant in &mut config.grants {
        if grant.name != "default" {
            grant.mailboxes = vec![mailbox.clone()].into();
        }
        grant.limits.envelope_bytes = 1024;
    }
    config.limits.envelope_bytes = 1024;
    fixture.configure(&config);
    fixture.input["account_generation"] = json!(2);
    fixture.input["mailbox"] = json!(mailbox);
    fixture.server.expect_named_draft_target(&mailbox, 77);
    assert_eq!(
        fixture.save(support::MAILCTL).await["error"]["code"],
        "response_too_large"
    );
    assert_eq!(
        fixture.status(support::MAILCTL, false).await["error"]["code"],
        "operation_not_found"
    );
    assert_eq!(fixture.server.interrupted(), 0);
    for grant in &mut config.grants {
        grant.limits.envelope_bytes = 4096;
    }
    config.limits.envelope_bytes = 4096;
    fixture.configure(&config);
    fixture
        .server
        .expect_named_append(&mailbox, server::DraftReply::Created(true));
    let created = fixture.save(support::MAILCTL).await;
    assert_eq!(created["result"]["state"], "created");
    for grant in &mut config.grants {
        grant.limits.envelope_bytes = 1024;
    }
    config.limits.envelope_bytes = 1024;
    fixture.configure(&config);
    let bounded = fixture.save(support::MAILCTL).await;
    assert_eq!(bounded["error"]["code"], "outcome_unknown");
    assert_eq!(bounded["error"]["retryable"], false);
    assert_eq!(
        bounded["error"]["draft_operation"]["identity"]["operation_id"],
        fixture.input["operation_id"]
    );
    for grant in &mut config.grants {
        grant.limits.envelope_bytes = 4096;
    }
    config.limits.envelope_bytes = 4096;
    fixture.configure(&config);
    assert_eq!(
        fixture.save(support::MAILCTL).await["result"],
        created["result"]
    );
    assert_eq!(fixture.server.interrupted(), 1);
    assert_eq!(fixture.server.accepted(), 2);
    fixture.server.finish();
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_inadmissible_response_budget_refuses_startup_before_drafts() {
    let mut fixture = Fixture::new(support::MAILCTL_MCP);
    let mut config = fixture.configuration();
    config.limits.envelope_bytes = 1024;
    for grant in &mut config.grants {
        grant.limits.envelope_bytes = 1024;
    }
    fixture.configure(&config);
    let mut command = fixture.command(support::MAILCTL_MCP);
    command.args(["--grant", "writer", "--use-configured-grant"]);
    let refused = run_bounded(command);
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8(refused.stderr).unwrap().contains("setup"));
    assert_eq!(fixture.server.accepted(), 0);
    config.limits.envelope_bytes = 4096;
    for grant in &mut config.grants {
        grant.limits.envelope_bytes = 4096;
    }
    fixture.configure(&config);
    assert_eq!(
        fixture.status(support::MAILCTL_MCP, false).await["error"]["code"],
        "operation_not_found"
    );
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let created = fixture.save(support::MAILCTL_MCP).await;
    assert_eq!(created["result"]["state"], "created");
    assert_appended_content(&fixture, &created);
    fixture.server.finish();
}
