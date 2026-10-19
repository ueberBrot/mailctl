//! Ownership spans real APPEND, process death, and explicit reconciliation.
use super::*;

async fn start_request(
    fixture: &Fixture,
    executable: &str,
    tool: &str,
    input: Value,
    grant: &str,
) -> tokio::process::Child {
    use std::process::Stdio;
    #[cfg(feature = "cli")]
    if executable == support::MAILCTL {
        let mut command = tokio::process::Command::from(fixture.cli_command(tool, &input, grant));
        #[cfg(windows)]
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE);
        return command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
    }
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut command = fixture.command(executable);
    command.args(["--grant", grant, "--use-configured-grant"]);
    let mut child = tokio::process::Command::from(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let initialization = json!({"jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
        "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"packaged-draft-fixture", "version":"1"}
    }});
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{initialization}\n").as_bytes())
        .await
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(
        serde_json::from_str::<Value>(&line)
            .unwrap()
            .get("result")
            .is_some()
    );
    child.stdout = Some(stdout.into_inner());
    let initialized = json!({"jsonrpc":"2.0", "method":"notifications/initialized"});
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":tool, "arguments":input}});
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{initialized}\n{request}\n").as_bytes())
        .await
        .unwrap();
    child
}

#[cfg(feature = "cli")]
fn cancel_cli(child: &tokio::process::Child) {
    #[cfg(unix)]
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    #[cfg(windows)]
    native_support::cancel(child.id().unwrap());
}

#[cfg(feature = "mcp")]
async fn response(
    stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    id: u64,
) -> Value {
    let response = next_response(stdout).await;
    assert_eq!(response["id"], id, "unexpected MCP response: {response}");
    response
}

#[cfg(feature = "mcp")]
async fn next_response(stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>) -> Value {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line))
        .await
        .expect("MCP response deadline")
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

#[cfg(all(feature = "cli", feature = "mcp"))]
fn assert_owner_held(fixture: &Fixture, state: &str) {
    let writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.state().join(format!(
            "draft-{}.lock",
            fixture.input["account_id"].as_str().unwrap()
        )))
        .unwrap();
    assert!(matches!(
        writer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    let database = rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
    let operation = uuid::Uuid::parse_str(fixture.input["operation_id"].as_str().unwrap()).unwrap();
    let retained: String = database
        .query_row(
            "SELECT state FROM draft_operations WHERE operation_id = ?1",
            [operation.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, state);
}

async fn unread_creation_response(executable: &str) {
    use rusqlite::OptionalExtension;

    let mut fixture = Fixture::new(executable);
    let acknowledged = fixture.server.expect_observed_creation();
    let mut owner = start_request(
        &fixture,
        executable,
        "email_save_draft",
        fixture.input.clone(),
        "writer",
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), acknowledged)
        .await
        .expect("provider flushes tagged APPEND ACK")
        .unwrap();
    let database = rusqlite::Connection::open_with_flags(
        fixture.state().join("drafts.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let operation = uuid::Uuid::parse_str(fixture.input["operation_id"].as_str().unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state: Option<String> = database
                .query_row(
                    "SELECT state FROM draft_operations WHERE operation_id = ?1",
                    [operation.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();
            if state.as_deref() == Some("created") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("independent reader observes committed creation after provider ACK");
    drop(database);

    // No read/poll/drain of the save response: only MCP initialization was
    // consumed. The receipt may have reached the OS pipe; killing the process
    // and discarding that unread pipe models caller response loss after commit,
    // not loss of the provider ACK or a consumed-and-discarded full receipt.
    owner.kill().await.unwrap();
    drop(owner.stdout.take());
    drop(owner.stdin.take());
    tokio::time::timeout(Duration::from_secs(5), owner.wait())
        .await
        .expect("original caller exits without reading its receipt")
        .unwrap();
    let retained = history::rows(&fixture);
    assert_eq!(retained.len(), 1);
    let status = fixture.status(executable, false).await;
    assert_eq!(status["result"]["state"], "created");
    assert_eq!(status["result"]["dispatched"], true);
    assert!(status["result"]["message_reference"].is_string());
    assert_appended_content(&fixture, &status);
    assert_eq!(fixture.save(executable).await["result"], status["result"]);
    assert_eq!(
        fixture.status(executable, true).await["result"],
        status["result"]
    );
    let mut conflict = fixture.input.clone();
    conflict["draft"]["body"] = json!("Conflicting input after unread receipt");
    assert_eq!(
        fixture.call(executable, "email_save_draft", conflict).await["error"]["code"],
        "operation_conflict"
    );
    assert_eq!(history::rows(&fixture), retained);
    assert_eq!(fixture.server.accepted(), 1);
    assert_eq!(fixture.server.interrupted(), 1);
    fixture.server.finish();
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_unread_first_creation_response_replays_committed_receipt() {
    unread_creation_response(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_unread_first_creation_response_replays_committed_receipt() {
    unread_creation_response(support::MAILCTL_MCP).await;
}

async fn interrupted_creation(executable: &str) {
    for crash in [true, false] {
        let mut fixture = Fixture::new(executable);
        fixture
            .server
            .expect_append(server::DraftReply::Hold(Default::default()));
        let mut owner = start_request(
            &fixture,
            executable,
            "email_save_draft",
            fixture.input.clone(),
            "writer",
        )
        .await;
        fixture.appended(1).await;
        assert_eq!(
            fixture.status(executable, false).await["error"]["code"],
            "operation_in_progress"
        );
        assert_eq!(
            fixture.save(executable).await["error"]["code"],
            "operation_in_progress"
        );
        if crash {
            owner.kill().await.unwrap();
        } else {
            #[cfg(feature = "cli")]
            if executable == support::MAILCTL {
                cancel_cli(&owner);
            }
            // MCP EOF must release ownership and preserve possible dispatch.
            drop(owner.stdin.take());
        }
        tokio::time::timeout(Duration::from_secs(5), owner.wait())
            .await
            .expect("interrupted writer exits")
            .unwrap();
        assert_uncertain(&fixture.save(executable).await, &fixture);
        assert_uncertain(&fixture.status(executable, false).await, &fixture);
        fixture.server.expect_reconciliation();
        let verified = fixture.status(executable, true).await;
        assert_eq!(verified["result"]["state"], "duplicate");
        assert_appended_content(&fixture, &verified);
        assert_eq!(fixture.server.interrupted(), 1);
        assert_eq!(fixture.server.accepted(), 2);
        fixture.server.finish();
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_crash_and_cancellation_release_real_append_ownership() {
    interrupted_creation(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_crash_and_eof_release_real_append_ownership() {
    interrupted_creation(support::MAILCTL_MCP).await;
}

async fn interrupted_reconciliation(executable: &str) {
    for cancel in [false, true] {
        let mut fixture = Fixture::new(executable);
        fixture.server.expect_append(server::DraftReply::Disconnect);
        assert_uncertain(&fixture.save(executable).await, &fixture);
        let mut config = fixture.configuration();
        config.limits.operation_seconds = 2;
        config.limits.connection_seconds = 2;
        for grant in &mut config.grants {
            grant.limits.operation_seconds = 2;
            grant.limits.connection_seconds = 2;
        }
        fixture.configure(&config);
        fixture.server.expect_stalled_reconciliation();
        if cancel {
            let mut owner = start_request(
                &fixture,
                executable,
                "email_draft_status",
                fixture.status_input(true),
                "writer",
            )
            .await;
            tokio::time::timeout(Duration::from_secs(3), async {
                while fixture.server.stalled_reconciliations() == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("reconciliation reaches provider search");
            #[cfg(feature = "cli")]
            if executable == support::MAILCTL {
                cancel_cli(&owner);
            }
            drop(owner.stdin.take());
            let output = tokio::time::timeout(Duration::from_secs(5), owner.wait_with_output())
                .await
                .expect("reconciliation cancellation exits")
                .unwrap();
            #[cfg(feature = "cli")]
            if executable == support::MAILCTL {
                assert_eq!(output.status.code(), Some(7));
                assert_uncertain(&envelope(&output), &fixture);
            }
            #[cfg(not(feature = "cli"))]
            let _ = output;
        } else {
            assert_uncertain(&fixture.status(executable, true).await, &fixture);
        }
        assert_eq!(fixture.server.stalled_reconciliations(), 1);
        assert_uncertain(&fixture.save(executable).await, &fixture);
        assert_uncertain(&fixture.status(executable, false).await, &fixture);
        fixture.server.expect_reconciliation();
        assert_eq!(
            fixture.status(executable, true).await["result"]["state"],
            "duplicate"
        );
        assert_eq!(fixture.server.interrupted(), 1);
        fixture.server.finish();
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cli_reconciliation_deadline_retains_original_uncertainty() {
    interrupted_reconciliation(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_reconciliation_deadline_retains_original_uncertainty() {
    interrupted_reconciliation(support::MAILCTL_MCP).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn mcp_request_cancellation_releases_append_and_reconciliation_without_ending_session() {
    use tokio::io::{AsyncWriteExt, BufReader};

    for reconcile in [false, true] {
        let mut fixture = Fixture::new(support::MAILCTL_MCP);
        let (tool, input) = if reconcile {
            fixture.server.expect_append(server::DraftReply::Disconnect);
            assert_uncertain(&fixture.save(support::MAILCTL_MCP).await, &fixture);
            fixture.server.expect_stalled_reconciliation();
            ("email_draft_status", fixture.status_input(true))
        } else {
            fixture
                .server
                .expect_append(server::DraftReply::Hold(Default::default()));
            ("email_save_draft", fixture.input.clone())
        };
        let mut child = start_request(&fixture, support::MAILCTL_MCP, tool, input, "writer").await;
        if reconcile {
            tokio::time::timeout(Duration::from_secs(5), async {
                while fixture.server.stalled_reconciliations() == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("MCP reconciliation reaches provider");
        } else {
            fixture.appended(1).await;
        }
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let cancel = json!({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId":1, "reason":"synthetic cancellation"}});
        let ping = json!({"jsonrpc":"2.0", "id":2, "method":"ping"});
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{cancel}\n{ping}\n").as_bytes())
            .await
            .unwrap();
        assert!(response(&mut stdout, 2).await.get("result").is_some());
        let writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.state().join(format!(
                "draft-{}.lock",
                fixture.input["account_id"].as_str().unwrap()
            )))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match writer.try_lock() {
                    Ok(()) => {
                        writer.unlock().unwrap();
                        break;
                    }
                    Err(std::fs::TryLockError::WouldBlock) => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(error) => panic!("writer lock: {error}"),
                }
            }
        })
        .await
        .expect("request cancellation releases draft ownership promptly");
        for (id, tool, input) in [
            (3, "email_draft_status", fixture.status_input(false)),
            (4, "email_save_draft", fixture.input.clone()),
        ] {
            let request = json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{"name":tool, "arguments":input}});
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
            let retained = response(&mut stdout, id).await;
            let retained = support::assert_mcp_envelope(
                serde_json::from_value(retained["result"].clone()).unwrap(),
            );
            assert_uncertain(&retained, &fixture);
        }
        fixture.server.expect_reconciliation();
        let request = json!({"jsonrpc":"2.0", "id":5, "method":"tools/call", "params":{"name":"email_draft_status", "arguments":fixture.status_input(true)}});
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let verified = response(&mut stdout, 5).await;
        let verified = support::assert_mcp_envelope(
            serde_json::from_value(verified["result"].clone()).unwrap(),
        );
        assert_eq!(verified["result"]["state"], "duplicate");
        assert_appended_content(&fixture, &verified);
        drop(child.stdin.take());
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fixture.server.interrupted(), 1);
        assert_eq!(fixture.server.accepted(), if reconcile { 3 } else { 2 });
        fixture.server.finish();
    }
}

#[cfg(all(feature = "cli", feature = "mcp"))]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cross_same_id_and_conflicting_inputs_share_one_append_across_grants() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncWriteExt, BufReader};
    let mut fixture = Fixture::new(support::MAILCTL);
    // Leave transport capacity for the ping after two pending draft calls.
    let mut config = fixture.configuration();
    config.limits.envelope_bytes = 64 * 1024;
    for grant in &mut config.grants {
        grant.limits.envelope_bytes = 64 * 1024;
    }
    fixture.configure(&config);
    let release = Arc::new(AtomicUsize::new(0));
    fixture
        .server
        .expect_append(server::DraftReply::Hold(release.clone()));
    let owner_command = fixture.cli_command("email_save_draft", &fixture.input, "writer");
    let owner = tokio::task::spawn_blocking(move || run_bounded(owner_command));
    fixture.appended(1).await;
    let caller = Caller::start(&fixture, support::MAILCTL_MCP, "other-writer", false).await;
    assert_eq!(
        caller
            .call(&fixture, "email_draft_status", fixture.status_input(false))
            .await["error"]["code"],
        "operation_in_progress"
    );
    let mut conflict = fixture.input.clone();
    conflict["draft"]["body"] = json!("Conflicting concurrent input");
    // Both contenders must finish a bounded ownership wait while APPEND is
    // still held. A sequential replay cannot satisfy these public responses.
    let (same, different) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            caller.call(&fixture, "email_save_draft", fixture.input.clone()),
            caller.call(&fixture, "email_save_draft", conflict.clone()),
        )
    })
    .await
    .expect("both saves have bounded writer waits");
    for blocked in [same, different] {
        assert_eq!(blocked["error"]["code"], "operation_in_progress");
    }
    assert_owner_held(&fixture, "in_flight");

    // Submit another pair before release and keep their original successful
    // replay/conflict assertions. FIFO STDIO followed by a ping response proves
    // both request frames reached the server while durable ownership remains.
    let mut pending = start_request(
        &fixture,
        support::MAILCTL_MCP,
        "email_save_draft",
        fixture.input.clone(),
        "other-writer",
    )
    .await;
    let different = json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"email_save_draft", "arguments":conflict}});
    let ping = json!({"jsonrpc":"2.0", "id":3, "method":"ping"});
    pending
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{different}\n{ping}\n").as_bytes())
        .await
        .unwrap();
    let mut stdout = BufReader::new(pending.stdout.take().unwrap());
    let pong = response(&mut stdout, 3).await;
    assert!(pong.get("result").is_some(), "{pong}");
    assert_owner_held(&fixture, "in_flight");
    assert!(!owner.is_finished());
    release.store(1, Ordering::SeqCst);
    let mut results = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let received = next_response(&mut stdout).await;
        let id = received["id"].as_u64().unwrap();
        let value = support::assert_mcp_envelope(
            serde_json::from_value(received["result"].clone()).unwrap(),
        );
        assert!(results.insert(id, value).is_none());
    }
    let same = results.remove(&1).unwrap();
    let different = results.remove(&2).unwrap();
    drop(pending.stdin.take());
    tokio::time::timeout(Duration::from_secs(5), pending.wait())
        .await
        .unwrap()
        .unwrap();
    let output = owner.await.unwrap();
    support::assert_success(&output);
    let created = envelope(&output);
    assert_eq!(same["result"], created["result"]);
    assert_eq!(different["error"]["code"], "operation_conflict");
    assert_appended_content(&fixture, &created);
    assert_eq!(
        caller
            .call(&fixture, "email_draft_status", fixture.status_input(true))
            .await["result"],
        created["result"]
    );
    caller.finish().await;
    assert_eq!(
        fixture.save(support::MAILCTL).await["result"],
        created["result"]
    );
    assert_eq!(fixture.server.accepted(), 1);
    assert_eq!(fixture.server.interrupted(), 1);
    fixture.server.finish();
}

#[cfg(all(feature = "cli", feature = "mcp"))]
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "requires an explicitly disposable Windows identity and native credentials"
)]
async fn cross_crashed_owner_and_concurrent_reconciliation_never_append_again() {
    let mut fixture = Fixture::new(support::MAILCTL);
    fixture
        .server
        .expect_append(server::DraftReply::Hold(Default::default()));
    let mut owner = start_request(
        &fixture,
        support::MAILCTL,
        "email_save_draft",
        fixture.input.clone(),
        "writer",
    )
    .await;
    fixture.appended(1).await;
    let caller = Caller::start(&fixture, support::MAILCTL_MCP, "other-writer", false).await;
    assert_eq!(
        caller
            .call(&fixture, "email_draft_status", fixture.status_input(true))
            .await["error"]["code"],
        "operation_in_progress"
    );
    owner.kill().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), owner.wait())
        .await
        .unwrap()
        .unwrap();
    assert_uncertain(
        &caller
            .call(&fixture, "email_save_draft", fixture.input.clone())
            .await,
        &fixture,
    );
    assert_uncertain(&fixture.status(support::MAILCTL, false).await, &fixture);
    let (search, release) = fixture.server.expect_held_reconciliation();
    let command = fixture.cli_command("email_draft_status", &fixture.status_input(true), "writer");
    let cli = tokio::task::spawn_blocking(move || run_bounded(command));
    tokio::time::timeout(Duration::from_secs(5), search)
        .await
        .expect("owner reconciliation reaches provider SEARCH")
        .unwrap();
    assert_owner_held(&fixture, "outcome_unknown");
    let blocked = tokio::time::timeout(
        Duration::from_secs(3),
        caller.call(&fixture, "email_draft_status", fixture.status_input(true)),
    )
    .await
    .expect("rival reconciliation has a bounded writer wait");
    assert_eq!(blocked["error"]["code"], "rate_limited");
    assert_owner_held(&fixture, "outcome_unknown");
    assert!(!cli.is_finished());
    release.send(()).unwrap();
    let cli = cli.await.unwrap();
    support::assert_success(&cli);
    let verified = envelope(&cli);
    assert_eq!(verified["result"]["state"], "duplicate");
    let mcp = caller
        .call(&fixture, "email_draft_status", fixture.status_input(true))
        .await;
    assert_eq!(mcp["result"], verified["result"]);
    caller.finish().await;
    assert_appended_content(&fixture, &verified);
    assert_eq!(
        fixture.save(support::MAILCTL).await["result"],
        verified["result"]
    );
    assert_eq!(fixture.server.accepted(), 2);
    assert_eq!(fixture.server.interrupted(), 1);
    fixture.server.finish();
}
