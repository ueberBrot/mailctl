#![cfg(all(feature = "cli", feature = "mcp"))]
#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[path = "../../imap_support/process.rs"]
mod server;
#[path = "../../support/mod.rs"]
mod support;
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use support::{Installation, assert_success, envelope, run_bounded};

#[tokio::test]
async fn independent_cli_and_mcp_create_once_and_inspect_without_provider_work() {
    let mut f = DraftFixture::new();
    f.input["draft"]["subject"] = json!("Synthetic");
    f.input["draft"]["bcc"] = json!([{"address":"hidden@example.test", "name":"Hidden"}]);
    std::fs::write(
        &f.composition,
        serde_json::to_vec(&f.input["draft"]).unwrap(),
    )
    .unwrap();
    f.server.expect_append(server::DraftReply::Created(false));
    let output = run_bounded(f.save());
    assert_success(&output);
    let prepared = envelope(&output)["result"].clone();
    assert_eq!(prepared["state"], "created_reference_unavailable");
    assert_eq!(prepared["dispatched"], true);
    let provider_connections = f.server.accepted();
    assert_eq!(provider_connections, 1);

    let mut command = f.installation.mcp();
    command
        .args(["--grant", "writer", "--use-configured-grant"])
        .env("MAILCTL_FIXTURE_CA", &f.server.certificate);
    let client =
        ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
            .await
            .unwrap();
    let tools = client.list_all_tools().await.unwrap();
    for name in ["email_save_draft", "email_draft_status"] {
        assert!(tools.iter().any(|t| t.name == name));
    }
    assert!(!tools.iter().any(|t| t.name == "email_get_message"));
    let result = call(&client, "email_save_draft", f.input.clone()).await;
    assert_eq!(result["result"], prepared);
    let lookup = f.status();
    let id = f.input["account_id"].as_str().unwrap();
    let lock_path = f
        .installation
        .config()
        .parent()
        .unwrap()
        .join("state")
        .join(format!("draft-{id}.lock"));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lock.lock().unwrap();
    assert_eq!(
        call(&client, "email_draft_status", lookup.clone()).await["result"],
        prepared
    );
    drop(lock);
    let mut conflict = f.input.clone();
    conflict["draft"]["body"] = json!("Changed");
    assert_eq!(
        call(&client, "email_save_draft", conflict).await["error"]["code"],
        "operation_conflict"
    );
    // A second executable can save an independent operation while MCP remains alive.
    f.input["operation_id"] = json!(uuid::Uuid::new_v4());
    f.server.expect_append(server::DraftReply::Created(false));
    let command = f.save();
    let concurrent = f.input.clone();
    let cli = tokio::task::spawn_blocking(move || run_bounded(command));
    let (cli, mcp) = tokio::join!(cli, call(&client, "email_save_draft", concurrent));
    let cli = cli.unwrap();
    assert_success(&cli);
    assert_eq!(envelope(&cli)["result"], mcp["result"]);
    client.cancel().await.unwrap();
    // Normal MCP startup narrows a draft-capable grant to read-only.
    let mut command = f.installation.mcp();
    command.args(["--grant", "writer"]);
    let client =
        ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
            .await
            .unwrap();
    assert!(
        !client
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|t| t.name == "email_save_draft" || t.name == "email_draft_status")
    );
    assert!(
        client
            .call_tool(
                CallToolRequestParams::new("email_draft_status")
                    .with_arguments(lookup.as_object().unwrap().clone())
            )
            .await
            .is_err()
    );
    client.cancel().await.unwrap();
    assert_eq!(f.server.accepted(), provider_connections + 1);
    f.server.finish();
}
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    input: Value,
) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let response = client
            .call_tool(
                CallToolRequestParams::new(name).with_arguments(input.as_object().unwrap().clone()),
            )
            .await
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let structured = response.structured_content.unwrap();
        assert_eq!(response.is_error, Some(structured.get("error").is_some()));
        assert_eq!(
            serde_json::from_str::<Value>(&response.content[0].as_text().unwrap().text).unwrap(),
            structured
        );
        structured
    })
    .await
    .unwrap()
}

struct DraftFixture {
    installation: Installation,
    server: server::ImapServer,
    input: Value,
    composition: std::path::PathBuf,
}
impl DraftFixture {
    fn new() -> Self {
        let installation = Installation::two_accounts();
        let server = server::ImapServer::new(installation.config().parent().unwrap());
        let mut config = mailctl::config::Config::parse(
            &std::fs::read_to_string(installation.config()).unwrap(),
        )
        .unwrap();
        config.accounts[0].server = "127.0.0.1".into();
        config.accounts[0].port = server.port;
        config.accounts[0].from_identities = vec!["work@example.test".into()];
        config.limits.initialization_seconds = 1;
        for grant in &mut config.grants {
            grant.limits.initialization_seconds = 1;
        }
        let mut other = config
            .grants
            .iter()
            .find(|g| g.name == "writer")
            .unwrap()
            .clone();
        other.name = "other-writer".into();
        config.grants.push(other);
        std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
        let mut setup = installation.cli();
        setup.args(["--json", "setup"]);
        assert_success(&run_bounded(setup));
        let mut list = installation.cli();
        list.args(["--json", "account", "list"]);
        let output = run_bounded(list);
        assert_success(&output);
        let accounts = envelope(&output);
        let input = json!({"mailbox":"Drafts", "account_id":accounts["result"]["accounts"][0]["account_id"],
            "account_generation":1, "operation_id":uuid::Uuid::new_v4(), "draft":{"body":"Synthetic body"}});
        let composition = installation.config().with_file_name("input.json");
        std::fs::write(&composition, serde_json::to_vec(&input["draft"]).unwrap()).unwrap();
        Self {
            installation,
            server,
            input,
            composition,
        }
    }
    fn save(&self) -> std::process::Command {
        let mut command = self.installation.cli();
        command
            .env("MAILCTL_FIXTURE_CA", &self.server.certificate)
            .args([
                "--json",
                "--grant",
                "writer",
                "draft",
                "save",
                "--mailbox",
                "Drafts",
                "--account-id",
                self.input["account_id"].as_str().unwrap(),
                "--account-generation",
                "1",
                "--operation-id",
                self.input["operation_id"].as_str().unwrap(),
                "--input",
            ])
            .arg(&self.composition);
        command
    }
    async fn mcp(&self) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
        let mut command = self.installation.mcp();
        command
            .env("MAILCTL_FIXTURE_CA", &self.server.certificate)
            .args(["--grant", "other-writer", "--use-configured-grant"]);
        ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
            .await
            .unwrap()
    }
    fn status(&self) -> Value {
        let mut status = self.input.clone();
        status.as_object_mut().unwrap().remove("draft");
        status
    }
    async fn appended(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.server.interrupted() == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn startup_during_live_append_keeps_pending_and_owner_death_releases_lock() {
    let mut f = DraftFixture::new();
    f.server
        .expect_append(server::DraftReply::Hold(Default::default()));
    let mut owner = f
        .save()
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    f.appended().await;
    let client = f.mcp().await;
    let pending = call(&client, "email_draft_status", f.status()).await;
    assert_eq!(pending["error"]["code"], "operation_in_progress");
    let input = f.input.clone();
    let waiting = call(&client, "email_save_draft", input).await;
    assert_eq!(waiting["error"]["code"], "operation_in_progress");
    assert_eq!(f.server.interrupted(), 1);
    // Killing the owner skips all Rust destructors. The OS must release its lock.
    owner.kill().unwrap();
    owner.wait().unwrap();
    let recovered = call(&client, "email_save_draft", f.input.clone()).await;
    assert_eq!(recovered["error"]["code"], "outcome_unknown");
    assert_eq!(recovered["error"]["retryable"], false);
    assert_eq!(
        recovered["error"]["draft_operation"]["identity"]["operation_id"],
        f.input["operation_id"]
    );
    let replay = run_bounded(f.save());
    assert_eq!(replay.status.code(), Some(7));
    assert_eq!(envelope(&replay)["error"]["code"], "outcome_unknown");
    assert_eq!(
        call(&client, "email_draft_status", f.status()).await["error"]["code"],
        "outcome_unknown"
    );
    client.cancel().await.unwrap();
    assert_eq!(f.server.accepted(), 1);
    f.server.finish();
}

#[tokio::test]
async fn concurrent_cli_and_mcp_saves_with_different_grants_share_one_creation() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let mut f = DraftFixture::new();
    let release = Arc::new(AtomicUsize::new(0));
    f.server
        .expect_append(server::DraftReply::Hold(release.clone()));
    let command = f.save();
    let owner = tokio::task::spawn_blocking(move || run_bounded(command));
    f.appended().await;
    let client = f.mcp().await;
    let retry = call(&client, "email_save_draft", f.input.clone());
    let mut conflict = f.input.clone();
    conflict["draft"]["body"] = json!("Different");
    let conflicting = call(&client, "email_save_draft", conflict);
    let unblock = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        release.store(1, Ordering::SeqCst);
    };
    let (saved, conflict, _) = tokio::join!(retry, conflicting, unblock);
    assert_eq!(conflict["error"]["code"], "operation_conflict");
    let output = owner.await.unwrap();
    assert_success(&output);
    assert_eq!(saved["result"], envelope(&output)["result"]);
    let mut conflict = f.input.clone();
    conflict["draft"]["body"] = json!("Different");
    assert_eq!(
        call(&client, "email_save_draft", conflict).await["error"]["code"],
        "operation_conflict"
    );
    assert_eq!(f.server.interrupted(), 1);
    client.cancel().await.unwrap();
    f.server.finish();
}

#[tokio::test]
async fn lost_acknowledgement_and_rejection_replay_across_processes() {
    for reply in [
        server::DraftReply::Disconnect,
        server::DraftReply::Rejected,
        server::DraftReply::Created(true),
    ] {
        let mut f = DraftFixture::new();
        f.server.expect_append(reply);
        let first = run_bounded(f.save());
        let expected = envelope(&first);
        let client = f.mcp().await;
        let replay = call(&client, "email_save_draft", f.input.clone()).await;
        assert_eq!(expected["result"], replay["result"]);
        assert_eq!(expected["error"], replay["error"]);
        let status = call(&client, "email_draft_status", f.status()).await;
        assert_eq!(status["result"], replay["result"]);
        assert_eq!(status["error"], replay["error"]);
        assert_eq!(f.server.accepted(), 1);
        assert_eq!(f.server.interrupted(), 1);
        client.cancel().await.unwrap();
        f.server.finish();
    }
}

#[tokio::test]
async fn mcp_eof_during_append_preserves_uncertainty_and_releases_writer() {
    use std::{
        io::{BufRead, BufReader, Write},
        process::Stdio,
    };
    let mut f = DraftFixture::new();
    f.server
        .expect_append(server::DraftReply::Hold(Default::default()));
    let mut child = f
        .installation
        .mcp()
        .env("MAILCTL_FIXTURE_CA", &f.server.certificate)
        .args(["--grant", "other-writer", "--use-configured-grant"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
        "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"draft-fixture", "version":"1"}
    }})).unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(
        serde_json::from_str::<Value>(&line)
            .unwrap()
            .get("result")
            .is_some()
    );
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{}",
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"})
    )
    .unwrap();
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{}",
        json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
            "name":"email_save_draft", "arguments":f.input
        }})
    )
    .unwrap();
    f.appended().await;
    drop(child.stdin.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("MCP retained the draft writer after EOF");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let replay = run_bounded(f.save());
    assert_eq!(replay.status.code(), Some(7));
    assert_eq!(envelope(&replay)["error"]["code"], "outcome_unknown");
    assert_eq!(f.server.interrupted(), 1);
    f.server.finish();
}

#[tokio::test]
async fn authentication_rejection_precedes_dispatch_and_keeps_absent_history_absent() {
    let mut f = DraftFixture::new();
    f.server.reject_authentication(false);
    let failed = run_bounded(f.save());
    assert_eq!(envelope(&failed)["error"]["code"], "authentication_failed");
    let client = f.mcp().await;
    assert_eq!(
        call(&client, "email_draft_status", f.status()).await["error"]["code"],
        "operation_not_found"
    );
    assert_eq!(f.server.interrupted(), 0);
    client.cancel().await.unwrap();
    f.server.finish();
}
