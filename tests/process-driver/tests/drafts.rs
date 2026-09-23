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
async fn independent_cli_and_mcp_prepare_once_and_inspect_without_provider_work() {
    let installation = Installation::two_accounts();
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let text = std::fs::read_to_string(installation.config())
        .unwrap()
        .replace(
            "server = \"imap.example.test\"",
            &format!("server = \"127.0.0.1\"\nport = {}", server.port),
        )
        .replace(
            "from_identities = [\"work\"]",
            "from_identities = [\"work@example.test\"]",
        );
    std::fs::write(installation.config(), text).unwrap();
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
    let mut command = installation.cli();
    command.args(["--json", "account", "list"]);
    let output = run_bounded(command);
    assert_success(&output);
    let account = envelope(&output)["result"]["accounts"][0].clone();
    let id = account["account_id"].as_str().unwrap();
    let op = uuid::Uuid::new_v4().to_string();
    let input = json!({"mailbox":"Drafts", "account_id": id, "account_generation":1, "operation_id":op,
        "draft":{"subject":"Synthetic", "body":"Synthetic body", "bcc":[{"address":"hidden@example.test", "name":"Hidden"}]}});
    let file = installation.config().with_file_name("composition.json");
    std::fs::write(&file, serde_json::to_vec(&input["draft"]).unwrap()).unwrap();
    server.expect_draft_target();
    let mut command = installation.cli();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args([
            "--json",
            "--grant",
            "writer",
            "draft",
            "save",
            "--mailbox",
            "Drafts",
            "--account-id",
            id,
            "--account-generation",
            "1",
            "--operation-id",
            &op,
            "--input",
        ])
        .arg(&file);
    let output = run_bounded(command);
    assert_success(&output);
    let prepared = envelope(&output)["result"].clone();
    assert_eq!(prepared["state"], "prepared");
    assert_eq!(prepared["dispatched"], false);
    let provider_connections = server.accepted();
    assert_eq!(provider_connections, 1);

    let mut command = installation.mcp();
    command
        .args(["--grant", "writer", "--use-configured-grant"])
        .env("MAILCTL_FIXTURE_CA", &server.certificate);
    let client =
        ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
            .await
            .unwrap();
    let tools = client.list_all_tools().await.unwrap();
    for name in ["email_save_draft", "email_draft_status"] {
        assert!(tools.iter().any(|t| t.name == name));
    }
    assert!(!tools.iter().any(|t| t.name == "email_get_message"));
    let result = call(&client, "email_save_draft", input.clone()).await;
    assert_eq!(result["result"], prepared);
    let mut lookup = input.clone();
    lookup.as_object_mut().unwrap().remove("draft");
    let lock_path = installation
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
    let mut conflict = input.clone();
    conflict["draft"]["body"] = json!("Changed");
    assert_eq!(
        call(&client, "email_save_draft", conflict).await["error"]["code"],
        "operation_conflict"
    );
    // A second executable can prepare an independent operation while MCP remains alive.
    let second = uuid::Uuid::new_v4().to_string();
    server.expect_draft_target();
    let mut command = installation.cli();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args([
            "--json",
            "--grant",
            "writer",
            "draft",
            "save",
            "--mailbox",
            "Drafts",
            "--account-id",
            id,
            "--account-generation",
            "1",
            "--operation-id",
            &second,
            "--input",
        ])
        .arg(&file);
    let mut concurrent = input.clone();
    concurrent["operation_id"] = json!(second);
    let cli = tokio::task::spawn_blocking(move || run_bounded(command));
    let (cli, mcp) = tokio::join!(cli, call(&client, "email_save_draft", concurrent));
    let cli = cli.unwrap();
    assert_success(&cli);
    assert_eq!(envelope(&cli)["result"], mcp["result"]);
    client.cancel().await.unwrap();
    // Normal MCP startup narrows a draft-capable grant to read-only.
    let mut command = installation.mcp();
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
    assert_eq!(server.accepted(), provider_connections + 1);
    server.finish();
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
