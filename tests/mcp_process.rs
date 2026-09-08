//! STDIO acceptance tests for the standalone MCP component.
#![cfg(feature = "mcp")]

mod support;

use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Map, Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use support::{Installation, MAILCTL_MCP, assert_success, envelope, run_bounded};

fn setup(installation: &Installation) {
    let output = run_bounded({
        let mut command = installation.mcp();
        command.args(["--json", "setup"]);
        command
    });
    assert_success(&output);
}

type McpClient = rmcp::service::RunningService<rmcp::RoleClient, ()>;

async fn client(installation: &Installation, arguments: &[&str]) -> McpClient {
    let mut command = tokio::process::Command::new(MAILCTL_MCP);
    command
        .arg("--config")
        .arg(installation.config())
        .args(arguments);
    let transport = TokioChildProcess::new(command).expect("start MCP component");
    ().serve(transport).await.expect("negotiate MCP")
}

async fn listed_accounts(installation: &Installation, arguments: &[&str]) -> (McpClient, Value) {
    let client = client(installation, arguments).await;
    let response = client
        .call_tool(CallToolRequestParams::new("email_list_accounts"))
        .await
        .expect("call account discovery tool");
    (
        client,
        response
            .structured_content
            .expect("structured discovery envelope"),
    )
}

#[tokio::test]
async fn standalone_mcp_negotiates_schemas_and_applies_configured_grant_scope() {
    let installation = Installation::two_accounts();
    setup(&installation);

    let all_client = client(&installation, &["--grant", "all"]).await;
    let tools = all_client.list_all_tools().await.expect("list tools");
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        ["email_list_accounts", "email_capabilities"]
    );
    let discovery = &tools[0];
    assert!(discovery.input_schema.contains_key("properties"));
    assert!(discovery.input_schema["properties"].get("limit").is_some());
    let output_schema = discovery.output_schema.as_ref().unwrap();
    assert!(
        output_schema.contains_key("$schema") || output_schema.contains_key("$ref"),
        "MCP output schema must be a JSON Schema document"
    );

    let response = all_client
        .call_tool(CallToolRequestParams::new("email_list_accounts"))
        .await
        .expect("call discovery");
    assert_eq!(response.is_error, Some(false));
    let envelope = response.structured_content.unwrap();
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["accounts"].as_array().unwrap().len(), 2);

    let invalid = all_client
        .call_tool(
            CallToolRequestParams::new("email_list_accounts")
                .with_arguments(Map::from_iter([(String::from("limit"), json!(0))])),
        )
        .await
        .expect("receive application error envelope");
    assert_eq!(invalid.is_error, Some(true));
    assert_eq!(
        invalid.structured_content.unwrap()["error"]["code"],
        "invalid_request"
    );
    all_client.cancel().await.expect("close MCP session");

    let (restricted, envelope) = listed_accounts(&installation, &[]).await;
    assert_eq!(envelope["result"]["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(envelope["result"]["accounts"][0]["alias"], "work");
    restricted.cancel().await.expect("close restricted session");

    let read_only_writer = client(&installation, &["--grant", "writer"]).await;
    let read_only_capabilities = read_only_writer
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .expect("call narrowed capabilities");
    assert_eq!(
        read_only_capabilities.structured_content.unwrap()["result"]["permissions"],
        json!(["list_accounts"]),
        "MCP narrows a configured writer grant unless explicitly opted in"
    );
    read_only_writer
        .cancel()
        .await
        .expect("close narrowed writer session");

    let configured_writer = client(
        &installation,
        &["--grant", "writer", "--use-configured-grant"],
    )
    .await;
    let configured_capabilities = configured_writer
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .expect("call configured capabilities");
    assert_eq!(
        configured_capabilities.structured_content.unwrap()["result"]["permissions"],
        json!(["list_accounts", "append_draft", "inspect_draft_operation"])
    );
    configured_writer
        .cancel()
        .await
        .expect("close configured writer session");
}

#[tokio::test]
async fn mcp_hides_administration_tools_and_releases_setup_after_eof() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let client = client(&installation, &[]).await;
    let tools = client.list_all_tools().await.expect("list tools");
    assert!(
        tools
            .iter()
            .all(|tool| !tool.name.contains("credential") && !tool.name.contains("setup"))
    );
    assert!(
        client
            .call_tool(CallToolRequestParams::new("email_credential_set"))
            .await
            .is_err(),
        "administration must not be callable as an MCP tool"
    );

    let busy = run_bounded({
        let mut command = installation.mcp();
        command.args(["--json", "setup"]);
        command
    });
    assert_eq!(busy.status.code(), Some(5));
    assert_eq!(envelope(&busy)["error"]["code"], "rate_limited");

    client.cancel().await.expect("EOF closes MCP session");
    let ready = run_bounded({
        let mut command = installation.mcp();
        command.args(["--json", "setup"]);
        command
    });
    assert_success(&ready);
}

#[test]
fn malformed_stdio_frames_are_not_parsed_or_kept_alive() {
    let installation = Installation::two_accounts();
    setup(&installation);
    for frame in [
        vec![0xff, b'\n'],
        format!("{}0{}\n", "[".repeat(65), "]".repeat(65)).into_bytes(),
        vec![b'x'; 65 * 1024],
    ] {
        let mut command = Command::new(MAILCTL_MCP);
        command
            .arg("--config")
            .arg(installation.config())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("start MCP component");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&frame)
            .expect("write malformed frame");
        let output = wait_for_exit(child);
        assert!(
            output.stdout.is_empty(),
            "malformed input must not be reflected to stdout"
        );
    }
}

#[test]
fn mcp_does_not_dispatch_a_tool_before_initialization() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let output = raw_mcp(
        &installation,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"email_list_accounts","arguments":{}}}
"#,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("work") && !stdout.contains("accounts"),
        "a pre-initialization request reached the application: {stdout}"
    );
}

fn raw_mcp(installation: &Installation, frame: &[u8]) -> std::process::Output {
    let mut command = Command::new(MAILCTL_MCP);
    command
        .arg("--config")
        .arg(installation.config())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("start MCP component");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(frame)
        .expect("write STDIO frame");
    wait_for_exit(child)
}

fn wait_for_exit(mut child: std::process::Child) -> std::process::Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().expect("inspect MCP process").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("MCP process did not exit after EOF");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("collect MCP output")
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_runs_and_exits_while_a_standalone_mcp_session_owns_its_own_lease() {
    use support::MAILCTL;

    let installation = Installation::two_accounts();
    setup(&installation);
    let client = client(&installation, &[]).await;
    let output = run_bounded({
        let mut command = installation.command(MAILCTL);
        command.args(["--json", "account", "list"]);
        command
    });
    assert_success(&output);
    assert_eq!(
        envelope(&output)["result"]["accounts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    client.cancel().await.expect("close MCP session");
}
