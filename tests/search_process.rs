#![cfg(any(feature = "cli", feature = "mcp"))]
mod support;

#[cfg(feature = "mcp")]
use serde_json::json;
#[cfg(feature = "cli")]
use support::envelope;
use support::{Installation, run_bounded};

fn setup(installation: &Installation) {
    #[cfg(feature = "cli")]
    let mut command = installation.cli();
    #[cfg(not(feature = "cli"))]
    let mut command = installation.mcp();
    command.args(["--json", "setup"]);
    support::assert_success(&run_bounded(command));
}

#[cfg(feature = "cli")]
#[test]
fn cli_search_rejects_invalid_criteria_and_stale_references_without_credentials() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let mut command = installation.cli();
    command.args([
        "--json",
        "message",
        "search",
        "--mailbox",
        "invalid",
        "--fuzzy",
    ]);
    let output = run_bounded(command);
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(envelope(&output)["error"]["code"], "stale_reference");
    let mut command = installation.cli();
    command.args([
        "--json",
        "message",
        "search",
        "--mailbox",
        "invalid",
        "--criteria",
        r#"[{"field":"required_flag","flag":"seen"},{"field":"forbidden_flag","flag":"seen"}]"#,
    ]);
    let output = run_bounded(command);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(envelope(&output)["error"]["code"], "invalid_request");
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_search_publishes_schemas_and_matches_cli_errors_under_the_effective_grant() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    let installation = Installation::two_accounts();
    setup(&installation);
    let command = tokio::process::Command::from(installation.mcp());
    let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
    let tools = client.list_all_tools().await.unwrap();
    let search = tools
        .iter()
        .find(|tool| tool.name == "email_search_messages")
        .expect("search tool");
    assert!(search.input_schema["properties"].get("criteria").is_some());
    assert_eq!(
        search.input_schema["properties"]["fuzzy"]["type"],
        "boolean"
    );
    assert!(search.output_schema.is_some());
    let response = client
        .call_tool(
            CallToolRequestParams::new("email_search_messages").with_arguments(
                json!({"mailbox":"invalid","fuzzy":true})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.is_error, Some(true));
    let structured = support::assert_mcp_envelope(response);
    assert_eq!(structured["error"]["code"], "stale_reference");
    client.cancel().await.unwrap();

    let mut command = tokio::process::Command::from(installation.mcp());
    command.args(["--grant", "writer", "--use-configured-grant"]);
    let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
    assert!(
        !client
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|tool| tool.name == "email_search_messages")
    );
    client.cancel().await.unwrap();
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_accepts_the_full_search_schema_before_rejecting_a_stale_reference() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    let installation = Installation::two_accounts();
    setup(&installation);
    let command = tokio::process::Command::from(installation.mcp());
    let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
    let criteria = vec![json!({"field":"text","value":"\u{0001}".repeat(4096)}); 32];
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.call_tool(
            CallToolRequestParams::new("email_search_messages").with_arguments(
                json!({"mailbox":"invalid","criteria":criteria})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        ),
    )
    .await
    .unwrap()
    .expect("a schema-ceiling search reaches application validation");
    assert_eq!(
        response.structured_content.unwrap()["error"]["code"],
        "stale_reference"
    );
    client.cancel().await.unwrap();
}
