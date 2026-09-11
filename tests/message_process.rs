#![cfg(any(feature = "cli", feature = "mcp"))]
mod support;

#[test]
fn message_get_rejects_stale_references_before_authentication() {
    let installation = support::Installation::two_accounts();
    #[cfg(feature = "cli")]
    let mut setup = installation.cli();
    #[cfg(not(feature = "cli"))]
    let mut setup = installation.mcp();
    setup.args(["--json", "setup"]);
    support::assert_success(&support::run_bounded(setup));
    #[cfg(feature = "cli")]
    {
        let mut command = installation.cli();
        command.args(["--json", "message", "get", "--message", "invalid"]);
        let output = support::run_bounded(command);
        assert_eq!(output.status.code(), Some(6));
        assert_eq!(
            support::envelope(&output)["error"]["code"],
            "stale_reference"
        );
    }
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_message_schema_and_errors_match_the_cli_and_hide_from_drafts_only() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use serde_json::json;
    let installation = support::Installation::two_accounts();
    let mut setup = installation.mcp();
    setup.args(["--json", "setup"]);
    support::assert_success(&support::run_bounded(setup));
    for (grant, exposed) in [("default", true), ("writer", false)] {
        let mut command = tokio::process::Command::new(support::MAILCTL_MCP);
        command.arg("--config").arg(installation.config()).args([
            "--grant",
            grant,
            "--use-configured-grant",
        ]);
        let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
        let tools = client.list_all_tools().await.unwrap();
        let tool = tools.iter().find(|tool| tool.name == "email_get_message");
        assert_eq!(tool.is_some(), exposed);
        if let Some(tool) = tool {
            assert!(tool.output_schema.is_some());
            assert_eq!(tool.input_schema["additionalProperties"], false);
            for (input, error) in [
                (json!({"message":"invalid"}), "stale_reference"),
                (
                    json!({"message":"invalid", "unknown":true}),
                    "invalid_request",
                ),
            ] {
                let response = client
                    .call_tool(
                        CallToolRequestParams::new("email_get_message")
                            .with_arguments(input.as_object().unwrap().clone()),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.is_error, Some(true));
                let structured = response.structured_content.unwrap();
                assert_eq!(structured["error"]["code"], error);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(
                        &response.content[0].as_text().unwrap().text
                    )
                    .unwrap(),
                    structured
                );
            }
        }
        client.cancel().await.unwrap();
    }
}
