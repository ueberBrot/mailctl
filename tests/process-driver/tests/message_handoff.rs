#![cfg(all(feature = "cli", feature = "mcp"))]
#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[path = "../../imap_support/process.rs"]
mod server;
#[path = "../../support/mod.rs"]
mod support;
use support::{Installation, assert_success, envelope, run_bounded};

#[tokio::test]
async fn cli_mcp_and_restarted_sessions_continue_under_fresh_authorization() {
    let installation = Installation::two_accounts();
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let configuration = std::fs::read_to_string(installation.config())
        .unwrap()
        .replace(
            "server = \"imap.example.test\"",
            &format!("server = \"127.0.0.1\"\nport = {}", server.port),
        )
        .replace(
            "mailboxes = [\"INBOX\", \"Drafts\"]",
            "mailboxes = [\"INBOX\", \"Drafts\", \"Archive\"]",
        )
        .replace(
            "mailboxes = [\"INBOX\"]",
            "mailboxes = [\"INBOX\", \"Archive\"]",
        )
        + "\n[[grants]]\nname = \"text\"\naccounts = [\"work\"]\nmailboxes = [\"Archive\"]\n[grants.limits]\ntext_page_bytes = 4\n\n[[grants]]\nname = \"restricted\"\naccounts = [\"work\"]\nmailboxes = [\"INBOX\"]\n";
    std::fs::write(installation.config(), configuration).unwrap();
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
    for executable in [support::MAILCTL, support::MAILCTL_MCP] {
        let mut doctor = installation.command(executable);
        doctor
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .args(["--json", "doctor"]);
        let output = run_bounded(doctor);
        assert_success(&output);
        assert_eq!(envelope(&output)["result"]["status"], "ready");
        assert_eq!(server.accepted(), 0);
    }
    server.expect_mailboxes(
        "work@example.test",
        "disposable-password",
        &["Archive", "INBOX"],
    );
    let mut command = installation.cli();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args(["--json", "mailbox", "list", "--limit", "1"]);
    let output = run_bounded(command);
    assert_success(&output);
    let mailbox = envelope(&output)["result"]["mailboxes"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    server.expect_search("work@example.test", "disposable-password", "Archive", None);
    let mut command = installation.cli();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args([
            "--json",
            "message",
            "search",
            "--mailbox",
            &mailbox,
            "--limit",
            "1",
        ]);
    let output = run_bounded(command);
    assert_success(&output);
    let message = envelope(&output)["result"]["messages"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    text_handoffs(&installation, &server, &message).await;
    server.finish();
}

async fn text_handoffs(installation: &Installation, server: &server::ImapServer, message: &str) {
    let mut cursor: Option<String> = None;
    let mut reconstructed = String::new();
    for (index, expected) in ["Shor", "t bo", "dy.\r", "\n"].into_iter().enumerate() {
        server.expect_body("work@example.test", "disposable-password", "Archive");
        let result = if index == 0 || index == 3 {
            let mut command = installation.cli();
            command
                .env("MAILCTL_FIXTURE_CA", &server.certificate)
                .args([
                    "--json",
                    "--grant",
                    "text",
                    "message",
                    "get",
                    "--message",
                    message,
                ]);
            if let Some(cursor) = &cursor {
                command.args(["--cursor", cursor]);
            }
            let output = run_bounded(command);
            assert_success(&output);
            envelope(&output)["result"].take()
        } else {
            let mut command = installation.mcp();
            command
                .args(["--grant", "text"])
                .env("MAILCTL_FIXTURE_CA", &server.certificate);
            mcp_message(command, message, cursor.as_deref()).await["result"].take()
        };
        assert_eq!(result["body"]["text"], expected);
        reconstructed.push_str(expected);
        cursor = result["body"]["next_cursor"].as_str().map(str::to_owned);
        assert_eq!(result["body"]["truncated"], cursor.is_some());
        if let Some(cursor) = &cursor {
            let before = server.accepted();
            let mut denied = installation.cli();
            denied.args([
                "--json",
                "--grant",
                "restricted",
                "message",
                "get",
                "--message",
                message,
                "--cursor",
                cursor,
            ]);
            assert_eq!(
                envelope(&run_bounded(denied))["error"]["code"],
                "mailbox_not_allowed"
            );
            let mut command = installation.mcp();
            command.args(["--grant", "restricted"]);
            assert_eq!(
                mcp_message(command, message, Some(cursor)).await["error"]["code"],
                "mailbox_not_allowed"
            );
            assert_eq!(server.accepted(), before);
        }
    }
    assert_eq!(reconstructed, "Short body.\r\n");
    assert!(cursor.is_none());
}

async fn mcp_message(
    command: std::process::Command,
    message: &str,
    cursor: Option<&str>,
) -> serde_json::Value {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use serde_json::{Value, json};

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let client =
            ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
                .await
                .unwrap();
        let response = client
            .call_tool(
                CallToolRequestParams::new("email_get_message").with_arguments(
                    serde_json::Map::from_iter([
                        ("message".into(), json!(message)),
                        ("cursor".into(), json!(cursor)),
                    ]),
                ),
            )
            .await
            .unwrap();
        let structured = response.structured_content.unwrap();
        assert_eq!(response.is_error, Some(structured.get("error").is_some()));
        assert_eq!(
            serde_json::from_str::<Value>(&response.content[0].as_text().unwrap().text).unwrap(),
            structured
        );
        client.cancel().await.unwrap();
        structured
    })
    .await
    .expect("MCP message request and shutdown finish within the deadline")
}
