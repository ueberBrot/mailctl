#![cfg(all(feature = "cli", feature = "mcp"))]
#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[path = "../../imap_support/process.rs"]
mod server;
#[path = "../../support/mod.rs"]
mod support;
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use support::{Installation, assert_mcp_envelope, assert_success, envelope, run_bounded};

type McpClient = rmcp::service::RunningService<rmcp::RoleClient, ()>;
const READ_MAILBOX: &str = "Archive*Literal%";

#[tokio::test]
async fn cli_mcp_and_restarted_sessions_continue_under_fresh_authorization() {
    let installation = Installation::two_accounts();
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let mut configuration: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    for account in configuration["accounts"].as_array_mut().unwrap() {
        let account = account.as_table_mut().unwrap();
        account.insert("server".into(), "127.0.0.1".into());
        account.insert("port".into(), toml::Value::Integer(server.port.into()));
        account.remove("mailboxes");
    }
    for grant in configuration["grants"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .take(2)
    {
        grant.as_table_mut().unwrap().remove("mailboxes");
    }
    let configuration = toml::to_string(&configuration).unwrap()
        + "\n[[grants]]\nname = \"text\"\naccounts = [\"work\"]\nmailboxes = [\"Archive*Literal%\"]\n[grants.limits]\ntext_page_bytes = 8\nattachment_chunk_bytes = 3\n\n[[grants]]\nname = \"restricted\"\naccounts = [\"work\"]\nmailboxes = [\"INBOX\"]\n";
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
    server.expect_all_mailboxes(
        "work@example.test",
        "disposable-password",
        &[READ_MAILBOX, "INBOX"],
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
    server.expect_all_mailboxes(
        "work@example.test",
        "disposable-password",
        &[READ_MAILBOX, "INBOX"],
    );
    let mut command = installation.cli();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args([
            "--json",
            "--grant",
            "text",
            "mailbox",
            "list",
            "--reference",
            &mailbox,
        ]);
    let resolved = run_bounded(command);
    assert_success(&resolved);
    let resolved = envelope(&resolved)["result"].take();
    assert_eq!(resolved["mailboxes"].as_array().unwrap().len(), 1);
    assert_eq!(resolved["mailboxes"][0]["metadata"]["name"], READ_MAILBOX);
    server.expect_all_mailboxes(
        "work@example.test",
        "disposable-password",
        &[READ_MAILBOX, "INBOX"],
    );
    let mut command = installation.mcp();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args(["--grant", "text"]);
    assert_eq!(
        mcp_tool(
            command,
            "email_list_mailboxes",
            json!({"reference": mailbox})
        )
        .await["result"],
        resolved
    );
    server.expect_search(
        "work@example.test",
        "disposable-password",
        READ_MAILBOX,
        None,
    );
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
    let message_before = envelope(&output)["result"]["messages"][0].clone();
    assert_eq!(message_before["flags"], json!(["\\Seen"]));
    let search_cursor = envelope(&output)["result"]["next_cursor"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = server.accepted();
    for (arguments, tool, input) in [
        (
            vec!["mailbox", "list", "--reference", &mailbox],
            "email_list_mailboxes",
            json!({"reference": mailbox}),
        ),
        (
            vec![
                "message",
                "search",
                "--mailbox",
                &mailbox,
                "--cursor",
                &search_cursor,
                "--limit",
                "1",
            ],
            "email_search_messages",
            json!({"mailbox": mailbox, "cursor": search_cursor, "limit": 1}),
        ),
    ] {
        let mut denied = installation.cli();
        denied
            .args(["--json", "--grant", "restricted"])
            .args(arguments);
        assert_eq!(
            envelope(&run_bounded(denied))["error"]["code"],
            "mailbox_not_allowed"
        );
        let mut command = installation.mcp();
        command.args(["--grant", "restricted"]);
        assert_eq!(
            mcp_tool(command, tool, input).await["error"]["code"],
            "mailbox_not_allowed"
        );
    }
    assert_eq!(server.accepted(), before);
    server.expect_search(
        "work@example.test",
        "disposable-password",
        READ_MAILBOX,
        None,
    );
    let mut command = installation.mcp();
    command.env("MAILCTL_FIXTURE_CA", &server.certificate);
    let searched = mcp_tool(
        command,
        "email_search_messages",
        serde_json::json!({"mailbox": mailbox, "limit": 1}),
    )
    .await;
    assert_eq!(searched["result"]["messages"][0], message_before);
    text_handoffs(&installation, &server, &message).await;
    attachment_handoffs(&installation, &server, &message).await;
    // The transcript permits only EXAMINE, metadata FETCH, and BODY.PEEK reads.
    // Re-read the fixed fixture's flags and metadata after body and attachment access.
    server.expect_search(
        "work@example.test",
        "disposable-password",
        READ_MAILBOX,
        None,
    );
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
    let after = run_bounded(command);
    assert_success(&after);
    assert_eq!(envelope(&after)["result"]["messages"][0], message_before);
    hostile_presentation(&installation, &server, &message).await;
    hostile_failures(&installation, &server);
    server.finish();
}

async fn text_handoffs(installation: &Installation, server: &server::ImapServer, message: &str) {
    let mut cursor: Option<String> = None;
    let mut reconstructed = String::new();
    for (index, expected) in ["Shor", "t bo", "dy.\r", "\n"].into_iter().enumerate() {
        server.expect_body("work@example.test", "disposable-password", READ_MAILBOX);
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
                    "--max-bytes",
                    "4",
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
            mcp_message(command, message, cursor.as_deref(), Some(4)).await["result"].take()
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
                mcp_message(command, message, Some(cursor), Some(4)).await["error"]["code"],
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
    max_bytes: Option<usize>,
) -> serde_json::Value {
    mcp_tool(
        command,
        "email_get_message",
        serde_json::json!({"message": message, "max_bytes": max_bytes, "cursor": cursor}),
    )
    .await
}

async fn mcp_tool(
    command: std::process::Command,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let client =
            ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
                .await
                .unwrap();
        let structured = mcp_call(&client, tool, arguments).await;
        client.cancel().await.unwrap();
        structured
    })
    .await
    .expect("MCP message request and shutdown finish within the deadline")
}

async fn mcp_call(client: &McpClient, tool: &str, arguments: Value) -> Value {
    let response = client
        .call_tool(
            CallToolRequestParams::new(tool.to_owned())
                .with_arguments(arguments.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_mcp_envelope(response)
}

async fn attachment_handoffs(
    installation: &Installation,
    server: &server::ImapServer,
    message: &str,
) {
    let cli = |arguments: &[&str]| {
        let mut command = installation.cli();
        command
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .args(["--json", "--grant", "text"])
            .args(arguments);
        run_bounded(command)
    };
    server.expect_attachment(
        "work@example.test",
        "disposable-password",
        READ_MAILBOX,
        server::AttachmentPhase::List,
    );
    let listed = cli(&["attachment", "list", "--message", message]);
    assert_success(&listed);
    let listed = envelope(&listed)["result"].take();
    let attachment = listed["attachments"][0]["reference"].as_str().unwrap();
    server.expect_attachment(
        "work@example.test",
        "disposable-password",
        READ_MAILBOX,
        server::AttachmentPhase::List,
    );
    let mut command = installation.mcp();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args(["--grant", "text"]);
    assert_eq!(
        mcp_tool(
            command,
            "email_list_attachments",
            json!({"message": message})
        )
        .await["result"],
        listed
    );

    for phase in [
        server::AttachmentPhase::Start,
        server::AttachmentPhase::Continue,
    ] {
        server.expect_attachment(
            "work@example.test",
            "disposable-password",
            READ_MAILBOX,
            phase,
        );
    }
    let downloaded = cli(&["attachment", "get", "--attachment", attachment]);
    assert_success(&downloaded);
    let downloaded = envelope(&downloaded)["result"].take();
    assert_eq!(downloaded["bytes_base64"], "YWJjZGVm");
    assert_eq!(downloaded["progress"]["total_decoded_bytes"], 6);
    assert_eq!(
        downloaded["progress"]["sha256"],
        "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    );

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut command = installation.mcp();
        command
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .args(["--grant", "text"]);
        let client =
            ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
                .await
                .unwrap();
        server.expect_attachment(
            "work@example.test",
            "disposable-password",
            READ_MAILBOX,
            server::AttachmentPhase::Start,
        );
        let first = mcp_call(
            &client,
            "email_get_attachment",
            json!({"attachment": attachment}),
        )
        .await;
        assert_eq!(first["result"]["decoded_offset"], 0);
        assert_eq!(first["result"]["bytes_base64"], "YWJj");
        assert_eq!(first["result"]["progress"]["status"], "continue");
        let token = first["result"]["progress"]["next_token"].as_str().unwrap();
        server.expect_attachment(
            "work@example.test",
            "disposable-password",
            READ_MAILBOX,
            server::AttachmentPhase::Continue,
        );
        let last = mcp_call(&client, "email_get_attachment", json!({"token": token})).await;
        assert_eq!(last["result"]["decoded_offset"], 3);
        assert_eq!(last["result"]["bytes_base64"], "ZGVm");
        assert_eq!(last["result"]["progress"], downloaded["progress"]);
        client.cancel().await.unwrap();
    })
    .await
    .expect("attachment chunks and shutdown finish within the deadline");

    let before = server.accepted();
    for (arguments, tool, input) in [
        (
            vec!["attachment", "list", "--message", message],
            "email_list_attachments",
            json!({"message": message}),
        ),
        (
            vec!["attachment", "get", "--attachment", attachment],
            "email_get_attachment",
            json!({"attachment": attachment}),
        ),
    ] {
        let mut denied = installation.cli();
        denied
            .args(["--json", "--grant", "restricted"])
            .args(arguments);
        assert_eq!(
            envelope(&run_bounded(denied))["error"]["code"],
            "mailbox_not_allowed"
        );
        let mut command = installation.mcp();
        command.args(["--grant", "restricted"]);
        assert_eq!(
            mcp_tool(command, tool, input).await["error"]["code"],
            "mailbox_not_allowed"
        );
    }
    assert_eq!(server.accepted(), before);
}

async fn hostile_presentation(
    installation: &Installation,
    server: &server::ImapServer,
    message: &str,
) {
    let mut bytes = "Private café\r\n\r\nNext\tcolumn\u{1b}]52;c;clipboard-secret\u{7}end\u{1b}[31mred\u{1b}[0m\u{202e}\u{0000}\u{007f}".as_bytes().to_vec();
    bytes.extend_from_slice(&[0xff]);
    bytes.extend_from_slice("界".repeat(300).as_bytes());
    // The existing MIME representation prefixes a marker when decoding replaces bytes.
    let semantic = format!("�{}", String::from_utf8_lossy(&bytes));
    for level in ["error", "warn", "info", "debug", "trace"] {
        for json in [false, true] {
            server.expect_body_bytes(READ_MAILBOX, &bytes);
            let mut command = installation.cli();
            command
                .env("MAILCTL_FIXTURE_CA", &server.certificate)
                .env("RUST_LOG", "trace")
                .args([
                    "--log-format",
                    "json",
                    "--log-level",
                    level,
                    "--color",
                    "always",
                    "message",
                    "get",
                    "--message",
                    message,
                ]);
            if json {
                command.arg("--json");
            }
            let output = run_bounded(command);
            assert_success(&output);
            let diagnostics = std::str::from_utf8(&output.stderr).unwrap();
            for secret in [
                "Private",
                "café",
                "clipboard-secret",
                "界",
                "disposable-password",
                "work@example.test",
                message,
            ] {
                assert!(!diagnostics.contains(secret));
            }
            for line in diagnostics.lines() {
                assert!(line.len() < 2048);
                let _: serde_json::Value = serde_json::from_str(line).unwrap();
            }
            if json {
                assert_eq!(
                    envelope(&output)["result"]["body"]["text"],
                    semantic.as_str()
                );
            } else {
                let text = String::from_utf8(output.stdout).unwrap();
                assert!(
                    text.contains(
                        "Private café\n\nNext    columnendred\\u{202e}\\u{0000}\\u{007f}�"
                    )
                );
                assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
                assert!(!text.contains("clipboard-secret"));
            }
        }
    }
    server.expect_body_bytes(READ_MAILBOX, &bytes);
    let mut command = installation.mcp();
    command.env("MAILCTL_FIXTURE_CA", &server.certificate);
    let response = mcp_message(command, message, None, None).await;
    assert_eq!(response["result"]["body"]["text"], semantic.as_str());
}

fn hostile_failures(installation: &Installation, server: &server::ImapServer) {
    for level in ["error", "warn", "info", "debug", "trace"] {
        for (malformed, exit, code) in [
            (false, 4, "authentication_failed"),
            (true, 5, "provider_unavailable"),
        ] {
            server.reject_authentication(malformed);
            let mut command = installation.cli();
            command
                .env("MAILCTL_FIXTURE_CA", &server.certificate)
                .env("RUST_LOG", "trace")
                .args([
                    "--json",
                    "--log-format",
                    "json",
                    "--log-level",
                    level,
                    "doctor",
                    "--check-account",
                ]);
            let output = run_bounded(command);
            assert_eq!(output.status.code(), Some(exit));
            let stderr = std::str::from_utf8(&output.stderr).unwrap();
            assert!(
                !stderr.contains("fixture-private")
                    && !stderr.contains("payload")
                    && !stderr.contains('\u{1b}')
            );
            let mut failed = false;
            for line in stderr.lines() {
                assert!(line.len() < 2048);
                let event: serde_json::Value = serde_json::from_str(line).unwrap();
                if event["event"] == "operation_failed" {
                    failed = true;
                    assert_eq!(event["code"], code);
                    assert_eq!(event["request_id"], envelope(&output)["request_id"]);
                }
            }
            assert!(failed, "provider failure must emit a diagnostic");
        }
    }
}
