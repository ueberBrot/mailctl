#![cfg(any(feature = "cli", feature = "mcp"))]
#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[path = "../../imap_support/process.rs"]
mod server;
#[path = "../../support/mod.rs"]
mod support;

use serde_json::Value;
#[cfg(feature = "cli")]
use support::envelope;
use support::{Installation, assert_success, run_bounded};

fn prepare(executable: &str) -> (Installation, server::ImapServer) {
    let installation = Installation::two_accounts();
    let server = server::ImapServer::new(installation.config().parent().unwrap());
    let configuration = std::fs::read_to_string(installation.config())
        .unwrap()
        .replace(
            "server = \"imap.example.test\"",
            &format!("server = \"127.0.0.1\"\nport = {}", server.port),
        );
    std::fs::write(installation.config(), configuration).unwrap();
    let mut setup = installation.command(executable);
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    (installation, server)
}

fn configure_depth(installation: &Installation, ceiling: usize) {
    let mut configuration: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    // Exercise the actual default as well as the largest operator ceiling.
    if ceiling == 20 {
        configuration.as_table_mut().unwrap().remove("limits");
    } else {
        configuration.as_table_mut().unwrap().insert(
            "limits".into(),
            toml::Value::Table(toml::map::Map::from_iter([(
                "mime_depth".into(),
                toml::Value::Integer(ceiling.try_into().unwrap()),
            )])),
        );
    }
    std::fs::write(
        installation.config(),
        toml::to_string(&configuration).unwrap(),
    )
    .unwrap();
}

fn assert_depth(result: &Value, depth: usize, ceiling: usize, kind: usize) {
    if depth <= ceiling {
        assert_eq!(result["result"]["attachments"], serde_json::json!([]));
    } else {
        assert_eq!(
            result["error"]["code"], "response_too_large",
            "depth={depth} ceiling={ceiling} kind={kind}: {result}"
        );
    }
}

#[cfg(feature = "cli")]
#[test]
fn cli_decodes_deep_mime_from_a_one_mib_lifecycle_caller() {
    let (installation, mut server) = prepare(support::MAILCTL);
    let cli = |args: &[&str]| {
        let mut command = installation.cli();
        command
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .arg("--json")
            .args(args);
        run_bounded(command)
    };
    server.expect_mailboxes("work@example.test", "disposable-password", &["INBOX"]);
    let mailboxes = cli(&["mailbox", "list"]);
    assert_success(&mailboxes);
    let mailbox = envelope(&mailboxes)["result"]["mailboxes"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    server.expect_search("work@example.test", "disposable-password", "INBOX", None);
    let messages = cli(&["message", "search", "--mailbox", &mailbox, "--limit", "1"]);
    assert_success(&messages);
    let message = envelope(&messages)["result"]["messages"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    for ceiling in [40, 20] {
        configure_depth(&installation, ceiling);
        for kind in 0..3 {
            // Deeper legal frames are typed before semantic rejection; 64/1000
            // also exercise the protocol nesting guard. No rejection may fetch
            // body bytes. The direct codec probe separately checks its budget.
            for depth in [ceiling, ceiling + 1, 63, 64, 1000] {
                server.expect_mime_depth(depth, kind, depth <= ceiling);
                let output = cli(&["attachment", "list", "--message", &message]);
                assert_eq!(
                    output.status.code(),
                    Some(if depth <= ceiling { 0 } else { 8 }),
                    "depth={depth} ceiling={ceiling} kind={kind}; stderr {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_depth(&envelope(&output), depth, ceiling, kind);
            }
        }
    }
    server.finish();
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_decodes_deep_mime_from_a_one_mib_lifecycle_caller() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use serde_json::json;
    type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;
    async fn call(client: &Client, tool: &str, arguments: Value) -> Value {
        support::assert_mcp_envelope(
            client
                .call_tool(
                    CallToolRequestParams::new(tool.to_owned())
                        .with_arguments(arguments.as_object().unwrap().clone()),
                )
                .await
                .unwrap(),
        )
    }

    let (installation, mut server) = prepare(support::MAILCTL_MCP);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for ceiling in [40, 20] {
            configure_depth(&installation, ceiling);
            let mut command = installation.mcp();
            command.env("MAILCTL_FIXTURE_CA", &server.certificate);
            let client =
                ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
                    .await
                    .unwrap();
            server.expect_mailboxes("work@example.test", "disposable-password", &["INBOX"]);
            let mailboxes = call(&client, "email_list_mailboxes", json!({})).await;
            let mailbox = mailboxes["result"]["mailboxes"][0]["reference"]
                .as_str()
                .unwrap();
            server.expect_search("work@example.test", "disposable-password", "INBOX", None);
            let messages = call(
                &client,
                "email_search_messages",
                json!({"mailbox": mailbox, "limit": 1}),
            )
            .await;
            let message = messages["result"]["messages"][0]["reference"]
                .as_str()
                .unwrap();
            for kind in 0..3 {
                for depth in [ceiling, ceiling + 1, 63, 64, 1000] {
                    server.expect_mime_depth(depth, kind, depth <= ceiling);
                    let result = call(
                        &client,
                        "email_list_attachments",
                        json!({"message": message}),
                    )
                    .await;
                    assert_depth(&result, depth, ceiling, kind);
                }
            }
            // The same session remains usable after every rejected structure.
            server.expect_mailboxes("work@example.test", "disposable-password", &["INBOX"]);
            assert!(
                call(&client, "email_list_mailboxes", json!({}))
                    .await
                    .get("result")
                    .is_some()
            );
            client.cancel().await.unwrap();
        }
    })
    .await
    .expect("deep MIME requests and MCP shutdown finish within the deadline");
    server.finish();
}
