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

#[tokio::test]
async fn all_folder_setup_discovers_later_folders_in_the_same_mcp_session() {
    let installation = Installation::empty();
    let mut setup = installation.cli();
    setup.args([
        "--json",
        "setup",
        "--alias",
        "work",
        "--server",
        "127.0.0.1",
        "--username",
        "work@example.test",
    ]);
    assert_success(&run_bounded(setup));
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let mut configuration: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    configuration["accounts"][0]["port"] = toml::Value::Integer(server.port.into());
    std::fs::write(
        installation.config(),
        toml::to_string(&configuration).unwrap(),
    )
    .unwrap();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    let saved_configuration = std::fs::read(installation.config()).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut command = installation.mcp();
        command.env("MAILCTL_FIXTURE_CA", &server.certificate);
        let client =
            ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap())
                .await
                .unwrap();

        server.expect_all_mailboxes(
            "work@example.test",
            "disposable-password",
            &["Projects", "INBOX", "Archive"],
        );
        let first = cli_mailboxes(&installation, &server, &["--limit", "2"]);
        assert_eq!(names(&first), ["Archive", "INBOX"]);
        assert_eq!(first["complete"], false);
        let cursor = first["next_cursor"].as_str().unwrap();

        server.expect_all_mailboxes(
            "work@example.test",
            "disposable-password",
            &["Projects", "INBOX", "Archive"],
        );
        let last = mcp_mailboxes(&client, json!({"cursor": cursor, "limit": 2})).await;
        assert_eq!(names(&last["result"]), ["Projects"]);
        assert_eq!(last["result"]["complete"], true);
        assert_eq!(
            last["result"]["mailboxes"][0]["metadata"]["selectable"],
            false
        );
        assert_eq!(last["result"]["account_id"], first["account_id"]);

        server.expect_all_mailboxes(
            "work@example.test",
            "disposable-password",
            &["Projects", "Later", "INBOX", "Archive"],
        );
        let later = mcp_mailboxes(&client, json!({})).await;
        assert_eq!(
            names(&later["result"]),
            ["Archive", "INBOX", "Later", "Projects"]
        );
        assert_eq!(later["result"]["complete"], true);
        assert_eq!(
            later["result"]["mailboxes"][0]["metadata"]["special_use"],
            json!(["\\Archive"])
        );

        server.expect_all_mailboxes(
            "work@example.test",
            "disposable-password",
            &["Projects", "Later", "INBOX", "Archive"],
        );
        let cli = cli_mailboxes(&installation, &server, &[]);
        assert_eq!(cli, later["result"]);

        server.expect_all_mailboxes(
            "work@example.test",
            "disposable-password",
            &["Projects", "Later", "INBOX", "Archive"],
        );
        let stale = mcp_mailboxes(&client, json!({"cursor": cursor, "limit": 2})).await;
        assert_eq!(stale["error"]["code"], "stale_cursor");
        client.cancel().await.unwrap();
    })
    .await
    .expect("mailbox discovery and shutdown finish within the deadline");

    assert_eq!(
        std::fs::read(installation.config()).unwrap(),
        saved_configuration
    );
    server.finish();
}

fn cli_mailboxes(
    installation: &Installation,
    server: &server::ImapServer,
    arguments: &[&str],
) -> Value {
    let mut command = installation.cli();
    command
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args(["--json", "mailbox", "list"])
        .args(arguments);
    let output = run_bounded(command);
    assert_success(&output);
    envelope(&output)["result"].take()
}

async fn mcp_mailboxes(client: &McpClient, arguments: Value) -> Value {
    let response = client
        .call_tool(
            CallToolRequestParams::new("email_list_mailboxes")
                .with_arguments(arguments.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_mcp_envelope(response)
}

fn names(page: &Value) -> Vec<&str> {
    page["mailboxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mailbox| mailbox["metadata"]["name"].as_str().unwrap())
        .collect()
}
