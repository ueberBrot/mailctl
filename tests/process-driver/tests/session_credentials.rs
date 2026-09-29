#![cfg(all(unix, feature = "cli"))]

#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[path = "../../native_support/process.rs"]
mod process;
#[path = "../../imap_support/process.rs"]
mod server;
#[path = "../../support/mod.rs"]
mod support;
#[path = "../../native_support/terminal.rs"]
mod terminal;

use mailctl::config::{Config, CredentialSource};
use serde_json::json;
use std::fs;
use support::{Installation, MAILCTL, assert_success, envelope, run_bounded};

fn installation() -> (Installation, server::ImapServer) {
    let installation = Installation::two_accounts();
    let server = server::ImapServer::new(installation.config().parent().unwrap());
    let mut config = Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.accounts[0].credential = CredentialSource::Session {};
    config.accounts[0].server = "127.0.0.1".into();
    config.accounts[0].port = server.port;
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    (installation, server)
}

#[test]
fn foreground_session_authenticates_without_echo_or_persistent_credentials() {
    let (installation, mut server) = installation();
    for secret in ["disposable-password", " rotated-session-password "] {
        server.expect("work@example.test", secret);
        let result = invoke_terminal(
            &installation,
            &server,
            &["--interactive", "doctor", "--check-account"],
            json!({"secret": secret}),
        );
        assert_prompt(&result, 0);
        assert!(result["output"].as_str().unwrap().contains("authenticated"));
        assert_no_stored_secret(installation.config().parent().unwrap(), secret.as_bytes());
    }
    let mut unattended = installation.cli();
    unattended
        .env("MAILCTL_FIXTURE_CA", &server.certificate)
        .args(["--json", "doctor", "--check-account"]);
    let result = envelope(&run_bounded(unattended));
    assert_eq!(
        result["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
        "interaction_required"
    );
    assert_eq!(server.accepted(), 2);
    server.finish();
}

#[test]
fn session_prompt_edits_utf8_characters_and_clears_input() {
    let (installation, mut server) = installation();
    for input in [
        "pasé\u{7f}s",
        "pas€\u{8}s",
        "pas🔐\u{7f}s",
        "discard\u{15}pass",
    ] {
        server.expect("work@example.test", "pass");
        let result = invoke_terminal(
            &installation,
            &server,
            &["--interactive", "doctor", "--check-account"],
            json!({"secret": input}),
        );
        assert_prompt(&result, 0);
        assert!(result["output"].as_str().unwrap().contains("authenticated"));
    }
    server.finish();
}

#[test]
fn foreground_session_reads_mailboxes_at_the_effective_secret_limit() {
    let (installation, mut server) = installation();
    let mut config = Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.grants[0].limits.secret_bytes = 8;
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    server.expect_mailboxes("work@example.test", "12345678", &["INBOX"]);
    let result = invoke_terminal(
        &installation,
        &server,
        &["--interactive", "mailbox", "list"],
        json!({"secret": "12345678"}),
    );
    assert_prompt(&result, 0);
    assert!(result["output"].as_str().unwrap().contains("INBOX"));
    server.finish();
}

fn invoke_terminal(
    installation: &Installation,
    server: &server::ImapServer,
    arguments: &[&str],
    mut request: serde_json::Value,
) -> serde_json::Value {
    let mut command = vec![MAILCTL, "--config", installation.config().to_str().unwrap()];
    command.extend_from_slice(arguments);
    request["command"] = json!(command);
    request["environment"] = json!({"MAILCTL_FIXTURE_CA": server.certificate});
    terminal::run(request)
}

fn assert_prompt(result: &serde_json::Value, exit: i64) {
    assert_eq!(result["exit"], exit, "{result}");
    assert_eq!(result["prompted"], true);
    assert_eq!(result["echo_during_prompt"], false);
    assert_eq!(result["echo_enabled"], true);
    assert_eq!(result["secret_disclosed"], false);
}

fn assert_no_stored_secret(path: &std::path::Path, secret: &[u8]) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_stored_secret(&path, secret);
        } else {
            assert!(
                !fs::read(path)
                    .unwrap()
                    .windows(secret.len())
                    .any(|bytes| bytes == secret)
            );
        }
    }
}

#[test]
fn session_prompt_restores_terminal_on_cancellation_invalid_input_and_deadline() {
    let (installation, mut server) = installation();
    let mut config = Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.limits.operation_seconds = 2;
    config.limits.connection_seconds = 1;
    config.limits.initialization_seconds = 1;
    for grant in &mut config.grants {
        grant.limits = config.limits.clone();
    }
    config.grants[0].limits.secret_bytes = 8;
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    for (request, exit) in [
        (json!({"secret": ""}), 4),
        (json!({"secret": "x\u{8}"}), 4),
        (json!({"secret": "123456789"}), 4),
        (json!({"signal": "SIGINT"}), 130),
        (json!({"signal": "SIGTERM"}), 130),
        (json!({"wait": true}), 5),
    ] {
        let result = invoke_terminal(
            &installation,
            &server,
            &["--interactive", "doctor", "--check-account"],
            request,
        );
        assert_prompt(&result, exit);
    }
    assert_eq!(server.accepted(), 0);
    server.finish();
}

#[test]
fn session_resolution_requires_explicit_foreground_human_use() {
    let (installation, mut server) = installation();
    for (args, background) in [
        (vec!["doctor", "--check-account"], false),
        (vec!["--json", "doctor", "--check-account"], false),
        (
            vec!["--interactive", "--json", "doctor", "--check-account"],
            false,
        ),
        (vec!["--interactive", "doctor", "--check-account"], true),
    ] {
        let result = invoke_terminal(
            &installation,
            &server,
            &args,
            json!({"background": background}),
        );
        assert_eq!(result["exit"], 4, "{result}");
        assert_eq!(result["prompted"], false, "{result}");
        assert_eq!(result["echo_enabled"], true);
        if args.contains(&"--json") {
            assert!(
                result["output"]
                    .as_str()
                    .unwrap()
                    .contains("interaction_required")
            );
        }
    }
    let mut unattended = installation.cli();
    unattended.args(["--interactive", "doctor", "--check-account"]);
    let result = run_bounded(unattended);
    assert_eq!(result.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("Password:"));
    assert_eq!(server.accepted(), 0);
    server.finish();
}

#[test]
fn session_availability_is_not_authentication_and_grants_precede_prompting() {
    let (installation, mut server) = installation();
    for (args, exit, expected) in [
        (vec!["--interactive", "doctor"], 0, "configured"),
        (
            vec!["--interactive", "--account", "work", "credential", "status"],
            0,
            "configured",
        ),
        (
            vec!["--interactive", "--account", "work", "credential", "set"],
            4,
            "credential_unavailable",
        ),
        (
            vec!["--interactive", "--grant", "writer", "mailbox", "list"],
            3,
            "permission_denied",
        ),
        (
            vec![
                "--interactive",
                "--account",
                "personal",
                "doctor",
                "--check-account",
            ],
            3,
            "account_not_allowed",
        ),
    ] {
        let result = invoke_terminal(&installation, &server, &args, json!({}));
        assert_eq!(result["exit"], exit, "{result}");
        assert_eq!(result["prompted"], false);
        assert!(
            result["output"].as_str().unwrap().contains(expected),
            "{result}"
        );
        assert!(!result["output"].as_str().unwrap().contains("authenticated"));
    }
    assert_eq!(server.accepted(), 0);
    server.finish();
}

#[test]
fn session_secrets_and_provider_errors_remain_private_at_every_log_level() {
    let (installation, mut server) = installation();
    for level in ["off", "error", "warn", "info", "debug", "trace"] {
        server.reject_authentication(false);
        let result = invoke_terminal(
            &installation,
            &server,
            &[
                "--interactive",
                "--log-format",
                if level == "off" { "off" } else { "json" },
                "--log-level",
                if level == "off" { "trace" } else { level },
                "doctor",
                "--check-account",
            ],
            json!({"secret": "disposable-password"}),
        );
        assert_prompt(&result, 4);
        assert!(
            !result["output"]
                .as_str()
                .unwrap()
                .contains("fixture-private-provider-secret")
        );
        assert_no_stored_secret(
            installation.config().parent().unwrap(),
            b"disposable-password",
        );
    }
    server.finish();
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_session_sources_return_interaction_required_without_provisioning_tools() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use tokio::io::AsyncReadExt;
    let (installation, mut server) = installation();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut command = installation.mcp();
        command.env("MAILCTL_FIXTURE_CA", &server.certificate);
        let (transport, stderr) =
            TokioChildProcess::builder(tokio::process::Command::from(command))
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
        let capture = tokio::spawn(async move {
            let mut text = String::new();
            stderr
                .unwrap()
                .take(65536)
                .read_to_string(&mut text)
                .await
                .unwrap();
            text
        });
        let client = ().serve(transport).await.unwrap();
        let tools = client.list_all_tools().await.unwrap();
        assert!(
            !tools
                .iter()
                .any(|tool| tool.name.contains("credential") || tool.name.contains("setup"))
        );
        let response = client
            .call_tool(
                CallToolRequestParams::new("email_list_mailboxes")
                    .with_arguments(serde_json::Map::new()),
            )
            .await
            .unwrap();
        assert_eq!(
            response.structured_content.unwrap()["error"]["credential_failure"],
            "interaction_required"
        );
        client.cancel().await.unwrap();
        assert!(!capture.await.unwrap().contains("Password:"));
    })
    .await
    .unwrap();
    assert_eq!(server.accepted(), 0);
    server.finish();
}
