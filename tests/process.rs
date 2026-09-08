#![cfg(feature = "cli")]

mod support;

use std::process::Command;
use support::{Installation, MAILCTL, assert_success, envelope, run_bounded};

#[test]
fn cli_executable_exposes_ordinary_commands_without_an_embedded_mcp_server() {
    let help = Command::new(MAILCTL).arg("--help").output().unwrap();
    assert_success(&help);
    assert!(help.stderr.is_empty(), "help must not emit diagnostics");
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("Usage:") && text.contains("mailctl"));
    assert!(
        !text.contains("Serve email tools over STDIO"),
        "the CLI must not retain an embedded MCP command"
    );

    let version = Command::new(MAILCTL).arg("--version").output().unwrap();
    assert_success(&version);
    assert!(version.stderr.is_empty());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        "mailctl 0.1.0\n"
    );
}

#[test]
fn cli_setup_initializes_an_explicit_disposable_installation() {
    let installation = Installation::two_accounts();
    let output = run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "setup"]);
        command
    });
    assert_success(&output);
    let result = &envelope(&output)["result"];
    assert_eq!(result["accounts"], 2);
    assert_eq!(result["grants"], 3);
    assert!(result["installation_id"].is_string());
}

#[test]
fn cli_setup_creates_then_updates_accounts_without_replacing_other_identities() {
    let installation = Installation::empty();
    let created = run_bounded({
        let mut command = installation.cli();
        command.args([
            "--json",
            "setup",
            "--alias",
            "work",
            "--server",
            "imap.example.test",
            "--username",
            "work@example.test",
        ]);
        command
    });
    assert_success(&created);
    assert_eq!(envelope(&created)["result"]["accounts"], 1);

    let added = run_bounded({
        let mut command = installation.cli();
        command.args([
            "--json",
            "setup",
            "--alias",
            "personal",
            "--server",
            "imap.example.test",
            "--username",
            "personal@example.test",
        ]);
        command
    });
    assert_success(&added);
    assert_eq!(envelope(&added)["result"]["accounts"], 2);

    let before = run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "account", "list"]);
        command
    });
    assert_success(&before);
    let personal_id = envelope(&before)["result"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["alias"] == "personal")
        .unwrap()["account_id"]
        .clone();

    let renamed = run_bounded({
        let mut command = installation.cli();
        command.args([
            "--json",
            "--account",
            "personal",
            "setup",
            "--alias",
            "private",
        ]);
        command
    });
    assert_success(&renamed);
    let after = run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "account", "list"]);
        command
    });
    assert_success(&after);
    let accounts = envelope(&after)["result"]["accounts"]
        .as_array()
        .unwrap()
        .clone();
    assert!(accounts.iter().any(|account| account["alias"] == "work"));
    assert!(
        accounts
            .iter()
            .all(|account| account["alias"] != "personal")
    );
    assert_eq!(
        accounts
            .iter()
            .find(|account| account["alias"] == "private")
            .unwrap()["account_id"],
        personal_id
    );
}

#[test]
fn cli_credential_commands_remain_explicitly_unsupported() {
    let installation = Installation::two_accounts();
    for command_name in ["set", "delete", "status"] {
        let output = run_bounded({
            let mut command = installation.cli();
            command.args(["--json", "credential", command_name]);
            command
        });
        assert_eq!(output.status.code(), Some(8));
        assert_eq!(envelope(&output)["error"]["code"], "unsupported_capability");
    }
}
