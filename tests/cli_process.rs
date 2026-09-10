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

#[cfg(target_os = "macos")]
#[test]
fn isolated_invocation_is_explicit_and_cannot_run_operator_setup() {
    let help = Command::new(MAILCTL).arg("--help").output().unwrap();
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("--isolated")
    );

    let installation = Installation::empty();
    let output = run_bounded({
        let mut command = installation.cli();
        command.args(["--isolated", "--json", "setup"]);
        command
    });
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(envelope(&output)["error"]["code"], "invalid_request");
    assert!(!installation.config().exists());
}
