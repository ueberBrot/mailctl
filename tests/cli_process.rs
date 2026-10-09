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
fn invalid_arguments_name_the_problem_and_keep_machine_output_after_the_error() {
    let installation = Installation::empty();
    for (arguments, expected) in [
        (vec!["message", "search"], "--mailbox"),
        (
            vec![
                "message",
                "search",
                "--mailbox",
                "reference",
                "--limit",
                "201",
            ],
            "--limit",
        ),
        (
            vec![
                "message",
                "search",
                "--mailbox",
                "reference",
                "--criteria",
                "fixture-private-predicate",
            ],
            "--criteria",
        ),
        (
            vec!["message", "search", "--mailbox", "reference", "--limit"],
            "--limit",
        ),
        (vec!["--log-level"], "--log-level"),
    ] {
        let output = run_bounded({
            let mut command = installation.cli();
            command
                .args(arguments)
                .args(["--json", "--log-format", "off"]);
            command
        });
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let error = &envelope(&output)["error"];
        assert_eq!(error["code"], "invalid_request");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
        assert!(message.contains("help"), "{message}");
        assert!(!message.contains("fixture-private-predicate"));
    }
}

#[test]
fn human_errors_keep_account_selection_guidance_when_logging_is_off() {
    let installation = Installation::two_accounts();
    assert_success(&run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "setup"]);
        command
    }));
    let output = run_bounded({
        let mut command = installation.cli();
        command.args(["--log-format", "off", "credential", "status"]);
        command
    });
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8(output.stderr).unwrap();
    assert!(message.contains("Select exactly one email account with --account"));
    assert!(message.contains("invalid_request"));
    assert!(!message.contains("operation_failed"));
}

#[test]
fn installed_guides_and_input_schemas_are_available_without_setup() {
    let installation = Installation::empty();
    let executables = [
        MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ];
    for executable in executables {
        let guide = run_bounded({
            let mut command = installation.command(executable);
            command.args(["guide", "reading"]);
            command
        });
        assert_success(&guide);
        let text = String::from_utf8(guide.stdout).unwrap();
        assert!(text.contains("mailbox") && text.contains("cursor"));
        assert!(guide.stderr.is_empty());

        let schema = run_bounded({
            let mut command = installation.command(executable);
            command.args(["schema", "search_messages"]);
            command
        });
        assert_success(&schema);
        let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
        assert!(schema["properties"].get("criteria").is_some());
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("mailbox"))
        );

        let guide = run_bounded({
            let mut command = installation.command(executable);
            command.args(["guide", "--json"]);
            command
        });
        assert_success(&guide);
        assert_eq!(envelope(&guide)["result"]["topic"], "overview");
        assert!(!installation.config().exists());
        assert!(
            !installation
                .config()
                .parent()
                .unwrap()
                .join("state")
                .exists()
        );
    }
}

#[test]
fn human_account_discovery_is_concise_and_keeps_identity_for_draft_workflows() {
    let installation = Installation::two_accounts();
    assert_success(&run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "setup"]);
        command
    }));
    let machine = run_bounded({
        let mut command = installation.cli();
        command.args(["--grant", "all", "--json", "account", "list"]);
        command
    });
    assert_success(&machine);
    let human = run_bounded({
        let mut command = installation.cli();
        command.args(["--grant", "all", "account", "list"]);
        command
    });
    assert_success(&human);
    let text = String::from_utf8(human.stdout).unwrap();
    for account in envelope(&machine)["result"]["accounts"].as_array().unwrap() {
        assert!(text.contains(account["alias"].as_str().unwrap()));
        assert!(text.contains(account["account_id"].as_str().unwrap()));
    }
    assert!(text.contains("generation 1"));
    assert!(text.lines().count() <= 8, "{text}");
    assert!(!text.contains("\"capabilities\""));
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
