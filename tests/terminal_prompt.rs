#![cfg(all(target_os = "macos", feature = "cli"))]

mod support;

use std::{
    io::Write,
    process::{Command, Stdio},
};
use support::{Installation, MAILCTL, assert_success, run_bounded};

const TERMINAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/native_support/terminal.py"
);

#[test]
fn credential_prompt_restores_echo_after_invalid_input_and_cancellation() {
    let installation = Installation::two_accounts();
    setup(&installation);

    assert_prompt(&installation, serde_json::json!({"secret": ""}), 4);
    assert_prompt(&installation, serde_json::json!({"secret": "x\u{8}"}), 4);
    assert_prompt(&installation, serde_json::json!({"signal": "SIGINT"}), 130);
    assert_prompt(
        &installation,
        serde_json::json!({"secret": "x".repeat(16 * 1024 + 1)}),
        4,
    );
}

#[test]
fn credential_prompt_deadline_restores_echo() {
    let installation = Installation::two_accounts();
    let configuration = std::fs::read_to_string(installation.config()).unwrap();
    std::fs::write(
        installation.config(),
        configuration.replacen(
            "[[accounts]]",
            "[limits]\noperation_seconds = 1\nconnection_seconds = 1\ninitialization_seconds = 1\n\n[[accounts]]",
            1,
        ),
    )
    .unwrap();
    setup(&installation);

    assert_prompt(&installation, serde_json::json!({"wait": true}), 5);
}

fn setup(installation: &Installation) {
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
}

fn assert_prompt(installation: &Installation, request: serde_json::Value, exit: i64) {
    let mut request = request.as_object().unwrap().clone();
    request.insert(
        "command".into(),
        serde_json::json!([
            MAILCTL,
            "--config",
            installation.config(),
            "--account",
            "work",
            "credential",
            "set",
        ]),
    );
    let mut child = Command::new("python3")
        .arg(TERMINAL)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start terminal fixture");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("collect terminal fixture");
    assert!(output.status.success(), "terminal fixture failed");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["exit"], exit, "fixture output: {}", result["output"]);
    assert_eq!(result["prompted"], true);
    assert_eq!(result["echo_enabled"], true);
    assert_eq!(result["secret_disclosed"], false);
}
