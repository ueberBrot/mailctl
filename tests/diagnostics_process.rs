#![cfg(feature = "cli")]

mod support;

use serde_json::Value;
use std::{path::PathBuf, process::Command};
use support::MAILCTL;

fn missing_config() -> PathBuf {
    std::env::temp_dir().join(format!("mailctl-missing-{}.toml", uuid::Uuid::new_v4()))
}

#[test]
fn explicit_off_suppresses_diagnostics_for_failed_machine_commands() {
    let output = Command::new(MAILCTL)
        .arg("--config")
        .arg(missing_config())
        .args([
            "--json",
            "--log-format",
            "off",
            "--log-level",
            "trace",
            "account",
            "list",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error"]["code"], "invalid_request");
}

#[test]
fn machine_modes_reject_compact_diagnostics_before_initialization() {
    let output = Command::new(MAILCTL)
        .arg("--config")
        .arg(missing_config())
        .args(["--json", "--log-format", "compact", "account", "list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["event"], "operation_failed");
    assert_eq!(diagnostic["code"], "invalid_request");
    let _: Value = serde_json::from_slice(&output.stdout).unwrap();
}

#[test]
fn every_log_level_keeps_request_content_and_dependency_filters_out_of_diagnostics() {
    let secret = "fixture-secret\u{1b}]52;c;payload\u{7}\u{202e}";
    for level in ["error", "warn", "info", "debug", "trace"] {
        let output = Command::new(MAILCTL)
            .arg("--config")
            .arg(missing_config().join(secret))
            .args([
                "--json",
                "--log-format",
                "json",
                "--log-level",
                level,
                "--color",
                "always",
                "--account",
                secret,
                "account",
                "list",
            ])
            .env("RUST_LOG", "trace")
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("fixture-secret") && !stderr.contains("payload"));
        assert!(!stderr.contains('\u{1b}') && !stderr.contains('\u{202e}'));
        let events: Vec<Value> = stderr
            .lines()
            .map(|line| {
                assert!(line.len() < 2048);
                serde_json::from_str(line).unwrap()
            })
            .collect();
        assert!(!events.is_empty());
        let failure = events
            .iter()
            .find(|event| event["event"] == "operation_failed")
            .unwrap();
        assert_eq!(failure["request_id"], envelope["request_id"]);
        assert_eq!(failure["code"], "invalid_request");
        if matches!(level, "info" | "debug" | "trace") {
            assert_eq!(events[0]["event"], "request_started");
            assert_eq!(events[0]["request_id"], envelope["request_id"]);
        }
        let started = events
            .iter()
            .any(|event| event["event"] == "process_started");
        assert_eq!(started, matches!(level, "info" | "debug" | "trace"));
    }
}

#[test]
fn diagnostic_controls_apply_to_early_schema_errors() {
    for prefix in [None, Some("setup")] {
        for format in ["off", "json"] {
            let mut command = Command::new(MAILCTL);
            command.arg("--config").arg(missing_config());
            if let Some(prefix) = prefix {
                command.arg(prefix);
            }
            let output = command
                .args([
                    "--log-format",
                    format,
                    "--color",
                    "never",
                    "--not-an-option",
                    "fixture-secret",
                ])
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            if format == "off" {
                assert!(output.stderr.is_empty());
            } else {
                let event: Value = serde_json::from_slice(&output.stderr).unwrap();
                assert_eq!(event["code"], "invalid_request");
                assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-secret"));
            }
        }
    }
}

#[test]
fn human_compact_diagnostics_remain_plain_on_redirected_streams() {
    for color in ["auto", "always", "never"] {
        let output = Command::new(MAILCTL)
            .arg("--config")
            .arg(missing_config())
            .args([
                "--log-format",
                "compact",
                "--color",
                color,
                "account",
                "list",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("operation_failed") && text.contains("invalid_request"));
        assert!(!text.contains('\u{1b}'));
    }
}

#[cfg(unix)]
#[test]
fn color_is_resolved_for_each_terminal_stream_and_respects_no_color() {
    use std::io::Write;
    use std::process::Stdio;
    let installation = support::Installation::two_accounts();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    support::assert_success(&support::run_bounded(setup));
    for stdout_terminal in [false, true] {
        for stderr_terminal in [false, true] {
            for (color, no_color) in [("auto", ""), ("always", ""), ("never", ""), ("always", "1")]
            {
                let request = serde_json::json!({
                    "command": [MAILCTL, "--config", installation.config().to_str().unwrap(), "--color", color,
                        "--log-format", "compact", "--log-level", "info", "account", "list"],
                    "stdout": stdout_terminal, "stderr": stderr_terminal,
                });
                let mut child = Command::new("python3")
                    .arg(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/support/output_terminal.py"
                    ))
                    .env("NO_COLOR", no_color)
                    .env("TERM", "xterm-256color")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(&serde_json::to_vec(&request).unwrap())
                    .unwrap();
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let captured: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(captured["exit"], 0);
                assert!(captured["stdout"].as_str().unwrap().contains("Result"));
                assert_eq!(
                    captured["stdout"].as_str().unwrap().contains('\u{1b}'),
                    stdout_terminal && color != "never" && no_color.is_empty()
                );
                assert_eq!(
                    captured["stderr"].as_str().unwrap().contains('\u{1b}'),
                    stderr_terminal && color != "never" && no_color.is_empty()
                );
            }
        }
    }
}

#[cfg(feature = "mcp")]
#[test]
fn mcp_startup_and_administration_keep_machine_streams_clean() {
    for administration in [false, true] {
        for format in ["off", "json", "compact"] {
            let mut command = Command::new(support::MAILCTL_MCP);
            command.arg("--config").arg(missing_config()).args([
                "--color",
                "always",
                "--log-format",
                format,
            ]);
            if administration {
                command.args(["--json", "doctor"]);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            if administration {
                let _: Value = serde_json::from_slice(&output.stdout).unwrap();
            } else {
                assert!(output.stdout.is_empty());
            }
            assert!(!output.stderr.contains(&0x1b));
            if format == "off" {
                assert!(output.stderr.is_empty());
            } else {
                for line in String::from_utf8(output.stderr).unwrap().lines() {
                    let event: Value = serde_json::from_str(line).unwrap();
                    assert_eq!(event["code"], "invalid_request");
                }
            }
        }
    }
}

#[test]
fn invalid_configuration_payloads_stay_private_and_schema_guidance_survives() {
    let installation = support::Installation::two_accounts();
    for level in ["error", "warn", "info", "debug", "trace"] {
        std::fs::write(
            installation.config(),
            "fixture-private-config-secret\u{1b}]52;c;payload\u{7}".repeat(3000),
        )
        .unwrap();
        let mut command = installation.cli();
        command.args(["--json", "--log-level", level, "account", "list"]);
        let output = support::run_bounded(command);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            support::envelope(&output)["error"]["code"],
            "invalid_request"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("fixture-private") && !stderr.contains("payload"));
        for line in stderr.lines() {
            assert!(line.len() < 2048);
            let _: Value = serde_json::from_str(line).unwrap();
        }
    }
    std::fs::write(installation.config(), "version = 999\n").unwrap();
    let mut command = installation.cli();
    command.args(["--log-format", "json", "account", "list"]);
    let output = support::run_bounded(command);
    let event: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(
        event["message"],
        mailctl::domain::Error::incompatible_schema().message
    );
}
