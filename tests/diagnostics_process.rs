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
