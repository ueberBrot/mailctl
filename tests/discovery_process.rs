//! Portable acceptance coverage for the independently runnable email CLI.
#![cfg(feature = "cli")]

mod support;

use std::{collections::BTreeMap, thread};
use support::{Installation, MAILCTL, assert_success, envelope, run_bounded};

fn setup(installation: &Installation) {
    let output = run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "setup"]);
        command
    });
    assert_success(&output);
}

fn accounts(installation: &Installation, arguments: &[&str]) -> serde_json::Value {
    let output = run_bounded({
        let mut command = installation.cli();
        command.args(arguments);
        command
    });
    assert_success(&output);
    envelope(&output)["result"].clone()
}

fn account_ids(result: &serde_json::Value) -> BTreeMap<String, String> {
    result["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| {
            (
                account["alias"].as_str().unwrap().to_owned(),
                account["account_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn default_grant_and_explicit_narrowing_discover_only_authorized_account_aliases() {
    let installation = Installation::two_accounts();
    setup(&installation);

    let default = accounts(&installation, &["--json", "account", "list"]);
    assert_eq!(default["complete"], true);
    assert_eq!(default["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(default["accounts"][0]["alias"], "work");

    let all = accounts(
        &installation,
        &["--json", "--grant", "all", "account", "list"],
    );
    let mut aliases = all["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["alias"].as_str().unwrap())
        .collect::<Vec<_>>();
    aliases.sort_unstable();
    assert_eq!(aliases, ["personal", "work"]);

    let selected = accounts(
        &installation,
        &[
            "--json",
            "--grant",
            "all",
            "--account",
            "personal",
            "account",
            "list",
        ],
    );
    assert_eq!(selected["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(selected["accounts"][0]["alias"], "personal");

    let denied_by_default_grant = accounts(
        &installation,
        &["--json", "--account", "personal", "account", "list"],
    );
    assert_eq!(denied_by_default_grant["accounts"], serde_json::json!([]));
}

#[test]
fn concurrent_first_setup_preserves_one_shared_account_identity() {
    let installation = Installation::two_accounts();
    let first = {
        let mut command = installation.cli();
        command.args(["--json", "setup"]);
        thread::spawn(move || run_bounded(command))
    };
    let second = {
        let mut command = installation.cli();
        command.args(["--json", "setup"]);
        thread::spawn(move || run_bounded(command))
    };
    assert_success(&first.join().unwrap());
    assert_success(&second.join().unwrap());

    let result = accounts(
        &installation,
        &["--json", "--grant", "all", "account", "list"],
    );
    let ids = account_ids(&result);
    assert_eq!(ids.len(), 2);
    assert!(ids.values().all(|id| uuid::Uuid::parse_str(id).is_ok()));
}

#[test]
fn repeated_setup_preserves_every_configured_account_identity() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let before = account_ids(&accounts(
        &installation,
        &["--json", "--grant", "all", "account", "list"],
    ));

    setup(&installation);
    let after = account_ids(&accounts(
        &installation,
        &["--json", "--grant", "all", "account", "list"],
    ));
    assert_eq!(after, before);
}

#[test]
fn copied_cli_uses_the_same_explicit_configuration_and_installation_history() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let expected = accounts(&installation, &["--json", "account", "list"]);
    let copied = installation.copy_executable(MAILCTL, "mailctl-isolated-copy");
    let output = run_bounded({
        let mut command = installation.command(copied.to_str().unwrap());
        command.args(["--json", "account", "list"]);
        command
    });
    assert_success(&output);
    assert_eq!(envelope(&output)["result"], expected);
}
