#![cfg(any(feature = "cli", feature = "mcp"))]

mod support;
use support::{Installation, assert_success, envelope, run_bounded};

fn executables() -> Vec<&'static str> {
    vec![
        #[cfg(feature = "cli")]
        support::MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ]
}

#[test]
fn each_component_sets_up_and_updates_accounts_without_replacing_other_identities() {
    for executable in executables() {
        let installation = Installation::empty();
        let created = run_bounded({
            let mut command = installation.command(executable);
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
            let mut command = installation.command(executable);
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

        let before = accounts(&installation);
        let personal_id = before["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["alias"] == "personal")
            .unwrap()["account_id"]
            .clone();

        let renamed = run_bounded({
            let mut command = installation.command(executable);
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
        let accounts = accounts(&installation)["accounts"]
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
}

#[test]
fn credential_commands_require_an_unambiguous_account_and_machine_set_never_prompts() {
    for executable in executables() {
        let installation = Installation::two_accounts();
        assert_success(&run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup"]);
            command
        }));
        for command_name in ["set", "delete", "status"] {
            let output = run_bounded({
                let mut command = installation.command(executable);
                command.args(["--json", "credential", command_name]);
                command
            });
            assert_eq!(output.status.code(), Some(2));
            assert_eq!(envelope(&output)["error"]["code"], "invalid_request");
            assert!(
                envelope(&output)["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("--account")
            );
        }
        let output = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "--account", "work", "credential", "set"]);
            command
        });
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(
            envelope(&output)["error"]["credential_failure"],
            "interaction_required"
        );
    }
}

#[test]
fn both_components_inspect_external_sources_and_require_an_authorized_explicit_check() {
    for executable in executables() {
        let installation = Installation::two_accounts();
        let text = std::fs::read_to_string(installation.config()).unwrap();
        std::fs::write(
            installation.config(),
            text.replace("source = \"native\"", "source = \"session\""),
        )
        .unwrap();
        assert_success(&run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup"]);
            command
        }));
        let status = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "--account", "work", "credential", "status"]);
            command
        });
        assert_success(&status);
        assert_eq!(
            envelope(&status)["result"]["availability"],
            "interaction_required"
        );
        assert_eq!(envelope(&status)["result"]["provisioning"], "external");
        let local = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "doctor"]);
            command
        });
        assert_success(&local);
        let local = envelope(&local);
        let accounts = local["result"]["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].get("authentication").is_none());

        let checked = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "--account", "work", "doctor", "--check-account"]);
            command
        });
        assert_eq!(checked.status.code(), Some(4));
        let checked = envelope(&checked);
        let authentication = &checked["result"]["accounts"][0]["authentication"];
        assert_eq!(authentication["outcome"]["status"], "failed");
        assert_eq!(
            authentication["outcome"]["error"]["credential_failure"],
            "interaction_required"
        );
        assert!(authentication["checked_at"].as_u64().unwrap() > 1_700_000_000);
        for (grant, account, expected) in [
            ("default", "personal", "account_not_allowed"),
            ("all", "", "invalid_request"),
        ] {
            let denied = run_bounded({
                let mut command = installation.command(executable);
                command.args(["--json", "--grant", grant]);
                if !account.is_empty() {
                    command.args(["--account", account]);
                }
                command.args(["doctor", "--check-account"]);
                command
            });
            assert_eq!(envelope(&denied)["error"]["code"], expected);
        }
    }
}

#[test]
fn setup_guidance_is_actionable_without_a_sibling_executable() {
    for executable in executables() {
        let installation = Installation::empty();
        let output = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup"]);
            command
        });
        assert_eq!(output.status.code(), Some(2));
        let result = envelope(&output);
        let message = result["error"]["message"].as_str().unwrap();
        assert!(message.contains("setup"));
        assert!(!message.contains("mailctl setup"));
        let diagnostics = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostics.contains(message));
    }
}

#[test]
fn unsupported_configuration_and_state_versions_preserve_established_identities() {
    for executable in executables() {
        let installation = Installation::two_accounts();
        assert_success(&run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup"]);
            command
        }));
        let original = std::fs::read_to_string(installation.config()).unwrap();
        let state_path = installation
            .config()
            .parent()
            .unwrap()
            .join("state/accounts.json");
        let state = std::fs::read(&state_path).unwrap();
        let unsupported = original.replacen(
            "version = 1",
            "version = 999\nfuture_schema_field = true",
            1,
        );
        std::fs::write(installation.config(), &unsupported).unwrap();
        let output = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup", "--alias", "work"]);
            command
        });
        assert_eq!(output.status.code(), Some(2));
        assert!(
            envelope(&output)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("compatible")
        );
        assert_eq!(std::fs::read(&state_path).unwrap(), state);
        assert_eq!(
            std::fs::read_to_string(installation.config()).unwrap(),
            unsupported
        );
        std::fs::write(installation.config(), &original).unwrap();
        let mut future_state: serde_json::Value = serde_json::from_slice(&state).unwrap();
        future_state["version"] = serde_json::json!(999);
        future_state["future_schema_field"] = serde_json::json!(true);
        let future_state = serde_json::to_vec(&future_state).unwrap();
        std::fs::write(&state_path, &future_state).unwrap();
        let output = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup", "--alias", "work"]);
            command
        });
        assert_eq!(output.status.code(), Some(2));
        assert!(
            envelope(&output)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("compatible")
        );
        assert_eq!(std::fs::read(&state_path).unwrap(), future_state);
        assert_eq!(
            std::fs::read_to_string(installation.config()).unwrap(),
            original
        );
    }
}

#[test]
fn setup_rejects_an_oversized_replacement_without_changing_configuration() {
    for executable in executables() {
        let installation = Installation::two_accounts();
        let mut text = format!(
            "version = 1\nstate_dir = {}\n",
            support::toml_string(&installation.config().parent().unwrap().join("state")),
        );
        let labels = (0..816)
            .map(|index| format!("'{index:04}{}'", "x".repeat(1020)))
            .collect::<Vec<_>>()
            .join(",");
        for index in 0..5 {
            text.push_str(&format!(
                "\n[[accounts]]\nkey = 'account{index}'\nalias = 'account{index}'\nserver = 'imap.example.test'\nusername = 'account{index}'\nmailboxes = [{labels}]\nfrom_identities = ['account{index}']\n[accounts.credential]\nsource = 'native'\n",
            ));
        }
        text.push_str(
            "\n[[grants]]\nname = 'default'\naccounts = ['account0']\nmailboxes = ['INBOX']\n",
        );
        let config = mailctl::config::Config::parse(&text).unwrap();
        assert!(toml::to_string_pretty(&config).unwrap().len() > 4 * 1024 * 1024);
        std::fs::write(installation.config(), &text).unwrap();
        let output = run_bounded({
            let mut command = installation.command(executable);
            command.args(["--json", "setup", "--alias", "account0"]);
            command
        });
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            std::fs::read_to_string(installation.config()).unwrap(),
            text
        );
    }
}

fn accounts(installation: &Installation) -> serde_json::Value {
    use mailctl::{
        config::Config,
        domain::{ListAccountsInput, Operation},
        policy::Narrowing,
        service::Service,
    };
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    let grant = config.default_grant.clone();
    let service = Service::open(config).unwrap();
    let context = service.context(&grant, &Narrowing::default()).unwrap();
    serde_json::to_value(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(service.execute(
                &context,
                Operation::ListAccounts(ListAccountsInput::default()),
            ))
            .unwrap(),
    )
    .unwrap()
}
