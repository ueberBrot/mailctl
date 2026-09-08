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
fn each_component_keeps_credential_commands_explicitly_unsupported() {
    for executable in executables() {
        let installation = Installation::two_accounts();
        for command_name in ["set", "delete", "status"] {
            let output = run_bounded({
                let mut command = installation.command(executable);
                command.args(["--json", "credential", command_name]);
                command
            });
            assert_eq!(output.status.code(), Some(8));
            assert_eq!(envelope(&output)["error"]["code"], "unsupported_capability");
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
        service
            .execute(
                &context,
                Operation::ListAccounts(ListAccountsInput::default()),
            )
            .unwrap(),
    )
    .unwrap()
}
