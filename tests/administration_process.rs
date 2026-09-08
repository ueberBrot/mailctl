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
        service
            .execute(
                &context,
                Operation::ListAccounts(ListAccountsInput::default()),
            )
            .unwrap(),
    )
    .unwrap()
}
