#![cfg(any(feature = "cli", feature = "mcp"))]
#[path = "../../support/mod.rs"]
mod support;
use support::{Installation, assert_success, envelope, run_bounded};

#[test]
#[allow(
    clippy::single_element_loop,
    reason = "feature selections exercise one or both executables"
)]
fn new_setup_omits_mailbox_scopes_and_keeps_read_only_access() {
    for executable in [
        #[cfg(feature = "cli")]
        support::MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ] {
        let installation = Installation::empty();
        let mut setup = installation.command(executable);
        setup.args([
            "--json",
            "setup",
            "--alias",
            "work",
            "--server",
            "imap.example.test",
            "--username",
            "work@example.test",
        ]);
        assert_success(&run_bounded(setup));
        let configuration: toml::Value =
            toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        assert!(configuration["accounts"][0].get("mailboxes").is_none());
        assert!(configuration["grants"][0].get("mailboxes").is_none());
        assert_eq!(
            configuration["grants"][0]["profile"].as_str(),
            Some("read_only")
        );
        assert!(configuration["accounts"][0].get("drafts_mailbox").is_none());
    }
}

#[test]
#[allow(
    clippy::single_element_loop,
    reason = "feature selections exercise one or both executables"
)]
fn setup_edits_preserve_explicit_scopes_and_credential_references() {
    for executable in [
        #[cfg(feature = "cli")]
        support::MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ] {
        let installation = Installation::two_accounts();
        let read = || {
            toml::from_str::<toml::Value>(&std::fs::read_to_string(installation.config()).unwrap())
                .unwrap()
        };
        let original = read();
        for arguments in [
            vec!["--json", "setup"],
            vec!["--json", "--account", "work", "setup", "--alias", "office"],
        ] {
            let mut setup = installation.command(executable);
            setup.args(arguments);
            assert_success(&run_bounded(setup));
            let current = read();
            for index in 0..2 {
                for field in ["key", "mailboxes", "credential"] {
                    assert_eq!(
                        current["accounts"][index][field],
                        original["accounts"][index][field]
                    );
                }
            }
            for index in 0..3 {
                assert_eq!(
                    current["grants"][index]["mailboxes"],
                    original["grants"][index]["mailboxes"]
                );
            }
            for (field, expected) in original["accounts"][1].as_table().unwrap() {
                assert_eq!(&current["accounts"][1][field], expected);
            }
        }
    }
}

#[test]
#[allow(
    clippy::single_element_loop,
    reason = "feature selections exercise one or both executables"
)]
fn setup_and_credential_status_do_not_load_tls_trust() {
    for executable in [
        #[cfg(feature = "cli")]
        support::MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ] {
        let installation = Installation::two_accounts();
        let mut setup = installation.command(executable);
        setup
            .env_remove("MAILCTL_FIXTURE_CA")
            .args(["--json", "setup"]);
        assert_success(&run_bounded(setup));
        let mut status = installation.command(executable);
        status.env_remove("MAILCTL_FIXTURE_CA").args([
            "--json",
            "--account",
            "work",
            "credential",
            "status",
        ]);
        let output = run_bounded(status);
        assert_success(&output);
        assert_eq!(envelope(&output)["result"]["availability"], "available");
        assert_eq!(envelope(&output)["result"]["provisioning"], "external");
    }
}
