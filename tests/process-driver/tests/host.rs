#![cfg(any(feature = "cli", feature = "mcp"))]
#[path = "../../support/mod.rs"]
mod support;
use support::{Installation, assert_success, envelope, run_bounded};

#[test]
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
