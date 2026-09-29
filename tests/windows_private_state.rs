#![cfg(all(windows, any(feature = "cli", feature = "mcp")))]
mod support;
use std::process::Command;
use support::{Installation, assert_success, run_bounded};
fn executable() -> &'static str {
    #[cfg(feature = "cli")]
    return support::MAILCTL;
    #[cfg(not(feature = "cli"))]
    return support::MAILCTL_MCP;
}
#[test]
fn native_private_files_reject_foreign_read_access_and_hard_links() {
    for target in ["config.toml", "state", "state/accounts.json"] {
        let installation = Installation::empty();
        let mut setup = installation.command(executable());
        setup.args([
            "--json",
            "setup",
            "--alias",
            "work",
            "--server",
            "imap.example.test",
            "--username",
            "synthetic@example.test",
        ]);
        assert_success(&run_bounded(setup));
        let path = installation.config().parent().unwrap().join(target);
        let mut grant = Command::new("icacls.exe");
        grant.arg(&path).args(["/grant", "*S-1-1-0:(R)"]);
        assert_success(&run_bounded(grant));
        let mut status = installation.command(executable());
        status.args(["--json", "credential", "status"]);
        assert_eq!(run_bounded(status).status.code(), Some(2));
    }
    let installation = Installation::two_accounts();
    std::fs::hard_link(
        installation.config(),
        installation.config().with_extension("linked"),
    )
    .unwrap();
    let mut setup = installation.command(executable());
    setup.args(["--json", "setup"]);
    assert_eq!(run_bounded(setup).status.code(), Some(2));
}
