#![cfg(all(windows, any(feature = "cli", feature = "mcp")))]
mod support;
use mailctl::{config::Config, domain::ErrorCode, service::Service};
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

#[test]
fn backup_creates_a_private_directory_without_inheriting_public_access() {
    let installation = Installation::two_accounts();
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    Service::setup(config.clone()).unwrap();
    let parent = installation
        .config()
        .parent()
        .unwrap()
        .join("public-backups");
    std::fs::create_dir(&parent).unwrap();
    let mut grant = Command::new("icacls.exe");
    grant.arg(&parent).args(["/grant", "*S-1-1-0:(OI)(CI)(R)"]);
    assert_success(&run_bounded(grant));

    let destination = parent.join("backup");
    Service::backup(&config, &destination).unwrap();
    let manifest = std::fs::read(destination.join("manifest.json")).unwrap();
    assert_eq!(
        Service::backup(&config, &destination).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        std::fs::read(destination.join("manifest.json")).unwrap(),
        manifest
    );
    Service::restore(&config, &destination).unwrap();
}

#[test]
fn backup_rejects_junction_ancestor_before_creating_destination() {
    let installation = Installation::two_accounts();
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    Service::setup(config.clone()).unwrap();
    let parent = installation.config().parent().unwrap();
    let target = parent.join("junction-target");
    std::fs::create_dir(&target).unwrap();
    let junction = parent.join("junction");
    let mut create_junction = Command::new("cmd.exe");
    create_junction
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target);
    assert_success(&run_bounded(create_junction));

    let destination = junction.join("backup");
    assert_eq!(
        Service::backup(&config, &destination).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert!(!target.join("backup").exists());
}
