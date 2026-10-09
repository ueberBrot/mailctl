mod support;
use mailctl::{config::Config, domain::ErrorCode, service::Service};

#[test]
fn component_upgrade_verification_refuses_unknown_schema_without_replacing_history() {
    let installation = support::Installation::two_accounts();
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    Service::setup(config.clone()).unwrap();
    Service::verify_state(&config).unwrap();
    let path = config.state_dir.join("drafts.sqlite");
    let database = rusqlite::Connection::open(&path).unwrap();
    database
        .execute_batch("ALTER TABLE draft_operations ADD COLUMN unsupported TEXT;")
        .unwrap();
    drop(database);
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        Service::verify_state(&config).unwrap_err().code,
        ErrorCode::JournalUnavailable
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn both_executables_expose_offline_maintenance_with_a_suspension_receipt() {
    for executable in [
        #[cfg(feature = "cli")]
        support::MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ] {
        let installation = support::Installation::two_accounts();
        let mut help = installation.command(executable);
        help.args(["state", "--help"]);
        let help = support::run_bounded(help);
        support::assert_success(&help);
        let help = String::from_utf8(help.stdout).unwrap();
        for guidance in [
            "OFFLINE RECOVERY",
            "external",
            "drafts.suspended",
            "journal_full",
        ] {
            assert!(help.contains(guidance), "missing guidance: {guidance}");
        }
        let config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        Service::setup(config.clone()).unwrap();
        let destination = config.state_dir.parent().unwrap().join("backup");
        for (action, flag) in [("backup", "--destination"), ("restore", "--source")] {
            let mut command = installation.command(executable);
            command
                .args(["--json", "state", action, flag])
                .arg(&destination);
            let output = support::run_bounded(command);
            support::assert_success(&output);
            let result = support::envelope(&output);
            assert_eq!(result["result"]["action"], action);
            assert_eq!(
                result["result"]["draft_creation_suspended"],
                action == "restore"
            );
        }
        let mut command = installation.command(executable);
        command.args(["--json", "state", "verify"]);
        support::assert_success(&support::run_bounded(command));
    }
}

#[test]
fn restore_rejects_incomplete_tampered_and_foreign_snapshots_before_mutation() {
    for fault in ["incomplete", "tampered", "foreign"] {
        let installation = support::Installation::two_accounts();
        let config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        Service::setup(config.clone()).unwrap();
        let source = config.state_dir.parent().unwrap().join("backup");
        Service::backup(&config, &source).unwrap();
        let before = std::fs::read(config.state_dir.join("accounts.json")).unwrap();
        match fault {
            "incomplete" => std::fs::remove_file(source.join("manifest.json")).unwrap(),
            "tampered" => std::fs::write(source.join("drafts.sqlite"), b"broken snapshot").unwrap(),
            _ => {
                let other = support::Installation::two_accounts();
                let other_config =
                    Config::parse(&std::fs::read_to_string(other.config()).unwrap()).unwrap();
                Service::setup(other_config.clone()).unwrap();
                assert!(Service::restore(&other_config, &source).is_err());
                assert!(!other_config.state_dir.join("drafts.suspended").exists());
                continue;
            }
        }
        assert!(Service::restore(&config, &source).is_err());
        assert_eq!(
            std::fs::read(config.state_dir.join("accounts.json")).unwrap(),
            before
        );
        assert!(!config.state_dir.join("drafts.suspended").exists());
    }
}

#[test]
fn restore_rejects_unknown_registry_layout_before_mutation() {
    use sha2::{Digest, Sha256};

    for future_layout in [false, true] {
        let installation = support::Installation::two_accounts();
        let config =
            Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        Service::setup(config.clone()).unwrap();
        let source = config.state_dir.parent().unwrap().join("backup");
        Service::backup(&config, &source).unwrap();
        let before = std::fs::read(config.state_dir.join("accounts.json")).unwrap();
        let mut registry: serde_json::Value = serde_json::from_slice(&before).unwrap();
        registry["unknown_field"] = true.into();
        if future_layout {
            registry = serde_json::json!({"future": {"layout": true}});
        }
        let bytes = serde_json::to_vec(&registry).unwrap();
        std::fs::write(source.join("accounts.json"), &bytes).unwrap();
        let manifest_path = source.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let checksum: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        manifest["files"]["accounts.json"] = checksum.into();
        std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        assert_eq!(
            Service::restore(&config, &source).unwrap_err(),
            mailctl::domain::Error::setup_required()
        );
        assert_eq!(
            std::fs::read(config.state_dir.join("accounts.json")).unwrap(),
            before
        );
        assert!(!config.state_dir.join("drafts.suspended").exists());
    }
}

#[test]
fn interrupted_restore_remains_fenced_and_can_be_repeated() {
    let installation = support::Installation::two_accounts();
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    Service::setup(config.clone()).unwrap();
    let source = config.state_dir.parent().unwrap().join("backup");
    Service::backup(&config, &source).unwrap();
    // Fail registry replacement after the journal has been restored.
    let path = config.state_dir.join("accounts.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(Service::restore(&config, &source).is_err());
    assert_eq!(
        std::fs::read(config.state_dir.join("drafts.suspended")).unwrap(),
        b"restoring"
    );
    assert!(Service::open(config.clone()).is_err());
    std::fs::remove_dir(&path).unwrap();
    let receipt = Service::restore(&config, &source).unwrap();
    assert!(receipt.draft_creation_suspended);
    Service::open(config).unwrap();
}

#[test]
fn maintenance_preserves_canonical_identity_and_rejects_unsafe_backup_destinations() {
    let installation = support::Installation::two_accounts();
    let mut config =
        Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    let original = Service::setup(config.clone()).unwrap();
    let source = config.state_dir.parent().unwrap().join("canonical-backup");
    config.state_dir = config.state_dir.join(".");
    let nested = config.state_dir.join("backup");
    assert!(Service::backup(&config, &nested).is_err());
    assert!(!nested.exists());
    assert_eq!(
        Service::backup(&config, &source)
            .unwrap()
            .installation
            .installation_id,
        original.installation_id
    );
    assert!(Service::backup(&config, &source).is_err());
    Service::verify_state(&config).unwrap();
    Service::restore(&config, &source).unwrap();
    assert_eq!(
        Service::setup(config).unwrap().installation_id,
        original.installation_id
    );
}
