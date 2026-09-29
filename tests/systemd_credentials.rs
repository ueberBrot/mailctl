mod support;

#[test]
fn configuration_validates_systemd_credential_names_and_rejects_paths() {
    use mailctl::config::{Config, CredentialSource};
    let installation = support::Installation::two_accounts();
    let mut config =
        Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    for name in ["imap-password", "work.password", "account_1"] {
        config.accounts[0].credential = CredentialSource::Systemd { name: name.into() };
        assert!(config.validate().is_ok(), "rejected {name:?}");
    }
    for name in [
        "",
        ".",
        "..",
        "../secret",
        "/secret",
        "a/b",
        "a\\b",
        "a\0b",
        "white space",
    ] {
        config.accounts[0].credential = CredentialSource::Systemd { name: name.into() };
        assert!(config.validate().is_err(), "accepted {name:?}");
    }
    assert!(
        serde_json::from_value::<CredentialSource>(serde_json::json!({
            "source": "systemd", "path": "/etc/secret"
        }))
        .is_err()
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::support::{Installation, assert_success, run_bounded};
    use mailctl::{
        config::{CredentialSource, Limits},
        credentials::{Availability, ResolutionLimits, SourceError, source_for},
    };
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
        process::Command,
    };
    use uuid::Uuid;

    #[test]
    fn source_probe() {
        let Ok(expected) = std::env::var("MAILCTL_SYSTEMD_PROBE") else {
            return;
        };
        let source = source_for(&CredentialSource::Systemd {
            name: std::env::var("MAILCTL_SYSTEMD_NAME").unwrap(),
        });
        let id = Uuid::new_v4();
        assert!(source.mutable_store().is_none());
        let limits = ResolutionLimits::try_from(&Limits {
            secret_bytes: 8,
            ..Limits::default()
        })
        .unwrap();
        let resolved = source
            .resolve_with_limits(id, &limits)
            .map(|secret| secret.len());
        let (availability, result) = match expected.as_str() {
            "missing" => (Availability::Missing, Err(SourceError::Missing)),
            "denied" => (Availability::AccessDenied, Err(SourceError::AccessDenied)),
            "unavailable" => (Availability::Unavailable, Err(SourceError::Unavailable)),
            "invalid" => (Availability::Configured, Err(SourceError::InvalidSecret)),
            length => (Availability::Configured, Ok(length.parse().unwrap())),
        };
        assert_eq!(source.availability(id), availability);
        assert_eq!(resolved, result);
    }

    fn probe(directory: Option<&Path>, name: &str, expected: &str) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "linux::source_probe", "--nocapture"])
            .env_remove("CREDENTIALS_DIRECTORY")
            .env("MAILCTL_SYSTEMD_NAME", name)
            .env("MAILCTL_SYSTEMD_PROBE", expected);
        if let Some(directory) = directory {
            command.env("CREDENTIALS_DIRECTORY", directory);
        }
        assert_success(&run_bounded(command));
    }

    #[test]
    fn systemd_source_is_bounded_metadata_only_and_preserves_whitespace() {
        let installation = Installation::empty();
        let directory = installation.config().parent().unwrap();
        let path = directory.join("password");
        probe(None, "password", "unavailable");
        probe(Some(Path::new("relative")), "password", "unavailable");
        probe(Some(directory), "password", "missing");
        for (bytes, expected) in [
            (b" pass \r\n".as_slice(), "8"),
            (b"123456789".as_slice(), "invalid"),
            (b"\xff".as_slice(), "invalid"),
            (b"".as_slice(), "invalid"),
        ] {
            if path.exists() {
                fs::remove_file(&path).unwrap();
            }
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            probe(Some(directory), "password", expected);
        }
    }

    #[test]
    fn systemd_source_rejects_redirected_writable_and_nonregular_files() {
        let installation = Installation::empty();
        let directory = installation.config().parent().unwrap();
        let path = directory.join("password");
        fs::write(&path, b"fixture").unwrap();
        for mode in [0o600, 0o440, 0o404, 0o000] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            probe(Some(directory), "password", "denied");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        probe(Some(directory), "../password", "denied");
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        probe(Some(directory), "link", "denied");
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        probe(Some(directory), "password", "denied");
        fs::remove_file(&link).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        probe(Some(directory), "password", "denied");
        fs::remove_dir(&path).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR,
            0,
        )
        .unwrap();
        probe(Some(directory), "password", "denied");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let redirected = directory.join("redirected");
        symlink(directory, &redirected).unwrap();
        probe(Some(&redirected), "password", "denied");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        probe(Some(directory), "password", "denied");
    }
}
