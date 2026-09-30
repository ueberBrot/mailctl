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
        os::unix::{
            fs::{MetadataExt, PermissionsExt, chown, symlink},
            process::CommandExt,
        },
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

    #[test]
    #[ignore = "requires a disposable root Linux environment with POSIX ACL support"]
    fn systemd_source_accepts_only_the_service_user_acl() {
        assert_eq!(
            std::env::var("MAILCTL_DISPOSABLE_SYSTEMD").as_deref(),
            Ok("1")
        );
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        const UID: u32 = 65534;
        const NO_ID: u32 = u32::MAX;
        let installation = Installation::empty();
        let outer = installation.config().parent().unwrap();
        let executable = outer.join("source-probe");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(outer, fs::Permissions::from_mode(0o755)).unwrap();
        let directory = outer.join("credentials");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("password");
        fs::write(&path, b"fixture").unwrap();

        let directory_acl = [
            (1, 5, NO_ID),
            (2, 5, UID),
            (4, 0, NO_ID),
            (16, 5, NO_ID),
            (32, 0, NO_ID),
        ];
        let file_acl = [
            (1, 4, NO_ID),
            (2, 4, UID),
            (4, 0, NO_ID),
            (16, 4, NO_ID),
            (32, 0, NO_ID),
        ];
        let set_acl = |path: &Path, entries: &[(u16, u16, u32)]| {
            let mut acl = 2_u32.to_le_bytes().to_vec();
            for (tag, permissions, id) in entries {
                acl.extend(tag.to_le_bytes());
                acl.extend(permissions.to_le_bytes());
                acl.extend(id.to_le_bytes());
            }
            rustix::fs::setxattr(
                path,
                "system.posix_acl_access",
                &acl,
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
        };
        let probe_as = |uid, expected| {
            let mut command = Command::new(&executable);
            command
                .args(["--exact", "linux::source_probe", "--nocapture"])
                .env("CREDENTIALS_DIRECTORY", &directory)
                .env("MAILCTL_SYSTEMD_NAME", "password")
                .env("MAILCTL_SYSTEMD_PROBE", expected)
                .uid(uid)
                .gid(uid);
            assert_success(&run_bounded(command));
        };
        set_acl(&directory, &directory_acl);
        set_acl(&path, &file_acl);
        assert_eq!(fs::metadata(&directory).unwrap().uid(), 0);
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o550);
        assert_eq!(fs::metadata(&path).unwrap().uid(), 0);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o440);
        probe_as(UID, "7");
        probe_as(0, "denied");

        for index in [1, 2, 4] {
            let mut acl = file_acl;
            if index == 1 {
                acl[index].2 = UID - 1;
            } else {
                acl[index].1 = 4;
            }
            set_acl(&path, &acl);
            probe_as(UID, "denied");
        }
        for (tag, id) in [(2, UID + 1), (8, UID)] {
            let mut acl = file_acl.to_vec();
            acl.insert(if tag == 2 { 2 } else { 3 }, (tag, 4, id));
            set_acl(&path, &acl);
            probe_as(UID, "denied");
        }
        set_acl(&path, &file_acl);
        let mut acl = directory_acl;
        acl[2].1 = 5;
        set_acl(&directory, &acl);
        probe_as(UID, "denied");
        set_acl(&directory, &directory_acl);
        rustix::fs::removexattr(&path, "system.posix_acl_access").unwrap();
        chown(&path, Some(0), Some(UID)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        probe_as(UID, "denied");
        set_acl(&path, &file_acl);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        probe_as(UID, "denied");
    }
}
