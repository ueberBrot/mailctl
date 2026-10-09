#![cfg(unix)]
#[path = "../../support/mod.rs"]
mod support;
use mailctl::{
    config::{CredentialCommand, CredentialSource, Limits},
    credentials::{Availability, ResolutionLimits, SourceError, source_for},
};
use std::fs;
use support::Installation;
use uuid::Uuid;

fn configuration(installation: &Installation, args: Vec<String>) -> CredentialCommand {
    CredentialCommand {
        executable: fs::canonicalize(env!("CARGO_BIN_EXE_credential-helper")).unwrap(),
        args,
        working_dir: installation.config().parent().unwrap().into(),
        protected_paths: vec![],
    }
}

#[test]
fn command_status_is_metadata_only_and_secret_output_is_bounded() {
    let installation = Installation::empty();
    let path = installation.config().with_file_name("synthetic-secret");
    let config = configuration(
        &installation,
        vec!["file".into(), path.to_str().unwrap().into()],
    );
    let source = source_for(&CredentialSource::Command(config));
    let id = Uuid::new_v4();
    assert_eq!(source.availability(id), Availability::Configured);
    assert!(source.mutable_store().is_none());
    let limits = ResolutionLimits::try_from(&Limits {
        secret_bytes: 8,
        ..Limits::default()
    })
    .unwrap();
    for (bytes, expected) in [
        (b" pass \r\n".as_slice(), Some(6)),
        (b"pass\n\n".as_slice(), Some(5)),
        (b"pass\r".as_slice(), Some(5)),
        (b"12345678\r\n".as_slice(), Some(8)),
        (b"123456789".as_slice(), None),
        (b"\xff".as_slice(), None),
        (b"\r\n".as_slice(), None),
        (b"".as_slice(), None),
    ] {
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            source
                .resolve_with_limits(id, &limits)
                .map(|secret| secret.len()),
            expected.ok_or(SourceError::InvalidSecret)
        );
    }
}

#[test]
fn command_secret_limit_preserves_a_full_sized_value_and_rejects_overflow() {
    let installation = Installation::empty();
    let path = installation.config().with_file_name("synthetic-secret");
    let source = source_for(&CredentialSource::Command(configuration(
        &installation,
        vec!["file".into(), path.to_str().unwrap().into()],
    )));
    let limits = ResolutionLimits::try_from(&Limits {
        secret_bytes: mailctl::credentials::MAX_SECRET_BYTES,
        ..Limits::default()
    })
    .unwrap();
    let id = Uuid::new_v4();
    for suffix in [b"".as_slice(), b"\n", b"\r\n"] {
        let mut bytes = vec![b'x'; limits.secret_bytes()];
        bytes.extend_from_slice(suffix);
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            source.resolve_with_limits(id, &limits).unwrap().len(),
            limits.secret_bytes()
        );
    }
    fs::write(&path, vec![b'x'; limits.secret_bytes() + 3]).unwrap();
    assert_eq!(
        source.resolve_with_limits(id, &limits).unwrap_err(),
        SourceError::InvalidSecret
    );
}

#[test]
fn ready_command_streams_are_drained_fairly_with_inclusive_limits() {
    let installation = Installation::empty();
    let limits = ResolutionLimits::try_from(&Limits {
        secret_bytes: mailctl::credentials::MAX_SECRET_BYTES,
        command_stderr_bytes: 32 * 1024,
        ..Limits::default()
    })
    .unwrap();
    for extra_stderr in [0, 1] {
        let source = source_for(&CredentialSource::Command(configuration(
            &installation,
            vec![
                "streams".into(),
                limits.secret_bytes().to_string(),
                (limits.stderr_bytes() + extra_stderr).to_string(),
            ],
        )));
        assert_eq!(
            source
                .resolve_with_limits(Uuid::new_v4(), &limits)
                .map(|secret| secret.len()),
            if extra_stderr == 0 {
                Ok(limits.secret_bytes())
            } else {
                Err(SourceError::Unavailable)
            }
        );
    }
}

#[test]
fn command_execution_closes_unrelated_handles_and_controls_its_context() {
    use std::os::fd::AsRawFd;
    let installation = Installation::empty();
    let file = fs::File::create(installation.config().with_file_name("unrelated")).unwrap();
    let file = rustix::io::fcntl_dupfd_cloexec(&file, 200).unwrap();
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
    assert!(fs::metadata(format!("/dev/fd/{}", file.as_raw_fd())).is_ok());
    let config = configuration(
        &installation,
        vec![
            "context".into(),
            installation
                .config()
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
                .into(),
            "$(touch injected); * $HOME".into(),
            file.as_raw_fd().to_string(),
        ],
    );
    let secret = source_for(&CredentialSource::Command(config))
        .resolve(Uuid::new_v4())
        .unwrap();
    assert_eq!(secret.len(), 19);
    assert!(!installation.config().with_file_name("injected").exists());
}

#[test]
fn untrusted_paths_and_dependencies_are_rejected_before_execution() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let installation = Installation::empty();
    let path = installation.config().with_file_name("dependency");
    fs::write(&path, b"fixture").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let mut config = configuration(&installation, vec!["hang".into()]);
    config.protected_paths.push(path.clone());
    let source = source_for(&CredentialSource::Command(config.clone()));
    assert_eq!(
        source.availability(Uuid::new_v4()),
        Availability::AccessDenied
    );
    assert_eq!(
        source.resolve(Uuid::new_v4()).unwrap_err(),
        SourceError::AccessDenied
    );
    let link = path.with_file_name("redirected");
    symlink(&path, &link).unwrap();
    config.executable = link;
    config.protected_paths.clear();
    assert_eq!(
        source_for(&CredentialSource::Command(config)).availability(Uuid::new_v4()),
        Availability::AccessDenied
    );
}

#[test]
fn command_stderr_limit_is_inclusive() {
    let installation = Installation::empty();
    let limits = ResolutionLimits::try_from(&Limits {
        command_stderr_bytes: 8,
        ..Limits::default()
    })
    .unwrap();
    for (bytes, expected) in [(8, Ok(19)), (9, Err(SourceError::Unavailable))] {
        assert_eq!(
            source_for(&CredentialSource::Command(configuration(
                &installation,
                vec!["stderr".into(), bytes.to_string()]
            )))
            .resolve_with_limits(Uuid::new_v4(), &limits)
            .map(|secret| secret.len()),
            expected
        );
    }
}

#[cfg(all(feature = "cli", feature = "mcp"))]
#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[cfg(all(feature = "cli", feature = "mcp"))]
#[path = "../../imap_support/process.rs"]
mod server;

#[cfg(all(feature = "cli", feature = "mcp"))]
#[tokio::test]
async fn cli_and_mcp_resolve_the_command_only_for_explicit_authentication() {
    use support::{assert_success, envelope, run_bounded};
    let installation = Installation::two_accounts();
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let secret = installation.config().with_file_name("synthetic-secret");
    let mut config =
        mailctl::config::Config::parse(&fs::read_to_string(installation.config()).unwrap())
            .unwrap();
    for account in &mut config.accounts {
        account.server = "127.0.0.1".into();
        account.port = server.port;
        account.credential = CredentialSource::Command(configuration(
            &installation,
            vec!["file".into(), secret.to_str().unwrap().into()],
        ));
    }
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    for executable in [support::MAILCTL, support::MAILCTL_MCP] {
        let mut status = installation.command(executable);
        status.args(["--json", "--account", "work", "credential", "status"]);
        let output = run_bounded(status);
        assert_success(&output);
        assert_eq!(envelope(&output)["result"]["availability"], "configured");
        assert_eq!(envelope(&output)["result"]["provisioning"], "external");
        let mut doctor = installation.command(executable);
        doctor
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .args(["--json", "doctor"]);
        let output = run_bounded(doctor);
        assert_success(&output);
        assert!(
            envelope(&output)["result"]["accounts"][0]
                .get("authentication")
                .is_none()
        );
    }
    assert_eq!(server.accepted(), 0);
    for (executable, password) in [
        (support::MAILCTL, "disposable-password"),
        (support::MAILCTL_MCP, " rotated-password "),
    ] {
        fs::write(&secret, format!("{password}\r\n")).unwrap();
        server.expect("work@example.test", password);
        let mut doctor = installation.command(executable);
        doctor.env("MAILCTL_FIXTURE_CA", &server.certificate).args([
            "--json",
            "--account",
            "work",
            "doctor",
            "--check-account",
        ]);
        let output = run_bounded(doctor);
        assert_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(password));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(password));
    }
    server.expect_mailboxes("work@example.test", " rotated-password ", &["INBOX"]);
    let (result, diagnostics) = mcp_mailboxes(&installation, &server, "trace").await;
    assert_eq!(
        result["result"]["mailboxes"][0]["metadata"]["name"],
        "INBOX"
    );
    assert!(!result.to_string().contains(" rotated-password "));
    assert!(!diagnostics.contains(" rotated-password "));

    config.accounts[0].credential =
        CredentialSource::Command(configuration(&installation, vec!["fail".into()]));
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    let mut setup = installation.cli();
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    let connections = server.accepted();
    for level in ["off", "error", "warn", "info", "debug", "trace"] {
        let mut doctor = installation.cli();
        doctor
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .env("RUST_LOG", "trace")
            .args([
                "--json",
                "--log-format",
                if level == "off" { "off" } else { "json" },
                "--log-level",
                if level == "off" { "trace" } else { level },
                "--account",
                "work",
                "doctor",
                "--check-account",
            ]);
        let output = run_bounded(doctor);
        assert_eq!(
            envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
            "unavailable"
        );
        assert_private_output(
            &String::from_utf8(output.stdout).unwrap(),
            &String::from_utf8(output.stderr).unwrap(),
        );
        let (result, diagnostics) = mcp_mailboxes(&installation, &server, level).await;
        assert_eq!(result["error"]["credential_failure"], "unavailable");
        assert_private_output(&result.to_string(), &diagnostics);
    }
    assert_eq!(server.accepted(), connections);
    server.finish();
}

#[cfg(all(feature = "cli", feature = "mcp"))]
fn assert_private_output(result: &str, diagnostics: &str) {
    for private in [
        "private-command-error-secret",
        "private-command-output-secret",
    ] {
        assert!(!result.contains(private));
        assert!(!diagnostics.contains(private));
    }
}

#[cfg(all(feature = "cli", feature = "mcp"))]
async fn mcp_mailboxes(
    installation: &Installation,
    server: &server::ImapServer,
    level: &str,
) -> (serde_json::Value, String) {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut command = installation.mcp();
        command
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .env("RUST_LOG", "trace")
            .args([
                "--log-format",
                if level == "off" { "off" } else { "json" },
                "--log-level",
                if level == "off" { "trace" } else { level },
            ]);
        let (transport, stderr) =
            TokioChildProcess::builder(tokio::process::Command::from(command))
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
        let capture = tokio::spawn(async move {
            let mut text = String::new();
            stderr
                .unwrap()
                .take(65536)
                .read_to_string(&mut text)
                .await
                .unwrap();
            text
        });
        let client = ().serve(transport).await.unwrap();
        let response = client
            .call_tool(
                CallToolRequestParams::new("email_list_mailboxes")
                    .with_arguments(serde_json::Map::new()),
            )
            .await
            .unwrap();
        let structured = response.structured_content.unwrap();
        client.cancel().await.unwrap();
        (structured, capture.await.unwrap())
    })
    .await
    .unwrap()
}

#[test]
fn deadline_and_overflow_kill_the_helper_group_and_reap_its_leader() {
    use std::time::{Duration, Instant};
    let limits = ResolutionLimits::try_from(&Limits {
        secret_command_seconds: 1,
        secret_bytes: 16,
        command_stderr_bytes: 8,
        ..Limits::default()
    })
    .unwrap();
    for (mode, failure) in [
        ("hang", SourceError::Unavailable),
        ("stdout", SourceError::InvalidSecret),
        ("stderr", SourceError::Unavailable),
        ("exit", SourceError::Unavailable),
    ] {
        let installation = Installation::empty();
        let marker = installation.config().with_file_name("processes");
        let source = source_for(&CredentialSource::Command(configuration(
            &installation,
            vec![
                "descendant".into(),
                marker.to_str().unwrap().into(),
                mode.into(),
            ],
        )));
        let start = Instant::now();
        assert_eq!(
            source
                .resolve_with_limits(Uuid::new_v4(), &limits)
                .unwrap_err(),
            failure
        );
        assert!(start.elapsed() < Duration::from_secs(4));
        let pids: Vec<i32> = fs::read_to_string(marker)
            .unwrap()
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect();
        let leader = rustix::process::Pid::from_raw(pids[0]).unwrap();
        assert_eq!(
            rustix::process::waitpid(Some(leader), rustix::process::WaitOptions::NOHANG)
                .unwrap_err(),
            rustix::io::Errno::CHILD
        );
        // An orphan can briefly remain a zombie until the OS reaps it. A zombie cannot execute.
        for pid in pids {
            let output = std::process::Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let state = String::from_utf8(output.stdout).unwrap();
            assert!(
                state.trim().is_empty() || state.trim().starts_with('Z'),
                "helper is still running"
            );
        }
    }
}

#[test]
fn invalid_executables_cannot_trigger_a_shell_fallback() {
    use std::os::unix::fs::PermissionsExt;
    let installation = Installation::empty();
    let executable = installation.config().with_file_name("shell-fallback");
    for (bytes, failure) in [
        (
            b"printf disposable-password".as_slice(),
            SourceError::AccessDenied,
        ),
        (
            b"\x7fELF\nprintf disposable-password".as_slice(),
            SourceError::Unavailable,
        ),
    ] {
        fs::write(&executable, bytes).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = configuration(&installation, vec![]);
        config.executable = executable.clone();
        assert_eq!(
            source_for(&CredentialSource::Command(config))
                .resolve(Uuid::new_v4())
                .unwrap_err(),
            failure
        );
    }
}

#[test]
fn credential_status_rejects_a_fifo_without_waiting_for_a_writer() {
    let installation = Installation::empty();
    let fifo = installation.config().with_file_name("fifo");
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .args(["-m", "700"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut config = configuration(&installation, vec![]);
    config.executable = fifo;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        sender
            .send(source_for(&CredentialSource::Command(config)).availability(Uuid::new_v4()))
            .unwrap();
    });
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
        Availability::AccessDenied
    );
}
