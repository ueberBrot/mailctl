#![cfg(all(target_os = "linux", any(feature = "cli", feature = "mcp")))]

mod imap_support;
#[path = "imap_support/process.rs"]
mod server;
mod support;

use mailctl::config::{Config, CredentialSource};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use support::{Installation, assert_success, envelope, run_bounded};

const FIRST: &str = "disposable-password";
const ROTATED: &str = " rotated-password ";

const COMPONENT_PATHS: &[&str] = &[
    #[cfg(feature = "cli")]
    support::MAILCTL,
    #[cfg(feature = "mcp")]
    support::MAILCTL_MCP,
];

fn unit(secret: Option<&Path>) -> Command {
    let mut command = Command::new("systemd-run");
    command.args([
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        "--property=User=65534",
        "--property=Group=65534",
        "--property=NoNewPrivileges=yes",
        "--property=RuntimeMaxSec=20s",
    ]);
    if let Some(secret) = secret {
        command.arg(format!(
            "--property=LoadCredential=password:{}",
            secret.display()
        ));
    }
    command
}

fn launch(
    executable: &str,
    installation: &Installation,
    secret: Option<&Path>,
    ca: &Path,
) -> Command {
    let mut command = unit(secret);
    command.arg(format!("--setenv=SSL_CERT_FILE={}", ca.display()));
    command
        .arg(executable)
        .arg("--config")
        .arg(installation.config());
    command
}

fn private_output(output: &std::process::Output) {
    for secret in [FIRST, ROTATED] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}

#[tokio::test]
#[ignore = "requires a disposable root Linux environment with systemd as PID 1"]
async fn systemd_provisions_independent_components_and_rotates_at_unit_restart() {
    assert_eq!(
        std::env::var("MAILCTL_DISPOSABLE_SYSTEMD").as_deref(),
        Ok("1")
    );
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let installation = Installation::two_accounts();
    let directory = installation.config().parent().unwrap();
    let mut server = server::ImapServer::new(directory);
    let mut config = Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.limits.connection_lifetime_seconds = 3;
    for grant in &mut config.grants {
        grant.limits = config.limits.clone();
    }
    for account in &mut config.accounts {
        account.server = "127.0.0.1".into();
        account.port = server.port;
        account.credential = CredentialSource::Systemd {
            name: "password".into(),
        };
    }
    let original_config = toml::to_string(&config).unwrap();
    fs::write(installation.config(), &original_config).unwrap();
    let mut ownership = Command::new("chown");
    ownership.args(["-R", "65534:65534"]).arg(directory);
    assert_success(&run_bounded(ownership));
    let provisioning = Installation::empty();
    let provision = provisioning.config().parent().unwrap();
    let secret = provision.join("password");
    fs::write(&secret, FIRST).unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let mut denied = unit(None);
    denied.args(["/usr/bin/test", "-r"]).arg(&secret);
    let denied = run_bounded(denied);
    assert!(
        !denied.status.success(),
        "runtime identity read the provisioning file"
    );

    let mut replace = unit(None);
    replace
        .arg("/usr/bin/mv")
        .arg(provision)
        .arg(provision.with_extension("replaced"));
    assert!(
        !run_bounded(replace).status.success(),
        "runtime identity replaced the provisioning directory"
    );
    let mut workers = unit(Some(&secret));
    workers
        .arg("--setenv=MAILCTL_SYSTEMD_WORKER_PROBE=1")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "systemd_workers_are_bounded_and_process_local",
            "--nocapture",
        ]);
    assert_success(&run_bounded(workers));

    for executable in COMPONENT_PATHS {
        let mut setup = launch(executable, &installation, None, &server.certificate);
        setup.args(["--json", "setup"]);
        assert_success(&run_bounded(setup));
        let mut status = launch(
            executable,
            &installation,
            Some(&secret),
            &server.certificate,
        );
        status.args(["--json", "--account", "work", "credential", "status"]);
        let output = run_bounded(status);
        assert_success(&output);
        assert_eq!(envelope(&output)["result"]["availability"], "configured");
        assert_eq!(envelope(&output)["result"]["provisioning"], "external");
        private_output(&output);
        let mut doctor = launch(
            executable,
            &installation,
            Some(&secret),
            &server.certificate,
        );
        doctor.args(["--json", "doctor"]);
        let output = run_bounded(doctor);
        assert_success(&output);
        let result = envelope(&output);
        assert_eq!(result["result"]["topology"], "native");
        assert!(
            result["result"]["accounts"][0]
                .get("authentication")
                .is_none()
        );
        assert!(
            result["result"]["prerequisites"]
                .to_string()
                .contains("LoadCredential=")
        );
        assert_eq!(server.accepted(), 0);
        for operation in ["set", "delete"] {
            let mut command = launch(
                executable,
                &installation,
                Some(&secret),
                &server.certificate,
            );
            command.args(["--account", "work", "credential", operation]);
            let output = run_bounded(command);
            assert!(!output.status.success());
            private_output(&output);
        }
    }
    for executable in COMPONENT_PATHS {
        for password in [FIRST, ROTATED] {
            fs::write(&secret, password).unwrap();
            server.expect("work@example.test", password);
            let mut doctor = launch(
                executable,
                &installation,
                Some(&secret),
                &server.certificate,
            );
            doctor.args(["--json", "--account", "work", "doctor", "--check-account"]);
            let output = run_bounded(doctor);
            assert_success(&output);
            assert_eq!(
                envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["status"],
                "authenticated"
            );
            private_output(&output);
        }
        for (provisioned, failure) in [
            (None, "unavailable"),
            (Some(secret.as_path()), "invalid_secret"),
        ] {
            fs::write(&secret, []).unwrap();
            let connections = server.accepted();
            let mut doctor = launch(executable, &installation, provisioned, &server.certificate);
            doctor.args(["--json", "--account", "work", "doctor", "--check-account"]);
            let output = run_bounded(doctor);
            assert_eq!(output.status.code(), Some(4));
            assert_eq!(
                envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
                failure
            );
            assert_eq!(server.accepted(), connections);
        }
    }
    #[cfg(feature = "mcp")]
    mcp_rotation(&installation, &secret, &server).await;
    assert_eq!(
        fs::read_to_string(installation.config()).unwrap(),
        original_config
    );
    server.finish();
}

#[cfg(feature = "mcp")]
async fn mcp_rotation(installation: &Installation, secret: &Path, server: &server::ImapServer) {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use tokio::io::AsyncReadExt;
    for initial in [FIRST, ROTATED] {
        fs::write(secret, initial).unwrap();
        let command = launch(
            support::MAILCTL_MCP,
            installation,
            Some(secret),
            &server.certificate,
        );
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
        for _ in 0..2 {
            server.expect_mailboxes("work@example.test", initial, &["INBOX"]);
            let response = client
                .call_tool(
                    CallToolRequestParams::new("email_list_mailboxes")
                        .with_arguments(serde_json::Map::new()),
                )
                .await
                .unwrap();
            let structured = response.structured_content.unwrap();
            assert_eq!(
                structured["result"]["mailboxes"][0]["metadata"]["name"],
                "INBOX"
            );
            assert!(!structured.to_string().contains(initial));
            fs::write(secret, ROTATED).unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), client.waiting())
            .await
            .expect("MCP must end within its configured session lifetime")
            .unwrap();
        let diagnostics = capture.await.unwrap();
        assert!(!diagnostics.contains(FIRST));
        assert!(!diagnostics.contains(ROTATED));
    }
}

#[tokio::test]
async fn systemd_source_probe_in_an_independent_process() {
    if std::env::var("MAILCTL_SYSTEMD_WORKER_PROBE").as_deref() != Ok("1") {
        return;
    }
    use mailctl::credentials::{Availability, source_for};
    assert_eq!(rustix::process::geteuid().as_raw(), 65534);
    let source = source_for(&CredentialSource::Systemd {
        name: "password".into(),
    });
    let id = uuid::Uuid::new_v4();
    let runtime = mailctl::authentication::Runtime::new(
        mailctl::config::Limits {
            credential_workers: 1,
            queued_credentials: 1,
            ..Default::default()
        },
        tokio_rustls::rustls::RootCertStore::empty(),
    )
    .unwrap();
    assert_eq!(
        runtime.inspect(id, 1, source.clone()).await.unwrap(),
        Availability::Configured
    );
    assert_eq!(source.resolve(id).unwrap().len(), FIRST.len());
}

#[tokio::test]
async fn systemd_workers_are_bounded_and_process_local() {
    if std::env::var("MAILCTL_SYSTEMD_WORKER_PROBE").as_deref() != Ok("1") {
        return;
    }
    use mailctl::{
        authentication::{Error, Runtime},
        config::Limits,
        credentials::{Availability, Secret, SecretSource, SourceError, source_for},
    };
    use std::{
        future::{Future, poll_fn},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        task::Poll,
    };
    use tokio_rustls::rustls::RootCertStore;
    use uuid::Uuid;

    struct HeldSource {
        inner: Arc<dyn SecretSource>,
        calls: AtomicUsize,
        started: tokio::sync::Notify,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl SecretSource for HeldSource {
        fn availability(&self, account: Uuid) -> Availability {
            let result = self.inner.availability(account);
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            let _ = self.release.lock().unwrap().recv();
            result
        }
        fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
            self.inner.resolve(account)
        }
    }
    let runtime = Arc::new(
        Runtime::new(
            Limits {
                credential_workers: 1,
                queued_credentials: 1,
                ..Limits::default()
            },
            RootCertStore::empty(),
        )
        .unwrap(),
    );
    // Dropping the sender also releases workers if an assertion panics.
    let (release, receiver) = mpsc::channel();
    let source = Arc::new(HeldSource {
        inner: source_for(&CredentialSource::Systemd {
            name: "password".into(),
        }),
        calls: AtomicUsize::new(0),
        started: tokio::sync::Notify::new(),
        release: Mutex::new(receiver),
    });
    let active = {
        let runtime = runtime.clone();
        let source = source.clone();
        tokio::spawn(async move { runtime.inspect(Uuid::new_v4(), 1, source).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), source.started.notified())
        .await
        .unwrap();
    let mut queued = std::pin::pin!(runtime.inspect(Uuid::new_v4(), 1, source.clone()));
    poll_fn(|context| {
        assert!(queued.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        runtime.inspect(Uuid::new_v4(), 1, source.clone()).await,
        Err(Error::RateLimited)
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    let mut independent = Command::new(std::env::current_exe().unwrap());
    independent.args([
        "--exact",
        "systemd_source_probe_in_an_independent_process",
        "--nocapture",
    ]);
    assert_success(&run_bounded(independent));
    drop(release);
    assert_eq!(active.await.unwrap(), Ok(Availability::Configured));
    assert_eq!(queued.await, Ok(Availability::Configured));
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}
