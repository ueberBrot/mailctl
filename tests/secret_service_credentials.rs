#![cfg(all(target_os = "linux", any(feature = "cli", feature = "mcp")))]

mod imap_support;
#[path = "native_support/process.rs"]
mod process;
#[path = "imap_support/process.rs"]
mod server;
mod support;
#[path = "native_support/terminal.rs"]
mod terminal;

use mailctl::{
    config::{Config, CredentialSource},
    credentials::{self, Availability, Secret, SourceError},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{ErrorKind, Read},
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use support::{Installation, assert_success, envelope, run_bounded};
use uuid::Uuid;

const FIRST: &str = "first-synthetic-account-password";
const SECOND: &str = "second-distinct-synthetic-password";
const ROTATED: &str = " replacement-utf8-é🦀-password ";
const KEYRING_PASSWORD: &str = "mailctl-disposable-keyring-password";

fn executables() -> Vec<&'static str> {
    let selected =
        std::env::var("MAILCTL_PACKAGED_COMPONENTS").unwrap_or_else(|_| "cli,mcp".into());
    assert!(matches!(selected.as_str(), "cli" | "mcp" | "cli,mcp"));
    let mut executables = Vec::new();
    #[cfg(feature = "cli")]
    if selected != "mcp" {
        executables.push(support::MAILCTL);
    }
    #[cfg(feature = "mcp")]
    if selected != "cli" {
        executables.push(support::MAILCTL_MCP);
    }
    assert!(
        !executables.is_empty(),
        "requested component is not compiled"
    );
    executables
}

fn private_output(bytes: &[u8]) {
    for value in [FIRST, SECOND, ROTATED, KEYRING_PASSWORD] {
        assert!(
            !bytes
                .windows(value.len())
                .any(|bytes| bytes == value.as_bytes()),
            "a disposable credential escaped its source"
        );
    }
}

fn private_result(output: &Output) {
    private_output(&output.stdout);
    private_output(&output.stderr);
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("Password:"));
        assert!(!text.contains("work@example.test"));
        assert!(!text.contains("personal@example.test"));
    }
}

fn admin(installation: &Installation, executable: &str, arguments: &[&str]) -> Value {
    let mut command = installation.command(executable);
    command
        .args(["--json", "--log-level", "trace"])
        .args(arguments);
    let output = run_bounded(command);
    private_result(&output);
    assert_success(&output);
    envelope(&output)["result"].clone()
}

fn status(installation: &Installation, executable: &str, alias: &str, id: Uuid, expected: &str) {
    let result = admin(
        installation,
        executable,
        &["--account", alias, "credential", "status"],
    );
    assert_eq!(result["account_id"], id.to_string());
    assert_eq!(result["availability"], expected);
}

fn provision(
    installation: &Installation,
    executable: &str,
    alias: &str,
    password: &str,
    exit: i64,
) {
    let command = installation.command(executable);
    let mut argv = vec![command.get_program().to_string_lossy().into_owned()];
    argv.extend(
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );
    argv.extend(["--account", alias, "credential", "set"].map(str::to_owned));
    let response = terminal::run(json!({"command": argv, "secret": password}));
    private_output(response["output"].as_str().unwrap().as_bytes());
    assert_eq!(response["exit"], exit, "{response}");
    assert_eq!(response["prompted"], true, "{response}");
    assert_eq!(response["echo_during_prompt"], false);
    assert_eq!(response["echo_enabled"], true);
    assert_eq!(response["secret_disclosed"], false);
}

fn authenticate(
    installation: &Installation,
    server: &server::ImapServer,
    executable: &str,
    alias: &str,
    username: &'static str,
    password: &'static str,
) {
    server.expect(username, password);
    let mut command = installation.command(executable);
    command
        .env("SSL_CERT_FILE", &server.certificate)
        .env_remove("SSL_CERT_DIR")
        .args([
            "--grant",
            "all",
            "--json",
            "--log-level",
            "trace",
            "--account",
            alias,
            "doctor",
            "--check-account",
        ]);
    let output = run_bounded(command);
    private_result(&output);
    assert_success(&output);
    assert_eq!(
        envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["status"],
        "authenticated"
    );
}

struct Entries(Vec<Uuid>);
impl Drop for Entries {
    fn drop(&mut self) {
        let source = credentials::source_for(&CredentialSource::Native {});
        if let Some(store) = source.mutable_store() {
            for id in &self.0 {
                let _ = store.delete(*id);
            }
        }
    }
}

#[test]
#[ignore = "requires an explicitly disposable Linux identity, private D-Bus and native Secret Service"]
fn native_secret_service_credentials_cross_components_rotate_and_clean_up() {
    let root = support::secret_service::assert_disposable();
    let binaries = executables();
    let installation = Installation::two_accounts();
    let directory = installation.config().parent().unwrap();
    let mut server = server::ImapServer::new(directory);
    let mut config = Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
    for account in &mut config.accounts {
        account.server = "127.0.0.1".into();
        account.port = server.port;
    }
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    admin(&installation, binaries[0], &["setup"]);
    let registry: Value =
        serde_json::from_slice(&fs::read(directory.join("state/accounts.json")).unwrap()).unwrap();
    let id = |alias: &str| {
        Uuid::parse_str(registry["accounts"][alias]["account_id"].as_str().unwrap()).unwrap()
    };
    let first = id("work");
    let second = id("personal");
    assert_ne!(first, second);
    let _cleanup = Entries(vec![first, second]);
    let source = credentials::source_for(&CredentialSource::Native {});
    assert_eq!(source.availability(first), Availability::Missing);
    assert_eq!(source.resolve(first).unwrap_err(), SourceError::Missing);
    for &executable in &binaries {
        status(&installation, executable, "work", first, "missing");
        status(&installation, executable, "personal", second, "missing");
    }

    let vacant = Uuid::new_v4();
    let mutation = hold_mutation(vacant);
    assert_eq!(
        source
            .mutable_store()
            .unwrap()
            .set(vacant, &Secret::new(FIRST.as_bytes().to_vec()).unwrap()),
        Err(SourceError::Unavailable)
    );
    assert_eq!(entry_count(vacant), 0);
    assert_eq!(source.availability(vacant), Availability::Missing);
    mutation.close().unwrap();

    provision(&installation, binaries[0], "work", FIRST, 0);
    provision(
        &installation,
        binaries.last().unwrap(),
        "personal",
        SECOND,
        0,
    );
    let monitor = Monitor::start();
    for &executable in &binaries {
        status(&installation, executable, "work", first, "available");
        status(&installation, executable, "personal", second, "available");
        let doctor = admin(&installation, executable, &["--grant", "all", "doctor"]);
        assert!(
            doctor["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|account| account.get("authentication").is_none())
        );
    }
    monitor.assert_metadata_only();
    assert_eq!(
        server.accepted(),
        0,
        "safe status never authenticates to the provider"
    );
    assert_eq!(entry_count(first), 1);
    assert_eq!(entry_count(second), 1);
    for &executable in &binaries {
        authenticate(
            &installation,
            &server,
            executable,
            "work",
            "work@example.test",
            FIRST,
        );
        authenticate(
            &installation,
            &server,
            executable,
            "personal",
            "personal@example.test",
            SECOND,
        );
    }

    let mutation = hold_mutation(first);
    for &executable in &binaries {
        provision(&installation, executable, "work", ROTATED, 4);
        status(&installation, executable, "work", first, "available");
        authenticate(
            &installation,
            &server,
            executable,
            "work",
            "work@example.test",
            FIRST,
        );
    }
    assert_eq!(entry_count(first), 1);
    mutation.close().unwrap();

    admin(
        &installation,
        binaries[0],
        &["--account", "work", "setup", "--alias", "renamed"],
    );
    provision(
        &installation,
        binaries.last().unwrap(),
        "renamed",
        ROTATED,
        0,
    );
    assert_eq!(
        entry_count(first),
        1,
        "rotation and alias changes must reuse one UUID reference"
    );
    assert_eq!(entry_count(second), 1);
    for &executable in &binaries {
        status(&installation, executable, "renamed", first, "available");
        authenticate(
            &installation,
            &server,
            executable,
            "renamed",
            "work@example.test",
            ROTATED,
        );
        let relocated =
            installation.copy_executable(executable, &format!("relocated-{}", Uuid::new_v4()));
        authenticate(
            &installation,
            &server,
            relocated.to_str().unwrap(),
            "renamed",
            "work@example.test",
            ROTATED,
        );
    }
    private_output(&fs::read(installation.config()).unwrap());
    private_state(&directory.join("state"));

    for &executable in &binaries {
        authenticate(
            &installation,
            &server,
            executable,
            "renamed",
            "work@example.test",
            ROTATED,
        );
        let mut unavailable = installation.command(executable);
        unavailable
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", root.join("absent-bus").display()),
            )
            .args([
                "--json",
                "--account",
                "renamed",
                "doctor",
                "--check-account",
            ]);
        let output = run_bounded(unavailable);
        private_result(&output);
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(
            envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
            "unavailable"
        );
    }

    admin(
        &installation,
        binaries[0],
        &["--account", "renamed", "credential", "delete"],
    );
    for &executable in &binaries {
        status(&installation, executable, "renamed", first, "missing");
        authenticate(
            &installation,
            &server,
            executable,
            "personal",
            "personal@example.test",
            SECOND,
        );
    }
    admin(
        &installation,
        binaries.last().unwrap(),
        &["--account", "personal", "credential", "delete"],
    );
    assert_eq!(entry_count(first), 0);
    assert_eq!(entry_count(second), 0);
    private_output(&fs::read(installation.config()).unwrap());
    private_state(&directory.join("state"));
    private_state(&root.join("data/keyrings"));
    provision(&installation, binaries[0], "renamed", ROTATED, 0);
    let restart_account = root.join("restart-account");
    fs::write(&restart_account, first.to_string()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&restart_account, fs::Permissions::from_mode(0o600)).unwrap();
    lock_collection();
    let monitor = Monitor::start();
    let before = server.accepted();
    for &executable in &binaries {
        status(&installation, executable, "renamed", first, "locked");
        let mut command = installation.command(executable);
        command.args([
            "--json",
            "--account",
            "renamed",
            "doctor",
            "--check-account",
        ]);
        let output = run_bounded(command);
        private_result(&output);
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(
            envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
            "locked"
        );
        let mut delete = installation.command(executable);
        delete.args(["--json", "--account", "renamed", "credential", "delete"]);
        let output = run_bounded(delete);
        private_result(&output);
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(envelope(&output)["error"]["credential_failure"], "locked");
        provision(&installation, executable, "renamed", ROTATED, 4);
    }
    #[cfg(feature = "mcp")]
    if binaries.contains(&support::MAILCTL_MCP) {
        locked_mcp(&installation);
    }
    monitor.assert_metadata_only();
    assert_eq!(server.accepted(), before);
    server.finish();
}

#[test]
#[ignore = "run after restarting the disposable daemon used by the native lifecycle test"]
fn native_secret_service_recovers_after_service_restart() {
    let root = support::secret_service::assert_disposable();
    let marker = root.join("restart-account");
    let account = Uuid::parse_str(&fs::read_to_string(&marker).unwrap()).unwrap();
    let source = credentials::source_for(&CredentialSource::Native {});
    assert_eq!(source.availability(account), Availability::Available);
    assert_eq!(source.resolve(account).unwrap().len(), ROTATED.len());
    source.mutable_store().unwrap().delete(account).unwrap();
    assert_eq!(source.availability(account), Availability::Missing);
    assert_eq!(source.resolve(account).unwrap_err(), SourceError::Missing);
    fs::remove_file(marker).unwrap();
}

fn private_state(path: &Path) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            private_state(&entry.path());
        } else {
            private_output(&fs::read(entry.path()).unwrap());
        }
    }
}

fn dbus(method: &str, arguments: &[&str]) -> String {
    let mut command = Command::new("/usr/bin/gdbus");
    command
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.secrets",
            "--object-path",
            "/org/freedesktop/secrets",
            "--method",
            method,
        ])
        .args(arguments);
    let output = run_bounded(command);
    private_result(&output);
    assert_success(&output);
    String::from_utf8(output.stdout).unwrap()
}

fn entry_count(id: Uuid) -> usize {
    dbus(
        "org.freedesktop.Secret.Service.SearchItems",
        &[&format!("{{'service': 'mailctl', 'username': '{id}'}}")],
    )
    .matches("/org/freedesktop/secrets/collection/")
    .count()
}

fn hold_mutation(account: Uuid) -> zbus::blocking::Connection {
    let connection = zbus::blocking::connection::Builder::session()
        .unwrap()
        .method_timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let bus = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .unwrap();
    let acquired: u32 = bus
        .call(
            "RequestName",
            &(
                format!("org.mailctl.Credential.a{}", account.simple()),
                4u32,
            ),
        )
        .unwrap();
    assert_eq!(acquired, 1);
    drop(bus);
    connection
}

fn lock_collection() {
    let alias = dbus("org.freedesktop.Secret.Service.ReadAlias", &["default"]);
    let collection = alias
        .strip_prefix("(objectpath '")
        .and_then(|value| value.strip_suffix("',)\n"))
        .expect("native default collection path");
    assert!(collection.starts_with("/org/freedesktop/secrets/collection/"));
    let result = dbus(
        "org.freedesktop.Secret.Service.Lock",
        &[&format!("[objectpath '{collection}']")],
    );
    assert!(result.contains(collection));
}

struct Monitor {
    child: Option<Child>,
    output: Vec<u8>,
}
impl Monitor {
    fn start() -> Self {
        let child = Command::new("/usr/bin/dbus-monitor")
            .args(["--session", "type='method_call'"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut monitor = Self {
            child: Some(child),
            output: Vec::new(),
        };
        let stdout = monitor.child.as_mut().unwrap().stdout.as_mut().unwrap();
        let flags = rustix::fs::fcntl_getfl(&*stdout).unwrap();
        rustix::fs::fcntl_setfl(&*stdout, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let marker = Self::marker();
            if monitor.observe(&marker, Instant::now() + Duration::from_millis(250)) {
                return monitor;
            }
            assert!(
                Instant::now() < deadline,
                "native metadata monitor readiness deadline"
            );
        }
    }

    fn marker() -> String {
        let marker = format!("org.mailctl.MetadataMarker.a{}", Uuid::new_v4().simple());
        let mut command = Command::new("/usr/bin/gdbus");
        command.args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.NameHasOwner",
            &marker,
        ]);
        let output = run_bounded(command);
        assert_success(&output);
        marker
    }

    fn observe(&mut self, marker: &str, deadline: Instant) -> bool {
        let stdout = self.child.as_mut().unwrap().stdout.as_mut().unwrap();
        let mut buffer = [0; 4096];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => panic!("native metadata monitor closed before its marker"),
                Ok(count) => self.output.extend_from_slice(&buffer[..count]),
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(_) => panic!("read native metadata monitor"),
            }
            assert!(self.output.len() <= 65536);
            if self
                .output
                .windows(marker.len())
                .any(|bytes| bytes == marker.as_bytes())
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_metadata_only(mut self) {
        let marker = Self::marker();
        assert!(
            self.observe(&marker, Instant::now() + Duration::from_secs(3)),
            "native metadata monitor must drain through the final marker"
        );
        let mut child = self.child.take().unwrap();
        child.kill().unwrap();
        let captured = process::capture(child, None, 65536, Duration::from_secs(5)).unwrap();
        assert!(!captured.stdout_exceeded_limit && !captured.stderr_exceeded_limit);
        self.output.extend_from_slice(&captured.output.stdout);
        private_output(&self.output);
        let output = String::from_utf8(std::mem::take(&mut self.output)).unwrap();
        assert!(
            output.contains("member=SearchItems"),
            "monitor must observe native metadata inspection"
        );
        for forbidden in [
            "member=GetSecret",
            "member=GetSecrets",
            "member=OpenSession",
            "member=Unlock",
            "member=Prompt",
        ] {
            assert!(
                !output.contains(forbidden),
                "metadata-only or locked access invoked {forbidden}"
            );
        }
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(feature = "mcp")]
fn locked_mcp(installation: &Installation) {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut command = installation.command(support::MAILCTL_MCP);
            command.args(["--account", "renamed"]);
            let client = ().serve(TokioChildProcess::new(tokio::process::Command::from(command)).unwrap()).await.unwrap();
            let tools = client.list_all_tools().await.unwrap();
            assert!(!tools.iter().any(|tool| tool.name.contains("credential") || tool.name.contains("setup")));
            let response = client.call_tool(CallToolRequestParams::new("email_list_mailboxes").with_arguments(serde_json::Map::new())).await.unwrap();
            let envelope = support::assert_mcp_envelope(response);
            assert_eq!(envelope["error"]["code"], "credential_unavailable");
            assert_eq!(envelope["error"]["credential_failure"], "locked");
            private_output(&serde_json::to_vec(&envelope).unwrap());
            client.cancel().await.unwrap();
        }).await.unwrap();
    });
}
