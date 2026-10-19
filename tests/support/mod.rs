#![allow(
    dead_code,
    reason = "each integration-test crate uses a different subset of this private fixture API"
)]

use serde_json::Value;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

// Avoid inheriting a writable executable-copy descriptor in a concurrent child.
// Only copying and spawning are serialized; child processes still run together.
static COPY_OR_SPAWN: Mutex<()> = Mutex::new(());

#[cfg(feature = "cli")]
static PACKAGED_CLI: OnceLock<PathBuf> = OnceLock::new();
#[cfg(feature = "mcp")]
static PACKAGED_MCP: OnceLock<PathBuf> = OnceLock::new();
const PRODUCT_COMPONENTS: &[(Option<&str>, &str, &OnceLock<PathBuf>)] = &[
    #[cfg(feature = "cli")]
    (
        option_env!("CARGO_BIN_EXE_mailctl"),
        "mailctl",
        &PACKAGED_CLI,
    ),
    #[cfg(feature = "mcp")]
    (
        option_env!("CARGO_BIN_EXE_mailctl-mcp"),
        "mailctl-mcp",
        &PACKAGED_MCP,
    ),
];
static PACKAGED_DIRECTORY: OnceLock<Option<PathBuf>> = OnceLock::new();

#[cfg(target_os = "linux")]
#[path = "../native_support/linux_secret_service.rs"]
pub(crate) mod secret_service;

#[cfg(feature = "cli")]
pub(crate) const MAILCTL: &str = match option_env!("CARGO_BIN_EXE_mailctl") {
    Some(path) => path,
    None => match option_env!("CARGO_BIN_EXE_mailctl-test-cli") {
        Some(path) => path,
        None => panic!("missing CLI test executable"),
    },
};
#[cfg(feature = "mcp")]
pub(crate) const MAILCTL_MCP: &str = match option_env!("CARGO_BIN_EXE_mailctl-mcp") {
    Some(path) => path,
    None => match option_env!("CARGO_BIN_EXE_mailctl-test-mcp") {
        Some(path) => path,
        None => panic!("missing MCP test executable"),
    },
};

/// Run installed release candidates with the existing disposable fixtures.
/// Test drivers and already copied fixture executables retain their own paths.
/// Validate each requested component once so a combined harness can also run
/// against an installation containing only one component.
pub(crate) fn selected_executable(executable: &str) -> PathBuf {
    let Some((_, name, packaged)) = PRODUCT_COMPONENTS
        .iter()
        .find(|(compiled, _, _)| *compiled == Some(executable))
    else {
        return executable.into();
    };
    let Some(directory) = PACKAGED_DIRECTORY.get_or_init(|| {
        let directory = PathBuf::from(std::env::var_os("MAILCTL_PACKAGED_BIN_DIR")?);
        assert!(
            directory.is_absolute(),
            "MAILCTL_PACKAGED_BIN_DIR must be an absolute directory"
        );
        assert!(
            directory.is_dir(),
            "MAILCTL_PACKAGED_BIN_DIR is not a directory: {}",
            directory.display()
        );
        Some(directory)
    }) else {
        return executable.into();
    };
    packaged
        .get_or_init(|| {
            let path = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
            assert!(
                path.is_file(),
                "missing packaged component: {}",
                path.display()
            );
            let mut version = Command::new(&path);
            version.arg("--version");
            let output = run_bounded(version);
            assert_success(&output);
            assert_eq!(
                String::from_utf8(output.stdout)
                    .expect("UTF-8 packaged component version")
                    .trim(),
                format!("{name} {}", env!("CARGO_PKG_VERSION")),
                "packaged component must match the acceptance harness version"
            );
            path
        })
        .clone()
}

/// A complete disposable installation, deliberately independent of the
/// operator's normal configuration and state directories.
pub(crate) struct Installation {
    directory: PathBuf,
    config: PathBuf,
    #[cfg(any(target_os = "linux", windows))]
    native_credentials: Mutex<Vec<Uuid>>,
}

impl Installation {
    pub(crate) fn empty() -> Self {
        let temporary =
            fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let directory = temporary.join(format!("mailctl-process-{}", Uuid::new_v4().simple()));
        fs::create_dir(&directory).expect("create temporary installation");
        protect(&directory, true);
        let config = directory.join("config.toml");
        Self {
            directory,
            config,
            #[cfg(any(target_os = "linux", windows))]
            native_credentials: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn two_accounts() -> Self {
        let installation = Self::empty();
        installation.write_configuration("default");
        installation
    }

    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn provision_packaged_native(&self, password: &str) {
        if std::env::var("MAILCTL_PACKAGED_CREDENTIAL_SOURCE").as_deref() != Ok("native") {
            return;
        }
        use mailctl::{
            config::CredentialSource,
            credentials::{self, Secret},
        };
        assert_disposable_native();
        let registry: Value =
            serde_json::from_slice(&fs::read(self.directory.join("state/accounts.json")).unwrap())
                .unwrap();
        let source = credentials::source_for(&CredentialSource::Native {});
        let store = source
            .mutable_store()
            .expect("mutable native credential source");
        let secret = Secret::new(password.as_bytes().to_vec()).unwrap();
        for account in registry["accounts"].as_object().unwrap().values() {
            let id = Uuid::parse_str(account["account_id"].as_str().unwrap()).unwrap();
            store
                .set(id, &secret)
                .expect("provision a disposable native credential");
            let mut owned = self.native_credentials.lock().unwrap();
            if !owned.contains(&id) {
                owned.push(id);
            }
        }
    }

    pub(crate) fn write_configuration(&self, default_grant: &str) {
        let state = self.directory.join("state");
        fs::write(
            &self.config,
            format!(
                r#"default_grant = {default_grant:?}
state_dir = {state}

[[accounts]]
key = "work"
alias = "work"
server = "imap.example.test"
username = "work@example.test"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["work"]
drafts_mailbox = "Drafts"
[accounts.credential]
source = "native"

[[accounts]]
key = "personal"
alias = "personal"
server = "imap.example.test"
username = "personal@example.test"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["personal"]
drafts_mailbox = "Drafts"
[accounts.credential]
source = "native"

[[grants]]
name = "default"
profile = "read_only"
accounts = ["work"]
mailboxes = ["INBOX"]

[[grants]]
name = "all"
profile = "read_only"
accounts = ["work", "personal"]
mailboxes = ["INBOX"]

[[grants]]
name = "writer"
profile = "drafts_only"
accounts = ["work"]
mailboxes = ["INBOX", "Drafts"]
"#,
                state = toml_string(&state),
            ),
        )
        .expect("write configuration");
        protect(&self.config, false);
    }

    #[cfg(feature = "cli")]
    pub(crate) fn cli(&self) -> Command {
        self.command(MAILCTL)
    }

    #[cfg(feature = "mcp")]
    pub(crate) fn mcp(&self) -> Command {
        self.command(MAILCTL_MCP)
    }

    pub(crate) fn command(&self, executable: &str) -> Command {
        let mut command = Command::new(selected_executable(executable));
        command.arg("--config").arg(&self.config);
        command
    }

    pub(crate) fn copy_executable(&self, executable: &str, name: &str) -> PathBuf {
        let executable = selected_executable(executable);
        let _copy_guard = COPY_OR_SPAWN.lock().expect("copy/spawn fixture lock");
        #[cfg(windows)]
        let copy = self.directory.join(format!("{name}.exe"));
        #[cfg(not(windows))]
        let copy = self.directory.join(name);
        fs::copy(&executable, &copy).expect("copy executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&executable)
                .expect("inspect source executable")
                .permissions()
                .mode();
            fs::set_permissions(&copy, fs::Permissions::from_mode(mode))
                .expect("make copied executable runnable");
        }
        copy
    }
}

impl Drop for Installation {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", windows))]
        if let Ok(accounts) = self.native_credentials.get_mut()
            && !accounts.is_empty()
        {
            use mailctl::{config::CredentialSource, credentials};
            let source = credentials::source_for(&CredentialSource::Native {});
            if let Some(store) = source.mutable_store() {
                for id in accounts {
                    let _ = store.delete(*id);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn run_bounded(command: Command) -> Output {
    run_bounded_with_timeout(command, Duration::from_secs(10))
}

pub(crate) fn run_bounded_with_timeout(mut command: Command, timeout: Duration) -> Output {
    let spawn_guard = COPY_OR_SPAWN.lock().expect("copy/spawn fixture lock");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start process");
    drop(spawn_guard);
    let stdout = child.stdout.take().expect("capture stdout");
    let stderr = child.stderr.take().expect("capture stderr");
    let stdout = thread::spawn(move || read_pipe(stdout));
    let stderr = thread::spawn(move || read_pipe(stderr));
    let started = Instant::now();
    let deadline = started + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("inspect process")
            && stdout.is_finished()
            && stderr.is_finished()
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().expect("reap process");
            // A descendant may still hold a pipe open. Never join an unfinished
            // reader after the deadline, even if the direct child has exited.
            let stdout = stdout
                .is_finished()
                .then(|| stdout.join().expect("read stdout"));
            let stderr = stderr
                .is_finished()
                .then(|| stderr.join().expect("read stderr"));
            panic!(
                "process {:?} {:?} did not finish after {:?}; exit {:?}; stdout {}; stderr {}",
                command.get_program(),
                command.get_args().collect::<Vec<_>>(),
                started.elapsed(),
                status.code(),
                stdout
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_else(|| "<capture incomplete>".into()),
                stderr
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_else(|| "<capture incomplete>".into()),
            );
        }
        thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: stdout.join().expect("read stdout"),
        stderr: stderr.join().expect("read stderr"),
    }
}

fn read_pipe(mut pipe: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).expect("read process output");
    bytes
}

pub(crate) fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "exit {:?}; stdout {}; stderr {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn envelope(output: &Output) -> Value {
    let stdout = std::str::from_utf8(&output.stdout).expect("UTF-8 machine output");
    assert!(stdout.ends_with('\n'), "machine output ends with a newline");
    assert_eq!(stdout.lines().count(), 1, "one envelope per CLI invocation");
    serde_json::from_str(stdout).expect("valid output envelope")
}

#[cfg(feature = "mcp")]
pub(crate) fn assert_mcp_envelope(response: rmcp::model::CallToolResult) -> Value {
    let structured = response
        .structured_content
        .expect("structured MCP output envelope");
    assert_eq!(response.is_error, Some(structured.get("error").is_some()));
    let text = response.content[0]
        .as_text()
        .expect("serialized MCP output envelope");
    assert_eq!(
        serde_json::from_str::<Value>(&text.text).expect("valid serialized MCP output envelope"),
        structured
    );
    structured
}

pub(crate) fn toml_string(path: &Path) -> String {
    toml::Value::String(path.to_string_lossy().into_owned()).to_string()
}

pub(crate) fn packaged_credential(
    directory: &Path,
    password: &str,
) -> mailctl::config::CredentialSource {
    #[cfg(unix)]
    use mailctl::config::CredentialCommand;
    use mailctl::config::CredentialSource;
    #[cfg(windows)]
    let _ = (directory, password);
    match std::env::var("MAILCTL_PACKAGED_CREDENTIAL_SOURCE").as_deref() {
        #[cfg(unix)]
        Err(std::env::VarError::NotPresent) | Ok("command") => {
            let secret = directory.join("synthetic-credential");
            fs::write(&secret, password).expect("write synthetic credential");
            protect(&secret, false);
            CredentialSource::Command(CredentialCommand {
                executable: fs::canonicalize("/bin/cat").expect("canonical credential helper"),
                args: vec![secret.to_str().unwrap().into()],
                working_dir: directory.into(),
                protected_paths: vec![secret],
            })
        }
        #[cfg(target_os = "linux")]
        Ok("systemd") => {
            assert_eq!(std::env::consts::OS, "linux");
            assert!(std::env::var_os("CREDENTIALS_DIRECTORY").is_some());
            CredentialSource::Systemd {
                name: "password".into(),
            }
        }
        #[cfg(any(target_os = "linux", windows))]
        Ok("native") => {
            assert_disposable_native();
            CredentialSource::Native {}
        }
        source => panic!("unsupported packaged credential source: {source:?}"),
    }
}

pub(crate) fn packaged_environment(command: &mut Command, certificate: &Path, empty_path: &Path) {
    command
        .env_clear()
        .env("PATH", empty_path)
        .env("SSL_CERT_FILE", certificate);
    if std::env::var("MAILCTL_PACKAGED_CREDENTIAL_SOURCE").as_deref() == Ok("systemd") {
        command.env(
            "CREDENTIALS_DIRECTORY",
            std::env::var_os("CREDENTIALS_DIRECTORY").unwrap(),
        );
    }
    #[cfg(windows)]
    for name in [
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(target_os = "linux")]
    if std::env::var("MAILCTL_PACKAGED_CREDENTIAL_SOURCE").as_deref() == Ok("native") {
        secret_service::assert_disposable();
        for name in ["DBUS_SESSION_BUS_ADDRESS", "HOME", "XDG_RUNTIME_DIR"] {
            command.env(name, std::env::var_os(name).unwrap());
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
fn assert_disposable_native() {
    #[cfg(target_os = "linux")]
    secret_service::assert_disposable();
    #[cfg(windows)]
    assert_eq!(
        std::env::var("MAILCTL_DISPOSABLE_WINDOWS").as_deref(),
        Ok("1"),
        "native acceptance requires an explicitly disposable Windows identity"
    );
}

pub(crate) fn protect(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .expect("protect disposable fixture");
    }
    #[cfg(windows)]
    {
        static SID: OnceLock<String> = OnceLock::new();
        let sid = SID.get_or_init(|| {
            let mut command = Command::new("whoami.exe");
            command.args(["/user", "/fo", "csv", "/nh"]);
            let output = run_bounded(command);
            assert_success(&output);
            let output = String::from_utf8_lossy(&output.stdout);
            let sid = output
                .trim()
                .rsplit_once("\",\"")
                .unwrap()
                .1
                .trim_end_matches('"');
            assert!(
                sid.starts_with("S-")
                    && sid
                        .bytes()
                        .all(|byte| byte == b'S' || byte == b'-' || byte.is_ascii_digit())
            );
            sid.into()
        });
        let flags = if directory { "(OI)(CI)(F)" } else { "(F)" };
        let mut command = Command::new("icacls.exe");
        command.arg(path).args([
            "/inheritance:r",
            "/grant:r",
            &format!("*{sid}:{flags}"),
            &format!("*S-1-5-18:{flags}"),
            &format!("*S-1-5-32-544:{flags}"),
        ]);
        assert_success(&run_bounded(command));
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (path, directory);
}
