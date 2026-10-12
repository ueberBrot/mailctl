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
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

// Avoid inheriting a writable executable-copy descriptor in a concurrent child.
// Only copying and spawning are serialized; child processes still run together.
static COPY_OR_SPAWN: Mutex<()> = Mutex::new(());

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

/// A complete disposable installation, deliberately independent of the
/// operator's normal configuration and state directories.
pub(crate) struct Installation {
    directory: PathBuf,
    config: PathBuf,
}

impl Installation {
    pub(crate) fn empty() -> Self {
        let temporary =
            fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let directory = temporary.join(format!("mailctl-process-{}", Uuid::new_v4().simple()));
        fs::create_dir(&directory).expect("create temporary installation");
        protect(&directory, true);
        let config = directory.join("config.toml");
        Self { directory, config }
    }

    pub(crate) fn two_accounts() -> Self {
        let installation = Self::empty();
        installation.write_configuration("default");
        installation
    }

    pub(crate) fn config(&self) -> &Path {
        &self.config
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
        let mut command = Command::new(executable);
        command.arg("--config").arg(&self.config);
        command
    }

    pub(crate) fn copy_executable(&self, executable: &str, name: &str) -> PathBuf {
        let _copy_guard = COPY_OR_SPAWN.lock().expect("copy/spawn fixture lock");
        #[cfg(windows)]
        let copy = self.directory.join(format!("{name}.exe"));
        #[cfg(not(windows))]
        let copy = self.directory.join(name);
        fs::copy(executable, &copy).expect("copy executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(executable)
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
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn run_bounded(mut command: Command) -> Output {
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
    let deadline = started + Duration::from_secs(10);
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

fn protect(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .expect("protect disposable fixture");
    }
    #[cfg(not(unix))]
    let _ = (path, directory);
}
