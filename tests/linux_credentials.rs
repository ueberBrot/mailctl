#![cfg(all(target_os = "linux", any(feature = "cli", feature = "mcp")))]

mod imap_support;
#[cfg(feature = "cli")]
#[path = "native_support/process.rs"]
mod process;
#[path = "imap_support/process.rs"]
mod server;
mod support;
#[cfg(feature = "cli")]
#[path = "native_support/terminal.rs"]
mod terminal;

use mailctl::config::{Config, CredentialSource};
use serde_json::Value;
#[cfg(feature = "cli")]
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use support::{Installation, assert_success, envelope, run_bounded};

const PASSWORD: &str = "disposable-password";

struct Fixture {
    installation: Installation,
    server: server::ImapServer,
    empty_path: PathBuf,
}

impl Fixture {
    fn new(executable: &str, session: bool) -> Self {
        if std::env::var("MAILCTL_LINUX_ACCEPTANCE").as_deref() == Ok("1") {
            assert_eq!(rustix::process::geteuid().as_raw(), 65534);
            assert_eq!(rustix::process::getegid().as_raw(), 65534);
        }
        let installation = Installation::two_accounts();
        let directory = installation.config().parent().unwrap();
        let server = server::ImapServer::new(directory);
        let empty_path = directory.join("empty-path");
        fs::create_dir(&empty_path).unwrap();
        let export_root = directory.join("exports");
        fs::create_dir(&export_root).unwrap();
        fs::set_permissions(&export_root, fs::Permissions::from_mode(0o700)).unwrap();
        let credential = if session {
            CredentialSource::Session {}
        } else {
            support::packaged_credential(directory, PASSWORD)
        };
        let mut config =
            Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
        config.export_roots = vec![export_root];
        for account in &mut config.accounts {
            account.server = "127.0.0.1".into();
            account.port = server.port;
            account.credential = credential.clone();
            account.from_identities = vec![account.username.clone()];
        }
        fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
        let fixture = Self {
            installation,
            server,
            empty_path,
        };
        let mut setup = fixture.command(executable);
        setup.args(["--json", "setup"]);
        assert_success(&run_bounded(setup));
        fixture
    }

    fn command(&self, executable: &str) -> Command {
        let mut command = self.installation.command(executable);
        support::packaged_environment(&mut command, &self.server.certificate, &self.empty_path);
        command
    }

    #[cfg(feature = "cli")]
    fn terminal(&self, arguments: &[&str], prompted: bool, exit: i64) -> Value {
        let command = self.command(support::MAILCTL);
        let mut argv = vec![command.get_program().to_string_lossy().into_owned()];
        argv.extend(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned()),
        );
        argv.push("--interactive".into());
        argv.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        let result = terminal::run(json!({
            "command": argv,
            "environment": {"SSL_CERT_FILE": self.server.certificate},
            "secret": PASSWORD,
        }));
        assert_eq!(result["exit"], exit, "{result}");
        assert_eq!(result["prompted"], prompted, "{result}");
        if prompted {
            assert_eq!(result["echo_during_prompt"], false);
        }
        assert_eq!(result["echo_enabled"], true);
        assert_eq!(result["secret_disclosed"], false);
        result
    }
}

fn assert_private(path: &Path, directory: bool) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(
        metadata.mode() & 0o777,
        if directory { 0o700 } else { 0o600 }
    );
    if directory {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap().path();
            assert_private(&entry, fs::symlink_metadata(&entry).unwrap().is_dir());
        }
    }
}

fn private_output(output: &std::process::Output) {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        for secret in [PASSWORD, " rotated-password "] {
            assert!(!text.contains(secret));
        }
        assert!(!text.contains("Password:"));
    }
}

fn explicit_source(executable: &str) {
    let mut fixture = Fixture::new(executable, false);
    let config = fs::read(fixture.installation.config()).unwrap();
    let mut status = fixture.command(executable);
    status.args(["--json", "--account", "work", "credential", "status"]);
    let output = run_bounded(status);
    assert_success(&output);
    assert_eq!(envelope(&output)["result"]["availability"], "configured");
    assert_eq!(envelope(&output)["result"]["provisioning"], "external");
    private_output(&output);
    let mut doctor = fixture.command(executable);
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
    let source =
        std::env::var("MAILCTL_PACKAGED_CREDENTIAL_SOURCE").unwrap_or_else(|_| "command".into());
    assert!(
        result["result"]["prerequisites"]
            .to_string()
            .contains(if source == "systemd" {
                "LoadCredential="
            } else {
                "trusted helper"
            })
    );
    assert!(
        result["result"]["prerequisites"]
            .to_string()
            .contains("/proc/self/fd")
    );
    assert_eq!(fixture.server.accepted(), 0);
    for operation in ["set", "delete"] {
        let mut command = fixture.command(executable);
        command.args(["--json", "--account", "work", "credential", operation]);
        let output = run_bounded(command);
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(envelope(&output)["error"]["code"], "credential_unavailable");
        private_output(&output);
    }
    fixture.server.expect("work@example.test", PASSWORD);
    let mut doctor = fixture.command(executable);
    doctor.args(["--json", "--account", "work", "doctor", "--check-account"]);
    let output = run_bounded(doctor);
    assert_success(&output);
    assert_eq!(
        envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["status"],
        "authenticated"
    );
    private_output(&output);
    if source == "command" {
        let secret = fixture
            .installation
            .config()
            .with_file_name("synthetic-credential");
        fs::write(&secret, " rotated-password \r\n").unwrap();
        fixture
            .server
            .expect("work@example.test", " rotated-password ");
        let mut doctor = fixture.command(executable);
        doctor.args(["--json", "--account", "work", "doctor", "--check-account"]);
        let output = run_bounded(doctor);
        assert_success(&output);
        private_output(&output);
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o666)).unwrap();
        let connections = fixture.server.accepted();
        let mut doctor = fixture.command(executable);
        doctor.args(["--json", "--account", "work", "doctor", "--check-account"]);
        let output = run_bounded(doctor);
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(
            envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
            "access_denied"
        );
        assert_eq!(fixture.server.accepted(), connections);
        private_output(&output);
    }
    assert_eq!(fs::read(fixture.installation.config()).unwrap(), config);
    assert_private(fixture.installation.config(), false);
    assert_private(&fixture.installation.config().with_file_name("state"), true);
    fixture.server.finish();
}

macro_rules! component_tests {
    ($scenario:ident, $cli:ident, $mcp:ident) => {
        #[cfg(feature = "cli")]
        #[test]
        fn $cli() {
            $scenario(support::MAILCTL);
        }
        #[cfg(feature = "mcp")]
        #[test]
        fn $mcp() {
            $scenario(support::MAILCTL_MCP);
        }
    };
}
component_tests!(
    explicit_source,
    cli_explicit_source_authenticates_and_preserves_private_state,
    mcp_explicit_source_authenticates_and_preserves_private_state
);

fn machine_session(executable: &str) {
    let mut fixture = Fixture::new(executable, true);
    let arguments = vec![vec!["--json", "doctor", "--check-account"]];
    #[cfg(feature = "cli")]
    let arguments = {
        let mut arguments = arguments;
        if executable == support::MAILCTL {
            arguments.extend([
                vec!["--interactive", "--json", "doctor", "--check-account"],
                vec!["--interactive", "doctor", "--check-account"],
            ]);
        }
        arguments
    };
    for arguments in arguments {
        let machine_output = arguments.contains(&"--json");
        let mut command = fixture.command(executable);
        command.args(arguments);
        let output = run_bounded(command);
        assert_eq!(output.status.code(), Some(4));
        private_output(&output);
        if machine_output {
            assert!(String::from_utf8_lossy(&output.stdout).contains("interaction_required"));
        }
    }
    assert_eq!(fixture.server.accepted(), 0);
    fixture.server.finish();
}
component_tests!(
    machine_session,
    cli_machine_session_does_not_prompt,
    mcp_administration_machine_session_does_not_prompt
);

#[cfg(feature = "cli")]
#[test]
fn cli_foreground_session_reads_and_recovers_one_draft_without_storing_credentials() {
    let mut fixture = Fixture::new(support::MAILCTL, true);
    fixture.server.expect("work@example.test", PASSWORD);
    fixture.terminal(&["doctor", "--check-account"], true, 0);
    fixture
        .server
        .expect_mailboxes("work@example.test", PASSWORD, &["INBOX"]);
    let listed = fixture.terminal(&["mailbox", "list"], true, 0);
    let reference = |response: &Value| {
        response["output"]
            .as_str()
            .unwrap()
            .lines()
            .find_map(|line| line.trim().strip_prefix("reference: "))
            .unwrap()
            .to_owned()
    };
    let mailbox = reference(&listed);
    fixture
        .server
        .expect_search("work@example.test", PASSWORD, "INBOX", None);
    let messages = fixture.terminal(
        &["message", "search", "--mailbox", &mailbox, "--limit", "1"],
        true,
        0,
    );
    let message = reference(&messages);
    fixture
        .server
        .expect_body_bytes("INBOX", b"Session reading body.\r\n");
    let body = fixture.terminal(&["message", "get", "--message", &message], true, 0);
    assert!(
        body["output"]
            .as_str()
            .unwrap()
            .contains("Session reading body.")
    );
    assert!(fixture.server.drafts().is_empty());

    let directory = fixture.installation.config().parent().unwrap();
    let registry: Value =
        serde_json::from_slice(&fs::read(directory.join("state/accounts.json")).unwrap()).unwrap();
    let account = registry["accounts"]["work"]["account_id"].as_str().unwrap();
    let operation = uuid::Uuid::new_v4().to_string();
    let composition = directory.join("draft.json");
    fs::write(
        &composition,
        serde_json::to_vec(&json!({
            "from":"work@example.test", "to":[{"address":"to@example.test"}],
            "subject":"Session draft", "body":"Session draft body."
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&composition, fs::Permissions::from_mode(0o600)).unwrap();
    let identity = [
        "--account-id",
        account,
        "--account-generation",
        "1",
        "--operation-id",
        &operation,
        "--mailbox",
        "Drafts",
    ];
    let mut save = vec!["--grant", "writer", "draft", "save"];
    save.extend(identity);
    save.extend(["--input", composition.to_str().unwrap()]);
    fixture.server.expect_append(server::DraftReply::Disconnect);
    let uncertain = fixture.terminal(&save, true, 7);
    assert!(
        uncertain["output"]
            .as_str()
            .unwrap()
            .contains("outcome_unknown")
    );
    assert!(uncertain["output"].as_str().unwrap().contains(&operation));
    let connections = fixture.server.accepted();
    fixture.terminal(&save, false, 7);
    let mut status = vec!["--grant", "writer", "draft", "status"];
    status.extend(identity);
    fixture.terminal(&status, false, 7);
    assert_eq!(fixture.server.accepted(), connections);
    fixture.server.expect_reconciliation();
    status.push("--reconcile");
    let verified = fixture.terminal(&status, true, 0);
    let decode = |response: &Value| {
        let text = response["output"].as_str().unwrap();
        serde_json::from_str::<Value>(text[text.find('{').unwrap()..].trim()).unwrap()
    };
    let receipt = decode(&verified);
    assert_eq!(receipt["state"], "duplicate");
    assert_eq!(receipt["operation_id"], operation);
    assert_eq!(decode(&fixture.terminal(&save, false, 0)), receipt);
    assert_eq!(fixture.server.accepted(), connections + 1);
    let drafts = fixture.server.drafts();
    assert_eq!(drafts.len(), 1);
    let draft = mail_parser::MessageParser::default()
        .parse(&drafts[0])
        .unwrap();
    assert_eq!(draft.subject(), Some("Session draft"));
    assert_eq!(draft.body_text(0).unwrap().trim(), "Session draft body.");
    let database = rusqlite::Connection::open(directory.join("state/drafts.sqlite")).unwrap();
    let state: String = database
        .query_row("SELECT state FROM draft_operations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "duplicate");
    for entry in fs::read_dir(fixture.installation.config().with_file_name("state")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert!(
                !fs::read(path)
                    .unwrap()
                    .windows(PASSWORD.len())
                    .any(|bytes| bytes == PASSWORD.as_bytes())
            );
        }
    }
    fixture.server.finish();
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_session_tools_return_interaction_required_without_a_prompt() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use tokio::io::AsyncReadExt;
    let mut fixture = Fixture::new(support::MAILCTL_MCP, true);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let command = fixture.command(support::MAILCTL_MCP);
        let (transport, stderr) =
            TokioChildProcess::builder(tokio::process::Command::from(command))
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
        let capture = tokio::spawn(async move {
            let mut output = String::new();
            stderr
                .unwrap()
                .take(65536)
                .read_to_string(&mut output)
                .await
                .unwrap();
            output
        });
        let client = ().serve(transport).await.unwrap();
        let tools = client.list_all_tools().await.unwrap();
        assert!(
            !tools
                .iter()
                .any(|tool| tool.name.contains("credential") || tool.name.contains("setup"))
        );
        let response = client
            .call_tool(
                CallToolRequestParams::new("email_list_mailboxes")
                    .with_arguments(serde_json::Map::new()),
            )
            .await
            .unwrap();
        let result: Value = support::assert_mcp_envelope(response);
        assert_eq!(result["error"]["code"], "credential_unavailable");
        assert_eq!(
            result["error"]["credential_failure"],
            "interaction_required"
        );
        client.cancel().await.unwrap();
        let output = capture.await.unwrap();
        assert!(!output.contains("Password:"));
        assert!(!output.contains(PASSWORD));
    })
    .await
    .unwrap();
    assert_eq!(fixture.server.accepted(), 0);
    fixture.server.finish();
}
