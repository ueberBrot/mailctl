//! Process evidence for discovery through the broker, CLI, and MCP adapter.

use std::process::{Command, Output};

#[cfg(unix)]
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use uuid::Uuid;

const MAILCTL: &str = env!("CARGO_BIN_EXE_mailctl");
const MAILD: &str = env!("CARGO_BIN_EXE_maild");
const MAIL_MCP: &str = env!("CARGO_BIN_EXE_mail-mcp");

#[test]
fn machine_cli_returns_one_safe_broker_unavailable_envelope_without_an_endpoint() {
    let hostile_alias = "not-an-account\u{1b}]52;c;private-data\u{7}";
    let output = Command::new(MAILCTL)
        .args(["--json", "--account", hostile_alias, "account", "list"])
        .output()
        .expect("mailctl starts");

    assert_eq!(output.status.code(), Some(5));
    assert_no_terminal_control(&output.stdout);
    assert_no_terminal_control(&output.stderr);

    let envelope = parse_one_json_envelope(&output);
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"]["code"], "broker_unavailable");
    assert_eq!(envelope["error"]["retryable"], true);
}

#[test]
fn mcp_rejects_conflicting_profile_flags_without_writing_protocol_stdout() {
    let output = Command::new(MAIL_MCP)
        .args(["--read-only", "--use-endpoint-grant"])
        .output()
        .expect("mail-mcp starts");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP stdout remains protocol-only");
    assert_no_terminal_control(&output.stdout);
    assert_no_terminal_control(&output.stderr);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid_request"),
        "the option conflict has a stable safe error category"
    );
}

#[cfg(unix)]
#[test]
fn broker_restart_preserves_email_account_identity_and_generation() {
    let mut fixture = BrokerFixture::new("work");
    fixture.start();
    let first = fixture.cli_json(["account", "list"]);
    fixture.stop();

    fixture.start();
    let second = fixture.cli_json(["account", "list"]);

    let first_account = &first["result"]["accounts"][0];
    let second_account = &second["result"]["accounts"][0];
    assert_eq!(first_account["account_id"], second_account["account_id"]);
    assert_eq!(first_account["generation"], second_account["generation"]);
}

#[cfg(unix)]
#[tokio::test]
async fn cli_and_mcp_expose_the_same_read_only_discovery_contract() {
    use rmcp::{
        ServiceExt,
        model::{CallToolRequestParams, ContentBlock},
        transport::{ConfigureCommandExt, TokioChildProcess},
    };

    let mut fixture = BrokerFixture::new("work");
    fixture.start();

    let cli = fixture.cli_json(["account", "list"]);
    assert_eq!(cli["ok"], true);
    assert_eq!(cli["result"]["accounts"].as_array().map(Vec::len), Some(1));
    assert_eq!(cli["result"]["accounts"][0]["alias"], "work");
    assert_eq!(cli["result"]["complete"], true);

    let capabilities = fixture.cli_json(["capability", "show"]);
    assert_eq!(capabilities["ok"], true);

    let transport =
        TokioChildProcess::new(tokio::process::Command::new(MAIL_MCP).configure(|command| {
            command
                .arg("--endpoint")
                .arg(fixture.endpoint())
                .arg("--broker-uid")
                .arg(fixture.uid().to_string());
        }))
        .expect("mail-mcp starts");
    let client = ().serve(transport).await.expect("MCP initialize succeeds");

    let tools = client
        .list_all_tools()
        .await
        .expect("MCP lists its read-only tools");
    let tool_names = tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<Vec<_>>();
    assert!(tool_names.iter().any(|name| *name == "email_list_accounts"));
    assert!(tool_names.iter().any(|name| *name == "email_capabilities"));
    assert!(tool_names.iter().all(|name| *name != "email_save_draft"));
    for tool in &tools {
        assert!(
            tool.input_schema.contains_key("type"),
            "{} has an input schema",
            tool.name
        );
        assert!(
            tool.output_schema.is_some(),
            "{} has an output schema",
            tool.name
        );
    }

    let result = client
        .call_tool(CallToolRequestParams::new("email_list_accounts"))
        .await
        .expect("listed MCP tool succeeds");
    assert_ne!(result.is_error, Some(true));
    let structured = result
        .structured_content
        .expect("MCP supplies structuredContent");
    let text = result
        .content
        .iter()
        .find_map(ContentBlock::as_text)
        .map(|content| serde_json::from_str::<Value>(&content.text).expect("MCP text is JSON"))
        .expect("MCP supplies a JSON text result");
    assert_eq!(structured, text, "MCP text and structured result agree");
    assert_eq!(without_request_id(structured), without_request_id(cli));

    assert!(
        client
            .call_tool(CallToolRequestParams::new("email_save_draft"))
            .await
            .is_err(),
        "a hidden tool is a JSON-RPC method failure"
    );
    let denied_profile = client
        .call_tool(
            CallToolRequestParams::new("email_list_accounts").with_arguments(
                json!({"profile": "read_and_drafts"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("a syntactically valid tool call returns a tool result");
    assert_eq!(denied_profile.is_error, Some(true));
    assert_eq!(
        denied_profile
            .structured_content
            .expect("profile error is structured")["error"]["code"],
        "invalid_request"
    );

    client.cancel().await.expect("MCP client stops");
}

#[cfg(unix)]
#[test]
fn cli_rejects_a_zero_discovery_limit_before_dispatch() {
    let mut fixture = BrokerFixture::new("work");
    fixture.start();
    let output = Command::new(MAILCTL)
        .arg("--endpoint")
        .arg(fixture.endpoint())
        .arg("--broker-uid")
        .arg(fixture.uid().to_string())
        .arg("--json")
        .args(["account", "list", "--limit", "0"])
        .output()
        .expect("mailctl starts");

    assert_eq!(output.status.code(), Some(2));
    let envelope = parse_one_json_envelope(&output);
    assert_eq!(envelope["error"]["code"], "invalid_request");
}

#[cfg(unix)]
#[tokio::test]
async fn drafts_only_mcp_requires_an_explicit_endpoint_grant_for_draft_permissions() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};

    let mut fixture = BrokerFixture::with_profile("work", "drafts_only");
    fixture.start();

    let default =
        ().serve(TokioChildProcess::new(fixture.mcp_command()).expect("MCP starts"))
            .await
            .expect("default read-only MCP initializes");
    let default_capabilities = default
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .expect("capability tool succeeds")
        .structured_content
        .expect("capability result is structured");
    assert_eq!(
        default_capabilities["result"]["permissions"],
        json!(["list_accounts"])
    );
    default.cancel().await.expect("default MCP stops");

    let mut explicit_command = fixture.mcp_command();
    explicit_command.arg("--use-endpoint-grant");
    let explicit =
        ().serve(TokioChildProcess::new(explicit_command).expect("MCP starts with endpoint grant"))
            .await
            .expect("endpoint-grant MCP initializes");
    let explicit_tools = explicit
        .list_all_tools()
        .await
        .expect("MCP lists implemented tools");
    assert!(
        explicit_tools
            .iter()
            .all(|tool| tool.name != "email_save_draft"),
        "unimplemented draft actions stay hidden"
    );
    let explicit_capabilities = explicit
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .expect("capability tool succeeds")
        .structured_content
        .expect("capability result is structured");
    let permissions = explicit_capabilities["result"]["permissions"]
        .as_array()
        .expect("permissions are an array");
    assert!(permissions.contains(&json!("list_accounts")));
    assert!(permissions.contains(&json!("append_draft")));
    assert!(permissions.contains(&json!("inspect_draft_operation")));
    explicit.cancel().await.expect("explicit MCP stops");
}

#[cfg(unix)]
#[tokio::test]
async fn broker_restart_invalidates_existing_mcp_sessions() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};

    let mut fixture = BrokerFixture::new("work");
    fixture.start();
    let stale =
        ().serve(TokioChildProcess::new(fixture.mcp_command()).expect("MCP starts"))
            .await
            .expect("MCP initializes");

    fixture.stop();
    fixture.start();

    let stale_result = stale
        .call_tool(CallToolRequestParams::new("email_list_accounts"))
        .await;
    match stale_result {
        Ok(result) => {
            assert_eq!(result.is_error, Some(true));
            assert_eq!(
                result
                    .structured_content
                    .expect("stale error is structured")["error"]["code"],
                "broker_unavailable"
            );
        }
        Err(_) => {}
    }
    stale.cancel().await.expect("stale MCP process stops");

    let fresh =
        ().serve(TokioChildProcess::new(fixture.mcp_command()).expect("fresh MCP starts"))
            .await
            .expect("fresh MCP initializes");
    assert_ne!(
        fresh
            .call_tool(CallToolRequestParams::new("email_list_accounts"))
            .await
            .expect("fresh MCP call succeeds")
            .is_error,
        Some(true)
    );
    fresh.cancel().await.expect("fresh MCP stops");
}

#[cfg(unix)]
#[test]
fn mcp_drops_oversized_and_deep_unframed_input_without_echoing_it() {
    let mut fixture = BrokerFixture::new("work");
    fixture.start();

    let oversized = fixture.run_unframed_mcp(&vec![b'x'; 64 * 1024 + 1]);
    assert_rejected_mcp_input(&oversized, b"xxxxxxxx");

    let nested = fixture.run_unframed_mcp(&vec![b'['; 33]);
    assert_rejected_mcp_input(&nested, b"[[[[[[[[");
}

#[cfg(unix)]
struct BrokerFixture {
    directory: PathBuf,
    config: PathBuf,
    endpoint: PathBuf,
    child: Option<Child>,
}

#[cfg(unix)]
impl BrokerFixture {
    fn new(alias: &str) -> Self {
        Self::with_profile(alias, "read_only")
    }

    fn with_profile(alias: &str, profile: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;

        let temporary_root = fs::canonicalize("/tmp")
            .or_else(|_| fs::canonicalize(std::env::temp_dir()))
            .expect("canonical temporary directory");
        let directory = temporary_root.join(format!("mc-{}", Uuid::new_v4().simple()));
        fs::create_dir(&directory).expect("create isolated test directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("protect test directory");
        let state_directory = directory.join("state");
        fs::create_dir(&state_directory).expect("create broker state directory");
        fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))
            .expect("protect broker state directory");
        let endpoint = directory.join("maild.sock");
        let config = directory.join("mailctl.toml");
        let config_body = format!(
            r#"version = 1
deployment = "cooperative"
topology = "native"
state_dir = "{}"

[[accounts]]
key = "primary"
alias = "{}"
server = "imap.example.test"
username = "synthetic@example.test"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["primary"]
drafts_mailbox = "Drafts"

[accounts.credential]
source = "native"

[[listeners]]
name = "reader"
endpoint = "{}"
peer_uids = [{}]
accounts = ["primary"]
mailboxes = ["INBOX", "Drafts"]
profile = "{}"
"#,
            state_directory.display(),
            alias,
            endpoint.display(),
            rustix::process::geteuid().as_raw(),
            profile,
        );
        fs::write(&config, config_body).expect("write broker configuration");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
            .expect("protect broker configuration");
        Self {
            directory,
            config,
            endpoint,
            child: None,
        }
    }

    fn start(&mut self) {
        assert!(self.child.is_none(), "broker is not already running");
        let child = Command::new(MAILD)
            .arg("--config")
            .arg(&self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("maild starts");
        self.child = Some(child);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.endpoint.exists() && self.is_ready() {
                return;
            }
            let child = self.child.as_mut().expect("broker child exists");
            if let Some(status) = child.try_wait().expect("inspect broker process") {
                let mut diagnostics = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_string(&mut diagnostics);
                }
                panic!(
                    "maild exited before binding {0}: {status}; diagnostics: {diagnostics}",
                    self.endpoint.display()
                );
            }
            assert!(
                Instant::now() < deadline,
                "maild did not bind {}",
                self.endpoint.display()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    fn uid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn mcp_command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(MAIL_MCP);
        command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--broker-uid")
            .arg(self.uid().to_string());
        command
    }

    fn run_unframed_mcp(&self, input: &[u8]) -> Output {
        let mut command = Command::new(MAIL_MCP);
        let mut child = command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--broker-uid")
            .arg(self.uid().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("mail-mcp starts");
        child
            .stdin
            .take()
            .expect("mail-mcp accepts stdin")
            .write_all(input)
            .expect("write malformed MCP input");

        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().expect("inspect mail-mcp process") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("mail-mcp did not terminate malformed input");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .stdout
            .take()
            .expect("capture MCP stdout")
            .read_to_end(&mut stdout)
            .expect("read MCP stdout");
        child
            .stderr
            .take()
            .expect("capture MCP stderr")
            .read_to_end(&mut stderr)
            .expect("read MCP stderr");
        Output {
            status,
            stdout,
            stderr,
        }
    }

    fn is_ready(&self) -> bool {
        Command::new(MAILCTL)
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--broker-uid")
            .arg(self.uid().to_string())
            .arg("--json")
            .args(["capability", "show"])
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn cli_json<const N: usize>(&self, tail: [&str; N]) -> Value {
        let mut command = Command::new(MAILCTL);
        command
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--broker-uid")
            .arg(self.uid().to_string())
            .arg("--json")
            .args(tail);
        let output = command.output().expect("mailctl starts");
        assert!(
            output.status.success(),
            "mailctl exited {:?}; stdout: {}; stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        parse_one_json_envelope(&output)
    }
}

#[cfg(unix)]
impl Drop for BrokerFixture {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn parse_one_json_envelope(output: &Output) -> Value {
    assert!(
        output.stdout.ends_with(b"\n"),
        "JSON stdout is line-delimited"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert_eq!(
        stdout.lines().count(),
        1,
        "machine stdout contains one JSON envelope"
    );
    serde_json::from_str(stdout).expect("machine stdout is a JSON envelope")
}

fn without_request_id(mut value: Value) -> Value {
    value
        .as_object_mut()
        .expect("response is an object")
        .remove("request_id");
    value
}

fn assert_no_terminal_control(bytes: &[u8]) {
    assert!(
        !bytes.contains(&0x1b),
        "output contains an ANSI escape sequence"
    );
}

#[cfg(unix)]
fn assert_rejected_mcp_input(output: &Output, marker: &[u8]) {
    assert!(!output.status.success(), "malformed MCP input is rejected");
    assert_no_terminal_control(&output.stdout);
    assert_no_terminal_control(&output.stderr);
    assert!(
        !output
            .stdout
            .windows(marker.len())
            .any(|window| window == marker)
    );
    assert!(
        !output
            .stderr
            .windows(marker.len())
            .any(|window| window == marker)
    );
}
