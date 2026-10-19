#![cfg(any(feature = "cli", feature = "mcp"))]
mod imap_support;
#[path = "imap_support/process.rs"]
mod server;
mod support;

use mailctl::{
    config::CredentialSource,
    credentials::{self, Secret},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};
use support::{Installation, assert_success, envelope, run_bounded_with_timeout};
use uuid::Uuid;

const WORK: &str = "work@example.test";
const FIRST: &str = "first-wsl-synthetic-password";
const SECOND: &str = "second-wsl-synthetic-password";
const ROTATED: &str = "disposable-password";
const COMPONENTS: &[&str] = &[
    #[cfg(feature = "cli")]
    "mailctl",
    #[cfg(feature = "mcp")]
    "mailctl-mcp",
];

fn mounted_path(path: &Path) -> String {
    let text = path.to_str().unwrap().trim_start_matches(r"\\?\");
    let bytes = text.as_bytes();
    assert!(bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    assert!(
        matches!(bytes[2], b'\\' | b'/'),
        "absolute Windows drive path"
    );
    format!(
        "/mnt/{}{}",
        (bytes[0] as char).to_ascii_lowercase(),
        text[2..].replace('\\', "/")
    )
}

fn wsl() -> Command {
    let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    assert!(system.is_absolute());
    let mut command = Command::new(system.join("System32/wsl.exe"));
    command.env_clear();
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
    command
}

fn linux() -> Command {
    let mut command = wsl();
    let distro = std::env::var("MAILCTL_WSL_DISTRO").unwrap();
    assert!(distro.starts_with("mailctl-wsl-") && distro.len() == 44);
    assert!(distro[12..].bytes().all(|byte| byte.is_ascii_hexdigit()));
    command.args(["--distribution", &distro, "--exec"]);
    command
}

fn run(command: Command) -> Output {
    let output = run_bounded_with_timeout(command, Duration::from_secs(60));
    for password in [FIRST, SECOND, ROTATED] {
        assert!(
            !output
                .stdout
                .windows(password.len())
                .any(|bytes| bytes == password.as_bytes())
        );
        assert!(
            !output
                .stderr
                .windows(password.len())
                .any(|bytes| bytes == password.as_bytes())
        );
    }
    output
}

fn text(output: &Output) -> String {
    assert_success(output);
    if output
        .stdout
        .iter()
        .skip(1)
        .step_by(2)
        .any(|byte| *byte == 0)
    {
        let (pairs, remainder) = output.stdout.as_chunks::<2>();
        assert!(remainder.is_empty(), "complete UTF-16 output units");
        let units: Vec<_> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        String::from_utf16(&units)
            .unwrap()
            .trim_start_matches('\u{feff}')
            .trim()
            .into()
    } else {
        String::from_utf8(output.stdout.clone())
            .unwrap()
            .trim()
            .into()
    }
}

fn boot_id() -> Uuid {
    let mut command = linux();
    command.args([
        "/bin/sh",
        "-c",
        "IFS= read -r boot < /proc/sys/kernel/random/boot_id; printf '%s\\n' \"$boot\"",
    ]);
    Uuid::parse_str(&text(&run(command))).unwrap()
}

fn windows_sid(output: &Output) -> String {
    text(output)
        .split('"')
        .find(|field| field.starts_with("S-1-"))
        .unwrap()
        .into()
}

fn assert_windows_identity() {
    let executable =
        PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/whoami.exe");
    let mut native = Command::new(&executable);
    native.args(["/user", "/fo", "csv", "/nh"]);
    let expected = windows_sid(&run(native));
    let mut interop = linux();
    interop
        .arg(mounted_path(&executable))
        .args(["/user", "/fo", "csv", "/nh"]);
    assert_eq!(windows_sid(&run(interop)), expected);
}

struct Credentials(Vec<Uuid>);
impl Credentials {
    fn set(&self, id: Uuid, password: &str) {
        assert!(self.0.contains(&id));
        credentials::source_for(&CredentialSource::Native {})
            .mutable_store()
            .unwrap()
            .set(id, &Secret::new(password.as_bytes().to_vec()).unwrap())
            .unwrap();
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        let source = credentials::source_for(&CredentialSource::Native {});
        for id in &self.0 {
            let _ = source.mutable_store().unwrap().delete(*id);
        }
    }
}

struct Fixture {
    installation: Installation,
    server: server::ImapServer,
    #[cfg(feature = "cli")]
    root: PathBuf,
    binaries: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let installation = Installation::empty();
        let directory = installation.config().parent().unwrap();
        let server = server::ImapServer::new(directory);
        let root = directory.join("Windows exports résumé 🦀");
        fs::create_dir(&root).unwrap();
        support::protect(&root, true);
        let configuration = format!(
            r#"topology = "windows_hosted_wsl"
state_dir = {state}
export_roots = [{root}]

[limits]
attachment_chunk_bytes = 3

[[accounts]]
key = "work"
alias = "work"
server = "127.0.0.1"
port = {port}
username = "work@example.test"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["work@example.test"]
drafts_mailbox = "Drafts"
retain_history = true
[accounts.credential]
source = "native"

[[accounts]]
key = "personal"
alias = "personal"
server = "127.0.0.1"
port = {port}
username = "personal@example.test"
mailboxes = ["INBOX"]
from_identities = ["personal@example.test"]
[accounts.credential]
source = "native"

[[grants]]
name = "default"
profile = "read_only"
accounts = ["work", "personal"]
mailboxes = ["INBOX"]

[[grants]]
name = "writer"
profile = "drafts_only"
accounts = ["work"]
mailboxes = ["Drafts"]
"#,
            state = support::toml_string(&directory.join("state")),
            root = support::toml_string(&root),
            port = server.port
        );
        fs::write(installation.config(), configuration).unwrap();
        support::protect(installation.config(), false);
        let binaries = PathBuf::from(std::env::var_os("MAILCTL_PACKAGED_BIN_DIR").unwrap());
        assert!(binaries.is_absolute() && binaries.is_dir());
        Self {
            installation,
            server,
            #[cfg(feature = "cli")]
            root,
            binaries,
        }
    }
    fn command(&self, component: &str) -> Command {
        let binary = self.binaries.join(format!("{component}.exe"));
        assert!(binary.is_file());
        let mut command = linux();
        command
            .arg(mounted_path(&binary))
            .arg("--config")
            .arg(self.installation.config())
            .env("WSLENV", "SSL_CERT_FILE")
            .env("SSL_CERT_FILE", &self.server.certificate);
        command
    }
    fn admin(&self, component: &str, arguments: &[&str]) -> Value {
        let mut command = self.command(component);
        command.arg("--json").args(arguments);
        let output = run(command);
        assert_success(&output);
        let value = envelope(&output);
        assert_eq!(value["ok"], true, "{value}");
        value["result"].clone()
    }
    fn ids(&self) -> Value {
        serde_json::from_slice::<Value>(
            &fs::read(
                self.installation
                    .config()
                    .parent()
                    .unwrap()
                    .join("state/accounts.json"),
            )
            .unwrap(),
        )
        .unwrap()["accounts"]
            .clone()
    }
    fn draft(id: Uuid) -> Value {
        json!({"account_id": id, "account_generation": 1, "operation_id": Uuid::new_v4(), "mailbox": "Drafts", "draft": {
            "from": WORK, "to": [{"address": "recipient@example.test", "name": "WSL résumé 🦀"}],
            "subject": "Windows-hosted WSL draft", "body": "Synthetic Unicode body.\nSecond line 🦀."}})
    }
}

fn assert_draft(bytes: &[u8], operation: &Value) {
    let message = mail_parser::MessageParser::default().parse(bytes).unwrap();
    let recipient = message.to().unwrap().first().unwrap();
    assert_eq!(recipient.address(), Some("recipient@example.test"));
    assert_eq!(recipient.name(), Some("WSL résumé 🦀"));
    assert_eq!(
        message.body_text(0).unwrap().replace("\r\n", "\n"),
        operation["draft"]["body"].as_str().unwrap()
    );
    let expected_id = format!(
        "{}.1.{}@mailctl.invalid",
        operation["account_id"].as_str().unwrap(),
        operation["operation_id"].as_str().unwrap()
    );
    assert_eq!(message.message_id(), Some(expected_id.as_str()));
}

enum Caller {
    #[cfg(feature = "cli")]
    Cli {
        component: &'static str,
        grant: &'static str,
    },
    #[cfg(feature = "mcp")]
    Mcp {
        client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
        child: Box<tokio::process::Child>,
    },
}
#[cfg_attr(
    not(feature = "mcp"),
    allow(
        clippy::unused_async,
        reason = "shared fixture awaits MCP when selected"
    )
)]
impl Caller {
    async fn start(fixture: &Fixture, component: &'static str, grant: &'static str) -> Self {
        #[cfg(feature = "cli")]
        if component == "mailctl" {
            return Self::Cli { component, grant };
        }
        #[cfg(feature = "mcp")]
        {
            use rmcp::ServiceExt;
            use std::process::Stdio;
            let mut command = fixture.command(component);
            command.args(["--account", "work", "--grant", grant]);
            if grant == "writer" {
                command.arg("--use-configured-grant");
            }
            let mut child = tokio::process::Command::from(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let pipes = (child.stdout.take().unwrap(), child.stdin.take().unwrap());
            let client = tokio::time::timeout(Duration::from_secs(60), ().serve(pipes))
                .await
                .unwrap()
                .unwrap();
            Self::Mcp {
                client,
                child: Box::new(child),
            }
        }
        #[cfg(not(feature = "mcp"))]
        {
            let _ = fixture;
            unreachable!("only selected CLI component is compiled")
        }
    }
    async fn response(
        &self,
        fixture: &Fixture,
        arguments: &[String],
        tool: &str,
        input: Value,
    ) -> Value {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli { component, grant } => {
                let _ = (tool, input);
                let mut command = fixture.command(component);
                command
                    .args(["--json", "--account", "work", "--grant", grant])
                    .args(arguments);
                let output = run(command);
                let response = envelope(&output);
                assert_eq!(output.status.success(), response["ok"] == true);
                if response["error"]["code"] == "outcome_unknown" {
                    assert_eq!(output.status.code(), Some(7));
                }
                response
            }
            #[cfg(feature = "mcp")]
            Self::Mcp { client, .. } => {
                let _ = (fixture, arguments);
                let request = rmcp::model::CallToolRequestParams::new(tool.to_owned())
                    .with_arguments(input.as_object().unwrap().clone());
                support::assert_mcp_envelope(
                    tokio::time::timeout(Duration::from_secs(60), client.call_tool(request))
                        .await
                        .unwrap()
                        .unwrap(),
                )
            }
        }
    }
    async fn call(
        &self,
        fixture: &Fixture,
        arguments: &[String],
        tool: &str,
        input: Value,
    ) -> Value {
        let mut result = self.response(fixture, arguments, tool, input).await;
        assert_eq!(result["ok"], true, "{result}");
        result["result"].take()
    }
    async fn draft(
        &self,
        fixture: &Fixture,
        operation: &Value,
        save: bool,
        reconcile: bool,
    ) -> Value {
        let mut input = operation.clone();
        let mut arguments = vec![
            "draft".into(),
            if save { "save".into() } else { "status".into() },
        ];
        for field in [
            "account_id",
            "account_generation",
            "operation_id",
            "mailbox",
        ] {
            arguments.push(format!("--{}", field.replace('_', "-")));
            arguments.push(if field == "account_generation" {
                input[field].to_string()
            } else {
                input[field].as_str().unwrap().into()
            });
        }
        if save {
            let path = fixture
                .installation
                .config()
                .with_file_name("composition résumé.json");
            fs::write(&path, serde_json::to_vec(&input["draft"]).unwrap()).unwrap();
            arguments.extend(["--input".into(), path.to_str().unwrap().into()]);
        } else {
            input.as_object_mut().unwrap().remove("draft");
            input["reconcile"] = json!(reconcile);
            if reconcile {
                arguments.push("--reconcile".into());
            }
        }
        self.response(
            fixture,
            &arguments,
            if save {
                "email_save_draft"
            } else {
                "email_draft_status"
            },
            input,
        )
        .await
    }
    async fn finish(self) {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli { .. } => {}
            #[cfg(feature = "mcp")]
            Self::Mcp { client, mut child } => {
                tokio::time::timeout(Duration::from_secs(30), client.cancel())
                    .await
                    .unwrap()
                    .unwrap();
                let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
                    .await
                    .expect("WSL interop exits after graceful MCP EOF")
                    .unwrap();
                assert!(
                    status.success(),
                    "WSL interop must exit gracefully: {status}"
                );
            }
        }
    }
}
fn args(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).into()).collect()
}

async fn read(fixture: &Fixture, component: &'static str) {
    let caller = Caller::start(fixture, component, "default").await;
    fixture.server.expect_mailboxes(WORK, ROTATED, &["INBOX"]);
    let mailbox = caller
        .call(
            fixture,
            &args(&["mailbox", "list"]),
            "email_list_mailboxes",
            json!({}),
        )
        .await["mailboxes"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    fixture.server.expect_search(WORK, ROTATED, "INBOX", None);
    let message = caller
        .call(
            fixture,
            &args(&["message", "search", "--mailbox", &mailbox, "--limit", "1"]),
            "email_search_messages",
            json!({"mailbox": mailbox, "limit": 1}),
        )
        .await["messages"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    fixture.server.expect_body(WORK, ROTATED, "INBOX");
    let body = caller
        .call(
            fixture,
            &args(&["message", "get", "--message", &message]),
            "email_get_message",
            json!({"message": message}),
        )
        .await;
    assert_eq!(body["body"]["text"], "Short body.\r\n");
    #[cfg(feature = "cli")]
    if component == "mailctl" {
        fixture
            .server
            .expect_attachment(WORK, ROTATED, "INBOX", server::AttachmentPhase::List);
        let attachment = caller
            .call(
                fixture,
                &args(&["attachment", "list", "--message", &message]),
                "email_list_attachments",
                json!({"message": message}),
            )
            .await["attachments"][0]["reference"]
            .as_str()
            .unwrap()
            .to_owned();
        for phase in [
            server::AttachmentPhase::Start,
            server::AttachmentPhase::Continue,
        ] {
            fixture
                .server
                .expect_attachment(WORK, ROTATED, "INBOX", phase);
        }
        let receipt = caller
            .call(
                fixture,
                &args(&[
                    "attachment",
                    "export",
                    "--attachment",
                    &attachment,
                    "--root",
                    fixture.root.to_str().unwrap(),
                    "--name",
                    "résumé 🦀.bin",
                ]),
                "unused_cli_export",
                json!({}),
            )
            .await;
        let destination = fixture.root.join("résumé 🦀.bin");
        assert_eq!(receipt["path"], destination.to_str().unwrap());
        assert!(
            receipt["filesystem"]
                .as_str()
                .unwrap()
                .starts_with("windows:")
        );
        assert_eq!(receipt["total_decoded_bytes"], 6);
        assert_eq!(
            receipt["sha256"],
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
        );
        assert_eq!(fs::read(destination).unwrap(), b"abcdef");
    }
    caller.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable Windows identity and an owned, running WSL2 distribution"]
async fn windows_hosted_wsl2_reading_drafts_and_restart() {
    assert_eq!(std::env::consts::OS, "windows");
    assert_eq!(
        std::env::var("MAILCTL_DISPOSABLE_WINDOWS").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("MAILCTL_PACKAGED_CREDENTIAL_SOURCE").as_deref(),
        Ok("native")
    );
    let before_boot = boot_id();
    assert_windows_identity();
    let mut fixture = Fixture::new();
    let first_component = COMPONENTS[0];
    let setup = fixture.admin(first_component, &["setup"]);
    assert_eq!(setup["accounts"], 2);
    let identity = setup["installation_id"].clone();
    let ids = fixture.ids();
    let first = Uuid::parse_str(ids["work"]["account_id"].as_str().unwrap()).unwrap();
    let second = Uuid::parse_str(ids["personal"]["account_id"].as_str().unwrap()).unwrap();
    let credentials = Credentials(vec![first, second]);
    credentials.set(first, FIRST);
    credentials.set(second, SECOND);
    let configuration = fs::read(fixture.installation.config()).unwrap();
    for component in COMPONENTS {
        let version = {
            let mut command = fixture.command(component);
            command.arg("--version");
            text(&run(command))
        };
        assert_eq!(
            version,
            format!("{component} {}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            fixture.admin(component, &["setup"])["installation_id"],
            identity
        );
        let doctor = fixture.admin(component, &["doctor"]);
        assert_eq!(doctor["topology"], "windows_hosted_wsl");
        assert_eq!(doctor["installation_id"], identity);
        assert!(
            doctor["prerequisites"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value
                    .as_str()
                    .unwrap()
                    .contains("Windows execution identity"))
        );
        assert_eq!(
            fs::read(fixture.installation.config()).unwrap(),
            configuration
        );
        for (alias, username, password, id) in [
            ("work", WORK, FIRST, first),
            ("personal", "personal@example.test", SECOND, second),
        ] {
            fixture.server.expect(username, password);
            let doctor = fixture.admin(
                component,
                &["--account", alias, "doctor", "--check-account"],
            );
            assert_eq!(doctor["accounts"][0]["account_id"], id.to_string());
            assert_eq!(
                doctor["accounts"][0]["authentication"]["outcome"]["status"],
                "authenticated"
            );
        }
    }
    credentials.set(first, ROTATED);
    let mut retained = Vec::new();
    for component in COMPONENTS {
        fixture.server.expect(WORK, ROTATED);
        let doctor = fixture.admin(
            component,
            &["--account", "work", "doctor", "--check-account"],
        );
        assert_eq!(
            doctor["accounts"][0]["authentication"]["outcome"]["status"],
            "authenticated"
        );
        read(&fixture, component).await;
        let caller = Caller::start(&fixture, component, "writer").await;
        let created = Fixture::draft(first);
        fixture
            .server
            .expect_append(server::DraftReply::Created(true));
        let result = caller.draft(&fixture, &created, true, false).await;
        assert_eq!(result["result"]["state"], "created", "{result}");
        assert_draft(fixture.server.drafts().last().unwrap(), &created);
        let uncertain = Fixture::draft(first);
        fixture.server.expect_append(server::DraftReply::Disconnect);
        let failed = caller.draft(&fixture, &uncertain, true, false).await;
        assert_eq!(failed["error"]["code"], "outcome_unknown", "{failed}");
        let accepted = fixture.server.accepted();
        assert_eq!(
            caller.draft(&fixture, &uncertain, true, false).await["error"]["code"],
            "outcome_unknown"
        );
        assert_eq!(fixture.server.accepted(), accepted);
        let captured = fixture.server.drafts().pop().unwrap();
        assert_draft(&captured, &uncertain);
        caller.finish().await;
        retained.push((
            component,
            created,
            result["result"].clone(),
            uncertain,
            captured,
        ));
    }
    assert_eq!(fixture.server.drafts().len(), COMPONENTS.len() * 2);
    let accepted = fixture.server.accepted();
    let mut shutdown = wsl();
    shutdown.arg("--shutdown");
    assert_success(&run(shutdown));
    let mut running = wsl();
    running.args(["--list", "--running", "--quiet"]);
    let distro = std::env::var("MAILCTL_WSL_DISTRO").unwrap();
    assert!(
        !text(&run(running))
            .lines()
            .any(|name| name.trim() == distro)
    );
    let after_boot = boot_id();
    assert_ne!(
        before_boot, after_boot,
        "actual WSL2 VM restart changes Linux boot identity"
    );
    assert_windows_identity();
    assert_eq!(fixture.ids(), ids);
    assert_eq!(
        fs::read(fixture.installation.config()).unwrap(),
        configuration
    );
    for (component, created, created_result, uncertain, captured) in retained {
        assert_eq!(
            fixture.admin(component, &["setup"])["installation_id"],
            identity
        );
        let caller = Caller::start(&fixture, component, "writer").await;
        assert_eq!(
            caller.draft(&fixture, &created, false, false).await["result"],
            created_result
        );
        let before_reconciliation = fixture.server.accepted();
        for save in [false, true] {
            let response = caller.draft(&fixture, &uncertain, save, false).await;
            assert_eq!(response["error"]["code"], "outcome_unknown", "{response}");
            assert_eq!(response["error"]["retryable"], false);
            assert_eq!(
                response["error"]["draft_operation"]["identity"]["operation_id"],
                uncertain["operation_id"]
            );
        }
        assert_eq!(fixture.server.accepted(), before_reconciliation);
        fixture.server.expect_reconciliation_bytes(captured);
        let verified = caller.draft(&fixture, &uncertain, false, true).await;
        assert_eq!(verified["result"]["state"], "duplicate", "{verified}");
        assert_eq!(
            caller.draft(&fixture, &uncertain, true, false).await["result"],
            verified["result"]
        );
        caller.finish().await;
    }
    assert_eq!(
        fixture.server.accepted(),
        accepted + COMPONENTS.len(),
        "restart performs only one explicit reconciliation per uncertain operation"
    );
    assert_eq!(
        fixture.server.drafts().len(),
        COMPONENTS.len() * 2,
        "recovery never dispatches another APPEND"
    );
    for component in COMPONENTS {
        for (alias, username, password, id) in [
            ("work", WORK, ROTATED, first),
            ("personal", "personal@example.test", SECOND, second),
        ] {
            fixture.server.expect(username, password);
            let doctor = fixture.admin(
                component,
                &["--account", alias, "doctor", "--check-account"],
            );
            assert_eq!(doctor["accounts"][0]["account_id"], id.to_string());
            assert_eq!(
                doctor["accounts"][0]["authentication"]["outcome"]["status"],
                "authenticated"
            );
        }
    }
    fixture.server.finish();
    println!(
        "WSL boot_id before={before_boot} after={after_boot}; same Windows identity, credentials, account state, and draft outcomes verified"
    );
}
