//! Reading acceptance through production executables and credential/CA sources.
//! MAILCTL_PACKAGED_BIN_DIR selects installed candidate bytes; cli_ and mcp_
//! test filters exercise installations that do not contain the other component.
#![cfg(all(target_os = "macos", any(feature = "cli", feature = "mcp")))]

mod imap_support;
#[path = "imap_support/process.rs"]
mod server;
mod support;

use serde_json::{Value, json};
#[cfg(feature = "cli")]
use std::os::unix::fs::MetadataExt;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
#[cfg(feature = "cli")]
use support::envelope;
use support::{Installation, assert_success, run_bounded};

const USERNAME: &str = "work@example.test";
const PASSWORD: &str = "disposable-password";
const SHA256: &str = "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721";

struct Fixture {
    installation: Installation,
    server: server::ImapServer,
    #[cfg(feature = "cli")]
    root: PathBuf,
    empty_path: PathBuf,
}

impl Fixture {
    fn new(executable: &str) -> Self {
        let installation = Installation::empty();
        let directory = installation.config().parent().unwrap();
        let server = server::ImapServer::new(directory);
        let root = directory.join("exports");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let empty_path = directory.join("empty-path");
        fs::create_dir(&empty_path).unwrap();
        let secret = directory.join("synthetic-credential");
        fs::write(&secret, PASSWORD).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            installation.config(),
            format!(
                r#"state_dir = {state}
export_roots = [{root}]

[limits]
wire_fetch_bytes = 2097152
attachment_chunk_bytes = 3

[[accounts]]
key = "work"
alias = "work"
server = "127.0.0.1"
port = {port}
username = "work@example.test"
mailboxes = ["INBOX"]
from_identities = ["work"]
[accounts.credential]
source = "command"
executable = {helper}
args = [{secret}]
working_dir = {directory}
protected_paths = [{secret}]

[[grants]]
name = "default"
profile = "read_only"
accounts = ["work"]
mailboxes = ["INBOX"]
"#,
                state = support::toml_string(&directory.join("state")),
                root = support::toml_string(&root),
                port = server.port,
                helper = support::toml_string(&fs::canonicalize("/bin/cat").unwrap()),
                secret = support::toml_string(&secret),
                directory = support::toml_string(directory),
            ),
        )
        .unwrap();
        fs::set_permissions(installation.config(), fs::Permissions::from_mode(0o600)).unwrap();
        let fixture = Self {
            installation,
            server,
            #[cfg(feature = "cli")]
            root,
            empty_path,
        };
        let mut setup = fixture.command(executable);
        setup.args(["--json", "setup"]);
        assert_success(&run_bounded(setup));
        fixture
    }

    fn command(&self, executable: &str) -> Command {
        let mut command = self.installation.command(executable);
        // No other mailctl component, broker, fixture credential hook, or
        // operator environment is available to the production process.
        command
            .env_clear()
            .env("PATH", &self.empty_path)
            .env("SSL_CERT_FILE", &self.server.certificate);
        command
    }

    #[cfg(feature = "cli")]
    fn cli(&self, arguments: &[&str]) -> std::process::Output {
        let mut command = self.command(support::MAILCTL);
        command.arg("--json").args(arguments);
        run_bounded(command)
    }
}

enum Reader {
    #[cfg(feature = "cli")]
    Cli,
    #[cfg(feature = "mcp")]
    Mcp(rmcp::service::RunningService<rmcp::RoleClient, ()>),
}

#[cfg_attr(
    not(feature = "mcp"),
    allow(
        clippy::unused_async,
        reason = "the shared process harness awaits MCP when that component is selected"
    )
)]
impl Reader {
    async fn start(fixture: &Fixture, executable: &str) -> Self {
        #[cfg(feature = "cli")]
        if executable == support::MAILCTL {
            return Self::Cli;
        }
        #[cfg(feature = "mcp")]
        {
            use rmcp::{ServiceExt, transport::TokioChildProcess};
            let command = tokio::process::Command::from(fixture.command(executable));
            Self::Mcp(
                ().serve(TokioChildProcess::new(command).unwrap())
                    .await
                    .unwrap(),
            )
        }
        #[cfg(not(feature = "mcp"))]
        {
            let _ = fixture;
            unreachable!("only the CLI component is compiled");
        }
    }

    async fn call(&self, fixture: &Fixture, arguments: &[&str], tool: &str, input: Value) -> Value {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli => {
                let _ = (tool, input);
                let output = fixture.cli(arguments);
                assert_success(&output);
                envelope(&output)["result"].take()
            }
            #[cfg(feature = "mcp")]
            Self::Mcp(client) => {
                let _ = (fixture, arguments);
                let response = client
                    .call_tool(
                        rmcp::model::CallToolRequestParams::new(tool.to_owned())
                            .with_arguments(input.as_object().unwrap().clone()),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.is_error, Some(false));
                support::assert_mcp_envelope(response)["result"].take()
            }
        }
    }

    async fn finish(self) {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli => {}
            #[cfg(feature = "mcp")]
            Self::Mcp(client) => {
                client.cancel().await.unwrap();
            }
        }
    }
}

async fn discover_message(fixture: &Fixture, reader: &Reader) -> (String, Value) {
    fixture
        .server
        .expect_mailboxes(USERNAME, PASSWORD, &["INBOX"]);
    let result = reader
        .call(
            fixture,
            &["mailbox", "list"],
            "email_list_mailboxes",
            json!({}),
        )
        .await;
    let mailbox = result["mailboxes"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    let message = search_message(fixture, reader, &mailbox).await;
    (mailbox, message)
}

async fn search_message(fixture: &Fixture, reader: &Reader, mailbox: &str) -> Value {
    fixture
        .server
        .expect_search(USERNAME, PASSWORD, "INBOX", None);
    reader
        .call(
            fixture,
            &["message", "search", "--mailbox", mailbox, "--limit", "1"],
            "email_search_messages",
            json!({"mailbox": mailbox, "limit": 1}),
        )
        .await["messages"][0]
        .take()
}

async fn read_and_continue_selected_bodies(executable: &str) {
    use server::BodyKind;

    let remote = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    remote.set_nonblocking(true).unwrap();
    let url = format!("http://{}/private", remote.local_addr().unwrap());
    let html = format!(
        r#"<!doctype html><html><head><script src="{url}">active-secret</script><style>@import url('{url}'); style-secret</style></head><body><p>a🦀éxyz</p><img src="{url}" alt=""></body></html>"#
    );
    for (kind, source, pages, complete, selected_part, media_type, converted) in [
        (
            BodyKind::Plain,
            b"Short body.\r\n".as_slice(),
            ["Shor", "t bo", "dy.\r", "\n"],
            "Short body.\r\n",
            "1",
            "text/plain",
            false,
        ),
        (
            BodyKind::Html,
            html.as_bytes(),
            ["a", "🦀", "éxy", "z\n"],
            "a🦀éxyz\n",
            "1",
            "text/html",
            true,
        ),
        (
            BodyKind::Alternative,
            "a🦀éxyz".as_bytes(),
            ["a", "🦀", "éxy", "z"],
            "a🦀éxyz",
            "1.2",
            "text/plain",
            false,
        ),
    ] {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut fixture = Fixture::new(executable);
            let reader = Reader::start(&fixture, executable).await;
            let (mailbox, before) = discover_message(&fixture, &reader).await;
            let message = before["reference"].as_str().unwrap();
            let mut cursor: Option<String> = None;
            let mut reconstructed = String::new();
            for (page, expected) in pages.iter().enumerate() {
                fixture.server.expect_body_kind("INBOX", kind, source);
                let mut arguments =
                    vec!["message", "get", "--message", message, "--max-bytes", "4"];
                if let Some(cursor) = &cursor {
                    arguments.extend(["--cursor", cursor]);
                }
                let result = reader
                    .call(
                        &fixture,
                        &arguments,
                        "email_get_message",
                        json!({"message": message, "max_bytes": 4, "cursor": cursor}),
                    )
                    .await;
                let body = &result["body"];
                let text = body["text"].as_str().unwrap();
                assert_eq!(text, *expected, "{kind:?} page {page}");
                assert!(text.len() <= 4);
                assert_eq!(body["selected_part"], selected_part);
                assert_eq!(body["source_media_type"], media_type);
                assert_eq!(body["converted"], converted);
                assert_eq!(body["replacements"], false);
                assert!(body["empty_reason"].is_null());
                reconstructed.push_str(text);
                cursor = body["next_cursor"].as_str().map(str::to_owned);
                let more = page + 1 < pages.len();
                assert_eq!(cursor.is_some(), more);
                assert_eq!(body["continuation_available"], more);
                assert_eq!(body["truncated"], more);
            }
            assert_eq!(reconstructed, complete);
            // Strict EXAMINE/PEEK transcripts independently reject mutation and
            // attachment payload fetches; metadata/flags also remain identical.
            assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
            reader.finish().await;
            fixture.server.finish();
            assert_eq!(
                remote.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "HTML resources must remain inert"
            );
        })
        .await
        .expect("standalone reading and shutdown deadline");
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_reads_selected_bodies_at_utf8_boundaries_without_attachment_downloads() {
    read_and_continue_selected_bodies(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_reads_selected_bodies_at_utf8_boundaries_without_attachment_downloads() {
    read_and_continue_selected_bodies(support::MAILCTL_MCP).await;
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_exports_privately_without_overwrite_and_cleans_up_failed_transfers() {
    use server::AttachmentPhase;
    let mut fixture = Fixture::new(support::MAILCTL);
    let reader = Reader::Cli;
    let (mailbox, before) = discover_message(&fixture, &reader).await;
    let message = before["reference"].as_str().unwrap();
    fixture
        .server
        .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::List);
    let listed = fixture.cli(&["attachment", "list", "--message", message]);
    assert_success(&listed);
    let reference = envelope(&listed)["result"]["attachments"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    let export = |name: &str, root: &std::path::Path| {
        fixture.cli(&[
            "attachment",
            "export",
            "--attachment",
            &reference,
            "--root",
            root.to_str().unwrap(),
            "--name",
            name,
        ])
    };
    let sentinel = fixture.root.join("fixture.bin");
    fs::write(&sentinel, b"existing operator file").unwrap();
    for phase in [AttachmentPhase::Start, AttachmentPhase::Continue] {
        fixture
            .server
            .expect_attachment(USERNAME, PASSWORD, "INBOX", phase);
    }
    let output = export("fixture.bin", &fixture.root);
    assert_success(&output);
    let receipt = envelope(&output)["result"].take();
    let destination = fixture.root.join("fixture.bin-1");
    assert_eq!(receipt["path"], destination.to_str().unwrap());
    assert_eq!(receipt["total_decoded_bytes"], 6);
    assert_eq!(receipt["sha256"], SHA256);
    assert!(
        receipt["filesystem"]
            .as_str()
            .unwrap()
            .starts_with("macos:")
    );
    assert_eq!(fs::read(&destination).unwrap(), b"abcdef");
    assert_eq!(
        fs::metadata(&destination).unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"existing operator file");
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 2);
    for name in ["../escape.bin", "NUL.txt"] {
        let accepted = fixture.server.accepted();
        assert_eq!(
            envelope(&export(name, &fixture.root))["error"]["code"],
            "invalid_request"
        );
        assert_eq!(fixture.server.accepted(), accepted);
    }
    let unapproved = fixture.root.with_file_name("unapproved");
    fs::create_dir(&unapproved).unwrap();
    let accepted = fixture.server.accepted();
    assert_eq!(
        envelope(&export("denied.bin", &unapproved))["error"]["code"],
        "permission_denied"
    );
    assert_eq!(fixture.server.accepted(), accepted);
    assert_eq!(fs::read_dir(&unapproved).unwrap().count(), 0);
    for after_first_chunk in [false, true] {
        if after_first_chunk {
            fixture
                .server
                .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::Start);
        }
        fixture.server.expect_attachment(
            USERNAME,
            PASSWORD,
            "INBOX",
            if after_first_chunk {
                AttachmentPhase::TruncatedContinuation
            } else {
                AttachmentPhase::Truncated
            },
        );
        let failed = export("failed.bin", &fixture.root);
        assert!(!failed.status.success());
        assert_eq!(envelope(&failed)["error"]["code"], "provider_unavailable");
        assert_eq!(
            fs::read_dir(&fixture.root).unwrap().count(),
            2,
            "no destination or partial remains after provider failure"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"abcdef");
        assert_eq!(fs::read(&sentinel).unwrap(), b"existing operator file");
    }
    assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
    fixture.server.finish();
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_transfers_bounded_attachment_chunks_with_a_verified_digest() {
    use server::AttachmentPhase;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut fixture = Fixture::new(support::MAILCTL_MCP);
        let reader = Reader::start(&fixture, support::MAILCTL_MCP).await;
        let (mailbox, before) = discover_message(&fixture, &reader).await;
        let message = before["reference"].as_str().unwrap();
        fixture
            .server
            .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::List);
        let listed = reader
            .call(
                &fixture,
                &[],
                "email_list_attachments",
                json!({"message": message}),
            )
            .await;
        let reference = listed["attachments"][0]["reference"].as_str().unwrap();
        fixture
            .server
            .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::Start);
        let first = reader
            .call(
                &fixture,
                &[],
                "email_get_attachment",
                json!({"attachment": reference}),
            )
            .await;
        assert_eq!(first["decoded_offset"], 0);
        assert_eq!(first["bytes_base64"], "YWJj");
        assert_eq!(first["progress"]["status"], "continue");
        fixture
            .server
            .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::Continue);
        let last = reader
            .call(
                &fixture,
                &[],
                "email_get_attachment",
                json!({"token": first["progress"]["next_token"]}),
            )
            .await;
        assert_eq!(last["decoded_offset"], 3);
        assert_eq!(last["bytes_base64"], "ZGVm");
        assert_eq!(
            last["progress"],
            json!({"status": "complete", "total_decoded_bytes": 6, "sha256": SHA256})
        );
        assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
        reader.finish().await;
        fixture.server.finish();
    })
    .await
    .expect("MCP chunk transfer and shutdown deadline");
}
