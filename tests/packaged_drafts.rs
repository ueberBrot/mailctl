//! Draft acceptance through production executables, real SQLite, and TLS IMAP.
//! MAILCTL_PACKAGED_BIN_DIR selects installer-verified candidate bytes. The cli_
//! and mcp_ filters need only that installed component; cross_ needs both.
#![cfg(all(
    any(target_os = "macos", target_os = "linux"),
    any(feature = "cli", feature = "mcp")
))]

#[path = "packaged_drafts/bounds.rs"]
mod bounds;
#[path = "packaged_drafts/composition.rs"]
mod composition;
#[path = "packaged_drafts/history.rs"]
mod history;
mod imap_support;
#[path = "packaged_drafts/ownership.rs"]
mod ownership;
#[path = "imap_support/process.rs"]
mod server;
mod support;

use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command, time::Duration};
use support::{Installation, envelope, run_bounded};

struct Fixture {
    installation: Installation,
    server: server::ImapServer,
    input: Value,
    empty_path: PathBuf,
    executable: String,
}

impl Fixture {
    fn new(executable: &str) -> Self {
        let installation = Installation::empty();
        let directory = installation.config().parent().unwrap();
        let server = server::ImapServer::new(directory);
        let empty_path = directory.join("empty-path");
        fs::create_dir(&empty_path).unwrap();
        let credential = support::packaged_credential(directory, "disposable-password");
        fs::write(
            installation.config(),
            format!(
                r#"
state_dir = {state}

[limits]
initialization_seconds = 1

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
{credential}

[[grants]]
name = "default"
profile = "read_only"
accounts = ["work"]
mailboxes = ["INBOX"]
[grants.limits]
initialization_seconds = 1

[[grants]]
name = "writer"
profile = "drafts_only"
accounts = ["work"]
mailboxes = ["Drafts"]
[grants.limits]
initialization_seconds = 1

[[grants]]
name = "other-writer"
profile = "drafts_only"
accounts = ["work"]
mailboxes = ["Drafts"]
[grants.limits]
initialization_seconds = 1
"#,
                state = support::toml_string(&directory.join("state")),
                port = server.port,
                credential = toml::to_string(&credential).unwrap(),
            ),
        )
        .unwrap();
        fs::set_permissions(installation.config(), fs::Permissions::from_mode(0o600)).unwrap();
        let mut fixture = Self {
            installation,
            server,
            empty_path,
            executable: executable.into(),
            input: json!({}),
        };
        let setup = fixture.admin(executable, &["setup"]);
        assert!(setup.get("error").is_none(), "{setup}");
        #[cfg(target_os = "linux")]
        fixture
            .installation
            .provision_packaged_native("disposable-password");
        let registry: Value =
            serde_json::from_slice(&fs::read(fixture.state().join("accounts.json")).unwrap())
                .unwrap();
        fixture.input = json!({
            "account_id": registry["accounts"]["work"]["account_id"],
            "account_generation": 1,
            "operation_id": uuid::Uuid::new_v4(),
            "mailbox": "Drafts",
            "draft": {
                "from": "work@example.test",
                "to": [{"address":"to@example.test", "name":"Synthetic To"}],
                "cc": [{"address":"cc@example.test"}],
                "bcc": [{"address":"hidden@example.test"}],
                "subject":"Packaged synthetic draft",
                "body":"Synthetic body.\nSecond line 🦀.",
                "in_reply_to":"original@example.test",
                "references":["ancestor@example.test", "original@example.test"]
            }
        });
        fixture
    }

    fn state(&self) -> PathBuf {
        self.installation.config().parent().unwrap().join("state")
    }

    fn command(&self, executable: &str) -> Command {
        let mut command = self.installation.command(executable);
        // Only production-supported credential/CA sources are supplied. No
        // fixture hook, broker, sibling binary, or operator environment exists.
        support::packaged_environment(&mut command, &self.server.certificate, &self.empty_path);
        command
    }

    fn admin(&self, executable: &str, arguments: &[&str]) -> Value {
        let mut command = self.command(executable);
        command.arg("--json").args(arguments);
        let output = run_bounded(command);
        let response = envelope(&output);
        assert_eq!(
            output.status.success(),
            response.get("error").is_none(),
            "{response}"
        );
        response
    }

    fn configuration(&self) -> mailctl::config::Config {
        mailctl::config::Config::parse(&fs::read_to_string(self.installation.config()).unwrap())
            .unwrap()
    }

    fn configure(&self, config: &mailctl::config::Config) {
        fs::write(self.installation.config(), toml::to_string(config).unwrap()).unwrap();
        let setup = self.admin(&self.executable, &["setup"]);
        assert!(setup.get("error").is_none(), "{setup}");
    }

    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(self.state().join("drafts.sqlite"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }

    fn new_operation(&mut self) {
        self.input["operation_id"] = json!(uuid::Uuid::new_v4());
    }

    fn status_input(&self, reconcile: bool) -> Value {
        let mut input = self.input.clone();
        input.as_object_mut().unwrap().remove("draft");
        input["reconcile"] = json!(reconcile);
        input
    }

    #[cfg(feature = "cli")]
    fn cli_command(&self, tool: &str, input: &Value, grant: &str) -> Command {
        let mut command = self.command(support::MAILCTL);
        command.args(["--json", "--grant", grant]);
        match tool {
            "email_save_draft" | "email_draft_status" => {
                command.args([
                    "draft",
                    if tool == "email_save_draft" {
                        "save"
                    } else {
                        "status"
                    },
                ]);
                for field in [
                    "account_id",
                    "account_generation",
                    "operation_id",
                    "mailbox",
                ] {
                    command.arg(format!("--{}", field.replace('_', "-")));
                    if field == "account_generation" {
                        command.arg(input[field].to_string());
                    } else {
                        command.arg(input[field].as_str().unwrap());
                    }
                }
                if tool == "email_save_draft" {
                    let composition = self
                        .installation
                        .config()
                        .with_file_name(format!("input-{}.json", uuid::Uuid::new_v4()));
                    fs::write(&composition, serde_json::to_vec(&input["draft"]).unwrap()).unwrap();
                    command.arg("--input").arg(composition);
                } else if input["reconcile"] == true {
                    command.arg("--reconcile");
                }
            }
            "email_list_accounts" => {
                command.args(["account", "list"]);
            }
            "email_list_mailboxes" => {
                command.args(["mailbox", "list"]);
            }
            "email_search_messages" => {
                command.args([
                    "message",
                    "search",
                    "--mailbox",
                    input["mailbox"].as_str().unwrap(),
                    "--limit",
                    "1",
                ]);
            }
            "email_get_message" => {
                command.args([
                    "message",
                    "get",
                    "--message",
                    input["message"].as_str().unwrap(),
                ]);
            }
            "email_capabilities" => {
                command.args(["capability", "show"]);
            }
            _ => panic!("unsupported CLI fixture operation: {tool}"),
        }
        command
    }

    async fn call(&self, executable: &str, tool: &str, input: Value) -> Value {
        let caller = Caller::start(self, executable, "writer", false).await;
        let response = caller.call(self, tool, input).await;
        caller.finish().await;
        response
    }

    async fn save(&self, executable: &str) -> Value {
        self.call(executable, "email_save_draft", self.input.clone())
            .await
    }

    async fn status(&self, executable: &str, reconcile: bool) -> Value {
        self.call(
            executable,
            "email_draft_status",
            self.status_input(reconcile),
        )
        .await
    }

    async fn appended(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.server.interrupted() < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("production APPEND must reach fixture");
    }
}

enum Caller {
    #[cfg(feature = "cli")]
    Cli { grant: String, narrowed: bool },
    #[cfg(feature = "mcp")]
    Mcp(rmcp::service::RunningService<rmcp::RoleClient, ()>),
}

#[cfg_attr(
    not(feature = "mcp"),
    allow(
        clippy::unused_async,
        reason = "shared harness awaits MCP when compiled"
    )
)]
impl Caller {
    async fn start(fixture: &Fixture, executable: &str, grant: &str, narrowed: bool) -> Self {
        #[cfg(feature = "cli")]
        if executable == support::MAILCTL {
            return Self::Cli {
                grant: grant.into(),
                narrowed,
            };
        }
        #[cfg(feature = "mcp")]
        {
            use rmcp::{ServiceExt, transport::TokioChildProcess};
            let mut command = fixture.command(executable);
            command.args(["--grant", grant]);
            if !narrowed {
                command.arg("--use-configured-grant");
            }
            Self::Mcp(
                tokio::time::timeout(
                    Duration::from_secs(10),
                    ().serve(
                        TokioChildProcess::new(tokio::process::Command::from(command)).unwrap(),
                    ),
                )
                .await
                .expect("MCP initialization deadline")
                .unwrap(),
            )
        }
        #[cfg(not(feature = "mcp"))]
        {
            let _ = fixture;
            unreachable!("only CLI is compiled");
        }
    }

    async fn call(&self, fixture: &Fixture, tool: &str, input: Value) -> Value {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli { grant, narrowed } => {
                let mut command = fixture.cli_command(tool, &input, grant);
                if *narrowed {
                    command.arg("--read-only");
                }
                let output = run_bounded(command);
                let response = envelope(&output);
                assert_eq!(
                    output.status.success(),
                    response.get("error").is_none(),
                    "{response}"
                );
                if let Some(code) = response["error"]["code"].as_str() {
                    let exit = match code {
                        "invalid_request" => 2,
                        "outcome_unknown" | "operation_in_progress" => 7,
                        "operation_conflict" | "operation_not_found" => 6,
                        "permission_denied" | "account_not_allowed" | "mailbox_not_allowed" => 3,
                        "authentication_failed" => 4,
                        "rate_limited" => 5,
                        _ => 8,
                    };
                    assert_eq!(output.status.code(), Some(exit), "{response}");
                }
                response
            }
            #[cfg(feature = "mcp")]
            Self::Mcp(client) => {
                let _ = fixture;
                let response = tokio::time::timeout(
                    Duration::from_secs(15),
                    client.call_tool(
                        rmcp::model::CallToolRequestParams::new(tool.to_owned())
                            .with_arguments(input.as_object().unwrap().clone()),
                    ),
                )
                .await
                .expect("MCP draft response deadline")
                .unwrap();
                support::assert_mcp_envelope(response)
            }
        }
    }

    async fn finish(self) {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli { .. } => {}
            #[cfg(feature = "mcp")]
            Self::Mcp(client) => {
                tokio::time::timeout(Duration::from_secs(10), client.cancel())
                    .await
                    .expect("MCP shutdown deadline")
                    .unwrap();
            }
        }
    }
}

// Parse the received literal independently of the production composer. The
// server separately parses APPEND and requires exact Drafts + initial \\Draft.
fn assert_appended_content(fixture: &Fixture, response: &Value) {
    use sha2::{Digest, Sha256};
    let drafts = fixture.server.drafts();
    assert_eq!(drafts.len(), 1, "one literal for this operation");
    let bytes = &drafts[0];
    let message = mail_parser::MessageParser::default().parse(bytes).unwrap();
    assert_eq!(message.subject(), Some("Packaged synthetic draft"));
    assert_eq!(
        message.from().unwrap().first().unwrap().address(),
        Some("work@example.test")
    );
    assert_eq!(
        message.to().unwrap().first().unwrap().address(),
        Some("to@example.test")
    );
    assert_eq!(
        message.cc().unwrap().first().unwrap().address(),
        Some("cc@example.test")
    );
    assert_eq!(
        message.bcc().unwrap().first().unwrap().address(),
        Some("hidden@example.test")
    );
    for addresses in [message.from(), message.to(), message.cc(), message.bcc()] {
        assert_eq!(addresses.unwrap().as_list().unwrap().len(), 1);
    }
    assert_eq!(
        message.to().unwrap().first().unwrap().name(),
        Some("Synthetic To")
    );
    assert_eq!(
        message.in_reply_to().as_text(),
        Some("original@example.test")
    );
    assert_eq!(
        message.references().as_text_list().unwrap(),
        ["ancestor@example.test", "original@example.test"]
    );
    assert_eq!(
        message.body_text(0).unwrap().replace("\r\n", "\n"),
        fixture.input["draft"]["body"].as_str().unwrap()
    );
    let expected_id = format!(
        "{}.1.{}@mailctl.invalid",
        fixture.input["account_id"].as_str().unwrap(),
        fixture.input["operation_id"].as_str().unwrap()
    );
    assert_eq!(message.message_id(), Some(expected_id.as_str()));
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(response["result"]["content_sha256"], hash);
    assert_eq!(response["result"]["mailbox"], fixture.input["mailbox"]);
    for key in ["account_id", "account_generation", "operation_id"] {
        assert_eq!(response["result"][key], fixture.input[key]);
    }
}

async fn read_only_message(fixture: &Fixture, executable: &str) -> Value {
    let before = history::rows(fixture);
    let appends = fixture.server.drafts();
    let reader = Caller::start(fixture, executable, "default", false).await;
    fixture
        .server
        .expect_mailboxes("work@example.test", "disposable-password", &["INBOX"]);
    let listed = reader
        .call(fixture, "email_list_mailboxes", json!({}))
        .await;
    assert!(listed.get("error").is_none(), "{listed}");
    let mailboxes = listed["result"]["mailboxes"].as_array().unwrap();
    assert_eq!(mailboxes.len(), 1);
    let mailbox = &mailboxes[0];
    assert_eq!(mailbox["account_id"], fixture.input["account_id"]);
    assert_eq!(mailbox["generation"], fixture.input["account_generation"]);
    assert_eq!(mailbox["metadata"]["name"], "INBOX");
    fixture
        .server
        .expect_search("work@example.test", "disposable-password", "INBOX", None);
    let search = reader
        .call(
            fixture,
            "email_search_messages",
            json!({"mailbox": mailbox["reference"], "limit": 1}),
        )
        .await;
    assert!(search.get("error").is_none(), "{search}");
    let message = &search["result"]["messages"][0];
    assert_eq!(message["message_id"]["value"], "<search-3@example.test>");
    assert_eq!(message["flags"], json!(["\\Seen"]));
    fixture
        .server
        .expect_body_bytes("INBOX", b"Short body.\r\n");
    let body = reader
        .call(
            fixture,
            "email_get_message",
            json!({"message": message["reference"]}),
        )
        .await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["result"]["account_id"], mailbox["account_id"]);
    assert_eq!(body["result"]["generation"], mailbox["generation"]);
    assert_eq!(body["result"]["message_reference"], message["reference"]);
    assert_eq!(body["result"]["body"]["text"], "Short body.\r\n");
    assert_eq!(body["result"]["body"]["truncated"], false);
    reader.finish().await;
    // Exact LIST/EXAMINE/SEARCH/PEEK transcripts forbid mutation. Reads must
    // leave both remote draft literals and the independent journal unchanged.
    assert_eq!(fixture.server.drafts(), appends);
    assert_eq!(history::rows(fixture), before);
    json!({"mailbox": mailbox, "message": message, "body": body["result"]})
}

macro_rules! component_tests {
    ($scenario:ident, $cli:ident, $mcp:ident) => {
        #[cfg(feature = "cli")]
        #[tokio::test]
        async fn $cli() {
            $scenario(support::MAILCTL).await;
        }
        #[cfg(feature = "mcp")]
        #[tokio::test]
        async fn $mcp() {
            $scenario(support::MAILCTL_MCP).await;
        }
    };
}

async fn acknowledged_creation(executable: &str) {
    for (uid, reference_budget) in [(true, 2048), (false, 2048), (true, 1)] {
        let mut fixture = Fixture::new(executable);
        if reference_budget == 1 {
            let mut config = fixture.configuration();
            config.limits.token_bytes = reference_budget;
            for grant in &mut config.grants {
                grant.limits.token_bytes = reference_budget;
            }
            fixture.configure(&config);
        }
        fixture
            .server
            .expect_append(server::DraftReply::Created(uid));
        let created = fixture.save(executable).await;
        assert_eq!(
            created["result"]["state"],
            if uid && reference_budget > 1 {
                "created"
            } else {
                "created_reference_unavailable"
            }
        );
        assert_eq!(created["result"]["dispatched"], true);
        assert_eq!(
            created["result"]["message_reference"].is_string(),
            uid && reference_budget > 1
        );
        assert_appended_content(&fixture, &created);
        for _ in 0..2 {
            assert_eq!(fixture.save(executable).await["result"], created["result"]);
            // Explicit reconciliation of completed work is also journal-only.
            assert_eq!(
                fixture.status(executable, true).await["result"],
                created["result"]
            );
        }
        let mut conflict = fixture.input.clone();
        conflict["draft"]["body"] = json!("Conflicting synthetic input");
        assert_eq!(
            fixture.call(executable, "email_save_draft", conflict).await["error"]["code"],
            "operation_conflict"
        );
        assert_eq!(fixture.server.accepted(), 1);
        fixture.server.finish();
    }
}
component_tests!(
    acknowledged_creation,
    cli_acknowledged_append_with_and_without_uid_is_durable,
    mcp_acknowledged_append_with_and_without_uid_is_durable
);

fn assert_uncertain(response: &Value, fixture: &Fixture) {
    assert_eq!(response["error"]["code"], "outcome_unknown", "{response}");
    assert_eq!(response["error"]["retryable"], false);
    assert_eq!(response["error"]["draft_operation"]["mailbox"], "Drafts");
    for key in ["account_id", "account_generation", "operation_id"] {
        assert_eq!(
            response["error"]["draft_operation"]["identity"][key],
            fixture.input[key]
        );
    }
    assert!(
        response.get("result").is_none(),
        "no unrelated message data"
    );
}

async fn immediate_append_failures(executable: &str) {
    for (reply, reason) in [
        (server::DraftReply::Disconnect, "imap_connection_closed"),
        (server::DraftReply::ParserPanic, "imap_parser_panic"),
    ] {
        let mut fixture = Fixture::new(executable);
        fixture.server.expect_append(reply);
        let response = fixture.save(executable).await;
        assert_uncertain(&response, &fixture);
        assert_eq!(response["error"]["reason"], reason);
        assert!(
            !response
                .to_string()
                .contains("fixture-private-parser-input")
        );
        for retained in [
            fixture.save(executable).await,
            fixture.status(executable, false).await,
        ] {
            assert_uncertain(&retained, &fixture);
            assert!(retained["error"].get("reason").is_none());
        }
        assert_eq!(fixture.server.drafts().len(), 1);
        assert_eq!(fixture.server.accepted(), 1);
        fixture.server.finish();
    }
}
component_tests!(
    immediate_append_failures,
    cli_uncertain_append_reports_safe_failure_reason_without_redispatch,
    mcp_uncertain_append_reports_safe_failure_reason_without_redispatch
);

async fn reconciliation_evidence(executable: &str) {
    use server::ReconciliationCase::*;
    for case in [
        Absent,
        Multiple,
        WrongMessageId,
        WrongContent,
        Recreated,
        Denied,
        SearchBudget,
        OversizedLiteral,
        WrongUid,
    ] {
        let mut fixture = Fixture::new(executable);
        fixture.server.expect_append(server::DraftReply::Disconnect);
        assert_uncertain(&fixture.save(executable).await, &fixture);
        // A normal retry/status never contacts the provider after lost ACK.
        assert_uncertain(&fixture.save(executable).await, &fixture);
        assert_uncertain(&fixture.status(executable, false).await, &fixture);
        let mut config = fixture.configuration();
        if matches!(case, SearchBudget) {
            config.limits.search_uid_window = 2;
            config.limits.search_windows = 1;
            for grant in &mut config.grants {
                grant.limits.search_uid_window = 2;
                grant.limits.search_windows = 1;
            }
            fixture.configure(&config);
        }
        let original_hash = if matches!(case, WrongMessageId) {
            // Isolate exact Message-ID verification from the independent MIME
            // hash check: even a matching retained hash must not bless a
            // substring match. The lost-ACK operation itself is genuine.
            use sha2::{Digest, Sha256};
            let bytes = fixture.server.drafts().pop().unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            let id = format!(
                "{}.1.{}@mailctl.invalid",
                fixture.input["account_id"].as_str().unwrap(),
                fixture.input["operation_id"].as_str().unwrap()
            );
            let changed = text.replace(&format!("<{id}>"), &format!("<prefix{id}>"));
            let database =
                rusqlite::Connection::open(fixture.state().join("drafts.sqlite")).unwrap();
            database
                .execute(
                    "UPDATE draft_operations SET content_sha256 = ?1",
                    [Sha256::digest(changed.as_bytes()).as_slice()],
                )
                .unwrap();
            Some(Sha256::digest(&bytes).to_vec())
        } else {
            None
        };
        fixture.server.expect_reconciliation_case(case);
        let failed = fixture.status(executable, true).await;
        assert_uncertain(&failed, &fixture);
        assert_uncertain(&fixture.save(executable).await, &fixture);
        if let Some(hash) = original_hash {
            rusqlite::Connection::open(fixture.state().join("drafts.sqlite"))
                .unwrap()
                .execute("UPDATE draft_operations SET content_sha256 = ?1", [hash])
                .unwrap();
        }
        if matches!(case, SearchBudget) {
            config.limits.search_windows = 10;
            config.limits.search_uid_window = 1000;
            for grant in &mut config.grants {
                grant.limits.search_windows = 10;
                grant.limits.search_uid_window = 1000;
            }
            fixture.configure(&config);
        }
        fixture.server.expect_reconciliation();
        let verified = fixture.status(executable, true).await;
        assert_eq!(
            verified["result"]["state"], "duplicate",
            "{case:?}: {verified}"
        );
        assert_appended_content(&fixture, &verified);
        assert_eq!(fixture.save(executable).await["result"], verified["result"]);
        assert_eq!(fixture.server.interrupted(), 1);
        assert_eq!(fixture.server.accepted(), 3);
        fixture.server.finish();
    }
}
component_tests!(
    reconciliation_evidence,
    cli_lost_ack_requires_exact_bounded_evidence_without_another_append,
    mcp_lost_ack_requires_exact_bounded_evidence_without_another_append
);

async fn journal_commit_faults(executable: &str) {
    for boundary in ["prepare", "dispatch", "outcome", "verification"] {
        let mut fixture = Fixture::new(executable);
        let sql = match boundary {
            "prepare" => {
                "CREATE TRIGGER fail_write BEFORE INSERT ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;"
            }
            "dispatch" => {
                "CREATE TRIGGER fail_write BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic'); END;"
            }
            "outcome" => {
                "CREATE TRIGGER fail_write BEFORE UPDATE ON draft_operations WHEN NEW.state != 'in_flight' BEGIN SELECT RAISE(ABORT, 'synthetic'); END;"
            }
            _ => {
                "CREATE TRIGGER fail_write BEFORE UPDATE ON draft_operations WHEN NEW.state = 'duplicate' BEGIN SELECT RAISE(ABORT, 'synthetic'); END;"
            }
        };
        fixture.sql(sql);
        if matches!(boundary, "prepare" | "dispatch") {
            fixture.server.expect_draft_target(77);
            assert_eq!(
                fixture.save(executable).await["error"]["code"],
                "journal_unavailable"
            );
            assert_eq!(fixture.server.interrupted(), 0);
            let before = fixture.status(executable, true).await;
            if boundary == "prepare" {
                assert_eq!(before["error"]["code"], "operation_not_found");
            } else {
                assert_eq!(before["result"]["state"], "prepared");
            }
            fixture.sql("DROP TRIGGER fail_write");
            fixture
                .server
                .expect_append(server::DraftReply::Created(true));
            let saved = fixture.save(executable).await;
            assert_eq!(saved["result"]["state"], "created");
            assert_appended_content(&fixture, &saved);
        } else {
            fixture.server.expect_append(if boundary == "outcome" {
                server::DraftReply::Created(true)
            } else {
                server::DraftReply::Disconnect
            });
            assert_uncertain(&fixture.save(executable).await, &fixture);
            if boundary == "verification" {
                fixture.server.expect_reconciliation();
                assert_uncertain(&fixture.status(executable, true).await, &fixture);
            }
            fixture.sql("DROP TRIGGER fail_write");
            assert_uncertain(&fixture.save(executable).await, &fixture);
            fixture.server.expect_reconciliation();
            let verified = fixture.status(executable, true).await;
            assert_eq!(verified["result"]["state"], "duplicate");
            assert_appended_content(&fixture, &verified);
        }
        assert_eq!(fixture.server.interrupted(), 1, "{boundary}");
        fixture.server.finish();
    }
}
component_tests!(
    journal_commit_faults,
    cli_sqlite_failures_fence_every_dispatch_boundary,
    mcp_sqlite_failures_fence_every_dispatch_boundary
);

async fn quota_and_authorization(executable: &str) {
    let mut fixture = Fixture::new(executable);
    let mut config = fixture.configuration();
    config.limits.journal_records = 1;
    for grant in &mut config.grants {
        grant.limits.journal_records = 1;
    }
    fixture.configure(&config);
    let ordinary = read_only_message(&fixture, executable).await;
    fixture.server.expect_append(server::DraftReply::Disconnect);
    assert_uncertain(&fixture.save(executable).await, &fixture);
    let original = fixture.input.clone();
    fixture.new_operation();
    assert_eq!(
        fixture.save(executable).await["error"]["code"],
        "journal_full"
    );
    assert_eq!(read_only_message(&fixture, executable).await, ordinary);
    fixture.input = original;
    assert_uncertain(&fixture.status(executable, false).await, &fixture);
    fixture.server.expect_reconciliation();
    let verified = fixture.status(executable, true).await;
    assert_eq!(verified["result"]["state"], "duplicate");
    assert_eq!(fixture.save(executable).await["result"], verified["result"]);
    // A valid grant cannot append to a different mailbox. Even a known
    // conflicting identity must not expose its history outside the exact scope.
    let mut conflict = fixture.input.clone();
    conflict["mailbox"] = json!("INBOX");
    conflict["draft"]["body"] = json!("Changed synthetic input");
    for known in [true, false] {
        if !known {
            conflict["operation_id"] = json!(uuid::Uuid::new_v4());
        }
        assert_eq!(
            fixture
                .call(executable, "email_save_draft", conflict.clone())
                .await["error"]["code"],
            "mailbox_not_allowed"
        );
    }
    let mut denied_status = fixture.status_input(true);
    denied_status["mailbox"] = json!("INBOX");
    assert_eq!(
        fixture
            .call(executable, "email_draft_status", denied_status)
            .await["error"]["code"],
        "mailbox_not_allowed"
    );
    let health = fixture
        .call(executable, "email_capabilities", json!({}))
        .await;
    assert!(health.get("error").is_none());
    assert_eq!(fixture.server.accepted(), 8);
    assert_eq!(fixture.server.interrupted(), 1);
    fixture.server.finish();
}
component_tests!(
    quota_and_authorization,
    cli_full_journal_preserves_reconciliation_and_authorization,
    mcp_full_journal_preserves_reconciliation_and_authorization
);
