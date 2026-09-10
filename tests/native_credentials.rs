#![cfg(all(target_os = "macos", feature = "cli", feature = "mcp"))]

#[allow(dead_code)]
mod imap_support;
#[path = "native_support/process.rs"]
mod process;
#[path = "native_support/server.rs"]
mod server;
mod support;
#[path = "native_support/terminal.rs"]
mod terminal;

use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};
use support::{Installation, MAILCTL, MAILCTL_MCP, assert_success, envelope, run_bounded};
use uuid::Uuid;

const KEYCHAIN_PASSWORD: &str = "disposable-native-keychain-fixture";
const FIRST: &str = "first-synthetic-account-password";
const SECOND: &str = "second-distinct-synthetic-password";
const ROTATED: &str = "replacement-synthetic-password-for-first-account";
const SECURITY_OUTPUT_BYTES: usize = 32 * 1024;

#[test]
#[ignore = "changes the User default keychain; run explicitly on a disposable macOS user"]
fn native_credentials_cross_components_rotate_and_clean_up() {
    let installation = Installation::two_accounts();
    let frozen_cli = installation.copy_executable(MAILCTL, "fixture-cli");
    let frozen_mcp = installation.copy_executable(MAILCTL_MCP, "fixture-mcp");
    let cli = frozen_cli.to_str().unwrap();
    let mcp = frozen_mcp.to_str().unwrap();
    let mut keychain = NativeKeychain::new(installation.config().parent().unwrap());
    let mut server = server::NativeServer::new(installation.config().parent().unwrap());
    let configuration = fs::read_to_string(installation.config())
        .unwrap()
        .replace(
            "mailboxes = [\"INBOX\", \"Drafts\"]",
            "mailboxes = [\"INBOX\", \"Drafts\", \"Archive\"]",
        )
        .replace(
            "mailboxes = [\"INBOX\"]",
            "mailboxes = [\"INBOX\", \"Archive\"]",
        )
        + "\n[[grants]]\nname = \"restricted\"\naccounts = [\"work\"]\nmailboxes = [\"INBOX\"]\n";
    fs::write(
        installation.config(),
        configuration.replace(
            r#"server = "imap.example.test""#,
            &format!("server = \"127.0.0.1\"\nport = {}", server.port),
        ),
    )
    .unwrap();
    let mut setup = installation.command(cli);
    setup.args(["--json", "setup"]);
    assert_success(&run_bounded(setup));
    let mut list = installation.command(cli);
    list.args(["--grant", "all", "--json", "account", "list"]);
    let output = run_bounded(list);
    assert_success(&output);
    let accounts = envelope(&output)["result"]["accounts"]
        .as_array()
        .unwrap()
        .clone();
    let identity = |alias: &str| {
        Uuid::parse_str(
            accounts
                .iter()
                .find(|account| account["alias"] == alias)
                .unwrap()["account_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    let first = identity("work");
    let second = identity("personal");
    status(&installation, cli, "work", first, "missing");
    status(&installation, mcp, "personal", second, "missing");

    provision(&installation, cli, "work", FIRST);
    provision(&installation, mcp, "personal", SECOND);
    assert_no_fixture_secrets(&fs::read(installation.config()).unwrap());
    assert_metadata_has_no_secret(&installation.config().parent().unwrap().join("state"));
    for (id, alias) in [(first, "work"), (second, "personal")] {
        assert!(
            security_result(&[
                "find-generic-password",
                "-s",
                "mailctl",
                "-a",
                &id.to_string(),
                keychain.path.to_str().unwrap()
            ]),
            "credential must be in the isolated fixture keychain"
        );
        for executable in [cli, mcp] {
            status(&installation, executable, alias, id, "available");
        }
    }

    assert_eq!(
        server.accepted(),
        0,
        "setup and safe status never contact the provider"
    );
    authenticate(
        &installation,
        &server,
        cli,
        "work",
        "work@example.test",
        FIRST,
    );
    authenticate(
        &installation,
        &server,
        mcp,
        "personal",
        "personal@example.test",
        SECOND,
    );
    authenticate(
        &installation,
        &server,
        mcp,
        "work",
        "work@example.test",
        FIRST,
    );
    authenticate(
        &installation,
        &server,
        cli,
        "personal",
        "personal@example.test",
        SECOND,
    );

    mailbox_handoffs(&installation, &server, cli, mcp);
    search_handoffs(&installation, &server, cli, mcp);

    let mut rename = installation.command(cli);
    rename.args(["--json", "--account", "work", "setup", "--alias", "renamed"]);
    assert_success(&run_bounded(rename));
    provision(&installation, mcp, "renamed", ROTATED);
    status(&installation, cli, "renamed", first, "available");
    status(&installation, mcp, "personal", second, "available");

    authenticate(
        &installation,
        &server,
        cli,
        "renamed",
        "work@example.test",
        ROTATED,
    );
    authenticate(
        &installation,
        &server,
        mcp,
        "renamed",
        "work@example.test",
        ROTATED,
    );
    let relocated = installation.copy_executable(mcp, "relocated-mcp");
    authenticate(
        &installation,
        &server,
        relocated.to_str().unwrap(),
        "renamed",
        "work@example.test",
        ROTATED,
    );
    keychain.lock();
    let previous_connections = server.accepted();
    let mut locked_check = installation.command(mcp);
    locked_check.args([
        "--grant",
        "all",
        "--json",
        "--log-level",
        "trace",
        "--account",
        "renamed",
        "doctor",
        "--check-account",
    ]);
    let output = run_bounded(locked_check);
    assert_private_output(&output.stdout);
    assert_private_output(&output.stderr);
    let result = envelope(&output);
    let failure = &result["result"]["accounts"][0]["authentication"]["outcome"]["error"];
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(failure["code"], "credential_unavailable");
    // macOS can report either authorization failure or interaction refusal
    // when a locked keychain is accessed with prompts disabled.
    assert!(matches!(
        failure["credential_failure"].as_str(),
        Some("access_denied" | "interaction_required")
    ));
    assert_eq!(server.accepted(), previous_connections);
    keychain.unlock();
    authenticate(
        &installation,
        &server,
        cli,
        "renamed",
        "work@example.test",
        ROTATED,
    );

    let mut delete = installation.command(cli);
    delete.args(["--json", "--account", "renamed", "credential", "delete"]);
    assert_success(&run_bounded(delete));
    status(&installation, mcp, "renamed", first, "missing");
    authenticate(
        &installation,
        &server,
        cli,
        "personal",
        "personal@example.test",
        SECOND,
    );
    let mut delete = installation.command(mcp);
    delete.args(["--json", "--account", "personal", "credential", "delete"]);
    assert_success(&run_bounded(delete));
    status(&installation, cli, "personal", second, "missing");
    server.finish();
    keychain
        .finish()
        .expect("restore defaults and remove isolated keychain");
}

fn status(installation: &Installation, executable: &str, alias: &str, id: Uuid, expected: &str) {
    let mut command = installation.command(executable);
    command.args(["--json", "--account", alias, "credential", "status"]);
    let output = run_bounded(command);
    assert_private_output(&output.stdout);
    assert_private_output(&output.stderr);
    assert_success(&output);
    let result = envelope(&output);
    assert_eq!(result["result"]["account_id"], id.to_string());
    assert_eq!(result["result"]["availability"], expected);
}

fn authenticate(
    installation: &Installation,
    server: &server::NativeServer,
    executable: &str,
    alias: &str,
    username: &'static str,
    password: &'static str,
) {
    for level in ["error", "warn", "info", "debug", "trace"] {
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
                level,
                "--account",
                alias,
                "doctor",
                "--check-account",
            ]);
        let output = run_bounded(command);
        assert_private_output(&output.stdout);
        assert_private_output(&output.stderr);
        assert_success(&output);
        let result = envelope(&output);
        assert_eq!(
            result["result"]["accounts"][0]["authentication"]["outcome"]["status"],
            "authenticated"
        );
        assert!(
            result["result"]["accounts"][0]["authentication"]["checked_at"]
                .as_u64()
                .is_some()
        );
    }
}

fn assert_private_output(output: &[u8]) {
    assert_no_fixture_secrets(output);
    for prohibited in ["work@example.test", "personal@example.test"] {
        assert!(
            !output
                .windows(prohibited.len())
                .any(|bytes| bytes == prohibited.as_bytes()),
            "native credential or provider data leaked into process output"
        );
    }
}

fn assert_no_fixture_secrets(bytes: &[u8]) {
    for secret in [FIRST, SECOND, ROTATED] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|value| value == secret.as_bytes()),
            "a fixture secret escaped its source"
        );
    }
}

fn assert_metadata_has_no_secret(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            assert_metadata_has_no_secret(&entry.path());
        } else {
            assert_no_fixture_secrets(&fs::read(entry.path()).unwrap());
        }
    }
}

fn provision(installation: &Installation, executable: &str, alias: &str, secret: &str) {
    let request = serde_json::json!({
        "command": [executable, "--config", installation.config().to_str().unwrap(), "--account", alias, "credential", "set"],
        "secret": secret,
    });
    let result = terminal::run(request);
    assert_private_output(result["output"].as_str().unwrap().as_bytes());
    assert_eq!(
        result["secret_disclosed"], false,
        "no terminal echo or credential output"
    );
    assert_eq!(
        result["prompted"], true,
        "explicit set must prompt on the terminal: {}",
        result["output"]
    );
    assert_eq!(
        result["exit"], 0,
        "credential provisioning failed: {}",
        result["output"]
    );
}

/// Owns only its temporary keychain and the User preferences it temporarily changes.
struct NativeKeychain {
    path: PathBuf,
    lock_path: PathBuf,
    recovery_path: PathBuf,
    original_default: Vec<String>,
    original_search: Vec<String>,
    active: bool,
}

impl NativeKeychain {
    fn new(directory: &Path) -> Self {
        use std::os::unix::fs::OpenOptionsExt;
        let lock_path = std::env::temp_dir().join("mailctl-native-qualification.lock");
        let _lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .expect("another native qualification fixture owns the User preferences");
        let snapshot = read_preference("default-keychain").and_then(|default| {
            if default.len() > 1 {
                return Err(());
            }
            read_preference("list-keychains").map(|search| (default, search))
        });
        let Ok((original_default, original_search)) = snapshot else {
            let _ = fs::remove_file(&lock_path);
            panic!("read and parse native-keychain preferences before mutation");
        };
        let path = directory.join("native-fixture.keychain-db");
        let mut fixture = Self {
            path,
            lock_path,
            recovery_path: std::env::temp_dir()
                .join(format!("mailctl-native-recovery-{}.json", Uuid::new_v4())),
            original_default,
            original_search,
            active: true,
        };
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&fixture.recovery_path)
            .unwrap()
            .write_all(
                &serde_json::to_vec(&serde_json::json!({
                    "default": fixture.original_default,
                    "search": fixture.original_search,
                    "fixture": fixture.path,
                }))
                .unwrap(),
            )
            .unwrap();
        CreateOptions::new()
            .password(KEYCHAIN_PASSWORD)
            .create(&fixture.path)
            .expect("create disposable native keychain");
        fixture.unlock();
        security(&["set-keychain-settings", fixture.path.to_str().unwrap()]);
        security(&[
            "default-keychain",
            "-d",
            "user",
            "-s",
            fixture.path.to_str().unwrap(),
        ]);
        security(&[
            "list-keychains",
            "-d",
            "user",
            "-s",
            fixture.path.to_str().unwrap(),
        ]);
        assert_eq!(
            preference("default-keychain"),
            vec![fixture.path.to_string_lossy()]
        );
        assert_eq!(
            preference("list-keychains"),
            vec![fixture.path.to_string_lossy()]
        );
        fixture
    }

    fn lock(&self) {
        security(&["lock-keychain", self.path.to_str().unwrap()]);
    }

    fn unlock(&mut self) {
        SecKeychain::open(&self.path)
            .unwrap()
            .unlock(Some(KEYCHAIN_PASSWORD))
            .unwrap();
    }

    fn finish(&mut self) -> Result<(), &'static str> {
        if !self.active {
            return Ok(());
        }
        let mut failed = false;
        let mut restore_default = vec!["default-keychain", "-d", "user", "-s"];
        restore_default.extend(self.original_default.iter().map(String::as_str));
        failed |= !security_result(&restore_default);
        if self.path.exists() {
            failed |= !security_result(&["delete-keychain", self.path.to_str().unwrap()]);
        }
        let mut restore_search = vec!["list-keychains", "-d", "user", "-s"];
        restore_search.extend(self.original_search.iter().map(String::as_str));
        failed |= !security_result(&restore_search);
        failed |= read_preference("default-keychain").as_ref() != Ok(&self.original_default);
        failed |= read_preference("list-keychains").as_ref() != Ok(&self.original_search);
        failed |= self.path.exists();
        if failed {
            return Err("native-keychain cleanup failed; consult private recovery file");
        }
        remove_if_exists(&self.recovery_path).map_err(|_| "remove recovery file")?;
        remove_if_exists(&self.lock_path).map_err(|_| "release native qualification lock")?;
        self.active = false;
        Ok(())
    }
}

impl Drop for NativeKeychain {
    fn drop(&mut self) {
        if self.finish().is_err() {
            eprintln!("native credential fixture could not restore User preferences");
        }
    }
}

fn security(arguments: &[&str]) {
    assert!(
        security_result(arguments),
        "native fixture security command failed"
    );
}

fn security_result(arguments: &[&str]) -> bool {
    security_output(arguments).is_ok_and(|output| output.status.success())
}

fn security_output(arguments: &[&str]) -> Result<Output, ()> {
    let child = Command::new("/usr/bin/security")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let captured = process::capture(child, None, SECURITY_OUTPUT_BYTES, Duration::from_secs(10))?;
    if captured.stdout_exceeded_limit || captured.stderr_exceeded_limit {
        return Err(());
    }
    Ok(captured.output)
}

fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn preference(command: &str) -> Vec<String> {
    read_preference(command).expect("read and parse native-keychain preferences")
}

fn read_preference(command: &str) -> Result<Vec<String>, ()> {
    let output = security_output(&[command, "-d", "user"])?;
    if !output.status.success() || output.stdout.len() > 32 * 1024 {
        return Err(());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| ())?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let line = line.trim();
            if line.len() < 2 || !line.starts_with('"') || !line.ends_with('"') {
                return Err(());
            }
            let mut result = String::new();
            let mut escaped = false;
            for character in line[1..line.len() - 1].chars() {
                if escaped {
                    if !matches!(character, '\\' | '"') {
                        return Err(());
                    }
                    result.push(character);
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    return Err(());
                } else {
                    result.push(character);
                }
            }
            if escaped || !Path::new(&result).is_absolute() {
                return Err(());
            }
            Ok(result)
        })
        .collect()
}

fn search_handoffs(
    installation: &Installation,
    server: &server::NativeServer,
    cli: &str,
    mcp: &str,
) {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use serde_json::{Value, json};
    server.expect_mailboxes("work@example.test", FIRST, &["Archive", "INBOX"]);
    let mut command = installation.command(cli);
    command
        .env("SSL_CERT_FILE", &server.certificate)
        .args(["--json", "mailbox", "list", "--limit", "1"]);
    let output = run_bounded(command);
    assert_success(&output);
    let reference = envelope(&output)["result"]["mailboxes"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    server.expect_search("work@example.test", FIRST, "Archive", None);
    let mut command = installation.command(cli);
    command.env("SSL_CERT_FILE", &server.certificate).args([
        "--json",
        "message",
        "search",
        "--mailbox",
        &reference,
        "--limit",
        "1",
    ]);
    let output = run_bounded(command);
    assert_success(&output);
    let first = envelope(&output)["result"].clone();
    assert_eq!(
        first["messages"][0]["message_id"]["value"],
        "<search-3@example.test>"
    );
    assert_eq!(first["complete"], false);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let connect = |grant: &str| {
                let mut command = tokio::process::Command::new(mcp);
                command
                    .arg("--config")
                    .arg(installation.config())
                    .args(["--grant", grant, "--account", "work"])
                    .env("SSL_CERT_FILE", &server.certificate);
                TokioChildProcess::new(command).unwrap()
            };
            let reader = ().serve(connect("default")).await.unwrap();
            server.expect_search("work@example.test", FIRST, "Archive", None);
            let response = reader
                .call_tool(
                    CallToolRequestParams::new("email_search_messages").with_arguments(
                        json!({"mailbox":reference,"limit":1})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                )
                .await
                .unwrap();
            assert_eq!(response.is_error, Some(false));
            let structured = response.structured_content.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&response.content[0].as_text().unwrap().text)
                    .unwrap(),
                structured
            );
            assert_eq!(structured["result"], first);
            server.expect_search("work@example.test", FIRST, "Archive", Some(2));
            let response = reader
                .call_tool(
                    CallToolRequestParams::new("email_search_messages").with_arguments(
                        json!({"mailbox":reference,"limit":1,"cursor":first["next_cursor"]})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                )
                .await
                .unwrap();
            let second = response.structured_content.unwrap()["result"].clone();
            assert_eq!(
                second["messages"][0]["message_id"]["value"],
                "<search-2@example.test>"
            );
            server.expect_search("work@example.test", FIRST, "Archive", Some(1));
            let mut command = installation.command(cli);
            command.env("SSL_CERT_FILE", &server.certificate).args([
                "--json",
                "message",
                "search",
                "--mailbox",
                &reference,
                "--limit",
                "1",
                "--cursor",
                second["next_cursor"].as_str().unwrap(),
            ]);
            let output = run_bounded(command);
            assert_success(&output);
            let last = envelope(&output)["result"].clone();
            assert_eq!(
                last["messages"][0]["message_id"]["value"],
                "<search-1@example.test>"
            );
            assert_eq!(last["complete"], true);
            assert!(last["next_cursor"].is_null());
            reader.cancel().await.unwrap();
            for (grant, error) in [
                ("restricted", "mailbox_not_allowed"),
                ("all", "stale_cursor"),
            ] {
                let reader = ().serve(connect(grant)).await.unwrap();
                let before = server.accepted();
                let response = reader
                    .call_tool(
                        CallToolRequestParams::new("email_search_messages").with_arguments(
                            json!({"mailbox":reference,"limit":1,"cursor":first["next_cursor"]})
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.is_error, Some(true));
                assert_eq!(response.structured_content.unwrap()["error"]["code"], error);
                assert_eq!(server.accepted(), before);
                reader.cancel().await.unwrap();
            }
        });
}

fn mailbox_handoffs(
    installation: &Installation,
    server: &server::NativeServer,
    cli: &str,
    mcp: &str,
) {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use serde_json::{Value, json};
    server.expect_mailboxes("work@example.test", FIRST, &["Archive", "INBOX"]);
    let mut command = installation.command(cli);
    command
        .env("SSL_CERT_FILE", &server.certificate)
        .args(["--json", "mailbox", "list", "--limit", "1"]);
    let output = run_bounded(command);
    assert_success(&output);
    let first = envelope(&output)["result"].clone();
    assert_eq!(first["mailboxes"][0]["metadata"]["name"], "Archive");
    assert_eq!(first["complete"], false);
    let reference = first["mailboxes"][0]["reference"].as_str().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let connect = |grant: &str| {
            let mut command = tokio::process::Command::new(mcp);
            command
                .arg("--config")
                .arg(installation.config())
                .args(["--grant", grant, "--account", "work"])
                .env("SSL_CERT_FILE", &server.certificate);
            TokioChildProcess::new(command).unwrap()
        };
        let reader = ().serve(connect("default")).await.unwrap();
        server.expect_mailboxes("work@example.test", FIRST, &["Archive", "INBOX"]);
        let response = reader
            .call_tool(
                CallToolRequestParams::new("email_list_mailboxes").with_arguments(
                    json!({"limit":1,"cursor":first["next_cursor"]})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(response.is_error, Some(false));
        let last = response.structured_content.unwrap();
        assert_eq!(last["result"]["mailboxes"][0]["metadata"]["name"], "INBOX");
        assert_eq!(last["result"]["complete"], true);
        let inbox = last["result"]["mailboxes"][0]["reference"]
            .as_str()
            .unwrap();
        server.expect_mailboxes("work@example.test", FIRST, &["INBOX"]);
        let mut command = installation.command(cli);
        command.env("SSL_CERT_FILE", &server.certificate).args([
            "--json",
            "mailbox",
            "list",
            "--reference",
            inbox,
        ]);
        let output = run_bounded(command);
        assert_success(&output);
        assert_eq!(
            envelope(&output)["result"]["mailboxes"][0],
            last["result"]["mailboxes"][0]
        );
        reader.cancel().await.unwrap();
        for grant in ["default", "all", "restricted"] {
            let reader = ().serve(connect(grant)).await.unwrap();
            let before = server.accepted();
            if grant != "restricted" {
                server.expect_mailboxes("work@example.test", FIRST, &["Archive"]);
            }
            let response = reader
                .call_tool(
                    CallToolRequestParams::new("email_list_mailboxes").with_arguments(
                        json!({"reference":reference}).as_object().unwrap().clone(),
                    ),
                )
                .await
                .unwrap();
            let structured = response.structured_content.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&response.content[0].as_text().unwrap().text)
                    .unwrap(),
                structured
            );
            if grant == "restricted" {
                assert_eq!(response.is_error, Some(true));
                assert_eq!(structured["error"]["code"], "mailbox_not_allowed");
                assert_eq!(server.accepted(), before);
            } else {
                assert_eq!(response.is_error, Some(false));
                assert_eq!(structured["result"]["mailboxes"][0], first["mailboxes"][0]);
            }
            reader.cancel().await.unwrap();
        }
        let before = server.accepted();
        let mut command = installation.command(cli);
        command.args([
            "--json",
            "--grant",
            "restricted",
            "mailbox",
            "list",
            "--reference",
            reference,
        ]);
        let output = run_bounded(command);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(envelope(&output)["error"]["code"], "mailbox_not_allowed");
        assert_eq!(server.accepted(), before);
    });
}
