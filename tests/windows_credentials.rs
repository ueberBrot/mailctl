#![cfg(all(windows, any(feature = "cli", feature = "mcp")))]
mod imap_support;
#[path = "imap_support/process.rs"]
mod server;
mod support;
#[path = "native_support/windows_terminal.rs"]
mod terminal;
use mailctl::{
    config::CredentialSource,
    credentials::{self, Availability, Secret},
};
use std::{fs, process::Command};
use support::{Installation, assert_success, envelope, run_bounded};
use uuid::Uuid;

const FIRST: &str = "first-synthetic-account-password";
const SECOND: &str = "second-distinct-synthetic-password";
const ROTATED: &str = "replacement-synthetic-password";

fn executables() -> Vec<&'static str> {
    vec![
        #[cfg(feature = "cli")]
        support::MAILCTL,
        #[cfg(feature = "mcp")]
        support::MAILCTL_MCP,
    ]
}
struct Cleanup(Vec<Uuid>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let source = credentials::source_for(&CredentialSource::Native {});
        for id in &self.0 {
            let _ = source.mutable_store().unwrap().delete(*id);
        }
    }
}
fn command(installation: &Installation, executable: &str, arguments: &[&str]) -> serde_json::Value {
    let mut command = installation.command(executable);
    command.arg("--json").args(arguments);
    let output = run_bounded(command);
    assert_success(&output);
    for secret in [FIRST, SECOND, ROTATED] {
        assert!(
            !output
                .stdout
                .windows(secret.len())
                .any(|bytes| bytes == secret.as_bytes())
        );
        assert!(
            !output
                .stderr
                .windows(secret.len())
                .any(|bytes| bytes == secret.as_bytes())
        );
    }
    envelope(&output)["result"].clone()
}

fn native_entry_count() -> usize {
    let mut command = Command::new("cmdkey.exe");
    command.arg("/list");
    let output = run_bounded(command);
    assert_success(&output);
    String::from_utf8_lossy(&output.stdout)
        .matches(".mailctl")
        .count()
}

#[test]
#[ignore = "requires an explicitly disposable Windows execution identity"]
fn native_windows_credentials_cross_processes_and_rotate() {
    assert_eq!(
        std::env::var("MAILCTL_DISPOSABLE_WINDOWS").as_deref(),
        Ok("1")
    );
    assert_eq!(
        native_entry_count(),
        0,
        "native acceptance requires an empty mailctl store"
    );
    let installation = Installation::empty();
    let binaries = executables();
    let first_binary = binaries[0];
    let second_binary = binaries[binaries.len() - 1];
    for (binary, alias, username) in [
        (first_binary, "work", "work@example.test"),
        (second_binary, "personal", "personal@example.test"),
    ] {
        command(
            &installation,
            binary,
            &[
                "setup",
                "--alias",
                alias,
                "--server",
                "imap.example.test",
                "--username",
                username,
            ],
        );
    }
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let mut config: toml::Value =
        toml::from_str(&fs::read_to_string(installation.config()).unwrap()).unwrap();
    for account in config["accounts"].as_array_mut().unwrap() {
        account["server"] = "127.0.0.1".into();
        account["port"] = i64::from(server.port).into();
    }
    fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    command(&installation, second_binary, &["setup"]);
    let id = |alias: &str| {
        Uuid::parse_str(
            command(
                &installation,
                first_binary,
                &["--account", alias, "credential", "status"],
            )["account_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    };
    let first = id("work");
    let second = id("personal");
    let _cleanup = Cleanup(vec![first, second]);
    let source = credentials::source_for(&CredentialSource::Native {});
    assert!(std::sync::Arc::ptr_eq(
        &source,
        &credentials::source_for(&CredentialSource::Native {})
    ));
    assert_eq!(source.availability(first), Availability::Missing);
    terminal::provision(
        &installation,
        first_binary,
        "work",
        "synthetic-é🦀-password",
    );
    assert_eq!(
        source.resolve(first).unwrap().len(),
        "synthetic-é🦀-password".len()
    );
    terminal::provision(&installation, first_binary, "work", FIRST);
    terminal::provision(&installation, second_binary, "personal", SECOND);
    terminal::cancel(&installation, first_binary, "work");
    for binary in &binaries {
        for alias in ["work", "personal"] {
            assert_eq!(
                command(
                    &installation,
                    binary,
                    &["--account", alias, "credential", "status"]
                )["availability"],
                "available"
            );
        }
    }
    assert_eq!(server.accepted(), 0);
    assert_eq!(source.resolve(first).unwrap().len(), FIRST.len());
    source
        .mutable_store()
        .unwrap()
        .set(first, &Secret::new(vec![b'x'; 2561]).unwrap())
        .unwrap_err();
    assert_eq!(source.resolve(first).unwrap().len(), FIRST.len());
    command(
        &installation,
        first_binary,
        &["--account", "work", "setup", "--alias", "renamed"],
    );
    terminal::provision(&installation, second_binary, "renamed", ROTATED);
    assert_eq!(
        native_entry_count(),
        2,
        "rename and rotation must not duplicate entries"
    );
    assert_eq!(
        command(
            &installation,
            first_binary,
            &["--account", "renamed", "credential", "status"]
        )["account_id"],
        first.to_string()
    );
    assert_eq!(source.resolve(second).unwrap().len(), SECOND.len());
    for binary in &binaries {
        for (alias, username, secret) in [
            ("renamed", "work@example.test", ROTATED),
            ("personal", "personal@example.test", SECOND),
        ] {
            server.expect(username, secret);
            let mut check = installation.command(binary);
            check
                .env("SSL_CERT_FILE", &server.certificate)
                .env_remove("SSL_CERT_DIR")
                .args(["--json", "--account", alias, "doctor", "--check-account"]);
            let output = run_bounded(check);
            assert_success(&output);
            assert_eq!(
                envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["status"],
                "authenticated"
            );
        }
    }
    #[cfg(feature = "cli")]
    {
        let mut configuration: toml::Value =
            toml::from_str(&fs::read_to_string(installation.config()).unwrap()).unwrap();
        let original = configuration.clone();
        configuration["accounts"][0]["credential"]["source"] = "session".into();
        fs::write(
            installation.config(),
            toml::to_string(&configuration).unwrap(),
        )
        .unwrap();
        command(&installation, first_binary, &["setup"]);
        server.expect("work@example.test", ROTATED);
        terminal::session(&installation, "renamed", ROTATED, &server.certificate);
        let mut unattended = installation.command(support::MAILCTL);
        unattended.args([
            "--json",
            "--account",
            "renamed",
            "doctor",
            "--check-account",
        ]);
        let output = run_bounded(unattended);
        assert_eq!(output.status.code(), Some(4));
        assert_eq!(
            envelope(&output)["result"]["accounts"][0]["authentication"]["outcome"]["error"]["credential_failure"],
            "interaction_required"
        );
        fs::write(installation.config(), toml::to_string(&original).unwrap()).unwrap();
        command(&installation, first_binary, &["setup"]);
    }
    #[cfg(feature = "mcp")]
    mcp_discovery(&installation, &server);
    command(
        &installation,
        second_binary,
        &["--account", "renamed", "credential", "delete"],
    );
    command(
        &installation,
        first_binary,
        &["--account", "personal", "credential", "delete"],
    );
    assert_eq!(source.availability(first), Availability::Missing);
    assert_eq!(source.availability(second), Availability::Missing);
    assert_eq!(native_entry_count(), 0, "native fixture cleanup");
    server.finish();
}

#[cfg(feature = "mcp")]
fn mcp_discovery(installation: &Installation, server: &server::ImapServer) {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut command = tokio::process::Command::new(support::MAILCTL_MCP);
            command
                .arg("--config")
                .arg(installation.config())
                .env("SSL_CERT_FILE", &server.certificate);
            let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
            let response = client
                .call_tool(CallToolRequestParams::new("email_list_accounts"))
                .await
                .unwrap();
            let value = response.structured_content.unwrap();
            assert_eq!(value["result"]["accounts"].as_array().unwrap().len(), 2);
            client.cancel().await.unwrap();
        });
}

#[test]
#[ignore = "private subprocess entry point for the disposable console fixture"]
fn console_provision() {
    terminal::child();
}
