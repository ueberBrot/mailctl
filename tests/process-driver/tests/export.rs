#![cfg(all(feature = "cli", target_os = "macos"))]
#[path = "../../imap_support/mod.rs"]
mod imap_support;
#[path = "../../imap_support/process.rs"]
mod server;
#[path = "../../support/mod.rs"]
mod support;
use std::os::unix::fs::PermissionsExt;
use support::{Installation, assert_success, envelope, run_bounded};

#[test]
fn cli_streams_attachment_to_approved_root_with_native_receipt() {
    let installation = Installation::two_accounts();
    let root = installation.config().parent().unwrap().join("exports");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut server = server::ImapServer::new(installation.config().parent().unwrap());
    let configuration = std::fs::read_to_string(installation.config())
        .unwrap()
        .replace(
            "server = \"imap.example.test\"",
            &format!("server = \"127.0.0.1\"\nport = {}", server.port),
        );
    std::fs::write(
        installation.config(),
        format!(
            "export_roots = [{}]\n{configuration}\n[limits]\nattachment_chunk_bytes = 3\n",
            support::toml_string(&root)
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let mut command = installation.cli();
        command
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .arg("--json")
            .args(args);
        run_bounded(command)
    };
    assert_success(&run(&["setup"]));
    server.expect_mailboxes("work@example.test", "disposable-password", &["INBOX"]);
    let mailboxes = run(&["mailbox", "list"]);
    assert_success(&mailboxes);
    let mailbox = envelope(&mailboxes)["result"]["mailboxes"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    server.expect_search("work@example.test", "disposable-password", "INBOX", None);
    let messages = run(&["message", "search", "--mailbox", &mailbox, "--limit", "1"]);
    assert_success(&messages);
    let message = envelope(&messages)["result"]["messages"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    server.expect_attachment(
        "work@example.test",
        "disposable-password",
        "INBOX",
        server::AttachmentPhase::List,
    );
    let attachments = run(&["attachment", "list", "--message", &message]);
    assert_success(&attachments);
    let reference = envelope(&attachments)["result"]["attachments"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned();
    for phase in [
        server::AttachmentPhase::Start,
        server::AttachmentPhase::Continue,
    ] {
        server.expect_attachment("work@example.test", "disposable-password", "INBOX", phase);
    }
    let downloaded = run(&["attachment", "get", "--attachment", &reference]);
    assert_success(&downloaded);
    let downloaded = envelope(&downloaded)["result"].take();
    assert_eq!(downloaded["bytes_base64"], "YWJjZGVm");
    assert_eq!(downloaded["decoded_offset"], 0);
    for phase in [
        server::AttachmentPhase::Start,
        server::AttachmentPhase::Continue,
    ] {
        server.expect_attachment("work@example.test", "disposable-password", "INBOX", phase);
    }
    let exported = run(&[
        "attachment",
        "export",
        "--attachment",
        &reference,
        "--root",
        root.to_str().unwrap(),
        "--name",
        "fixture.bin",
    ]);
    assert_success(&exported);
    let receipt = envelope(&exported)["result"].take();
    assert_eq!(receipt["path"], root.join("fixture.bin").to_str().unwrap());
    assert_eq!(receipt["total_decoded_bytes"], 6);
    assert_eq!(
        receipt["sha256"],
        "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    );
    assert_eq!(std::fs::read(root.join("fixture.bin")).unwrap(), b"abcdef");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    let denied = run(&[
        "--grant",
        "writer",
        "attachment",
        "export",
        "--attachment",
        &reference,
        "--root",
        root.to_str().unwrap(),
    ]);
    assert_eq!(envelope(&denied)["error"]["code"], "permission_denied");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    for cleanup_fails in [false, true] {
        server.expect_attachment(
            "work@example.test",
            "disposable-password",
            "INBOX",
            server::AttachmentPhase::Interrupted,
        );
        let interrupted = server.interrupted();
        let mut command = installation.cli();
        command
            .env("MAILCTL_FIXTURE_CA", &server.certificate)
            .args([
                "--json",
                "attachment",
                "export",
                "--attachment",
                &reference,
                "--root",
                root.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while server.interrupted() == interrupted || std::fs::read_dir(&root).unwrap().count() != 2
        {
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                panic!("export did not start");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if cleanup_fails {
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        assert!(
            std::process::Command::new("/bin/kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                panic!("cancelled export did not stop");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let cancelled = child.wait_with_output().unwrap();
        assert_eq!(
            envelope(&cancelled)["error"]["code"],
            if cleanup_fails {
                "export_cleanup_failed"
            } else {
                "cancelled"
            }
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        if cleanup_fails {
            let diagnostics = String::from_utf8(cancelled.stderr).unwrap();
            assert!(diagnostics.contains("cleanup failed"));
            assert!(!diagnostics.contains(&reference));
            assert!(!diagnostics.contains("disposable-password"));
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
            for entry in std::fs::read_dir(&root).unwrap().flatten() {
                if entry.file_name().to_string_lossy().ends_with(".partial") {
                    std::fs::remove_file(entry.path()).unwrap();
                }
            }
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    }
    server.finish();
}
