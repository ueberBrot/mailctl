use super::*;
use server::{AttachmentPhase, export_faults::ExportControl};
use std::{
    collections::HashSet,
    os::unix::fs::symlink,
    path::Path,
    process::{Child, Output, Stdio},
    time::{Duration, Instant},
};

const NAME: &str = "fixture-private-export.bin";

struct ExportProcess(Option<Child>);

impl ExportProcess {
    fn start(fixture: &Fixture, reference: &str) -> Self {
        let mut command = fixture.command(support::MAILCTL);
        command
            .args([
                "--json",
                "attachment",
                "export",
                "--attachment",
                reference,
                "--root",
                fixture.root.to_str().unwrap(),
                "--name",
                NAME,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Self(Some(command.spawn().unwrap()))
    }

    fn cancel(&self) {
        assert!(
            Command::new("/bin/kill")
                .args(["-TERM", &self.0.as_ref().unwrap().id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    fn finish(mut self) -> Output {
        let child = self.0.as_mut().unwrap();
        observed("export process stopped", || {
            child.try_wait().unwrap().is_some()
        });
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for ExportProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn observed(description: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "deadline: {description}");
        // Poll an independently observed provider/process condition. Elapsed
        // time never decides when a filesystem mutation or signal is applied.
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn attachment(fixture: &Fixture) -> String {
    let (_, message) = discover_message(fixture, &Reader::Cli).await;
    fixture
        .server
        .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::List);
    let listed = fixture.cli(&[
        "attachment",
        "list",
        "--message",
        message["reference"].as_str().unwrap(),
    ]);
    assert_success(&listed);
    envelope(&listed)["result"]["attachments"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn first_chunk_then_pause(fixture: &Fixture) -> ExportControl {
    fixture
        .server
        .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::Start);
    fixture.server.expect_export_pause()
}

fn partial(root: &Path) -> PathBuf {
    let partials: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "partial")
        })
        .collect();
    assert_eq!(partials.len(), 1);
    let path = partials.into_iter().next().unwrap();
    assert_private(&path);
    assert_eq!(fs::read(&path).unwrap(), b"abc");
    path
}

fn assert_private(path: &Path) {
    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

fn assert_error(output: &Output, reference: &str, code: &str, exit: i32) {
    assert_eq!(output.status.code(), Some(exit));
    let response = envelope(output);
    assert_eq!(response["error"]["code"], code);
    assert!(response.get("result").is_none(), "{response}");
    for bytes in [&output.stdout, &output.stderr] {
        let text = std::str::from_utf8(bytes).unwrap();
        for private in [reference, PASSWORD, NAME] {
            assert!(!text.contains(private), "safe export failure diagnostics");
        }
    }
}

#[tokio::test]
async fn cli_cancels_exports_before_and_after_first_chunk_and_reports_cleanup_failure() {
    for (after_first_chunk, cleanup_fails) in [(false, false), (true, false), (true, true)] {
        let mut fixture = Fixture::new(support::MAILCTL);
        let reference = attachment(&fixture).await;
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
                AttachmentPhase::InterruptedContinuation
            } else {
                AttachmentPhase::Interrupted
            },
        );
        let interrupted = fixture.server.interrupted();
        let process = ExportProcess::start(&fixture, &reference);
        observed("pending export provider operation", || {
            fixture.server.interrupted() > interrupted
        });
        let partial = after_first_chunk.then(|| partial(&fixture.root));
        assert_eq!(
            fs::read_dir(&fixture.root).unwrap().count(),
            usize::from(after_first_chunk)
        );
        if cleanup_fails {
            fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o500)).unwrap();
        }
        process.cancel();
        let output = process.finish();
        // Restore the disposable root before inspecting assertions or removing
        // the intentionally retained partial, including a failed cancellation.
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_error(
            &output,
            &reference,
            if cleanup_fails {
                "export_cleanup_failed"
            } else {
                "cancelled"
            },
            if cleanup_fails { 8 } else { 130 },
        );
        if cleanup_fails {
            assert!(
                std::str::from_utf8(&output.stderr)
                    .unwrap()
                    .contains("cleanup failed")
            );
            let path = partial.unwrap();
            assert_private(&path);
            assert_eq!(fs::read(&path).unwrap(), b"abc");
            assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
            fs::remove_file(path).unwrap();
        }
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
        // A new operation cannot pass the serial provider until the cancelled
        // connection has been disposed without an extra FETCH or LOGOUT.
        fixture
            .server
            .expect_mailboxes(USERNAME, PASSWORD, &["INBOX"]);
        assert_success(&fixture.cli(&["mailbox", "list"]));
        fixture.server.finish();
    }
}

#[derive(Clone, Copy, Debug)]
enum FileChange {
    RootRedirect,
    PartialFile,
    PartialDirectory,
    PartialSymlink,
    PublicationPermissions,
}

#[tokio::test]
async fn cli_rejects_export_root_and_partial_replacement_and_reports_created_destinations() {
    for change in [
        FileChange::RootRedirect,
        FileChange::PartialFile,
        FileChange::PartialDirectory,
        FileChange::PartialSymlink,
        FileChange::PublicationPermissions,
    ] {
        let mut fixture = Fixture::new(support::MAILCTL);
        let reference = attachment(&fixture).await;
        let control = first_chunk_then_pause(&fixture);
        let process = ExportProcess::start(&fixture, &reference);
        observed("first export chunk written", || control.waiting());
        let partial = partial(&fixture.root);
        let foreign = fixture.root.with_file_name("foreign");
        let moved = fixture.root.with_file_name("moved");
        fs::create_dir(&foreign).unwrap();
        let sentinel = foreign.join("operator-file");
        fs::write(&sentinel, b"foreign operator content").unwrap();
        let sentinel_metadata = fs::metadata(&sentinel).unwrap();
        match change {
            FileChange::RootRedirect => {
                fs::rename(&fixture.root, &moved).unwrap();
                symlink(&foreign, &fixture.root).unwrap();
            }
            FileChange::PartialFile => {
                fs::remove_file(&partial).unwrap();
                fs::write(&partial, b"foreign replacement").unwrap();
            }
            FileChange::PartialDirectory => {
                fs::remove_file(&partial).unwrap();
                fs::create_dir(&partial).unwrap();
                fs::write(partial.join("operator-file"), b"foreign replacement").unwrap();
            }
            FileChange::PartialSymlink => {
                fs::remove_file(&partial).unwrap();
                symlink(&sentinel, &partial).unwrap();
            }
            FileChange::PublicationPermissions => {
                fs::set_permissions(&partial, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        control.resume();
        let output = process.finish();
        assert_error(
            &output,
            &reference,
            match change {
                FileChange::RootRedirect => "export_failed",
                FileChange::PublicationPermissions => "export_finalization_failed",
                _ => "export_cleanup_failed",
            },
            8,
        );
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"foreign operator content",
            "{change:?}"
        );
        let metadata = fs::metadata(&sentinel).unwrap();
        assert_eq!(metadata.ino(), sentinel_metadata.ino());
        assert_eq!(metadata.mode(), sentinel_metadata.mode());
        assert_eq!(fs::read_dir(&foreign).unwrap().count(), 1);
        match change {
            FileChange::RootRedirect => {
                assert_eq!(fs::read_link(&fixture.root).unwrap(), foreign);
                assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
                fs::remove_file(&fixture.root).unwrap();
            }
            FileChange::PartialFile => {
                assert_eq!(fs::read(&partial).unwrap(), b"foreign replacement");
                assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
            }
            FileChange::PartialDirectory => {
                assert_eq!(
                    fs::read(partial.join("operator-file")).unwrap(),
                    b"foreign replacement"
                );
                assert_eq!(fs::read_dir(&partial).unwrap().count(), 1);
                assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
            }
            FileChange::PartialSymlink => {
                assert_eq!(fs::read_link(&partial).unwrap(), sentinel);
                assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
            }
            FileChange::PublicationPermissions => {
                assert!(
                    std::str::from_utf8(&output.stdout)
                        .unwrap()
                        .contains("created a destination")
                );
                assert!(!partial.exists());
                assert_eq!(fs::read(fixture.root.join(NAME)).unwrap(), b"abcdef");
                assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
            }
        }
        fixture.server.finish();
    }
}

#[tokio::test]
async fn cli_concurrent_exports_preserve_collisions_and_publish_distinct_private_receipts() {
    let mut fixture = Fixture::new(support::MAILCTL);
    let reference = attachment(&fixture).await;
    let sentinel = fixture.root.join(NAME);
    fs::write(&sentinel, b"operator collision").unwrap();
    let link = fixture.root.join(format!("{NAME}-1"));
    symlink(&sentinel, &link).unwrap();
    let first_control = first_chunk_then_pause(&fixture);
    let first = ExportProcess::start(&fixture, &reference);
    observed("first concurrent export chunk", || first_control.waiting());
    partial(&fixture.root);
    let second_control = first_chunk_then_pause(&fixture);
    let second = ExportProcess::start(&fixture, &reference);
    // Both real CLI processes overlap. This serial transcript releases the
    // first continuation before observing the second; it does not claim that
    // their filesystem publication instructions execute at the same instant.
    first_control.resume();
    observed("second concurrent export chunk", || {
        second_control.waiting()
    });
    let first_output = first.finish();
    partial(&fixture.root);
    second_control.resume();
    let mut paths = HashSet::new();
    for output in [first_output, second.finish()] {
        assert_success(&output);
        let result = envelope(&output)["result"].take();
        let path = PathBuf::from(result["path"].as_str().unwrap());
        assert_eq!(result["total_decoded_bytes"], 6);
        assert_eq!(result["sha256"], SHA256);
        assert_eq!(
            result["filesystem"],
            format!("macos:{}", fs::metadata(&fixture.root).unwrap().dev())
        );
        assert_eq!(fs::read(&path).unwrap(), b"abcdef");
        assert_private(&path);
        assert!(paths.insert(path));
    }
    assert_eq!(
        paths,
        [
            fixture.root.join(format!("{NAME}-2")),
            fixture.root.join(format!("{NAME}-3"))
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"operator collision");
    assert_eq!(fs::read_link(&link).unwrap(), sentinel);
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 4);
    fixture.server.finish();
}
