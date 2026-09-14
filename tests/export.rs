#![cfg(all(feature = "cli", target_os = "macos"))]
mod support;
use mailctl::{
    domain::{AttachmentChunk, AttachmentProgress, ErrorCode},
    export::ExportWriter,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
};

fn root(installation: &support::Installation) -> PathBuf {
    let root = installation.config().parent().unwrap().join("exports");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn chunk() -> AttachmentChunk {
    AttachmentChunk {
        account_id: "account".into(),
        generation: 1,
        attachment_reference: "reference".into(),
        bytes_base64: "YWJj".into(),
        decoded_offset: 0,
        progress: AttachmentProgress::Complete {
            total_decoded_bytes: 3,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        },
    }
}
#[test]
fn publishes_exact_bytes_privately_without_overwriting_collisions() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    fs::write(root.join("report.txt"), "keep").unwrap();
    symlink("report.txt", root.join("report.txt-1")).unwrap();
    let mut writer =
        ExportWriter::create(std::slice::from_ref(&root), &root, "report.txt", 3).unwrap();
    let partial = fs::read_dir(&root)
        .unwrap()
        .flatten()
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".partial"))
        .unwrap();
    assert_eq!(partial.metadata().unwrap().mode() & 0o777, 0o600);
    let receipt = writer.write_chunk(&chunk()).unwrap().unwrap();
    assert_eq!(receipt.path, root.join("report.txt-2"));
    assert_eq!(receipt.total_decoded_bytes, 3);
    assert_eq!(fs::read(&receipt.path).unwrap(), b"abc");
    assert_eq!(
        receipt.filesystem,
        format!("macos:{}", fs::metadata(&root).unwrap().dev())
    );
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"keep");
    assert_eq!(fs::metadata(&receipt.path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
}
#[test]
fn rejects_unapproved_roots_unsafe_names_and_symlink_ancestors() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    assert_eq!(
        ExportWriter::create(&[], &root, "a", 3).err().unwrap().code,
        ErrorCode::PermissionDenied
    );
    for name in [
        "../escape",
        "a/b",
        "a\\b",
        ".hidden",
        "CON.txt",
        "LPT1",
        "a\u{202e}txt",
        "a\n",
        "a.",
        "a ",
    ] {
        assert!(
            ExportWriter::create(std::slice::from_ref(&root), &root, name, 3).is_err(),
            "{name:?}"
        );
    }
    let maximum = "é".repeat(100);
    drop(ExportWriter::create(std::slice::from_ref(&root), &root, &maximum, 3).unwrap());
    assert!(ExportWriter::create(std::slice::from_ref(&root), &root, &(maximum + "a"), 3).is_err());
    let link = root.with_file_name("link");
    symlink(&root, &link).unwrap();
    assert!(ExportWriter::create(std::slice::from_ref(&link), &link, "a", 3).is_err());
    let traversal = root.join("..").join("exports");
    assert!(ExportWriter::create(std::slice::from_ref(&traversal), &traversal, "a", 3).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}
#[test]
fn bounded_chunks_and_integrity_failures_leave_no_output() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    for case in 0..5 {
        let mut writer = ExportWriter::create(
            std::slice::from_ref(&root),
            &root,
            "a",
            if case == 0 { 2 } else { 3 },
        )
        .unwrap();
        let mut chunk = chunk();
        match case {
            1 => chunk.decoded_offset = 1,
            2 => {
                chunk.progress = AttachmentProgress::Complete {
                    total_decoded_bytes: 3,
                    sha256: "wrong".into(),
                }
            }
            3 => {
                chunk.progress = AttachmentProgress::Complete {
                    total_decoded_bytes: 4,
                    sha256: "wrong".into(),
                }
            }
            4 => chunk.bytes_base64 = "!!!!".into(),
            _ => {}
        }
        assert!(writer.write_chunk(&chunk).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        assert!(writer.write_chunk(&crate::chunk()).is_err());
        writer.abort().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
}
#[test]
fn held_directory_prevents_redirection_and_cleans_after_rename() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let moved = root.with_file_name("moved");
    let other = root.with_file_name("other");
    fs::create_dir(&other).unwrap();
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap();
    fs::rename(&root, &moved).unwrap();
    symlink(&other, &root).unwrap();
    assert!(writer.write_chunk(&chunk()).is_err());
    writer.abort().unwrap();
    assert_eq!(fs::read_dir(moved).unwrap().count(), 0);
    assert_eq!(fs::read_dir(other).unwrap().count(), 0);
}
#[test]
fn dropping_a_partial_cleans_it_and_cleanup_failure_is_safe() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    drop(ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let mut writer =
        ExportWriter::create(std::slice::from_ref(&root), &root, "private-name", 3).unwrap();
    let partial = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
    fs::remove_file(&partial).unwrap();
    fs::create_dir(&partial).unwrap();
    let error = writer.abort().unwrap_err();
    assert_eq!(error.code, ErrorCode::ExportCleanupFailed);
    assert!(error.message.contains("cleanup failed"));
    assert!(!error.message.contains("private-name"));
    fs::remove_dir(partial).unwrap();
    writer.abort().unwrap();
}

#[test]
fn concurrent_exports_publish_distinct_complete_files() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut writer =
                    ExportWriter::create(std::slice::from_ref(&root), &root, "same.bin", 3)
                        .unwrap();
                barrier.wait();
                writer.write_chunk(&chunk()).unwrap().unwrap().path
            })
        })
        .collect();
    let paths: std::collections::HashSet<_> =
        tasks.into_iter().map(|task| task.join().unwrap()).collect();
    assert_eq!(paths.len(), 8);
    for path in paths {
        assert_eq!(fs::read(path).unwrap(), b"abc");
    }
    assert_eq!(fs::read_dir(&root).unwrap().count(), 8);
}

#[test]
fn replacing_a_partial_never_publishes_or_deletes_the_replacement() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap();
    let partial = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
    fs::remove_file(&partial).unwrap();
    fs::write(&partial, b"foreign").unwrap();
    assert!(writer.write_chunk(&chunk()).is_err());
    assert!(writer.abort().is_err());
    assert_eq!(fs::read(&partial).unwrap(), b"foreign");
    assert!(!root.join("a").exists());
    fs::remove_file(partial).unwrap();
    writer.abort().unwrap();
}

#[test]
fn failure_after_publication_reports_the_created_destination() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap();
    let partial = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        writer.write_chunk(&chunk()).unwrap_err().code,
        ErrorCode::ExportFinalizationFailed
    );
    let error = writer.abort().unwrap_err();
    assert_eq!(error.code, ErrorCode::ExportFinalizationFailed);
    assert!(error.message.contains("created a destination"));
    assert!(root.join("a").exists());
    assert!(!partial.exists());
}
