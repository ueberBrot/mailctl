#![cfg(all(feature = "cli", windows))]
#[path = "native_support/windows_export.rs"]
mod native_support;
mod support;
use mailctl::{
    domain::{AttachmentChunk, AttachmentProgress, ErrorCode},
    export::ExportWriter,
};
use std::{
    fs,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    process::Command,
};

fn root(installation: &support::Installation) -> PathBuf {
    let root = installation.config().parent().unwrap().join("exports");
    fs::create_dir(&root).unwrap();
    native_support::protect_root(&root);
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

fn partial(root: &Path) -> PathBuf {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".partial")
        })
        .expect("export owns a partial file")
}

#[allow(
    unsafe_code,
    reason = "independent Win32 volume observation verifies the native export receipt"
)]
fn filesystem(root: &Path) -> String {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, GetVolumeInformationByHandleW,
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .unwrap();
    let mut serial = 0;
    let mut name = [0u16; 32];
    let result = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    assert_ne!(
        result,
        0,
        "observe volume: {}",
        std::io::Error::last_os_error()
    );
    let length = name.iter().position(|value| *value == 0).unwrap();
    assert_eq!(String::from_utf16(&name[..length]).unwrap(), "NTFS");
    format!("windows:{serial:08X}")
}

#[test]
fn publishes_exact_bytes_with_private_acl_without_overwriting_collisions() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    fs::write(root.join("report.txt"), b"keep").unwrap();
    let target = root.with_file_name("collision-target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"keep").unwrap();
    native_support::junction(&root.join("report.txt-1"), &target);
    let mut writer =
        ExportWriter::create(std::slice::from_ref(&root), &root, "report.txt", 3).unwrap();
    native_support::assert_private(&partial(&root));
    let receipt = writer.write_chunk(&chunk()).unwrap().unwrap();
    assert!(receipt.path.is_absolute());
    assert_eq!(receipt.path, root.join("report.txt-2"));
    assert_eq!(receipt.total_decoded_bytes, 3);
    assert_eq!(
        receipt.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(receipt.filesystem, filesystem(&root));
    assert_eq!(fs::read(&receipt.path).unwrap(), b"abc");
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"keep");
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
    native_support::assert_private(&receipt.path);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
}

#[test]
fn preserves_binary_bytes_and_chunk_offsets_without_text_conversion() {
    let installation = support::Installation::empty();
    let root = root(&installation).join("résumé-📨");
    fs::create_dir(&root).unwrap();
    native_support::protect_root(&root);
    let name = format!("{}.bin", "é".repeat(98));
    assert_eq!(name.len(), 200);
    fs::write(root.join(&name), b"keep").unwrap();
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, &name, 6).unwrap();
    let mut first = chunk();
    first.bytes_base64 = "AP8N".into();
    first.progress = AttachmentProgress::Continue {
        next_token: "next".into(),
    };
    assert!(writer.write_chunk(&first).unwrap().is_none());
    let mut last = chunk();
    last.bytes_base64 = "CgCA".into();
    last.decoded_offset = 3;
    last.progress = AttachmentProgress::Complete {
        total_decoded_bytes: 6,
        sha256: "e07b129623ecec2771454ebae117ac798c53b26721a89ecc1b2c6978c99c5560".into(),
    };
    let receipt = writer.write_chunk(&last).unwrap().unwrap();
    assert_eq!(receipt.path, root.join(format!("{name}-1")));
    assert_eq!(fs::read(receipt.path).unwrap(), [0, 255, 13, 10, 0, 128]);
    assert_eq!(receipt.total_decoded_bytes, 6);
    assert_eq!(fs::read(root.join(name)).unwrap(), b"keep");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
}

#[test]
fn rejects_unapproved_traversing_and_foreign_readable_roots() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    assert_eq!(
        ExportWriter::create(&[], &root, "a", 3).err().unwrap().code,
        ErrorCode::PermissionDenied
    );
    for suffix in [r"\.\", r"\..\exports"] {
        let mut traversing = root.clone();
        // PathBuf::push normalizes dots in verbatim Windows paths.
        traversing.as_mut_os_string().push(suffix);
        assert!(
            ExportWriter::create(std::slice::from_ref(&traversing), &traversing, "a", 3).is_err()
        );
    }
    let relative = PathBuf::from("exports");
    assert!(ExportWriter::create(std::slice::from_ref(&relative), &relative, "a", 3).is_err());
    let mut command = Command::new("icacls.exe");
    command.arg(&root).args(["/grant", "*S-1-1-0:(R)"]);
    support::assert_success(&support::run_bounded(command));
    assert!(ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn rejects_junction_roots_and_ancestors_before_creating_partial_files() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let junction = root.with_file_name("junction");
    native_support::junction(&junction, &root);
    assert!(ExportWriter::create(std::slice::from_ref(&junction), &junction, "a", 3).is_err());
    let inner = root.join("inner");
    fs::create_dir(&inner).unwrap();
    native_support::protect_root(&inner);
    let redirected = junction.join("inner");
    assert!(ExportWriter::create(std::slice::from_ref(&redirected), &redirected, "a", 3).is_err());
    assert_eq!(fs::read_dir(&inner).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

#[test]
fn held_root_and_ancestor_handles_prevent_rename_redirection() {
    let installation = support::Installation::empty();
    let parent = root(&installation);
    let root = parent.join("inner");
    fs::create_dir(&root).unwrap();
    native_support::protect_root(&root);
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap();
    for path in [&root, &parent] {
        let destination = path.with_file_name("moved");
        assert!(fs::rename(path, &destination).is_err());
        assert!(path.is_dir());
        assert!(!destination.exists());
    }
    let receipt = writer.write_chunk(&chunk()).unwrap().unwrap();
    assert_eq!(fs::read(receipt.path).unwrap(), b"abc");
    let moved = root.with_file_name("moved");
    fs::rename(&root, &moved).unwrap();
    assert_eq!(fs::read(moved.join("a")).unwrap(), b"abc");
    drop(writer);
}

#[test]
fn exclusive_partial_handle_prevents_replacement_or_external_data_access() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap();
    let partial = partial(&root);
    assert!(fs::remove_file(&partial).is_err());
    assert!(fs::rename(&partial, root.join("stolen")).is_err());
    assert!(fs::write(&partial, b"foreign").is_err());
    assert!(fs::read(&partial).is_err());
    let linked = root.with_file_name("linked-partial");
    assert!(fs::hard_link(&partial, &linked).is_err());
    assert!(!linked.exists());
    assert!(
        fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&partial)
            .is_err()
    );
    assert!(!root.join("stolen").exists());
    let receipt = writer.write_chunk(&chunk()).unwrap().unwrap();
    assert_eq!(fs::read(receipt.path).unwrap(), b"abc");
    assert!(!partial.exists());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

#[test]
fn abort_and_drop_remove_partial_files_after_incomplete_transfers() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    for abort in [false, true] {
        let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 6).unwrap();
        let mut first = chunk();
        first.progress = AttachmentProgress::Continue {
            next_token: "next".into(),
        };
        assert!(writer.write_chunk(&first).unwrap().is_none());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        if abort {
            writer.abort().unwrap();
            writer.abort().unwrap();
        }
        drop(writer);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
    let mut writer = ExportWriter::create(std::slice::from_ref(&root), &root, "a", 3).unwrap();
    writer.abort().unwrap();
    fs::rename(&root, root.with_file_name("moved")).unwrap();
    drop(writer);
}

#[test]
fn read_only_partial_reports_safe_cleanup_failure_and_allows_retry() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let mut writer =
        ExportWriter::create(std::slice::from_ref(&root), &root, "private-name", 3).unwrap();
    let partial = partial(&root);
    let mut permissions = fs::metadata(&partial).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&partial, permissions).unwrap();
    let error = writer.abort().unwrap_err();
    assert_eq!(error.code, ErrorCode::ExportCleanupFailed);
    assert!(error.message.contains("cleanup failed"));
    assert!(!error.message.contains("private-name"));
    assert!(!error.message.contains(partial.to_string_lossy().as_ref()));
    assert!(partial.exists());
    assert!(!root.join("private-name").exists());
    native_support::clear_readonly(&partial);
    writer.abort().unwrap();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn concurrent_exports_publish_distinct_complete_files() {
    let installation = support::Installation::empty();
    let root = root(&installation);
    let barrier = std::sync::Barrier::new(8);
    let paths: std::collections::HashSet<_> = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let mut writer =
                        ExportWriter::create(std::slice::from_ref(&root), &root, "same.bin", 3)
                            .unwrap();
                    barrier.wait();
                    writer.write_chunk(&chunk()).unwrap().unwrap().path
                })
            })
            .collect();
        tasks.into_iter().map(|task| task.join().unwrap()).collect()
    });
    assert_eq!(paths.len(), 8);
    for path in paths {
        assert_eq!(fs::read(path).unwrap(), b"abc");
    }
    assert_eq!(fs::read_dir(&root).unwrap().count(), 8);
}

#[test]
fn chunk_bounds_and_integrity_failures_clean_partial_files() {
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
        assert!(!root.join("a").exists());
        assert!(writer.write_chunk(&crate::chunk()).is_err());
        writer.abort().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
}
