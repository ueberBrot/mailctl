#![cfg(feature = "cli")]
use mailctl::{domain::ErrorCode, export::ExportWriter};

#[test]
fn rejects_windows_device_names_before_creating_a_partial() {
    let root = std::env::temp_dir();
    for name in [
        "CON",
        "con.txt",
        "PRN.bin",
        "AUX",
        "NUL",
        "nul .txt",
        "COM1",
        "com9.bin",
        "LPT1.txt",
        "lpt9",
        "COM¹.txt",
        "COM²",
        "com³.bin",
        "LPT¹",
        "lpt².txt",
        "LPT³",
    ] {
        assert_eq!(
            ExportWriter::create(std::slice::from_ref(&root), &root, name, 3)
                .err()
                .expect("reserved basename")
                .code,
            ErrorCode::InvalidRequest,
            "{name:?}"
        );
    }
}

#[test]
fn rejects_path_syntax_controls_and_oversized_export_basenames() {
    let root = std::env::temp_dir();
    for name in [
        "../escape",
        "a/b",
        "a\\b",
        "a:stream",
        "C:escape",
        ".hidden",
        "a.",
        "a ",
        "a\n",
        "a\0",
        "a\u{202e}txt",
        "a\u{1b}[31m",
    ] {
        assert_eq!(
            ExportWriter::create(std::slice::from_ref(&root), &root, name, 3)
                .err()
                .expect("unsafe basename")
                .code,
            ErrorCode::InvalidRequest,
            "{name:?}"
        );
    }
    for name in ["a".repeat(201), "é".repeat(101)] {
        assert_eq!(
            ExportWriter::create(std::slice::from_ref(&root), &root, &name, 3)
                .err()
                .expect("oversized basename")
                .code,
            ErrorCode::InvalidRequest
        );
    }
}
