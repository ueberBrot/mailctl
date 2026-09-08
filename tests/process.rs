use std::process::Command;

const BINARIES: [(&str, &str); 4] = [
    ("mailctl", env!("CARGO_BIN_EXE_mailctl")),
    ("maild", env!("CARGO_BIN_EXE_maild")),
    ("mail-mcp", env!("CARGO_BIN_EXE_mail-mcp")),
    ("mail-admin", env!("CARGO_BIN_EXE_mail-admin")),
];

#[test]
fn executables_explain_their_interface_and_version() {
    for (name, path) in BINARIES {
        let help = Command::new(path).arg("--help").output().unwrap();
        assert!(help.status.success(), "{name} help failed");
        assert!(help.stderr.is_empty(), "{name} help wrote diagnostics");
        let text = String::from_utf8(help.stdout).unwrap();
        assert!(text.contains("Usage:") && text.contains(name));
        let version = Command::new(path).arg("--version").output().unwrap();
        assert!(version.status.success());
        assert!(version.stderr.is_empty());
        assert_eq!(
            String::from_utf8(version.stdout).unwrap(),
            format!("{name} 0.1.0\n")
        );
    }
}
