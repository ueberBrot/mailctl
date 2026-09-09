//! Public-process checks for the optional native macOS isolated server.
#![cfg(all(feature = "isolated", target_os = "macos"))]

use std::process::Command;

const SERVER: &str = env!("CARGO_BIN_EXE_mailctl-isolated");

#[test]
fn server_rejects_caller_arguments_before_reading_the_privileged_route() {
    let output = Command::new(SERVER)
        .arg("--config")
        .arg("/tmp/caller.toml")
        .output()
        .expect("start isolated server");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"mailctl-isolated: invalid request\n");
}
