#![cfg(feature = "mcp")]
mod support;

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdout, Stdio},
    thread,
    time::{Duration, Instant},
};
use support::{Installation, assert_success, run_bounded};

fn installation() -> Installation {
    let installation = Installation::two_accounts();
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.as_table_mut().unwrap().insert(
        "limits".into(),
        toml::toml! {
            operation_seconds = 1
            connection_seconds = 1
            initialization_seconds = 1
            active_requests = 1
            queued_requests = 1
        }
        .into(),
    );
    std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    setup(&installation);
    installation
}

fn setup(installation: &Installation) {
    let mut command = installation.mcp();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
}

fn session(installation: &Installation) -> (Child, BufReader<ChildStdout>) {
    let mut child = installation
        .mcp()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "{}", serde_json::json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"contention-fixture","version":"1"}}})).unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(value.get("result").is_some());
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    (child, reader)
}

fn exits(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("slow client retained its process beyond the deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn independent(installation: &Installation) {
    let (mut other, _reader) = session(installation);
    drop(other.stdin.take());
    exits(&mut other);
    #[cfg(feature = "cli")]
    {
        let mut command = installation.cli();
        command.args(["--json", "account", "list"]);
        assert_success(&run_bounded(command));
    }
}

#[test]
fn slow_output_does_not_block_independent_processes_and_releases_maintenance() {
    let installation = installation();
    let (mut child, _unread) = session(&installation);
    let mut input = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        for id in 1..512 {
            if writeln!(
                input,
                "{}",
                serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/list"})
            )
            .is_err()
            {
                break;
            }
        }
    });
    independent(&installation);
    exits(&mut child);
    writer.join().unwrap();
    setup(&installation);
}

#[test]
fn partial_frames_expire_and_process_death_allows_restart() {
    let installation = installation();
    let (mut slow, _reader) = session(&installation);
    slow.stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"jsonrpc\":")
        .unwrap();
    independent(&installation);
    exits(&mut slow);
    let (mut killed, _reader) = session(&installation);
    independent(&installation);
    killed.kill().unwrap();
    killed.wait().unwrap();
    setup(&installation);
    independent(&installation);
}
