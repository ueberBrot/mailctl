#![cfg(all(target_os = "macos", feature = "cli"))]

#[path = "native_support/process.rs"]
mod process;
mod support;
#[path = "native_support/terminal.rs"]
mod terminal;
use std::{
    fs,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use support::{Installation, MAILCTL, assert_success, run_bounded};

#[test]
fn bounded_capture_drains_large_pipes_before_the_child_exits() {
    let child = Command::new("python3")
        .args([
            "-c",
            "import sys\nfor _ in range(128):\n sys.stdout.write('x' * 1024); sys.stdout.flush()\n sys.stderr.write('y' * 1024); sys.stderr.flush()",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start large-output fixture");
    let captured = process::capture(child, None, 4096, Duration::from_secs(3))
        .expect("collect large-output fixture");
    assert!(captured.output.status.success());
    assert!(captured.stdout_exceeded_limit);
    assert!(captured.stderr_exceeded_limit);
    assert_eq!(captured.output.stdout.len(), 4096);
    assert_eq!(captured.output.stderr.len(), 4096);
}

#[test]
fn bounded_capture_drains_large_output_while_writing_input() {
    let input = vec![b'x'; 128 * 1024];
    let child = Command::new("python3")
        .args([
            "-c",
            "import sys\nwhile chunk := sys.stdin.buffer.read(4096):\n sys.stdout.buffer.write(chunk); sys.stdout.flush()\n sys.stderr.buffer.write(chunk); sys.stderr.flush()",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start full-duplex pipe fixture");
    let captured = process::capture(child, Some(input), 4096, Duration::from_secs(3))
        .expect("collect full-duplex pipe fixture");
    assert!(captured.output.status.success());
    assert!(captured.stdout_exceeded_limit);
    assert!(captured.stderr_exceeded_limit);
    assert_eq!(captured.output.stdout.len(), 4096);
    assert_eq!(captured.output.stderr.len(), 4096);
}

#[test]
fn bounded_capture_returns_when_an_exited_wrapper_leaves_pipe_writers() {
    let pid_file = std::env::temp_dir().join(format!("mailctl-capture-{}.pid", std::process::id()));
    let _ = fs::remove_file(&pid_file);
    let mut child = Command::new("python3")
        .args([
            "-c",
            "import os, subprocess\nchild = subprocess.Popen(['python3', '-c', 'import time; time.sleep(30)'])\nopen(os.environ['PID_FILE'], 'w').write(str(child.pid))",
        ])
        .env("PID_FILE", &pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start wrapper with inherited pipe writer");
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while !pid_file.exists() || child.try_wait().expect("inspect wrapper").is_none() {
        if Instant::now() >= ready_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("wrapper did not establish inherited pipes");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    assert!(process::capture(child, None, 4096, Duration::from_millis(200)).is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid: i32 = fs::read_to_string(&pid_file)
        .expect("wrapper records descendant PID")
        .trim()
        .parse()
        .expect("numeric descendant PID");
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid).expect("positive descendant PID"),
        rustix::process::Signal::KILL,
    );
    let _ = fs::remove_file(pid_file);
}

#[test]
fn credential_prompt_restores_echo_after_invalid_input_and_cancellation() {
    let installation = Installation::two_accounts();
    setup(&installation);

    assert_prompt(&installation, serde_json::json!({"secret": ""}), 4);
    assert_prompt(&installation, serde_json::json!({"secret": "x\u{8}"}), 4);
    assert_prompt(&installation, serde_json::json!({"signal": "SIGINT"}), 130);
    assert_prompt(
        &installation,
        serde_json::json!({"secret": "x".repeat(16 * 1024 + 1)}),
        4,
    );
}

#[test]
fn credential_prompt_deadline_restores_echo() {
    let installation = Installation::two_accounts();
    let configuration = std::fs::read_to_string(installation.config()).unwrap();
    std::fs::write(
        installation.config(),
        configuration.replacen(
            "[[accounts]]",
            "[limits]\noperation_seconds = 1\nconnection_seconds = 1\ninitialization_seconds = 1\n\n[[accounts]]",
            1,
        ),
    )
    .unwrap();
    setup(&installation);

    assert_prompt(&installation, serde_json::json!({"wait": true}), 5);
}

fn setup(installation: &Installation) {
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
}

fn assert_prompt(installation: &Installation, request: serde_json::Value, exit: i64) {
    let mut request = request.as_object().unwrap().clone();
    request.insert(
        "command".into(),
        serde_json::json!([
            MAILCTL,
            "--config",
            installation.config(),
            "--account",
            "work",
            "credential",
            "set",
        ]),
    );
    let result = terminal::run(serde_json::Value::Object(request));
    assert_eq!(result["exit"], exit, "fixture output: {}", result["output"]);
    assert_eq!(result["prompted"], true);
    assert_eq!(result["echo_enabled"], true);
    assert_eq!(result["secret_disclosed"], false);
}
