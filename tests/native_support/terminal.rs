use super::process;
use std::{
    process::{Command, Stdio},
    time::Duration,
};

const MAX_PROTOCOL_BYTES: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(12);
const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/native_support/terminal.py"
);

pub(crate) fn run(request: serde_json::Value) -> serde_json::Value {
    let request = serde_json::to_vec(&request).expect("serialize terminal fixture request");
    assert!(
        request.len() <= MAX_PROTOCOL_BYTES,
        "terminal fixture request exceeded protocol limit"
    );
    let child = Command::new("python3")
        .arg(SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start terminal fixture");
    let captured = process::capture(child, Some(request), MAX_PROTOCOL_BYTES, DEADLINE)
        .expect("collect bounded terminal fixture");
    assert!(
        !captured.stdout_exceeded_limit,
        "terminal fixture stdout exceeded protocol limit"
    );
    assert!(
        !captured.stderr_exceeded_limit,
        "terminal fixture stderr exceeded protocol limit"
    );
    assert!(captured.output.status.success(), "terminal fixture failed");
    serde_json::from_slice(&captured.output.stdout).expect("terminal fixture JSON")
}
