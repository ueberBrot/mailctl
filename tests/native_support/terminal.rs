use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_PROTOCOL_BYTES: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(12);
const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/native_support/terminal.py"
);

struct Captured {
    bytes: Vec<u8>,
    exceeded_limit: bool,
}

fn drain(mut stream: impl Read) -> std::io::Result<Captured> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let mut exceeded_limit = false;
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Ok(Captured {
                bytes,
                exceeded_limit,
            });
        }
        let remaining = MAX_PROTOCOL_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        exceeded_limit |= count > remaining;
    }
}

pub(crate) fn run(request: serde_json::Value) -> serde_json::Value {
    let request = serde_json::to_vec(&request).expect("serialize terminal fixture request");
    assert!(
        request.len() <= MAX_PROTOCOL_BYTES,
        "terminal fixture request exceeded protocol limit"
    );
    let mut child = Command::new("python3")
        .arg(SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start terminal fixture");
    let child_stdout = child
        .stdout
        .take()
        .expect("capture terminal fixture stdout");
    let child_stderr = child
        .stderr
        .take()
        .expect("capture terminal fixture stderr");
    let stdout = thread::spawn(move || drain(child_stdout));
    let stderr = thread::spawn(move || drain(child_stderr));
    let stdin = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        let mut stdin = stdin;
        stdin.write_all(&request)
    });
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("inspect terminal fixture") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait().expect("reap timed-out terminal fixture");
            panic!("terminal fixture did not terminate");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .join()
        .expect("terminal fixture stdout reader panicked")
        .expect("drain terminal fixture stdout");
    let stderr = stderr
        .join()
        .expect("terminal fixture stderr reader panicked")
        .expect("drain terminal fixture stderr");
    let writer = writer.join().expect("terminal fixture writer panicked");
    assert!(
        !stdout.exceeded_limit,
        "terminal fixture stdout exceeded protocol limit"
    );
    assert!(
        !stderr.exceeded_limit,
        "terminal fixture stderr exceeded protocol limit"
    );
    assert!(status.success(), "terminal fixture failed");
    writer.expect("write terminal fixture request");
    serde_json::from_slice(&stdout.bytes).expect("terminal fixture JSON")
}
