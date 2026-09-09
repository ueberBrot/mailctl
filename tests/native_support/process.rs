use std::{
    io::{Read, Write},
    process::{Child, Output},
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Captured {
    pub output: Output,
    pub stdout_exceeded_limit: bool,
    pub stderr_exceeded_limit: bool,
}

struct Stream {
    bytes: Vec<u8>,
    exceeded_limit: bool,
}

fn join(stream: Option<thread::JoinHandle<std::io::Result<Stream>>>) -> Result<Stream, ()> {
    match stream {
        Some(stream) => stream.join().ok().and_then(Result::ok).ok_or(()),
        None => Ok(Stream {
            bytes: Vec::new(),
            exceeded_limit: false,
        }),
    }
}

fn drain(mut stream: impl Read, limit: usize) -> std::io::Result<Stream> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let mut exceeded_limit = false;
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Ok(Stream {
                bytes,
                exceeded_limit,
            });
        }
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        exceeded_limit |= count > remaining;
    }
}

fn collect(
    stdout: Option<thread::JoinHandle<std::io::Result<Stream>>>,
    stderr: Option<thread::JoinHandle<std::io::Result<Stream>>>,
    writer: Option<thread::JoinHandle<std::io::Result<()>>>,
    status: Result<std::process::ExitStatus, ()>,
) -> Result<Captured, ()> {
    let stdout = join(stdout);
    let stderr = join(stderr);
    let writer = writer.map_or(Ok(()), |writer| {
        writer.join().ok().and_then(Result::ok).ok_or(())
    });
    let (Ok(stdout), Ok(stderr), Ok(()), Ok(status)) = (stdout, stderr, writer, status) else {
        return Err(());
    };
    Ok(Captured {
        output: Output {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        },
        stdout_exceeded_limit: stdout.exceeded_limit,
        stderr_exceeded_limit: stderr.exceeded_limit,
    })
}

/// Reaps a fixture child by its deadline while continuously draining both output pipes.
/// Errors deliberately carry no fixture output.
pub(crate) fn capture(
    mut child: Child,
    input: Option<Vec<u8>>,
    output_limit: usize,
    deadline: Duration,
) -> Result<Captured, ()> {
    let stdout = child
        .stdout
        .take()
        .map(|stdout| thread::spawn(move || drain(stdout, output_limit)));
    let stderr = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || drain(stderr, output_limit)));
    let stdin = child.stdin.take();
    let writer = input.map(|input| {
        let mut stdin = stdin.expect("capture bounded process stdin");
        thread::spawn(move || stdin.write_all(&input))
    });
    let deadline = Instant::now() + deadline;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(());
            }
        }
    };
    collect(stdout, stderr, writer, status)
}
