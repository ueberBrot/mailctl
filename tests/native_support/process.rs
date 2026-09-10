use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, Signal, getpgid, kill_process_group},
};
use std::{
    io::{ErrorKind, Read, Write},
    os::fd::AsFd,
    process::{Child, ChildStdin, Output},
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

fn nonblocking(stream: impl AsFd) -> Result<(), ()> {
    let flags = fcntl_getfl(stream.as_fd()).map_err(|_| ())?;
    fcntl_setfl(stream.as_fd(), flags | OFlags::NONBLOCK).map_err(|_| ())
}

/// Returns whether the stream reached EOF after draining every available byte.
fn drain(
    stream: &mut impl Read,
    captured: &mut Stream,
    limit: usize,
    deadline: Instant,
) -> Result<bool, ()> {
    let mut buffer = [0; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err(());
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                let remaining = limit.saturating_sub(captured.bytes.len());
                captured
                    .bytes
                    .extend_from_slice(&buffer[..count.min(remaining)]);
                captured.exceeded_limit |= count > remaining;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        }
    }
}

fn write_input(
    stdin: &mut ChildStdin,
    input: &[u8],
    offset: &mut usize,
    deadline: Instant,
) -> Result<(), ()> {
    while *offset < input.len() {
        if Instant::now() >= deadline {
            return Err(());
        }
        match stdin.write(&input[*offset..]) {
            Ok(0) => return Err(()),
            Ok(count) => *offset += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

fn terminate(child: &mut Child, group: Option<Pid>) {
    if let Some(group) = group {
        let _ = kill_process_group(group, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Reap one fixture command under an absolute deadline while continuously draining pipes.
/// The deadline includes pipe writers inherited by descendants after their direct parent exits.
pub(crate) fn capture(
    mut child: Child,
    input: Option<Vec<u8>>,
    output_limit: usize,
    timeout: Duration,
) -> Result<Captured, ()> {
    let pid = Pid::from_child(&child);
    let group = getpgid(Some(pid)).ok().filter(|group| *group == pid);
    let result = capture_output(
        &mut child,
        input.as_deref().unwrap_or_default(),
        output_limit,
        timeout,
    );
    if result.is_err() {
        terminate(&mut child, group);
    }
    result
}

fn capture_output(
    child: &mut Child,
    input: &[u8],
    output_limit: usize,
    timeout: Duration,
) -> Result<Captured, ()> {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut stdin = child.stdin.take();
    stdout.as_ref().map(nonblocking).transpose()?;
    stderr.as_ref().map(nonblocking).transpose()?;
    stdin.as_ref().map(nonblocking).transpose()?;
    let mut offset = 0;
    let mut captured_stdout = Stream {
        bytes: Vec::new(),
        exceeded_limit: false,
    };
    let mut captured_stderr = Stream {
        bytes: Vec::new(),
        exceeded_limit: false,
    };
    let deadline = Instant::now() + timeout;
    let mut status = None;
    loop {
        let stdout_eof = stdout
            .as_mut()
            .map(|stream| drain(stream, &mut captured_stdout, output_limit, deadline))
            .transpose()?;
        if stdout_eof == Some(true) {
            stdout = None;
        }
        let stderr_eof = stderr
            .as_mut()
            .map(|stream| drain(stream, &mut captured_stderr, output_limit, deadline))
            .transpose()?;
        if stderr_eof == Some(true) {
            stderr = None;
        }
        if status.is_none() {
            if let Some(stream) = stdin.as_mut() {
                write_input(stream, input, &mut offset, deadline)?;
                if offset == input.len() {
                    stdin = None;
                }
            }
            status = child.try_wait().map_err(|_| ())?;
            if status.is_some() {
                stdin = None;
            }
        }
        if let Some(status) = status
            && stdout.is_none()
            && stderr.is_none()
            && offset == input.len()
        {
            return Ok(Captured {
                output: Output {
                    status,
                    stdout: captured_stdout.bytes,
                    stderr: captured_stderr.bytes,
                },
                stdout_exceeded_limit: captured_stdout.exceeded_limit,
                stderr_exceeded_limit: captured_stderr.exceeded_limit,
            });
        }
        if Instant::now() >= deadline {
            return Err(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}
