//! Executes an operator-trusted helper without exposing its output to diagnostics.
use super::{Availability, ResolutionLimits, Secret, SecretSource, SourceError, nonblocking};
use crate::config::{CredentialCommand, Limits};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};
use std::{
    ffi::CString,
    fs,
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct CommandSource {
    config: CredentialCommand,
}

impl CommandSource {
    pub(super) fn new(config: CredentialCommand) -> Self {
        Self { config }
    }

    fn inspect(&self) -> Result<(), SourceError> {
        if !self.config.valid() {
            return Err(SourceError::AccessDenied);
        }
        let executable = trusted_path(&self.config.executable)?;
        if !executable.is_file()
            || executable.mode() & 0o111 == 0
            || executable.mode() & 0o6000 != 0
        {
            return Err(SourceError::AccessDenied);
        }
        let mut magic = [0; 4];
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&self.config.executable)
            .map_err(|_| SourceError::AccessDenied)?;
        let opened = file.metadata().map_err(|_| SourceError::AccessDenied)?;
        if !opened.is_file() || opened.dev() != executable.dev() || opened.ino() != executable.ino()
        {
            return Err(SourceError::AccessDenied);
        }
        file.read_exact(&mut magic)
            .map_err(|_| SourceError::AccessDenied)?;
        if !matches!(
            &magic,
            b"\x7fELF"
                | b"\xce\xfa\xed\xfe"
                | b"\xcf\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xce"
                | b"\xfe\xed\xfa\xcf"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        ) {
            return Err(SourceError::AccessDenied);
        }
        if !trusted_path(&self.config.working_dir)?.is_dir() {
            return Err(SourceError::AccessDenied);
        }
        for path in &self.config.protected_paths {
            trusted_path(path)?;
        }
        Ok(())
    }
}

impl SecretSource for CommandSource {
    fn prerequisite(&self) -> Option<&'static str> {
        Some(
            "Provision the trusted helper and its dependencies externally; it runs with an empty environment and no input",
        )
    }

    fn availability(&self, _: Uuid) -> Availability {
        self.inspect()
            .map(|()| Availability::Configured)
            .unwrap_or_else(Availability::from)
    }

    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
        self.resolve_with_limits(account, &ResolutionLimits::try_from(&Limits::default())?)
    }

    fn resolve_with_limits(
        &self,
        _: Uuid,
        limits: &ResolutionLimits,
    ) -> Result<Secret, SourceError> {
        self.inspect()?;
        let deadline = Instant::now() + limits.timeout;
        let mut command = Command::new(&self.config.executable);
        command
            .env_clear()
            .current_dir(&self.config.working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        direct_execution(&mut command, &self.config.executable, &self.config.args)?;
        let mut child = Running(command.spawn().map_err(|_| SourceError::Unavailable)?);
        let mut stdout = child.0.stdout.take().ok_or(SourceError::Unavailable)?;
        let mut stderr = child.0.stderr.take().ok_or(SourceError::Unavailable)?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let mut output = Zeroizing::new(Vec::with_capacity(limits.secret_bytes + 2));
        let mut stderr_bytes = 0;
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        loop {
            if Instant::now() >= deadline {
                return Err(SourceError::Unavailable);
            }
            // One read per stream keeps a noisy helper from starving either pipe or the deadline.
            let mut progressed = false;
            if !stdout_eof {
                let read = read_chunk(&mut stdout, |bytes| {
                    if output.len() + bytes.len() > limits.secret_bytes + 2 {
                        return Err(SourceError::InvalidSecret);
                    }
                    output.extend_from_slice(bytes);
                    Ok(())
                })?;
                stdout_eof = read == ReadState::Eof;
                progressed |= read == ReadState::Data;
            }
            if !stderr_eof {
                let read = read_chunk(&mut stderr, |bytes| {
                    stderr_bytes += bytes.len();
                    if stderr_bytes > limits.stderr_bytes {
                        return Err(SourceError::Unavailable);
                    }
                    Ok(())
                })?;
                stderr_eof = read == ReadState::Eof;
                progressed |= read == ReadState::Data;
            }
            // Leave the leader unreaped until group cleanup so its process ID cannot be reused.
            if let Some(status) = waitid(
                WaitId::Pid(child.pid()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(|_| SourceError::Unavailable)?
            {
                if status.exit_status() != Some(0) {
                    return Err(SourceError::Unavailable);
                }
                if stdout_eof && stderr_eof {
                    break;
                }
            }
            if !progressed {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let mut descriptors = [
                    PollFd::new(&stdout, PollFlags::IN),
                    PollFd::new(&stderr, PollFlags::IN),
                ];
                let live = match (stdout_eof, stderr_eof) {
                    (false, false) => &mut descriptors[..],
                    (false, true) => &mut descriptors[..1],
                    (true, false) => &mut descriptors[1..],
                    // Closed pipes cannot signal the leader's eventual exit.
                    // Check only that rare case at a bounded interval.
                    (true, true) => &mut descriptors[..0],
                };
                let timeout = Timespec::try_from(if live.is_empty() {
                    remaining.min(Duration::from_millis(10))
                } else {
                    remaining
                })
                .map_err(|_| SourceError::Unavailable)?;
                if let Err(error) = poll(live, Some(&timeout))
                    && error != rustix::io::Errno::INTR
                {
                    return Err(SourceError::Unavailable);
                }
            }
        }
        if output.last() == Some(&b'\n') {
            output.pop();
            if output.last() == Some(&b'\r') {
                output.pop();
            }
        }
        if output.len() > limits.secret_bytes {
            return Err(SourceError::InvalidSecret);
        }
        Secret::new(std::mem::take(&mut *output))
    }
}

fn trusted_path(path: &Path) -> Result<fs::Metadata, SourceError> {
    // inspect validates every configured path before checking filesystem metadata.
    let mut leaf = None;
    let uid = rustix::process::geteuid().as_raw();
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| SourceError::Unavailable)?;
        let owner = metadata.uid();
        // A root-owned sticky temporary parent cannot replace an entry owned by this identity.
        let sticky_parent = index > 0 && owner == 0 && metadata.mode() & 0o1000 != 0;
        if (!metadata.is_file() && !metadata.is_dir())
            || (owner != 0 && owner != uid)
            || (metadata.mode() & 0o022 != 0 && !sticky_parent)
        {
            return Err(SourceError::AccessDenied);
        }
        if index == 0 {
            leaf = Some(metadata);
        }
    }
    leaf.ok_or(SourceError::AccessDenied)
}

#[allow(
    unsafe_code,
    reason = "pre_exec requires an audited async-signal-safe descriptor closure hook"
)]
fn direct_execution(
    command: &mut Command,
    executable: &Path,
    args: &[String],
) -> Result<(), SourceError> {
    let executable =
        CString::new(executable.as_os_str().as_bytes()).map_err(|_| SourceError::AccessDenied)?;
    let args = args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).map_err(|_| SourceError::AccessDenied))
        .collect::<Result<Vec<_>, _>>()?;
    // SAFETY: all owned strings are prepared before fork. The child uses stack-only
    // pointer arrays, async-signal-safe descriptor marking and execve. CString storage
    // stays alive throughout execve; both arrays have a trailing null pointer. On error,
    // the hook returns without reaching std's execvp shell fallback. Rust's exec-error
    // pipe remains open until exec, and the parent's descriptor table is unaffected.
    unsafe {
        command.pre_exec(move || {
            close_fds::set_fds_cloexec(3, &[]);
            let mut argv = [std::ptr::null(); CredentialCommand::MAX_ARGS + 2];
            argv[0] = executable.as_ptr();
            for (slot, arg) in argv[1..=CredentialCommand::MAX_ARGS].iter_mut().zip(&args) {
                *slot = arg.as_ptr();
            }
            let environment = [std::ptr::null()];
            libc::execve(executable.as_ptr(), argv.as_ptr(), environment.as_ptr());
            Err(io::Error::last_os_error())
        });
    }
    Ok(())
}

#[derive(PartialEq)]
enum ReadState {
    Eof,
    Data,
    Pending,
}

fn read_chunk(
    pipe: &mut impl Read,
    accept: impl FnOnce(&[u8]) -> Result<(), SourceError>,
) -> Result<ReadState, SourceError> {
    let mut buffer = Zeroizing::new([0; 1024]);
    match pipe.read(&mut *buffer) {
        Ok(0) => Ok(ReadState::Eof),
        Ok(count) => {
            accept(&buffer[..count])?;
            Ok(ReadState::Data)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(ReadState::Pending)
        }
        Err(_) => Err(SourceError::Unavailable),
    }
}

struct Running(Child);
impl Running {
    fn pid(&self) -> Pid {
        Pid::from_raw(self.0.id() as i32).expect("spawned child has a positive PID")
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = kill_process_group(self.pid(), Signal::KILL);
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
