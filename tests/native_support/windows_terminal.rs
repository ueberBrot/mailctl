#![allow(
    unsafe_code,
    reason = "The disposable console fixture drives real Windows keyboard events"
)]
use crate::support::{Installation, assert_success, run_bounded};
use std::{
    fs::OpenOptions,
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{Console::*, Threading::DETACHED_PROCESS},
};

pub fn provision(installation: &Installation, binary: &str, alias: &str, secret: &str) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "console_provision", "--ignored", "--nocapture"])
        .env("MAILCTL_TEST_BINARY", binary)
        .env("MAILCTL_TEST_CONFIG", installation.config())
        .env("MAILCTL_TEST_ALIAS", alias)
        .env("MAILCTL_TEST_SECRET", secret)
        .creation_flags(DETACHED_PROCESS);
    assert_success(&run_bounded(command));
}

#[cfg(feature = "cli")]
pub fn session(
    installation: &Installation,
    alias: &str,
    secret: &str,
    certificate: &std::path::Path,
) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "console_provision", "--ignored", "--nocapture"])
        .env("MAILCTL_TEST_BINARY", crate::support::MAILCTL)
        .env("MAILCTL_TEST_CONFIG", installation.config())
        .env("MAILCTL_TEST_ALIAS", alias)
        .env("MAILCTL_TEST_SECRET", secret)
        .env("MAILCTL_TEST_SESSION", "1")
        .env("SSL_CERT_FILE", certificate)
        .env_remove("SSL_CERT_DIR")
        .creation_flags(DETACHED_PROCESS);
    assert_success(&run_bounded(command));
}

pub fn cancel(installation: &Installation, binary: &str, alias: &str) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "console_provision", "--ignored", "--nocapture"])
        .env("MAILCTL_TEST_BINARY", binary)
        .env("MAILCTL_TEST_CONFIG", installation.config())
        .env("MAILCTL_TEST_ALIAS", alias)
        .env("MAILCTL_TEST_SECRET", "cancelled-synthetic-secret")
        .env("MAILCTL_TEST_CANCEL", "1")
        .creation_flags(DETACHED_PROCESS);
    assert_success(&run_bounded(command));
}

unsafe extern "system" fn ignore_control(_: u32) -> i32 {
    1
}

struct Console;
impl Drop for Console {
    fn drop(&mut self) {
        unsafe {
            FreeConsole();
        }
    }
}

pub fn child() {
    assert_eq!(
        std::env::var("MAILCTL_DISPOSABLE_WINDOWS").as_deref(),
        Ok("1")
    );
    unsafe {
        assert_ne!(AllocConsole(), 0);
    }
    let _console = Console;
    unsafe {
        assert_ne!(SetConsoleCtrlHandler(Some(ignore_control), 1), 0);
    }
    let cancel = std::env::var_os("MAILCTL_TEST_CANCEL").is_some();
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .unwrap();
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONOUT$")
        .unwrap();
    let handle = input.as_raw_handle();
    let original = mode(handle);
    let secret = std::env::var("MAILCTL_TEST_SECRET").unwrap();
    let mut command = Command::new(std::env::var("MAILCTL_TEST_BINARY").unwrap());
    command.args([
        "--config",
        &std::env::var("MAILCTL_TEST_CONFIG").unwrap(),
        "--account",
        &std::env::var("MAILCTL_TEST_ALIAS").unwrap(),
    ]);
    if std::env::var_os("MAILCTL_TEST_SESSION").is_some() {
        command.args(["--interactive", "doctor", "--check-account"]);
    } else {
        command.args(["credential", "set"]);
    }
    let mut child = command
        .env_remove("MAILCTL_TEST_SECRET")
        .stdin(input.try_clone().unwrap())
        .stderr(output.try_clone().unwrap())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while mode(handle) & ENABLE_ECHO_INPUT != 0 {
        assert!(
            child.try_wait().unwrap().is_none(),
            "credential process exited before prompting"
        );
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("prompt deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let events: Vec<INPUT_RECORD> = secret
        .encode_utf16()
        .chain((!cancel).then_some(13))
        .map(|unit| INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: 1,
                    wRepeatCount: 1,
                    uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                    ..Default::default()
                },
            },
        })
        .collect();
    unsafe {
        let mut count = 0;
        assert_ne!(
            WriteConsoleInputW(handle, events.as_ptr(), events.len() as u32, &mut count),
            0
        );
        assert_eq!(count as usize, events.len());
    }
    if cancel {
        unsafe {
            assert_ne!(GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0), 0);
        }
    }
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("credential completion deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let result = child.wait_with_output().unwrap();
    if cancel {
        assert_eq!(result.status.code(), Some(130));
    } else {
        assert_success(&result);
    }
    assert_eq!(mode(handle), original);
    let mut screen = vec![0u16; 4096];
    unsafe {
        let mut count = 0;
        assert_ne!(
            ReadConsoleOutputCharacterW(
                output.as_raw_handle(),
                screen.as_mut_ptr(),
                screen.len() as u32,
                COORD { X: 0, Y: 0 },
                &mut count
            ),
            0
        );
        screen.truncate(count as usize);
    }
    assert!(
        !String::from_utf16_lossy(&screen).contains(&secret),
        "secret echoed to console"
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains(&secret));
}
fn mode(handle: HANDLE) -> u32 {
    let mut mode = 0;
    unsafe {
        assert_ne!(GetConsoleMode(handle, &mut mode), 0);
    }
    mode
}
