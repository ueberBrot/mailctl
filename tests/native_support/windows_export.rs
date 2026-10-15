#![allow(
    dead_code,
    reason = "native writer and CLI process tests use different parts of this fixture"
)]
use crate::support::{assert_success, run_bounded};
use serde_json::Value;
use std::{fs, path::Path, process::Command};

#[allow(
    clippy::permissions_set_readonly_false,
    reason = "Windows clears the read-only file attribute without changing its private DACL"
)]
pub(crate) fn clear_readonly(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}

pub(crate) fn protect_root(path: &Path) {
    let sid = current_sid();
    let mut command = Command::new("icacls.exe");
    command.arg(path).args([
        "/inheritance:r",
        "/grant:r",
        &format!("*{sid}:(OI)(CI)(F)"),
        "*S-1-5-18:(OI)(CI)(F)",
        "*S-1-5-32-544:(OI)(CI)(F)",
    ]);
    assert_success(&run_bounded(command));
}

pub(crate) fn assert_private(path: &Path) {
    let mut command = powershell();
    command.env("MAILCTL_EXPORT_ACL_FIXTURE", path).args([
        "-Command",
        r#"$ErrorActionPreference = 'Stop'; $acl = Get-Acl -LiteralPath $env:MAILCTL_EXPORT_ACL_FIXTURE; [ordered]@{ owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; protected = $acl.AreAccessRulesProtected; rules = @($acl.Access | ForEach-Object { [ordered]@{ sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; allowed = $_.AccessControlType.ToString(); inherited = $_.IsInherited; rights = [int64]$_.FileSystemRights } }) } | ConvertTo-Json -Depth 4 -Compress"#,
    ]);
    let output = run_bounded(command);
    assert_success(&output);
    let acl: Value = serde_json::from_slice(&output.stdout).expect("ACL observation is JSON");
    assert_eq!(acl["owner"], acl["current"], "operator owns export file");
    assert_eq!(acl["protected"], true, "export ACL disables inheritance");
    let current = acl["current"].as_str().unwrap();
    let rules = acl["rules"].as_array().unwrap();
    assert!(!rules.is_empty(), "export file has an explicit DACL");
    assert!(rules.iter().any(|rule| rule["sid"] == current));
    for rule in rules {
        assert_eq!(rule["inherited"], false);
        if rule["allowed"] == "Allow" && rule["rights"] != 0 {
            assert!(
                [current, "S-1-5-18", "S-1-5-32-544"].contains(&rule["sid"].as_str().unwrap()),
                "export DACL grants another identity access: {rule}"
            );
        }
    }
}

pub(crate) fn junction(path: &Path, target: &Path) {
    let mut command = Command::new("cmd.exe");
    command.args(["/C", "mklink", "/J"]).arg(path).arg(target);
    assert_success(&run_bounded(command));
}

pub(crate) fn cancel(process_id: u32) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env("MAILCTL_EXPORT_PROCESS_FIXTURE", process_id.to_string())
        .args([
            "--exact",
            "native_support::tests::cancel_export_console",
            "--ignored",
            "--nocapture",
        ]);
    assert_success(&run_bounded(command));
}

fn current_sid() -> String {
    let mut command = Command::new("whoami.exe");
    command.args(["/user", "/fo", "csv", "/nh"]);
    let output = run_bounded(command);
    assert_success(&output);
    whoami_sid(&output.stdout)
        .expect("whoami returns one account and numeric SID in quoted CSV")
        .to_owned()
}

fn whoami_sid(output: &[u8]) -> Option<&str> {
    let record = output
        .strip_suffix(b"\r\n")
        .or_else(|| output.strip_suffix(b"\n"))
        .unwrap_or(output)
        .strip_prefix(b"\"")?;
    // Account names can contain CSV escapes and bytes in the Windows code page.
    // Decode only the SID, after consuming exactly one quoted account field.
    let mut cursor = 0;
    loop {
        match record.get(cursor)? {
            b'\r' | b'\n' => return None,
            b'"' if record.get(cursor + 1) == Some(&b'"') => cursor += 2,
            b'"' => break,
            _ => cursor += 1,
        }
    }
    if cursor == 0 {
        return None;
    }
    let sid = std::str::from_utf8(
        record
            .get(cursor + 1..)?
            .strip_prefix(b",\"")?
            .strip_suffix(b"\"")?,
    )
    .ok()?;
    for (index, number) in sid.strip_prefix("S-1-")?.split('-').enumerate() {
        let maximum = if index == 0 {
            (1u64 << 48) - 1
        } else {
            u32::MAX as u64
        };
        if index > 15
            || number.is_empty()
            || !number.bytes().all(|byte| byte.is_ascii_digit())
            || number.parse::<u64>().ok()? > maximum
        {
            return None;
        }
    }
    Some(sid)
}

fn powershell() -> Command {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive"]);
    command
}

#[cfg(test)]
mod tests {
    use super::whoami_sid;

    #[cfg(windows)]
    #[test]
    #[ignore = "private subprocess entry point for export console cancellation"]
    #[allow(
        unsafe_code,
        reason = "The subprocess fixture attaches to the export console to send real Ctrl+C"
    )]
    fn cancel_export_console() {
        use windows_sys::Win32::System::Console::{
            AttachConsole, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
            SetConsoleCtrlHandler,
        };

        let process_id = std::env::var("MAILCTL_EXPORT_PROCESS_FIXTURE")
            .expect("export process ID")
            .parse::<u32>()
            .expect("numeric export process ID");
        struct Console;
        impl Drop for Console {
            fn drop(&mut self) {
                unsafe {
                    FreeConsole();
                }
            }
        }
        unsafe {
            // A helper may already be detached; only attachment must succeed.
            FreeConsole();
            assert_ne!(
                AttachConsole(process_id),
                0,
                "attach export console: {}",
                std::io::Error::last_os_error()
            );
        }
        let _console = Console;
        unsafe {
            assert_ne!(
                SetConsoleCtrlHandler(None, 1),
                0,
                "protect signal fixture: {}",
                std::io::Error::last_os_error()
            );
            assert_ne!(
                GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0),
                0,
                "cancel export: {}",
                std::io::Error::last_os_error()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    #[test]
    fn whoami_csv_keeps_the_numeric_sid_independent_of_account_encoding() {
        let expected = Some("S-1-5-21-123-456-789-1001");
        for output in [
            &b"\"runner\\account\",\"S-1-5-21-123-456-789-1001\""[..],
            &b"\"runner\\account\",\"S-1-5-21-123-456-789-1001\"\r\n"[..],
            &b"\"runner\\account\",\"S-1-5-21-123-456-789-1001\"\n"[..],
            &b"\"runner\\comma,name\",\"S-1-5-21-123-456-789-1001\"\r\n"[..],
            &b"\"runner\\quote\"\"name\",\"S-1-5-21-123-456-789-1001\"\r\n"[..],
            &b"\"runner\\\xE9name\",\"S-1-5-21-123-456-789-1001\"\r\n"[..],
        ] {
            assert_eq!(whoami_sid(output), expected);
        }
    }

    #[test]
    fn whoami_csv_rejects_unexpected_records_and_invalid_sid_fields() {
        for output in [
            &b""[..],
            &b"S-1-5-18"[..],
            &b"\"\",\"S-1-5-18\""[..],
            &b"account,\"S-1-5-18\""[..],
            &b"\"account\",S-1-5-18"[..],
            &b"\"account\",\"S-1-5-18\",\"extra\""[..],
            &b"\"account\",\"S-1-5-18\" trailing"[..],
            &b"\"account\",\"S-1-5-18\"\r\n\r\n"[..],
            &b"\"account\",\"S-1-5-18\"\n\"other\",\"S-1-5-19\"\n"[..],
            &b"\"ac\ncount\",\"S-1-5-18\""[..],
            &b"\"account\",\"S-1-5-18\n\""[..],
            &b"\"account\",\"SID\""[..],
            &b"\"account\",\"S-2-5-18\""[..],
            &b"\"account\",\"S-1-5-\""[..],
            &b"\"account\",\"S-1-5-+18\""[..],
            &b"\"account\",\"S-1-5-18:(F)\""[..],
            &b"\"account\",\"S-1-281474976710656-18\""[..],
            &b"\"account\",\"S-1-5-4294967296\""[..],
            &b"\"account\",\"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16\""[..],
            &b"\"account\",\"S-1-5-\xE9\""[..],
        ] {
            assert_eq!(whoami_sid(output), None, "unexpected CSV: {output:?}");
        }
    }
}
