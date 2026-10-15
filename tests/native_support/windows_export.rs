#![allow(
    dead_code,
    reason = "native writer and CLI process tests use different parts of this fixture"
)]
use crate::support::{assert_success, run_bounded};
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

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "The independent ACL observer reads native security descriptors and numeric SIDs"
)]
pub(crate) fn assert_private(path: &Path) {
    use std::{ffi::c_void, io, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER,
            Authorization::{ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
            INHERITED_ACE, IsValidAcl, IsValidSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
            SE_DACL_PROTECTED, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
    };

    struct Allocation(*mut c_void);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    assert!(!path[..path.len() - 1].contains(&0));
    let sid: Vec<u16> = current_sid().encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut current = ptr::null_mut();
        assert_ne!(
            ConvertStringSidToSidW(sid.as_ptr(), &mut current),
            0,
            "parse observer identity: {}",
            io::Error::last_os_error()
        );
        let current = Allocation(current);

        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // Query the named path independently of production's open-handle validation.
        let error = GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        );
        let descriptor = Allocation(descriptor);
        assert_eq!(
            error,
            0,
            "observe export ACL: {}",
            io::Error::from_raw_os_error(error as i32)
        );
        assert!(!owner.is_null() && IsValidSid(owner) != 0);
        assert_ne!(EqualSid(owner, current.0), 0, "operator owns export file");
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision),
            0
        );
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "export ACL disables inheritance"
        );
        assert!(
            !acl.is_null() && IsValidAcl(acl) != 0,
            "export file has an explicit DACL"
        );
        assert_ne!((*acl).AceCount, 0, "export file has an explicit DACL");
        let mut current_has_rule = false;
        for index in 0..(*acl).AceCount {
            let mut entry = ptr::null_mut();
            assert_ne!(GetAce(acl, u32::from(index), &mut entry), 0);
            let header = &*entry.cast::<ACE_HEADER>();
            assert_eq!(
                u32::from(header.AceFlags) & INHERITED_ACE,
                0,
                "export ACE is explicit"
            );
            let (sid, allows_access) = match u32::from(header.AceType) {
                ACCESS_ALLOWED_ACE_TYPE => {
                    let ace = &*entry.cast::<ACCESS_ALLOWED_ACE>();
                    (ptr::addr_of!(ace.SidStart).cast_mut().cast(), ace.Mask != 0)
                }
                ACCESS_DENIED_ACE_TYPE => {
                    let ace = &*entry.cast::<ACCESS_DENIED_ACE>();
                    (ptr::addr_of!(ace.SidStart).cast_mut().cast(), false)
                }
                kind => panic!("unexpected export ACE type: {kind}"),
            };
            assert_ne!(IsValidSid(sid), 0);
            let is_current = EqualSid(sid, current.0) != 0;
            current_has_rule |= is_current;
            if allows_access {
                assert!(
                    is_current
                        || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                        || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0,
                    "export DACL grants another identity access at ACE {index}"
                );
            }
        }
        assert!(
            current_has_rule,
            "export DACL includes the operator identity"
        );
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
