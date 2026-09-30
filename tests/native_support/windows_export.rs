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
    let mut command = powershell();
    command
        .env("MAILCTL_EXPORT_PROCESS_FIXTURE", process_id.to_string())
        .args([
            "-Command",
            r#"$ErrorActionPreference = 'Stop'; Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class ExportConsole { [DllImport("kernel32.dll", SetLastError=true)] public static extern bool FreeConsole(); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint process); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool ignore); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint control, uint group); }'; [void][ExportConsole]::FreeConsole(); if (-not [ExportConsole]::AttachConsole([uint32]$env:MAILCTL_EXPORT_PROCESS_FIXTURE)) { throw 'Cannot attach export console' }; try { if (-not [ExportConsole]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)) { throw 'Cannot protect signal fixture' }; if (-not [ExportConsole]::GenerateConsoleCtrlEvent(0, 0)) { throw 'Cannot cancel export' }; Start-Sleep -Milliseconds 200 } finally { [void][ExportConsole]::FreeConsole() }"#,
        ]);
    assert_success(&run_bounded(command));
}

fn current_sid() -> String {
    let mut command = powershell();
    command.args([
        "-Command",
        "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    ]);
    let output = run_bounded(command);
    assert_success(&output);
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn powershell() -> Command {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive"]);
    command
}
