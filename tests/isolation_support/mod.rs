//! Process and identity fixtures for the destructive native-isolation qualification.
//!
//! This module owns only the names and fixed deployment paths it creates.  The
//! ignored integration test checks every prerequisite before it changes macOS.

use crate::process;
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) const LABEL: &str = "org.ueberbrot.mailctl-isolated";
pub(crate) const INSTALL_ROOT: &str = "/Library/PrivilegedHelperTools/org.ueberbrot.mailctl";
pub(crate) const PUBLIC_ROOT: &str = "/Library/Application Support/mailctl-isolated";
pub(crate) const ROUTE: &str = "/Library/Application Support/mailctl-isolated/route.json";
pub(crate) const RUN: &str = "/Library/Application Support/mailctl-isolated/run";
pub(crate) const SOCKET: &str = "/Library/Application Support/mailctl-isolated/run/socket";
pub(crate) const SERVICE_HOME: &str = "/var/db/mailctl-isolated";
pub(crate) const CONFIG: &str = "/var/db/mailctl-isolated/config.toml";
pub(crate) const STATE: &str = "/var/db/mailctl-isolated/state";
pub(crate) const PLIST: &str = "/Library/LaunchDaemons/org.ueberbrot.mailctl-isolated.plist";

const INSTALLER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/deployment/macos-isolated/install.sh"
);
const SERVICE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/deployment/macos-isolated/service.sh"
);
const TERMINAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/isolation_support/terminal.py"
);
const PROBE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/isolation_support/ipc_probe.py"
);
const OUTPUT_BYTES: usize = 128 * 1024;
const DEADLINE: Duration = Duration::from_secs(12);

pub(crate) struct Qualification {
    pub(crate) service_user: String,
    pub(crate) caller_user: String,
    pub(crate) denied_user: String,
    pub(crate) service_uid: u32,
    pub(crate) caller_uid: u32,
    pub(crate) denied_uid: u32,
    artifacts: PathBuf,
    users: Vec<String>,
    installed: bool,
    trusted_certificate: Option<(PathBuf, String)>,
}

impl Qualification {
    pub(crate) fn begin(isolated: &Path, cli: &Path, mcp: &Path) -> Self {
        prerequisites();
        let suffix = Uuid::new_v4().simple().to_string();
        let service_user = format!("mailctliso{}", &suffix[..10]);
        let caller_user = format!("mailctlcall{}", &suffix[..9]);
        let denied_user = format!("mailctldeny{}", &suffix[..9]);
        let mut fixture = Self {
            service_user,
            caller_user,
            denied_user,
            service_uid: 0,
            caller_uid: 0,
            denied_uid: 0,
            artifacts: temporary_directory(&suffix),
            users: Vec::new(),
            installed: false,
            trusted_certificate: None,
        };
        fixture.service_uid = fixture.create_user(&fixture.service_user.clone(), true);
        fixture.caller_uid = fixture.create_user(&fixture.caller_user.clone(), false);
        fixture.denied_uid = fixture.create_user(&fixture.denied_user.clone(), false);
        copy_executable(isolated, &fixture.artifacts.join("mailctl-isolated"));
        copy_executable(cli, &fixture.artifacts.join("mailctl"));
        copy_executable(mcp, &fixture.artifacts.join("mailctl-mcp"));
        let installed = fixture.run_root(
            INSTALLER,
            [
                "--service-user",
                &fixture.service_user,
                "--caller-user",
                &fixture.caller_user,
                "--artifact-dir",
                fixture.artifacts.to_str().expect("UTF-8 artifact path"),
            ],
        );
        assert_success(&installed, "install isolated gateway");
        fixture.installed = true;
        let plist = fs::read_to_string(PLIST).unwrap().replace("</dict>\n</plist>", "<key>StandardErrorPath</key><string>/var/db/mailctl-isolated/diagnostic.log</string>\n</dict>\n</plist>");
        fs::write(PLIST, plist).unwrap();
        fixture
    }

    pub(crate) fn broker(&self, binary: &str) -> PathBuf {
        Path::new(INSTALL_ROOT).join(binary)
    }

    pub(crate) fn service_command(&self, binary: &str) -> Command {
        command_as(&self.service_user, binary)
    }

    pub(crate) fn caller_command(&self, binary: &str) -> Command {
        command_as(&self.caller_user, binary)
    }

    pub(crate) fn denied_command(&self, binary: &str) -> Command {
        command_as(&self.denied_user, binary)
    }

    pub(crate) fn run_root<I, S>(&self, program: &str, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        bounded(command(program).args(arguments))
    }

    pub(crate) fn start(&self) {
        assert_success(&self.run_root(SERVICE, ["start"]), "start launchd service");
        self.wait_for_socket();
    }

    pub(crate) fn restart(&self) {
        let previous = self.launchd_pid();
        assert_success(
            &self.run_root(SERVICE, ["restart"]),
            "restart launchd service",
        );
        self.wait_for_socket();
        let deadline = Instant::now() + DEADLINE;
        while self.current_launchd_pid().is_none_or(|pid| pid == previous) {
            assert!(
                Instant::now() < deadline,
                "launchd restart did not replace the service process"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub(crate) fn stop(&self) {
        let output = self.run_root(SERVICE, ["stop"]);
        assert_success(&output, "stop launchd service");
    }

    pub(crate) fn wait_for_socket(&self) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if fs::symlink_metadata(SOCKET).is_ok_and(|metadata| metadata.file_type().is_socket()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "launchd service did not bind its socket"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub(crate) fn launchd_pid(&self) -> u32 {
        self.current_launchd_pid()
            .expect("launchd reported a service PID")
    }

    fn current_launchd_pid(&self) -> Option<u32> {
        let output = self.run_root("/bin/launchctl", ["print", &format!("system/{LABEL}")]);
        assert_success(&output, "inspect launchd service");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("pid = ")
                    .and_then(|value| value.trim_end_matches(';').parse().ok())
            })
    }

    pub(crate) fn uid_of_pid(&self, pid: u32) -> u32 {
        let output = self.run_root("/bin/ps", ["-o", "uid=", "-p", &pid.to_string()]);
        assert_success(&output, "inspect service UID");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("numeric service UID")
    }

    /// Unlock the disposable fixture keychain in the broker's launchd session.
    pub(crate) fn unlock_broker_keychain(&self, keychain: &Path) {
        let broker_pid = self.launchd_pid().to_string();
        let keychain = keychain.to_str().expect("UTF-8 fixture keychain path");
        let output = bounded(command("/bin/launchctl").args([
            "bsexec",
            &broker_pid,
            "/usr/bin/security",
            "unlock-keychain",
            "-p",
            "mailctl-isolated-fixture",
            keychain,
        ]));
        assert_success(
            &output,
            "unlock disposable keychain in the broker launchd session",
        );
    }

    pub(crate) fn create_keychain(&mut self, certificate: &Path) -> PathBuf {
        let keychain = Path::new(SERVICE_HOME).join("native-fixture.keychain-db");
        let keychain_text = keychain.to_str().expect("UTF-8 keychain path");
        for arguments in [
            vec![
                "create-keychain",
                "-p",
                "mailctl-isolated-fixture",
                keychain_text,
            ],
            vec![
                "unlock-keychain",
                "-p",
                "mailctl-isolated-fixture",
                keychain_text,
            ],
            vec!["set-keychain-settings", keychain_text],
            vec!["default-keychain", "-d", "user", "-s", keychain_text],
            vec!["list-keychains", "-d", "user", "-s", keychain_text],
        ] {
            let output = bounded(self.service_command("/usr/bin/security").args(arguments));
            assert_success(&output, "provision disposable service keychain");
        }
        let certificate_text = certificate.to_str().expect("UTF-8 certificate path");
        let fingerprint = bounded(command("/usr/bin/openssl").args([
            "x509",
            "-in",
            certificate_text,
            "-noout",
            "-fingerprint",
            "-sha256",
        ]));
        assert_success(&fingerprint, "identify the synthetic provider certificate");
        let fingerprint = String::from_utf8(fingerprint.stdout)
            .expect("certificate fingerprint")
            .split_once('=')
            .expect("fingerprint value")
            .1
            .trim()
            .replace(':', "");
        assert!(
            fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        );
        self.trusted_certificate = Some((certificate.to_owned(), fingerprint));
        assert_success(
            &bounded(command("/usr/bin/security").args([
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                certificate_text,
            ])),
            "administrator trusts only the disposable synthetic provider certificate",
        );
        let default = bounded(self.service_command("/usr/bin/security").args([
            "default-keychain",
            "-d",
            "user",
        ]));
        assert_success(&default, "inspect service default keychain");
        let selected: String =
            serde_json::from_slice(&default.stdout).expect("quoted service default keychain");
        assert_eq!(
            fs::canonicalize(selected).unwrap(),
            fs::canonicalize(&keychain).unwrap(),
            "service User-domain default persists across processes"
        );
        keychain
    }

    pub(crate) fn provision_credential(&self, alias: &str, secret: &str) {
        let executable = self.broker("mailctl");
        let request = serde_json::json!({
            "command": [
                "/usr/bin/sudo", "-u", self.service_user, "-H", "--",
                executable.to_str().expect("UTF-8 broker path"), "--config", CONFIG,
                "--account", alias, "credential", "set"
            ],
            "secret": secret,
        });
        let mut child = command("python3")
            .arg(TERMINAL)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start terminal fixture");
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("terminal fixture stdin")
            .write_all(&serde_json::to_vec(&request).expect("serialize terminal request"))
            .expect("send terminal fixture request");
        let captured = process::capture(child, None, OUTPUT_BYTES, DEADLINE)
            .expect("collect terminal fixture");
        assert!(!captured.stdout_exceeded_limit && !captured.stderr_exceeded_limit);
        assert_success(&captured.output, "store service credential");
        let result: serde_json::Value =
            serde_json::from_slice(&captured.output.stdout).expect("terminal fixture response");
        assert_eq!(result["prompted"], true, "credential command prompted");
        assert_eq!(
            result["echo_enabled"], false,
            "credential prompt disables terminal echo"
        );
        assert_eq!(
            result["secret_disclosed"], false,
            "credential stayed private"
        );
        assert_eq!(
            result["exit"], 0,
            "credential command completed: {}",
            result["diagnostic"]
        );
    }

    pub(crate) fn hold_session(&self) -> HoldSession {
        let mut child = self
            .caller_command("python3")
            .arg(PROBE)
            .arg("hold")
            .arg(SOCKET)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("open raw isolated session");
        let line = readiness_line(&mut child, "session");
        assert_eq!(line, "ready\n", "raw session connected");
        let release = child.stdin.take().expect("probe session control pipe");
        HoldSession {
            child,
            release: Some(release),
        }
    }

    pub(crate) fn malformed_frame(&self) {
        let output = bounded(
            self.caller_command("python3")
                .arg(PROBE)
                .arg("malformed")
                .arg(SOCKET),
        );
        assert_success(&output, "gateway rejects a bounded malformed frame");
    }

    pub(crate) fn initialization_timeout(&self) {
        let output = bounded(
            self.caller_command("python3")
                .arg(PROBE)
                .arg("initialization-timeout")
                .arg(SOCKET),
        );
        assert_success(&output, "gateway enforces the mapped hello deadline");
    }

    pub(crate) fn null_hello(&self) {
        let output = bounded(
            self.caller_command("python3")
                .arg(PROBE)
                .arg("null-hello")
                .arg(SOCKET),
        );
        assert_success(&output, "gateway accepts the shallow valid hello");
    }

    pub(crate) fn account_hello_over_nesting_ceiling(&self) {
        let output = bounded(
            self.caller_command("python3")
                .arg(PROBE)
                .arg("account-hello")
                .arg(SOCKET),
        );
        assert_success(&output, "gateway enforces the mapped JSON nesting ceiling");
    }

    pub(crate) fn unauthorized_hello(&self) {
        let output = bounded(
            self.denied_command("python3")
                .arg(PROBE)
                .arg("unauthorized-hello")
                .arg(SOCKET),
        );
        assert_success(&output, "gateway closes an unauthorized raw hello");
    }

    pub(crate) fn start_wrong_peer(&self) -> WrongPeer {
        let run = Path::new(RUN);
        self.stop();
        remove_if_present(Path::new(SOCKET));
        fs::set_permissions(run, fs::Permissions::from_mode(0o777))
            .expect("temporarily permit endpoint-substitution probe");
        let mut child = self
            .caller_command("python3")
            .arg(PROBE)
            .arg("wrong-peer")
            .arg(SOCKET)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start wrong-peer endpoint");
        let line = readiness_line(&mut child, "wrong peer");
        assert_eq!(line, "ready\n", "wrong peer bound fixed endpoint");
        WrongPeer { child }
    }

    pub(crate) fn restore_after_wrong_peer(&self) {
        remove_if_present(Path::new(SOCKET));
        let run = Path::new(RUN);
        fs::set_permissions(run, fs::Permissions::from_mode(0o711))
            .expect("restore protected socket directory");
        let group = primary_group(&self.service_user);
        run_chown(run, self.service_uid, group);
        self.start();
    }

    fn create_user(&mut self, name: &str, service: bool) -> u32 {
        let uid = unused_uid();
        let record = format!("/Users/{name}");
        for arguments in [
            vec![".".to_owned(), "-create".to_owned(), record.clone()],
            vec![
                ".".to_owned(),
                "-create".to_owned(),
                record.clone(),
                "UniqueID".to_owned(),
                uid.to_string(),
            ],
            vec![
                ".".to_owned(),
                "-create".to_owned(),
                record.clone(),
                "PrimaryGroupID".to_owned(),
                "20".to_owned(),
            ],
            vec![
                ".".to_owned(),
                "-create".to_owned(),
                record.clone(),
                "NFSHomeDirectory".to_owned(),
                if service { SERVICE_HOME } else { "/var/empty" }.to_owned(),
            ],
            vec![
                ".".to_owned(),
                "-create".to_owned(),
                record,
                "UserShell".to_owned(),
                "/usr/bin/false".to_owned(),
            ],
        ] {
            let output = bounded(command("/usr/bin/dscl").args(arguments));
            assert_success(&output, "create disposable native identity");
        }
        self.users.push(name.to_owned());
        uid
    }
}

impl Drop for Qualification {
    fn drop(&mut self) {
        if let Ok(log) = fs::read_to_string("/var/db/mailctl-isolated/diagnostic.log") {
            for line in log
                .lines()
                .filter(|line| line.starts_with("[DEBUG-keychain]"))
            {
                eprintln!("{line}");
            }
        }
        if let Some((certificate, fingerprint)) = self.trusted_certificate.take() {
            cleanup_command(command("/usr/bin/security").args([
                "remove-trusted-cert",
                "-d",
                certificate.to_str().expect("certificate path"),
            ]));
            cleanup_command(command("/usr/bin/security").args([
                "delete-certificate",
                "-Z",
                &fingerprint,
                "/Library/Keychains/System.keychain",
            ]));
        }
        if self.installed {
            let _ = command("/bin/launchctl")
                .args(["bootout", "system", PLIST])
                .output();
            remove_if_present(Path::new(PLIST));
            remove_directory_if_present(Path::new(INSTALL_ROOT));
            remove_directory_if_present(Path::new(PUBLIC_ROOT));
            remove_directory_if_present(Path::new(SERVICE_HOME));
        }
        for user in self.users.iter().rev() {
            let _ = command("/usr/bin/dscl")
                .args([".", "-delete", &format!("/Users/{user}")])
                .output();
        }
        remove_directory_if_present(&self.artifacts);
    }
}

pub(crate) struct HoldSession {
    child: Child,
    release: Option<std::process::ChildStdin>,
}

impl Drop for HoldSession {
    fn drop(&mut self) {
        drop(self.release.take());
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
            }
        }
        terminate_probe(&mut self.child);
    }
}

pub(crate) struct WrongPeer {
    child: Child,
}

impl Drop for WrongPeer {
    fn drop(&mut self) {
        terminate_probe(&mut self.child);
    }
}

fn cleanup_command(command: &mut Command) {
    command.stdout(Stdio::null()).stderr(Stdio::null());
    if let Ok(child) = command.spawn() {
        let _ = process::capture(child, None, OUTPUT_BYTES, DEADLINE);
    }
}

fn terminate_probe(child: &mut Child) {
    use rustix::process::{Pid, Signal, getpgid, kill_process_group};
    let pid = Pid::from_child(child);
    if getpgid(Some(pid)).is_ok_and(|group| group == pid) {
        let _ = kill_process_group(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn bounded(command: &mut Command) -> Output {
    eprintln!("native isolation command: {}", command_identity(command));
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().expect("start bounded command");
    let captured = process::capture(child, None, OUTPUT_BYTES, DEADLINE)
        .expect("bounded command completed before deadline");
    assert!(
        !captured.stdout_exceeded_limit && !captured.stderr_exceeded_limit,
        "bounded command output stayed within the fixture limit"
    );
    captured.output
}

pub(crate) fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed: exit {:?}; stdout {}; stderr {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn assert_denied(output: &Output, action: &str) {
    assert!(
        !output.status.success(),
        "{action} unexpectedly succeeded: stdout {}; stderr {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.process_group(0);
    command
}

pub(crate) fn command_as(user: &str, program: &str) -> Command {
    let mut command = command("/usr/bin/sudo");
    command.args(["-u", user, "-H", "--", program]);
    command
}

fn command_identity(command: &Command) -> String {
    let program = command.get_program().to_string_lossy();
    if program == "/usr/bin/sudo" {
        let target = command
            .get_args()
            .skip_while(|argument| *argument != "--")
            .nth(1)
            .map(|argument| argument.to_string_lossy())
            .unwrap_or_else(|| "<missing target>".into());
        return format!("{program} -> {target}");
    }
    if program == "/usr/bin/security"
        && let Some(subcommand) = command.get_args().next()
    {
        return format!("{program} {}", subcommand.to_string_lossy());
    }
    program.into_owned()
}

pub(crate) fn sha256(path: &Path) -> String {
    let output =
        bounded(command("/usr/bin/shasum").args(["-a", "256", path.to_str().expect("UTF-8 path")]));
    assert_success(&output, "hash installed executable");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("SHA-256 output")
        .to_owned()
}

pub(crate) fn metadata(path: &Path) -> std::fs::Metadata {
    fs::symlink_metadata(path).expect("inspect deployed path")
}

pub(crate) fn patch_service_configuration(port: u16) {
    let mut configuration: toml::Value =
        toml::from_str(&fs::read_to_string(CONFIG).expect("read service configuration"))
            .expect("parse service configuration");
    let accounts = configuration["accounts"]
        .as_array_mut()
        .expect("service accounts");
    assert_eq!(accounts.len(), 2, "operator created two synthetic accounts");
    let work = accounts[0]["key"]
        .as_str()
        .expect("work account key")
        .to_owned();
    for account in accounts {
        account["server"] = "127.0.0.1".into();
        account["port"] = i64::from(port).into();
    }
    let mut grant = configuration["grants"]
        .as_array()
        .and_then(|grants| grants.first())
        .expect("default grant")
        .clone();
    grant["name"] = "isolated".into();
    grant["accounts"] = toml::Value::Array(vec![work.into()]);
    grant["limits"] = toml::Value::Table(toml::map::Map::from_iter([
        ("initialization_seconds".into(), 1.into()),
        ("json_nesting".into(), 12.into()),
    ]));
    configuration["default_grant"] = "isolated".into();
    configuration["grants"] = toml::Value::Array(vec![grant]);
    fs::write(
        CONFIG,
        toml::to_string_pretty(&configuration).expect("serialize service configuration"),
    )
    .expect("update service configuration");
}

pub(crate) fn set_grant_json_nesting(nesting: usize) {
    let mut configuration: toml::Value =
        toml::from_str(&fs::read_to_string(CONFIG).expect("read service configuration"))
            .expect("parse service configuration");
    configuration["grants"][0]["limits"]["json_nesting"] = (nesting as i64).into();
    fs::write(
        CONFIG,
        toml::to_string_pretty(&configuration).expect("serialize service configuration"),
    )
    .expect("update grant JSON nesting ceiling");
}

fn prerequisites() {
    assert_eq!(
        std::env::var("MAILCTL_DISPOSABLE_MACOS").as_deref(),
        Ok("1"),
        "MAILCTL_DISPOSABLE_MACOS=1 confirms a disposable macOS runner"
    );
    assert_eq!(
        std::env::consts::OS,
        "macos",
        "native qualification requires macOS"
    );
    let root = command("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("inspect test UID");
    assert!(root.status.success(), "inspect test UID");
    assert_eq!(
        String::from_utf8_lossy(&root.stdout).trim(),
        "0",
        "native qualification requires root"
    );
    for path in [INSTALL_ROOT, PUBLIC_ROOT, SERVICE_HOME, PLIST] {
        assert!(
            fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "fixed qualification path must be absent before installation: {path}"
        );
    }
    assert!(
        command("/bin/launchctl")
            .args(["print", &format!("system/{LABEL}")])
            .output()
            .is_ok_and(|output| !output.status.success()),
        "fixed launchd label must be absent before qualification"
    );
}

fn temporary_directory(suffix: &str) -> PathBuf {
    let directory = fs::canonicalize(std::env::temp_dir())
        .expect("canonical native temporary directory")
        .join(format!("mailctl-isolated-{suffix}"));
    fs::create_dir(&directory).expect("create native artifact directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("protect native artifact directory");
    directory
}

fn copy_executable(source: &Path, destination: &Path) {
    fs::copy(source, destination).expect("copy native executable artifact");
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
        .expect("make copied artifact executable");
}

fn unused_uid() -> u32 {
    let output = bounded(command("/usr/bin/dscl").args([".", "-list", "/Users", "UniqueID"]));
    assert_success(&output, "list native identities");
    let occupied = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().last()?.parse::<u32>().ok())
        .collect::<HashSet<_>>();
    (600..1000)
        .find(|uid| !occupied.contains(uid))
        .expect("an unused disposable UID")
}

fn primary_group(user: &str) -> u32 {
    let output = bounded(command("/usr/bin/id").args(["-g", user]));
    assert_success(&output, "inspect service group");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("numeric service group")
}

fn run_chown(path: &Path, uid: u32, gid: u32) {
    let output = bounded(
        command("/usr/sbin/chown")
            .arg(format!("{uid}:{gid}"))
            .arg(path),
    );
    assert_success(&output, "restore socket directory ownership");
}

fn remove_if_present(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove owned fixture file {}: {error}", path.display()),
    }
}

fn remove_directory_if_present(path: &Path) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove owned fixture directory {}: {error}", path.display()),
    }
}

fn readiness_line(child: &mut Child, name: &str) -> String {
    let stdout = child.stdout.take().expect("probe readiness stdout");
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = send.send(result);
    });
    let line = receive.recv_timeout(DEADLINE).unwrap_or_else(|_| {
        terminate_probe(child);
        panic!("{name} probe did not report readiness before deadline")
    });
    reader.join().expect("join probe readiness reader");
    line.expect("read probe readiness")
}
