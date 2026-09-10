//! Real launchd qualification for the opt-in macOS isolated installation.
//!
//! Run only on a disposable GitHub-hosted macOS runner as root:
//! `MAILCTL_DISPOSABLE_MACOS=1 cargo test --features isolated --test isolated_native -- --ignored`.
#![cfg(all(
    target_os = "macos",
    feature = "isolated",
    feature = "cli",
    feature = "mcp"
))]

#[allow(
    dead_code,
    reason = "the native TLS fixture shares the full IMAP transcript support"
)]
#[path = "imap_support/mod.rs"]
mod imap_support;
mod isolation_support;
#[path = "native_support/process.rs"]
mod process;
#[allow(
    dead_code,
    reason = "the qualification uses only the native authentication transcript"
)]
#[path = "native_support/server.rs"]
mod server;

use isolation_support::{
    BrokerPeer, CONFIG, INSTALL_ROOT, Qualification, ROUTE, RUN, SERVICE_HOME, SOCKET, STATE,
    assert_denied, assert_success, bounded, metadata, patch_service_configuration,
    set_grant_json_nesting, sha256,
};
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::Value;
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    process::Stdio,
    thread,
    time::Duration,
};

const ISOLATED: &str = env!("CARGO_BIN_EXE_mailctl-isolated");
const CLI: &str = env!("CARGO_BIN_EXE_mailctl");
const MCP: &str = env!("CARGO_BIN_EXE_mailctl-mcp");
const WORK_SECRET: &str = "isolated-native-work-secret";
// Exceeds the fixture's 12-per-minute doctor limit; this is not a Keychain-settling delay.
const DOCTOR_RECHECK: Duration = Duration::from_secs(6);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root and MAILCTL_DISPOSABLE_MACOS=1 on a disposable macOS runner"]
async fn isolated_launchd_qualification_uses_disposable_identities_and_a_real_native_keychain() {
    eprintln!("native isolation: provision disposable identities and install");
    let mut fixture = Qualification::begin(Path::new(ISOLATED), Path::new(CLI), Path::new(MCP));
    let mut provider = server::NativeServer::new(Path::new(SERVICE_HOME));

    eprintln!("native isolation: configure synthetic accounts");
    operator_setup(&fixture, "work", "work@isolated.example.test");
    operator_setup(&fixture, "private", "private@isolated.example.test");
    patch_service_configuration(provider.port);
    eprintln!("native isolation: provision service Keychain and credential");
    let keychain = fixture.create_keychain(&provider.certificate);
    fixture.provision_credential("work", WORK_SECRET);
    let work_account = service_account_id(&fixture, "work");
    assert_success(
        &bounded(fixture.service_command("/usr/bin/security").args([
            "find-generic-password",
            "-s",
            "mailctl",
            "-a",
            &work_account,
            keychain.to_str().expect("UTF-8 keychain path"),
        ])),
        "service identity reads its native mailctl credential",
    );

    eprintln!("native isolation: start launchd and verify protected resources");
    fixture.unlock_service_keychain_context(&keychain);
    fixture.start();
    assert_deployment_identity(&fixture, &keychain);
    record_environment(&fixture);
    assert_caller_cannot_mutate_protected_assets(&fixture, &keychain, &work_account);
    assert_client_has_no_embedded_administration_path(&fixture);
    assert_unassigned_identity_is_denied(&fixture);
    assert_embedded_service_shares_maintenance_lock(&fixture);

    eprintln!("native isolation: compare CLI/MCP and authenticate through service");
    assert_published_capacity(&fixture);
    let cli = listed_accounts(&fixture);
    let mcp = listed_accounts_over_mcp(&fixture).await;
    assert_eq!(
        mcp["ok"], true,
        "MCP completes an isolated service handshake"
    );
    assert_eq!(
        mcp["result"], cli["result"],
        "CLI and MCP expose the same service data"
    );
    assert_eq!(cli["result"]["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(cli["result"]["accounts"][0]["alias"], "work");
    assert_eq!(
        cli["result"]["accounts"][0]["account_id"], work_account,
        "broker and embedded service processes share account identity"
    );
    assert!(
        !cli.to_string().contains("private@isolated.example.test"),
        "the unassigned account is inaccessible to the isolated caller"
    );

    assert_service_authentication(&fixture, &provider);

    eprintln!("native isolation: verify IPC bounds, substitution, and restart");
    assert_bounded_malformed_and_exhausted_sessions(&fixture);
    assert_mapped_grant_limits(&fixture).await;
    assert_wrong_service_peer_is_rejected(&fixture);
    let previous_broker = fixture.broker_peer();
    fixture.restart();
    fixture.wait_for_process_exit(previous_broker.pid).await;
    let restarted_accounts = eventually_listed_accounts(&fixture);
    let restarted_broker = assert_deployment_identity(&fixture, &keychain);
    assert_ne!(
        restarted_broker.pid, previous_broker.pid,
        "restart replaces the socket-serving broker process"
    );
    assert_eq!(
        restarted_accounts["result"], cli["result"],
        "restart retains the installation"
    );
    assert_service_authentication(&fixture, &provider);
    assert_locked_keychain_failure(&fixture, &keychain, &provider).await;
    let final_broker = fixture.broker_peer();
    fixture.stop();
    fixture.wait_for_process_exit(final_broker.pid).await;
    provider.finish();
}

fn assert_service_authentication(fixture: &Qualification, provider: &server::NativeServer) {
    provider.expect("work@isolated.example.test", WORK_SECRET);
    let doctor = bounded(
        fixture
            .caller_command(fixture.broker("mailctl").to_str().unwrap())
            .args([
                "--isolated",
                "--json",
                "--account",
                "work",
                "doctor",
                "--check-account",
            ]),
    );
    assert_success(&doctor, "caller authenticates through the launchd service");
    let doctor = envelope(&doctor);
    assert_eq!(
        doctor["result"]["accounts"][0]["authentication"]["outcome"]["status"], "authenticated",
        "doctor uses the service identity's native Keychain credential"
    );
}

async fn assert_locked_keychain_failure(
    fixture: &Qualification,
    keychain: &Path,
    provider: &server::NativeServer,
) {
    tokio::time::sleep(DOCTOR_RECHECK).await;
    fixture.lock_service_keychain_context(keychain);
    let previous_connections = provider.accepted();
    let doctor = bounded(
        fixture
            .caller_command(fixture.broker("mailctl").to_str().unwrap())
            .args([
                "--isolated",
                "--json",
                "--account",
                "work",
                "doctor",
                "--check-account",
            ]),
    );
    assert_eq!(
        doctor.status.code(),
        Some(4),
        "a locked service keychain makes authentication fail safely"
    );
    let doctor = envelope(&doctor);
    let authentication = &doctor["result"]["accounts"][0]["authentication"];
    assert_eq!(
        authentication["outcome"]["status"], "failed",
        "doctor records the failed authentication"
    );
    let failure = &authentication["outcome"]["error"];
    assert_eq!(
        failure["code"], "credential_unavailable",
        "the locked keychain is reported as a credential failure"
    );
    assert!(matches!(
        failure["credential_failure"].as_str(),
        Some("access_denied" | "interaction_required")
    ));
    assert_eq!(
        provider.accepted(),
        previous_connections,
        "the locked keychain failure does not contact the provider"
    );
    fixture.unlock_service_keychain_context(keychain);
    tokio::time::sleep(DOCTOR_RECHECK).await;
    assert_service_authentication(fixture, provider);
}

fn operator_setup(fixture: &Qualification, alias: &str, username: &str) {
    let output = bounded(
        fixture
            .service_command(fixture.broker("mailctl").to_str().unwrap())
            .args([
                "--config",
                CONFIG,
                "--json",
                "setup",
                "--alias",
                alias,
                "--server",
                "127.0.0.1",
                "--username",
                username,
            ]),
    );
    assert_success(
        &output,
        "service identity provisions a synthetic account through CLI setup",
    );
}

fn service_account_id(fixture: &Qualification, alias: &str) -> String {
    let output = bounded(
        fixture
            .service_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--config", CONFIG, "--json", "account", "list"]),
    );
    assert_success(&output, "service identity lists provisioned accounts");
    envelope(&output)["result"]["accounts"]
        .as_array()
        .expect("service accounts")
        .iter()
        .find(|account| account["alias"] == alias)
        .and_then(|account| account["account_id"].as_str())
        .expect("synthetic account identity")
        .to_owned()
}

fn assert_deployment_identity(fixture: &Qualification, keychain: &Path) -> BrokerPeer {
    let launcher_pid = fixture.launchd_pid();
    let broker = fixture.broker_peer();
    assert_eq!(
        broker.uid, fixture.service_uid,
        "the socket-serving broker uses the dedicated service UID"
    );
    assert_eq!(
        fixture.uid_of_pid(broker.pid),
        fixture.service_uid,
        "the socket-serving broker process retains the expected service UID"
    );
    assert_eq!(
        fixture.process_group(broker.pid),
        launcher_pid,
        "the socket-serving broker remains in the launchd service process group"
    );
    for (path, owner) in [
        (Path::new(CONFIG), fixture.service_uid),
        (Path::new(STATE), fixture.service_uid),
        (Path::new(SERVICE_HOME), fixture.service_uid),
        (keychain, fixture.service_uid),
        (Path::new(ROUTE), 0),
        (Path::new(INSTALL_ROOT), 0),
        (&fixture.broker("mailctl-isolated"), 0),
        (&fixture.broker("mailctl"), 0),
        (&fixture.broker("mailctl-mcp"), 0),
        (Path::new(RUN), fixture.service_uid),
    ] {
        let metadata = metadata(path);
        assert_eq!(
            metadata.uid(),
            owner,
            "{} has the expected owner",
            path.display()
        );
        assert_eq!(
            metadata.mode() & 0o022,
            0,
            "{} cannot be replaced by caller access",
            path.display()
        );
    }
    assert_eq!(
        metadata(Path::new(ROUTE)).mode() & 0o777,
        0o644,
        "route is readable but immutable to callers"
    );
    assert_eq!(
        metadata(Path::new(RUN)).mode() & 0o777,
        0o711,
        "caller can connect but cannot replace the socket"
    );
    assert!(
        metadata(Path::new(SOCKET)).file_type().is_socket(),
        "service bound the fixed Unix socket"
    );
    broker
}

fn record_environment(fixture: &Qualification) {
    let os = bounded(isolation_support::command("/usr/bin/sw_vers").arg("-productVersion"));
    assert_success(&os, "read macOS version");
    let architecture = bounded(isolation_support::command("/usr/bin/uname").arg("-m"));
    assert_success(&architecture, "read architecture");
    let launcher_pid = fixture.launchd_pid();
    let broker = fixture.broker_peer();
    eprintln!(
        "isolated native qualification: macOS={} arch={} launcher_pid={} launcher_uid={} broker_pid={} broker_peer_uid={} broker_process_uid={} service_uid={} caller_uid={} denied_uid={} mailctl-isolated_sha256={} mailctl_sha256={} mailctl-mcp_sha256={}",
        String::from_utf8_lossy(&os.stdout).trim(),
        String::from_utf8_lossy(&architecture.stdout).trim(),
        launcher_pid,
        fixture.uid_of_pid(launcher_pid),
        broker.pid,
        broker.uid,
        fixture.uid_of_pid(broker.pid),
        fixture.service_uid,
        fixture.caller_uid,
        fixture.denied_uid,
        sha256(&fixture.broker("mailctl-isolated")),
        sha256(&fixture.broker("mailctl")),
        sha256(&fixture.broker("mailctl-mcp")),
    );
}

fn assert_caller_cannot_mutate_protected_assets(
    fixture: &Qualification,
    keychain: &Path,
    work_account: &str,
) {
    for path in [CONFIG, keychain.to_str().expect("UTF-8 keychain path")] {
        assert_denied(
            &bounded(fixture.caller_command("/bin/cat").arg(path)),
            "caller cannot read service-private state",
        );
    }
    assert_denied(
        &bounded(fixture.caller_command("/bin/ls").args(["-A", STATE])),
        "caller cannot enumerate service state",
    );
    assert_denied(
        &bounded(
            fixture
                .caller_command(fixture.broker("mailctl").to_str().unwrap())
                .args(["--config", CONFIG, "--json", "account", "list"]),
        ),
        "caller cannot bypass the isolated route through the service configuration",
    );
    assert_denied(
        &bounded(fixture.caller_command("/usr/bin/security").args([
            "find-generic-password",
            "-s",
            "mailctl",
            "-a",
            work_account,
            keychain.to_str().expect("UTF-8 keychain path"),
        ])),
        "caller cannot read the service native Keychain credential",
    );
    for path in [
        ROUTE,
        SOCKET,
        fixture.broker("mailctl-isolated").to_str().unwrap(),
        fixture.broker("mailctl").to_str().unwrap(),
        fixture.broker("mailctl-mcp").to_str().unwrap(),
    ] {
        assert_denied(
            &bounded(fixture.caller_command("/bin/rm").arg(path)),
            "caller cannot replace a protected deployment asset",
        );
    }
}

fn assert_client_has_no_embedded_administration_path(fixture: &Qualification) {
    let cli = fixture.broker("mailctl");
    for arguments in [
        vec!["--isolated", "--json", "setup"],
        vec![
            "--isolated",
            "--json",
            "--account",
            "work",
            "credential",
            "status",
        ],
        vec![
            "--isolated",
            "--config",
            "/var/empty/caller.toml",
            "account",
            "list",
        ],
        vec!["--isolated", "--grant", "isolated", "account", "list"],
    ] {
        let output = bounded(
            fixture
                .caller_command(cli.to_str().unwrap())
                .args(arguments),
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "client administration/configuration is rejected before local access"
        );
    }
}

fn assert_unassigned_identity_is_denied(fixture: &Qualification) {
    let output = bounded(
        fixture
            .denied_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--isolated", "--json", "account", "list"]),
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "route rejects an unassigned OS identity"
    );
    fixture.unauthorized_hello();
}

fn assert_embedded_service_shares_maintenance_lock(fixture: &Qualification) {
    let output = bounded(
        fixture
            .service_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--config", CONFIG, "--json", "setup"]),
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "an embedded service-identity maintenance command sees the gateway's shared installation lease"
    );
    assert_eq!(
        envelope(&output)["error"]["code"],
        "rate_limited",
        "the shared maintenance lock rejects concurrent mutation rather than creating a caller-owned installation"
    );
}

fn assert_published_capacity(fixture: &Qualification) {
    let output = bounded(
        fixture
            .caller_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--isolated", "--json", "capability", "show"]),
    );
    assert_success(&output, "publish broker capacity");
    let capacity = &envelope(&output)["result"]["capacity"];
    assert_eq!(capacity["per_process"]["active_requests"], 4);
    assert_eq!(capacity["per_process"]["queued_requests"], 0);
    assert_eq!(capacity["isolation"]["sessions"], 4);
    assert_eq!(capacity["isolation"]["active_requests_per_session"], 1);
    assert_eq!(capacity["isolation"]["request_bytes"], 65536);
}

fn listed_accounts(fixture: &Qualification) -> Value {
    let output = bounded(
        fixture
            .caller_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--isolated", "--json", "account", "list"]),
    );
    assert_success(
        &output,
        "caller lists accounts through the isolated gateway",
    );
    envelope(&output)
}

async fn listed_accounts_over_mcp(fixture: &Qualification) -> Value {
    let mut command = tokio::process::Command::new("/usr/bin/sudo");
    command
        .args([
            "-u",
            &fixture.caller_user,
            "-H",
            "--",
            fixture.broker("mailctl-mcp").to_str().unwrap(),
            "--isolated",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let transport = TokioChildProcess::new(command).expect("start isolated MCP client process");
    let client = tokio::time::timeout(Duration::from_secs(12), ().serve(transport))
        .await
        .expect("MCP initialization stays bounded")
        .expect("negotiate isolated MCP session");
    let response = tokio::time::timeout(
        Duration::from_secs(12),
        client.call_tool(CallToolRequestParams::new("email_list_accounts")),
    )
    .await
    .expect("MCP account discovery stays bounded")
    .expect("call isolated account discovery tool");
    let result = response
        .structured_content
        .expect("structured MCP account result");
    tokio::time::timeout(Duration::from_secs(12), client.cancel())
        .await
        .expect("MCP cancellation stays bounded")
        .expect("cancel isolated MCP session");
    result
}

fn assert_bounded_malformed_and_exhausted_sessions(fixture: &Qualification) {
    let holds = (0..4).map(|_| fixture.hold_session()).collect::<Vec<_>>();
    thread::sleep(Duration::from_millis(150));
    let rejected = bounded(
        fixture
            .caller_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--isolated", "--json", "account", "list"]),
    );
    assert_eq!(
        rejected.status.code(),
        Some(5),
        "a fifth session is rejected while four handshakes occupy the gateway"
    );
    drop(holds);
    thread::sleep(Duration::from_millis(100));
    fixture.malformed_frame();
    assert_eq!(
        listed_accounts(fixture)["ok"],
        true,
        "malformed IPC does not poison later sessions"
    );
}

async fn assert_mapped_grant_limits(fixture: &Qualification) {
    fixture.initialization_timeout();
    let first_broker = fixture.broker_peer();
    fixture.stop();
    fixture.wait_for_process_exit(first_broker.pid).await;
    set_grant_json_nesting(2);
    fixture.start();
    fixture.null_hello();
    fixture.account_hello_over_nesting_ceiling();
    let second_broker = fixture.broker_peer();
    fixture.stop();
    fixture.wait_for_process_exit(second_broker.pid).await;
    set_grant_json_nesting(12);
    fixture.start();
}

fn eventually_listed_accounts(fixture: &Qualification) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    loop {
        let output = bounded(
            fixture
                .caller_command(fixture.broker("mailctl").to_str().unwrap())
                .args(["--isolated", "--json", "account", "list"]),
        );
        if output.status.success() {
            return envelope(&output);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "restarted gateway did not accept an authorized caller before the readiness deadline: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn assert_wrong_service_peer_is_rejected(fixture: &Qualification) {
    let wrong_peer = fixture.start_wrong_peer();
    let output = bounded(
        fixture
            .caller_command(fixture.broker("mailctl").to_str().unwrap())
            .args(["--isolated", "--json", "account", "list"]),
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "client rejects an endpoint whose peer UID differs from the route service UID"
    );
    drop(wrong_peer);
    fixture.restore_after_wrong_peer();
    assert_eq!(
        listed_accounts(fixture)["ok"],
        true,
        "protected launchd endpoint recovers after substitution probe"
    );
}

fn envelope(output: &std::process::Output) -> Value {
    let text = std::str::from_utf8(&output.stdout).expect("UTF-8 JSON envelope");
    assert_eq!(text.lines().count(), 1, "one JSON envelope per CLI call");
    serde_json::from_str(text).expect("valid JSON envelope")
}
