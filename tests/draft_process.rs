#![cfg(feature = "cli")]
mod support;
use support::{Installation, assert_success, envelope, run_bounded};

#[test]
fn status_requires_original_identity_and_read_only_cannot_inspect_history() {
    let installation = Installation::two_accounts();
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
    let mut command = installation.cli();
    command.args(["--json", "account", "list"]);
    let discovery = envelope(&run_bounded(command));
    let id = discovery["result"]["accounts"][0]["account_id"]
        .as_str()
        .unwrap();
    let op = uuid::Uuid::new_v4().to_string();
    let args = [
        "--json",
        "draft",
        "status",
        "--mailbox",
        "Drafts",
        "--account-id",
        id,
        "--account-generation",
        "1",
        "--operation-id",
        &op,
    ];
    let mut command = installation.cli();
    command.args(args);
    let output = run_bounded(command);
    assert_eq!(envelope(&output)["error"]["code"], "permission_denied");
    let mut command = installation.cli();
    command.args(["--grant", "writer"]).args(args);
    let output = run_bounded(command);
    assert_eq!(envelope(&output)["error"]["code"], "operation_not_found");
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn writer_owner_child() {
    let Some(path) = std::env::var_os("MAILCTL_WRITER_FIXTURE") else {
        return;
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.lock().unwrap();
    std::fs::write(std::env::var_os("MAILCTL_WRITER_READY").unwrap(), b"ready").unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[tokio::test]
async fn status_ignores_live_writer_and_process_death_releases_ownership() {
    use mailctl::{
        config::Config,
        domain::{Operation, OperationResult},
        service::{MemoryDraftTargets, Service},
    };
    use serde_json::json;
    let installation = Installation::two_accounts();
    let text = std::fs::read_to_string(installation.config())
        .unwrap()
        .replace(
            "from_identities = [\"work\"]",
            "from_identities = [\"work@example.test\"]",
        );
    let mut config = Config::parse(&text).unwrap();
    config.limits.initialization_seconds = 1;
    for grant in &mut config.grants {
        grant.limits.initialization_seconds = 1;
    }
    std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    Service::setup(config.clone()).unwrap();
    let targets = std::sync::Arc::new(MemoryDraftTargets::default());
    targets.set("work", "Drafts", 77);
    let service = Service::open(config.clone())
        .unwrap()
        .with_draft_targets(targets);
    let context = service.context("writer", &Default::default()).unwrap();
    let OperationResult::Accounts(accounts) = service
        .execute(&context, Operation::ListAccounts(Default::default()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let id = &accounts.accounts[0].account_id;
    let op = uuid::Uuid::new_v4().to_string();
    let request = json!({"operation":"save_draft", "input":{"mailbox":"Drafts", "account_id":id, "account_generation":1, "operation_id":op, "draft":{}}});
    let result = serde_json::to_value(
        service
            .execute(&context, serde_json::from_value(request).unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    drop(service);
    let ready = installation.config().with_file_name("writer-ready");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "writer_owner_child", "--nocapture"])
        .env(
            "MAILCTL_WRITER_FIXTURE",
            config.state_dir.join(format!("draft-{id}.lock")),
        )
        .env("MAILCTL_WRITER_READY", &ready)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("writer fixture did not acquire ownership");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let identity = [
        "--mailbox",
        "Drafts",
        "--account-id",
        id,
        "--account-generation",
        "1",
        "--operation-id",
        &op,
    ];
    let mut command = installation.cli();
    command
        .args(["--json", "--grant", "writer", "draft", "status"])
        .args(identity);
    let status = run_bounded(command);
    let composition = installation.config().with_file_name("draft.json");
    std::fs::write(&composition, "{}").unwrap();
    let save = || {
        let mut c = installation.cli();
        c.args(["--json", "--grant", "writer", "draft", "save"])
            .args(identity)
            .arg("--input")
            .arg(&composition);
        c
    };
    let busy = run_bounded(save());
    child.kill().unwrap();
    child.wait().unwrap();
    assert_success(&status);
    assert_eq!(envelope(&status)["result"], result);
    assert_eq!(envelope(&busy)["error"]["code"], "rate_limited");
    let retry = run_bounded(save());
    assert_success(&retry);
    assert_eq!(envelope(&retry)["result"], result);
}

#[test]
fn composition_file_obeys_the_selected_grant_envelope_before_provider_work() {
    let installation = Installation::two_accounts();
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
    let mut command = installation.cli();
    command.args(["--json", "account", "list"]);
    let accounts = envelope(&run_bounded(command));
    let id = accounts["result"]["accounts"][0]["account_id"]
        .as_str()
        .unwrap();
    let mut config =
        mailctl::config::Config::parse(&std::fs::read_to_string(installation.config()).unwrap())
            .unwrap();
    config
        .grants
        .iter_mut()
        .find(|g| g.name == "writer")
        .unwrap()
        .limits
        .envelope_bytes = 1024;
    std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    let mut command = installation.cli();
    command.args(["--json", "setup"]);
    assert_success(&run_bounded(command));
    let file = installation.config().with_file_name("bounded-input.json");
    std::fs::write(
        &file,
        serde_json::to_vec(&serde_json::json!({"body":"x".repeat(1024)})).unwrap(),
    )
    .unwrap();
    let mut command = installation.cli();
    command
        .args([
            "--json",
            "--grant",
            "writer",
            "draft",
            "save",
            "--mailbox",
            "Drafts",
            "--account-id",
            id,
            "--account-generation",
            "1",
            "--operation-id",
            &uuid::Uuid::new_v4().to_string(),
            "--input",
        ])
        .arg(file);
    let output = run_bounded(command);
    assert_eq!(envelope(&output)["error"]["code"], "response_too_large");
}
