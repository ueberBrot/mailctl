use mailctl::{
    config::Config,
    domain::{ListAccountsInput, Operation},
    policy::Narrowing,
    service::Service,
};

fn configuration() -> String {
    r#"version = 1
deployment = "cooperative"
topology = "native"
state_dir = "/tmp/mailctl-contract-state"
[[accounts]]
key = "primary"
alias = "work"
server = "imap.example.test"
username = "synthetic@example.test"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["primary"]
[accounts.credential]
source = "native"
[[accounts]]
key = "private"
alias = "personal"
server = "imap.example.test"
username = "private@example.test"
mailboxes = ["INBOX"]
from_identities = ["private"]
[accounts.credential]
source = "native"
[[listeners]]
name = "reader"
endpoint = "/tmp/mailctl-contract/reader.sock"
peer_uids = [1000]
accounts = ["primary"]
mailboxes = ["INBOX"]
"#
    .replace(
        "\"/tmp/mailctl-contract-state\"",
        &serde_json::to_string(&std::env::temp_dir().join("mailctl-contract-state")).unwrap(),
    )
    .replace(
        "\"/tmp/mailctl-contract/reader.sock\"",
        &serde_json::to_string(
            &std::env::temp_dir()
                .join("mailctl-contract")
                .join("reader.sock"),
        )
        .unwrap(),
    )
}

#[test]
fn discovery_filters_email_accounts_and_reports_completion() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let result = service
        .execute(
            &context,
            Operation::ListAccounts(ListAccountsInput::default()),
        )
        .unwrap();
    assert_eq!(result["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(result["accounts"][0]["alias"], "work");
    assert_eq!(result["accounts"][0]["generation"], 1);
    assert_eq!(result["complete"], true);
}

#[test]
fn narrowing_intersects_accounts_without_authorizing_an_unlisted_account() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service
        .context(
            "reader",
            &Narrowing {
                read_only: true,
                accounts: Some(vec!["personal".into()]),
            },
        )
        .unwrap();
    let result = service
        .execute(
            &context,
            Operation::ListAccounts(ListAccountsInput::default()),
        )
        .unwrap();
    assert_eq!(result["accounts"], serde_json::json!([]));
    assert_eq!(result["complete"], true);
    assert_eq!(
        service.execute(&context, Operation::Health).unwrap()["accounts"],
        serde_json::json!([])
    );
}

#[test]
fn read_only_narrowing_of_drafts_only_retains_discovery_without_email_reads() {
    let input = configuration()
        .replace(
            "from_identities = [\"primary\"]",
            "from_identities = [\"primary\"]\ndrafts_mailbox = \"Drafts\"",
        )
        .replace(
            "name = \"reader\"",
            "name = \"reader\"\nprofile = \"drafts_only\"",
        );
    let mut config = Config::parse(&input.replace(
        "accounts = [\"primary\"]\nmailboxes = [\"INBOX\"]",
        "accounts = [\"primary\"]\nmailboxes = [\"INBOX\", \"Drafts\"]",
    ))
    .unwrap();
    config.listeners[0].profile = mailctl::policy::Profile::DraftsOnly;
    let service = Service::in_memory(config).unwrap();
    let context = service
        .context(
            "reader",
            &Narrowing {
                read_only: true,
                accounts: None,
            },
        )
        .unwrap();
    let narrowed = service.execute(&context, Operation::Capabilities).unwrap();
    assert_eq!(
        narrowed["permissions"],
        serde_json::json!(["list_accounts"])
    );
    let full = service.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        service.execute(&full, Operation::Capabilities).unwrap()["permissions"],
        serde_json::json!(["list_accounts", "append_draft", "inspect_draft_operation"])
    );
}

#[test]
fn bounded_discovery_distinguishes_partial_and_complete_inventory() {
    let input = configuration().replace(
        "accounts = [\"primary\"]",
        "accounts = [\"primary\", \"private\"]",
    );
    let service = Service::in_memory(Config::parse(&input).unwrap()).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let page = service
        .execute(
            &context,
            Operation::ListAccounts(ListAccountsInput { limit: Some(1) }),
        )
        .unwrap();
    assert_eq!(page["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(page["complete"], false);
    let inventory = service
        .execute(
            &context,
            Operation::ListAccounts(ListAccountsInput { limit: Some(2) }),
        )
        .unwrap();
    assert_eq!(inventory["accounts"].as_array().unwrap().len(), 2);
    assert_eq!(inventory["complete"], true);
    for limit in [0, 33] {
        assert_eq!(
            service
                .execute(
                    &context,
                    Operation::ListAccounts(ListAccountsInput { limit: Some(limit) })
                )
                .unwrap_err()
                .code,
            mailctl::domain::ErrorCode::InvalidRequest
        );
    }
}

#[test]
fn discovery_and_health_exclude_private_routing_and_authentication_claims() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    for operation in [
        Operation::ListAccounts(ListAccountsInput::default()),
        Operation::Health,
    ] {
        let result = service.execute(&context, operation).unwrap();
        let serialized = result.to_string();
        for private in [
            "imap.example.test",
            "synthetic@example.test",
            "private@example.test",
            "username",
            "credential",
            "authenticated",
        ] {
            assert!(!serialized.contains(private));
        }
        assert_eq!(result["accounts"][0]["availability"], "unknown");
    }
}

#[test]
fn configuration_rejects_unknown_fields_versions_and_unsafe_values() {
    for (old, new) in [
        ("version = 1", "version = 2"),
        ("version = 1", "version = 1\nunknown = true"),
        (
            "source = \"native\"",
            "source = \"native\"\npassword = \"fixture-secret\"",
        ),
        ("source = \"native\"", "source = \"environment\""),
        (
            "server = \"imap.example.test\"",
            "server = \"https://user:secret@example.test\"",
        ),
        ("username = \"synthetic@example.test\"", "username = \"\""),
        (
            "name = \"reader\"",
            "name = \"reader\"\nprofile = \"admin\"",
        ),
        ("peer_uids = [1000]", "peer_uids = []"),
        ("accounts = [\"primary\"]", "accounts = [\"absent\"]"),
        (
            "name = \"reader\"",
            "name = \"reader\"\nprofile = \"drafts_only\"",
        ),
        (
            "server = \"imap.example.test\"",
            "server = \"imap.example.test\"\ntls = \"plaintext\"",
        ),
    ] {
        assert!(
            Config::parse(&configuration().replace(old, new)).is_err(),
            "accepted {new}"
        );
    }
}

#[test]
fn resource_ceilings_apply_to_global_and_listener_limits() {
    let base = configuration();
    for fragment in [
        "accounts = 257",
        "json_nesting = 65",
        "ipc_frame_bytes = 67108865",
        "handshakes = 33",
        "clients = 129",
        "active_requests = 65",
        "queued_requests = 257",
        "buffered_bytes = 268435457",
        "operation_seconds = 121",
        "handshake_seconds = 11",
        "accounts = 0",
        "ipc_frame_bytes = 33554432\nbuffered_bytes = 67108864",
    ] {
        // Insert only one global limits table before the first email account.
        let input = base.replacen(
            "[[accounts]]",
            &format!("[limits]\n{fragment}\n[[accounts]]"),
            1,
        );
        assert!(Config::parse(&input).is_err(), "accepted {fragment}");
    }
    assert!(Config::parse(&(base.clone() + "\n[listeners.limits]\naccounts = 33\n")).is_err());
    let valid = Config::parse(&(base + "\n[listeners.limits]\naccounts = 1\n")).unwrap();
    let service = Service::in_memory(valid).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    assert!(
        service
            .execute(
                &context,
                Operation::ListAccounts(ListAccountsInput { limit: Some(2) })
            )
            .is_err()
    );
}

#[test]
fn contexts_cannot_cross_broker_restarts_or_instances() {
    let first = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let second = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = first.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        second
            .execute(&context, Operation::Capabilities)
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::PermissionDenied
    );
}

#[test]
fn persisted_account_identity_survives_alias_change_and_tracks_repointing() {
    let directory = std::env::temp_dir().join(format!("mailctl-contract-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let discover = |input: &str| {
        let mut config = Config::parse(input).unwrap();
        config.state_dir = directory.clone();
        let service = Service::open(config).unwrap();
        let context = service.context("reader", &Narrowing::default()).unwrap();
        service
            .execute(
                &context,
                Operation::ListAccounts(ListAccountsInput::default()),
            )
            .unwrap()["accounts"][0]
            .clone()
    };
    let before = discover(&configuration());
    let renamed = discover(&configuration().replace("alias = \"work\"", "alias = \"renamed\""));
    assert_eq!(before["account_id"], renamed["account_id"]);
    assert_eq!(renamed["alias"], "renamed");
    assert_eq!(renamed["generation"], 1);
    let repointed =
        discover(&configuration().replace("synthetic@example.test", "changed@example.test"));
    assert_eq!(before["account_id"], repointed["account_id"]);
    assert_eq!(repointed["generation"], 2);
    let restored = discover(&configuration());
    assert_eq!(before["account_id"], restored["account_id"]);
    assert_eq!(restored["generation"], 3);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn operation_schemas_reject_forged_authority_and_unknown_inputs() {
    for input in [
        r#"{"operation":"list_accounts","input":{"profile":"read_and_drafts"}}"#,
        r#"{"operation":"capabilities","input":{"read_only":false}}"#,
        r#"{"operation":"health","harness":"admin"}"#,
        r#"{"operation":"list_accounts","input":{"limit":-1}}"#,
    ] {
        assert!(
            serde_json::from_str::<Operation>(input).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn configuration_checks_every_resource_maximum() {
    let maxima = [
        ("ipc_frame_bytes", 67108864),
        ("json_nesting", 64),
        ("search_page", 200),
        ("search_uid_window", 10000),
        ("search_windows", 100),
        ("mailbox_page", 1000),
        ("mailbox_inventory", 1000),
        ("text_page_bytes", 2097152),
        ("wire_fetch_bytes", 8388608),
        ("header_bytes", 262144),
        ("mime_depth", 40),
        ("mime_parts", 1000),
        ("attachment_decoded_bytes", 33554432),
        ("attachment_wire_bytes", 67108864),
        ("attachment_chunk_bytes", 262144),
        ("transfer_seconds", 600),
        ("transfers_per_account", 4),
        ("token_bytes", 8192),
        ("draft_mime_bytes", 8388608),
        ("operation_seconds", 120),
        ("connection_seconds", 30),
        ("account_connections", 4),
        ("account_pending_requests", 64),
        ("secret_bytes", 65536),
        ("command_stderr_bytes", 32768),
        ("secret_command_seconds", 60),
        ("journal_records", 1000000),
        ("accounts", 256),
        ("listeners", 32),
        ("clients", 128),
        ("handshakes", 32),
        ("handshake_seconds", 10),
        ("active_requests", 64),
        ("queued_requests", 256),
        ("buffered_bytes", 268435456),
        ("credential_workers", 8),
        ("queued_credentials", 32),
        ("connection_lifetime_seconds", 900),
    ];
    let limits: String = maxima
        .iter()
        .map(|(name, max)| format!("{name} = {max}\n"))
        .collect();
    let input = configuration().replacen(
        "[[accounts]]",
        &format!("[limits]\n{limits}[[accounts]]"),
        1,
    );
    assert!(Config::parse(&input).is_ok());
    for (name, max) in maxima {
        let invalid = input.replace(
            &format!("{name} = {max}\n"),
            &format!("{name} = {}\n", max + 1),
        );
        assert!(
            Config::parse(&invalid).is_err(),
            "accepted above maximum {name}"
        );
    }
}

#[test]
fn private_account_history_fails_closed_on_corruption() {
    let directory = std::env::temp_dir().join(format!("mailctl-history-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = Config::parse(&configuration()).unwrap();
    config.state_dir = directory.clone();
    Service::open(config.clone()).unwrap();
    std::fs::write(directory.join("accounts.json"), b"{corrupt").unwrap();
    assert!(Service::open(config).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn capabilities_include_the_same_grant_filtered_safe_health_as_doctor() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let capabilities = service.execute(&context, Operation::Capabilities).unwrap();
    let health = service.execute(&context, Operation::Health).unwrap();
    assert_eq!(capabilities["health"], health);
    assert_eq!(
        capabilities["health"]["accounts"].as_array().unwrap().len(),
        1
    );
}
