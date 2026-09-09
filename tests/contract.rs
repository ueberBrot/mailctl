use mailctl::{
    config::Config,
    domain::{Error, ListAccountsInput, Operation},
    policy::{Narrowing, RequestContext},
    service::Service,
};

fn execute(
    service: &Service,
    context: &RequestContext,
    operation: Operation,
) -> Result<serde_json::Value, Error> {
    service
        .execute(context, operation)
        .map(|result| serde_json::to_value(result).unwrap())
}

fn configuration() -> String {
    r#"version = 1
default_grant = "reader"
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
[[grants]]
name = "reader"
accounts = ["primary"]
mailboxes = ["INBOX"]
"#
    .replace(
        "\"/tmp/mailctl-contract-state\"",
        &serde_json::to_string(&std::env::temp_dir().join("mailctl-contract-state")).unwrap(),
    )
}

#[test]
fn discovery_filters_email_accounts_and_reports_completion() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let result = execute(
        &service,
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
    let result = execute(
        &service,
        &context,
        Operation::ListAccounts(ListAccountsInput::default()),
    )
    .unwrap();
    assert_eq!(result["accounts"], serde_json::json!([]));
    assert_eq!(result["complete"], true);
    assert_eq!(
        execute(&service, &context, Operation::Health).unwrap()["accounts"],
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
    let input = input.replace("default_grant = \"reader\"", "default_grant = \"default\"")
        + "\n[[grants]]\nname = \"default\"\naccounts = [\"primary\"]\nmailboxes = [\"INBOX\"]\n";
    let mut config = Config::parse(&input.replace(
        "accounts = [\"primary\"]\nmailboxes = [\"INBOX\"]",
        "accounts = [\"primary\"]\nmailboxes = [\"INBOX\", \"Drafts\"]",
    ))
    .unwrap();
    config.grants[0].profile = mailctl::policy::Profile::DraftsOnly;
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
    let narrowed = execute(&service, &context, Operation::Capabilities).unwrap();
    assert_eq!(
        narrowed["permissions"],
        serde_json::json!(["list_accounts"])
    );
    let full = service.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        execute(&service, &full, Operation::Capabilities).unwrap()["permissions"],
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
    let page = execute(
        &service,
        &context,
        Operation::ListAccounts(ListAccountsInput { limit: Some(1) }),
    )
    .unwrap();
    assert_eq!(page["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(page["complete"], false);
    let inventory = execute(
        &service,
        &context,
        Operation::ListAccounts(ListAccountsInput { limit: Some(2) }),
    )
    .unwrap();
    assert_eq!(inventory["accounts"].as_array().unwrap().len(), 2);
    assert_eq!(inventory["complete"], true);
    for limit in [0, 33] {
        assert_eq!(
            execute(
                &service,
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
        let result = execute(&service, &context, operation).unwrap();
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
        (
            "name = \"reader\"",
            "name = \"reader\"\nendpoint = \"/tmp/legacy.sock\"",
        ),
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
fn resource_ceilings_apply_to_global_and_grant_limits() {
    let base = configuration();
    for fragment in [
        "accounts = 257",
        "json_nesting = 65",
        "envelope_bytes = 67108865",
        "runtimes = 33",
        "initialization_seconds = 11",
        "active_requests = 65",
        "queued_requests = 257",
        "buffered_bytes = 268435457",
        "operation_seconds = 121",
        "initialization_seconds = 11",
        "accounts = 0",
        "envelope_bytes = 33554432\nbuffered_bytes = 67108864",
    ] {
        // Insert only one global limits table before the first email account.
        let input = base.replacen(
            "[[accounts]]",
            &format!("[limits]\n{fragment}\n[[accounts]]"),
            1,
        );
        assert!(Config::parse(&input).is_err(), "accepted {fragment}");
    }
    assert!(Config::parse(&(base.clone() + "\n[grants.limits]\naccounts = 33\n")).is_err());
    let valid = Config::parse(&(base + "\n[grants.limits]\naccounts = 1\n")).unwrap();
    let service = Service::in_memory(valid).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    assert!(
        execute(
            &service,
            &context,
            Operation::ListAccounts(ListAccountsInput { limit: Some(2) })
        )
        .is_err()
    );
}

#[test]
fn contexts_cannot_cross_embedded_runtime_instances() {
    let first = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let second = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = first.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        execute(&second, &context, Operation::Capabilities)
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::PermissionDenied
    );
}

#[test]
fn persisted_account_identity_survives_alias_change_and_tracks_repointing() {
    let directory = std::env::temp_dir().join(format!("mailctl-contract-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let discover = |input: &str| {
        let mut config = Config::parse(input).unwrap();
        config.state_dir = directory.clone();
        Service::setup(config.clone()).unwrap();
        let service = Service::open(config).unwrap();
        let context = service.context("reader", &Narrowing::default()).unwrap();
        execute(
            &service,
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
        ("envelope_bytes", 67108864),
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
        ("grants", 32),
        ("initialization_seconds", 10),
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
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = Config::parse(&configuration()).unwrap();
    config.state_dir = directory.clone();
    let service = Service::open(config.clone()).unwrap();
    let foreign = Service::in_memory(config.clone()).unwrap();
    let context = foreign.context("reader", &Narrowing::default()).unwrap();
    std::fs::write(directory.join("accounts.json"), b"{corrupt").unwrap();
    assert_eq!(
        service
            .execute(&context, Operation::Health)
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::PermissionDenied
    );
    drop(service);
    assert!(Service::open(config).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn unchanged_configuration_rejects_missing_account_history() {
    let directory = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("mailctl-history-{}", uuid::Uuid::new_v4()));
    let mut config = Config::parse(&configuration()).unwrap();
    config.state_dir = directory.clone();
    Service::setup(config.clone()).unwrap();
    let registry_path = config.state_dir.join("accounts.json");
    let mut registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
    registry["accounts"]
        .as_object_mut()
        .unwrap()
        .remove(&config.accounts[0].key);
    let corrupted = serde_json::to_vec(&registry).unwrap();
    std::fs::write(&registry_path, &corrupted).unwrap();

    assert!(Service::open(config.clone()).is_err());
    let mut updated = false;
    assert!(
        Service::maintain(config, || {
            updated = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!updated);
    assert_eq!(std::fs::read(&registry_path).unwrap(), corrupted);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn capabilities_include_the_same_grant_filtered_safe_health_as_doctor() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let capabilities = execute(&service, &context, Operation::Capabilities).unwrap();
    let health = execute(&service, &context, Operation::Health).unwrap();
    assert_eq!(capabilities["health"], health);
    assert_eq!(
        capabilities["health"]["accounts"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn repeated_grant_account_keys_do_not_inflate_health_response_budgets() {
    let mut config = Config::parse(&configuration()).unwrap();
    config.grants[0].accounts = vec!["primary".into(); config.limits.accounts];
    let service = Service::in_memory(config).unwrap();
    for narrowing in [
        Narrowing::default(),
        Narrowing {
            accounts: Some(vec!["work".into(), "work".into(), "personal".into()]),
            ..Default::default()
        },
    ] {
        let context = service
            .context("reader", &narrowing)
            .unwrap()
            .with_response_limit(2048);
        let health = execute(&service, &context, Operation::Health).unwrap();
        assert_eq!(health["accounts"].as_array().unwrap().len(), 1);
        let capabilities = execute(&service, &context, Operation::Capabilities).unwrap();
        assert_eq!(capabilities["health"], health);
        let discovery = execute(
            &service,
            &context,
            Operation::ListAccounts(ListAccountsInput::default()),
        )
        .unwrap();
        assert_eq!(discovery["accounts"].as_array().unwrap().len(), 1);
        assert_eq!(discovery["accounts"][0]["alias"], "work");
        assert_eq!(discovery["complete"], true);
    }
}

#[test]
fn concurrent_processes_share_maintenance_leases_and_exclude_setup_until_they_are_dropped() {
    let directory =
        std::env::temp_dir().join(format!("mailctl-exclusive-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = Config::parse(&configuration()).unwrap();
    config.state_dir = directory.clone();
    let first = Service::open(config.clone()).unwrap();
    // Equivalent path spellings must keep the same revision and shared lease.
    let mut equivalent = config.clone();
    equivalent.state_dir = directory.join(".");
    let second = Service::open(equivalent).unwrap();
    assert_eq!(
        Service::setup(config.clone()).unwrap_err().code,
        mailctl::domain::ErrorCode::RateLimited
    );
    let first_context = first.context("reader", &Narrowing::default()).unwrap();
    let second_context = second.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        execute(&first, &first_context, Operation::Health).unwrap(),
        execute(&second, &second_context, Operation::Health).unwrap()
    );
    drop(first);
    drop(second);
    assert!(Service::setup(config).is_ok());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn narrowing_rejects_oversized_scopes_while_deserializing() {
    let at_limit = serde_json::json!({"accounts":vec!["x";256]});
    assert!(serde_json::from_value::<Narrowing>(at_limit).is_ok());
    // The excess element is rejected before its invalid nested payload is parsed.
    let prefix = format!(r#"{{"accounts":[{},"#, vec![r#""x""#; 256].join(","));
    let error = serde_json::from_str::<Narrowing>(&(prefix + "[not-json")).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("account scope exceeds its bound")
    );
    assert!(
        serde_json::from_value::<Narrowing>(serde_json::json!({"accounts":["x".repeat(1024)]}))
            .is_ok()
    );
    assert!(
        serde_json::from_value::<Narrowing>(serde_json::json!({"accounts":["x".repeat(1025)]}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<Narrowing>(serde_json::json!({"accounts":["é".repeat(513)]}))
            .is_err()
    );
}

#[test]
fn wire_envelopes_reject_invalid_discriminators_and_mixed_outcomes() {
    use mailctl::domain::{AccountDiscovery, Envelope};
    for text in [
        r#"{"schema_version":2,"request_id":"one","ok":true,"result":{"accounts":[],"complete":true}}"#,
        r#"{"schema_version":1,"request_id":"one","ok":false,"result":{"accounts":[],"complete":true}}"#,
        r#"{"schema_version":1,"request_id":"one","ok":true,"result":{"accounts":[],"complete":true},"error":{"code":"invalid_request","message":"Invalid request","retryable":false}}"#,
        r#"{"schema_version":1,"request_id":"one","ok":true}"#,
    ] {
        assert!(
            serde_json::from_str::<Envelope<AccountDiscovery>>(text).is_err(),
            "accepted {text}"
        );
    }
}

#[test]
fn default_selection_is_read_only_and_legacy_transport_configuration_is_rejected() {
    let input = configuration()
        .replace("default_grant = \"reader\"\n", "")
        .replace("name = \"reader\"", "name = \"default\"");
    let config = Config::parse(&input).unwrap();
    assert_eq!(config.default_grant, "default");
    for legacy in [
        "deployment = \"isolated\"",
        "deployment = \"cooperative\"",
        "listeners = []",
        "endpoint = \"/tmp/legacy.sock\"",
    ] {
        let error = Config::parse(&format!("{legacy}\n{input}")).unwrap_err();
        assert_eq!(error.code, mailctl::domain::ErrorCode::InvalidRequest);
        assert!(error.message.contains("setup subcommand"));
    }
    assert!(Config::parse(&input.replace("name = \"default\"", "name = \"other\"")).is_err());
    assert!(
        Config::parse(&input.replace(
            "name = \"default\"",
            "name = \"default\"\nprofile = \"drafts_only\""
        ))
        .is_err()
    );
}

#[test]
fn capabilities_publish_only_effective_per_process_limits() {
    let mut config = Config::parse(&configuration()).unwrap();
    config.grants[0].limits.active_requests = 2;
    config.grants[0].limits.queued_requests = 3;
    let service = Service::in_memory(config).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    let capacity =
        execute(&service, &context, Operation::Capabilities).unwrap()["capacity"].clone();
    assert_eq!(capacity["per_process"]["active_requests"], 2);
    assert_eq!(capacity["per_process"]["queued_requests"], 3);
    assert_eq!(capacity["per_process"]["buffered_bytes"], 64 * 1024 * 1024);
    assert_eq!(capacity.as_object().unwrap().len(), 1);
}

#[test]
fn obsolete_shared_runtime_capacity_settings_explain_the_migration() {
    let input = configuration();
    let settings = [
        format!("[limits]\nruntimes = 1\n{input}"),
        format!("{input}\n[grants.limits]\nruntime_slots = 1\n"),
        format!("{input}\n[grants.limits]\nshared_permits = 1\n"),
    ];
    for setting in settings {
        let error = Config::parse(&setting).unwrap_err();
        assert_eq!(error.code, mailctl::domain::ErrorCode::InvalidRequest);
        assert!(error.message.contains("per process"));
        assert!(error.message.contains("setup subcommand"));
    }
}

#[test]
fn maintenance_transaction_is_bounded_by_active_process_leases() {
    let directory =
        std::env::temp_dir().join(format!("mailctl-maintenance-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = Config::parse(&configuration()).unwrap();
    config.state_dir = directory.clone();
    let account_count = config.accounts.len();
    Service::setup(config.clone()).unwrap();
    let service = Service::open(config.clone()).unwrap();
    assert_eq!(
        Service::maintain(config.clone(), || Ok(()))
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::RateLimited
    );
    drop(service);
    let (setup, updated) = Service::maintain(config, || Ok("written")).unwrap();
    assert_eq!(updated, "written");
    assert_eq!(setup.accounts, account_count);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn checked_open_does_not_restore_a_stale_configuration_revision() {
    let directory =
        std::env::temp_dir().join(format!("mailctl-checked-open-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut stale = Config::parse(&configuration()).unwrap();
    stale.state_dir = directory.clone();
    let mut current = stale.clone();
    current.accounts[0].alias = "renamed".into();
    Service::setup(current.clone()).unwrap();
    let error = match Service::open_checked(stale, || {
        Err(Error::new(mailctl::domain::ErrorCode::OperationConflict))
    }) {
        Ok(_) => panic!("accepted a stale configuration"),
        Err(error) => error,
    };
    assert_eq!(error.code, mailctl::domain::ErrorCode::OperationConflict);
    let service = Service::open(current).unwrap();
    let context = service.context("reader", &Narrowing::default()).unwrap();
    assert_eq!(
        execute(
            &service,
            &context,
            Operation::ListAccounts(ListAccountsInput::default())
        )
        .unwrap()["accounts"][0]["alias"],
        "renamed"
    );
    drop(service);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn initialization_marker_is_checked_before_reconciling_a_changed_configuration() {
    let directory = std::env::temp_dir().join(format!("mailctl-marker-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut original = Config::parse(&configuration()).unwrap();
    original.state_dir = directory.clone();
    Service::setup(original.clone()).unwrap();
    let before = std::fs::read(directory.join("accounts.json")).unwrap();
    std::fs::write(
        directory.join("initialization.lock"),
        b"foreign-installation",
    )
    .unwrap();
    let mut changed = original;
    changed.accounts[0].alias = "renamed".into();
    assert!(Service::open(changed.clone()).is_err());
    let mut updated = false;
    assert!(
        Service::maintain(changed, || {
            updated = true;
            Ok(())
        })
        .is_err()
    );
    assert!(
        !updated,
        "invalid installation must not update configuration"
    );
    assert_eq!(
        std::fs::read(directory.join("accounts.json")).unwrap(),
        before
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn maintenance_checks_registry_capacity_before_updating_configuration() {
    let directory = std::env::temp_dir().join(format!("mailctl-capacity-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = Config::parse(&configuration()).unwrap();
    config.state_dir = directory.clone();
    config.accounts[0].retain_history = true;
    Service::setup(config.clone()).unwrap();

    let registry_path = directory.join("accounts.json");
    let mut registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
    let mut size = serde_json::to_vec(&registry).unwrap().len();
    let generations = registry["accounts"][&config.accounts[0].key]["generations"]
        .as_array_mut()
        .unwrap();
    let template = generations[0].clone();
    loop {
        let mut generation = template.clone();
        generation["generation"] = (generations.len() + 1).into();
        let additional = serde_json::to_vec(&generation).unwrap().len() + 1;
        if size + additional > 4 * 1024 * 1024 {
            break;
        }
        generations.push(generation);
        size += additional;
    }
    let before = serde_json::to_vec(&registry).unwrap();
    assert_eq!(before.len(), size);
    std::fs::write(&registry_path, &before).unwrap();

    config.accounts[0].server = "replacement.example.test".into();
    let mut updated = false;
    let error = Service::maintain(config, || {
        updated = true;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.code, mailctl::domain::ErrorCode::InvalidRequest);
    assert!(!updated);
    assert_eq!(std::fs::read(&registry_path).unwrap(), before);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn response_narrowing_rejects_large_results_and_cannot_be_widened() {
    let service = Service::in_memory(Config::parse(&configuration()).unwrap()).unwrap();
    let context = service
        .context("reader", &Narrowing::default())
        .unwrap()
        .with_response_limit(512)
        .with_response_limit(16 * 1024 * 1024);
    for operation in [
        Operation::ListAccounts(ListAccountsInput::default()),
        Operation::Capabilities,
        Operation::Health,
    ] {
        assert_eq!(
            service.execute(&context, operation).unwrap_err().code,
            mailctl::domain::ErrorCode::ResponseTooLarge
        );
    }
}

#[test]
fn configuration_serialization_is_independent_of_toml_spacing() {
    let input = configuration();
    let first = Config::parse(&input).unwrap();
    let second = Config::parse(&input.replace(" = ", "=")).unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
}
