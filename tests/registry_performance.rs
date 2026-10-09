mod support;

use mailctl::{
    config::Config,
    domain::{Error, ErrorCode, Operation},
    policy::Narrowing,
    service::Service,
};
use serde_json::Value;
use std::{fs, path::PathBuf};

struct RegistryFixture {
    _installation: support::Installation,
    config: Config,
    path: PathBuf,
    registry: Value,
    bytes: Vec<u8>,
}

impl RegistryFixture {
    fn retained(generations: usize) -> Self {
        let installation = support::Installation::two_accounts();
        let config = Config::parse(&fs::read_to_string(installation.config()).unwrap()).unwrap();
        Service::setup(config.clone()).unwrap();
        let path = config.state_dir.join("accounts.json");
        let mut registry: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let rows = registry["accounts"]["work"]["generations"]
            .as_array_mut()
            .unwrap();
        let original = rows[0].clone();
        for generation in 2..=generations {
            let mut row = original.clone();
            row["generation"] = (generation as u64).into();
            rows.push(row);
        }
        let bytes = serde_json::to_vec(&registry).unwrap();
        fs::write(&path, &bytes).unwrap();
        Self {
            _installation: installation,
            config,
            path,
            registry,
            bytes,
        }
    }

    fn open(&self) -> Service {
        Service::open(self.config.clone()).unwrap()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn health(
    runtime: &tokio::runtime::Runtime,
    service: &Service,
    context: &mailctl::policy::RequestContext,
) -> Result<Value, Error> {
    runtime
        .block_on(service.execute(context, Operation::Health))
        .map(|result| serde_json::to_value(result).unwrap())
}

#[test]
fn unchanged_registry_checks_do_not_allocate_for_every_retained_generation() {
    let runtime = runtime();
    let fixture = RegistryFixture::retained(4096);
    let service = fixture.open();
    let context = service.context("default", &Narrowing::default()).unwrap();
    let expected = health(&runtime, &service, &context).unwrap();
    assert_eq!(expected["accounts"][0]["generation"], 4096);
    assert_eq!(expected["accounts"].as_array().unwrap().len(), 1);
    let mut result = None;
    let allocation = allocation_counter::measure(|| {
        result = Some(
            runtime
                .block_on(service.execute(&context, Operation::Health))
                .unwrap(),
        );
    });
    assert_eq!(serde_json::to_value(result.unwrap()).unwrap(), expected);
    eprintln!(
        "unchanged registry bytes={}, generations=4096, {allocation:?}",
        fixture.bytes.len()
    );
    assert!(
        allocation.bytes_total <= fixture.bytes.len() as u64 + 16 * 1024,
        "unchanged requests must only allocate the bounded file read and request output: {allocation:?}"
    );
    assert!(
        allocation.count_total <= 64,
        "unchanged requests must not deserialize each retained generation: {allocation:?}"
    );
}

#[test]
fn changed_registry_bytes_preserve_semantic_equality_and_corruption_errors() {
    const ACCOUNT_ID: &str = "12345678-9abc-4def-8123-456789abcdef";

    let runtime = runtime();
    let fixture = RegistryFixture::retained(3);
    let service = fixture.open();
    let context = service.context("default", &Narrowing::default()).unwrap();
    let expected = health(&runtime, &service, &context).unwrap();

    let equivalent = serde_json::to_vec_pretty(&fixture.registry).unwrap();
    assert_ne!(equivalent, fixture.bytes);
    fs::write(&fixture.path, &equivalent).unwrap();
    assert_eq!(health(&runtime, &service, &context).unwrap(), expected);

    for fault in [
        "historical_route",
        "future_layout",
        "invalid_json",
        "duplicate_identity",
        "uppercase_identity",
        "simple_identity",
        "duplicate_alternate_spelling",
        "generation_sequence",
        "unknown_field",
    ] {
        let mut registry = fixture.registry.clone();
        let expected_error = match fault {
            "historical_route" => {
                registry["accounts"]["work"]["generations"][0]["server"] =
                    "changed.example.test".into();
                Error::new(ErrorCode::OperationConflict)
            }
            "future_layout" => {
                registry = serde_json::json!({"future": {"layout": true}});
                Error::setup_required()
            }
            "duplicate_identity" => {
                registry["accounts"]["personal"]["account_id"] =
                    registry["accounts"]["work"]["account_id"].clone();
                Error::setup_required()
            }
            "uppercase_identity" => {
                registry["accounts"]["work"]["account_id"] = ACCOUNT_ID.to_ascii_uppercase().into();
                Error::setup_required()
            }
            "simple_identity" => {
                registry["accounts"]["work"]["account_id"] = ACCOUNT_ID.replace('-', "").into();
                Error::setup_required()
            }
            "duplicate_alternate_spelling" => {
                registry["accounts"]["work"]["account_id"] = ACCOUNT_ID.into();
                registry["accounts"]["personal"]["account_id"] =
                    ACCOUNT_ID.to_ascii_uppercase().into();
                Error::setup_required()
            }
            "generation_sequence" => {
                registry["accounts"]["work"]["generations"][1]["generation"] = 9.into();
                Error::setup_required()
            }
            "unknown_field" => {
                registry["unexpected"] = true.into();
                Error::setup_required()
            }
            "invalid_json" => Error::setup_required(),
            _ => unreachable!(),
        };
        let bytes = if fault == "invalid_json" {
            b"{corrupt".to_vec()
        } else {
            serde_json::to_vec(&registry).unwrap()
        };
        fs::write(&fixture.path, &bytes).unwrap();
        assert_eq!(
            health(&runtime, &service, &context).unwrap_err(),
            expected_error,
            "registry fault: {fault}"
        );
        assert_eq!(fs::read(&fixture.path).unwrap(), bytes);
    }

    fs::write(&fixture.path, &fixture.bytes).unwrap();
    assert_eq!(health(&runtime, &service, &context).unwrap(), expected);
}

#[test]
fn unchanged_registry_checks_still_require_a_present_bounded_file() {
    let runtime = runtime();
    let fixture = RegistryFixture::retained(1);
    let service = fixture.open();
    let context = service.context("default", &Narrowing::default()).unwrap();
    let expected = health(&runtime, &service, &context).unwrap();
    let moved = fixture.path.with_file_name("retained-registry.json");
    fs::rename(&fixture.path, &moved).unwrap();
    assert_eq!(
        health(&runtime, &service, &context).unwrap_err(),
        Error::setup_required()
    );
    fs::rename(&moved, &fixture.path).unwrap();

    // Trailing JSON whitespace keeps valid content while exceeding the file ceiling.
    let mut oversized = fixture.bytes.clone();
    oversized.resize(4 * 1024 * 1024 + 1, b' ');
    fs::write(&fixture.path, &oversized).unwrap();
    assert_eq!(
        health(&runtime, &service, &context).unwrap_err(),
        Error::setup_required()
    );
    fs::write(&fixture.path, &fixture.bytes).unwrap();
    assert_eq!(health(&runtime, &service, &context).unwrap(), expected);
}

#[cfg(unix)]
#[test]
fn unchanged_registry_bytes_still_require_private_unredirected_single_link_storage() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let runtime = runtime();
    let fixture = RegistryFixture::retained(1);
    let service = fixture.open();
    let context = service.context("default", &Narrowing::default()).unwrap();
    let expected = health(&runtime, &service, &context).unwrap();
    let moved = fixture.path.with_file_name("retained-registry.json");

    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        health(&runtime, &service, &context).unwrap_err(),
        Error::setup_required()
    );
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();

    fs::rename(&fixture.path, &moved).unwrap();
    symlink(&moved, &fixture.path).unwrap();
    assert_eq!(
        health(&runtime, &service, &context).unwrap_err(),
        Error::setup_required()
    );
    fs::remove_file(&fixture.path).unwrap();
    fs::rename(&moved, &fixture.path).unwrap();

    fs::hard_link(&fixture.path, &moved).unwrap();
    assert_eq!(
        health(&runtime, &service, &context).unwrap_err(),
        Error::setup_required()
    );
    fs::remove_file(&moved).unwrap();
    assert_eq!(health(&runtime, &service, &context).unwrap(), expected);
}
