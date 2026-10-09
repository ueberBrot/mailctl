use mailctl::{config::Config, domain::Error};
use std::fmt::Write;

fn configuration() -> String {
    let state_dir =
        serde_json::to_string(&std::env::temp_dir().join("mailctl-config-performance")).unwrap();
    let mut input = format!(
        "version = 1\ndefault_grant = 'reader'\nstate_dir = {state_dir}\n[limits]\naccounts = 256\n",
    );
    for account in 0..256 {
        writeln!(input, "[[accounts]]\nkey = 'account-{account}'\nalias = 'account-{account}'\nserver = 'imap.example.test'\nusername = 'synthetic-{account}@example.test'\nfrom_identities = [").unwrap();
        for identity in 0..100 {
            writeln!(input, "'sender-{identity}@example.test',").unwrap();
        }
        input.push_str("]\n[accounts.credential]\nsource = 'session'\n");
    }
    input.push_str("[[grants]]\nname = 'reader'\naccounts = [");
    for account in 0..256 {
        write!(input, "'account-{account}',").unwrap();
    }
    input.push_str("]\n");
    input
}

#[test]
fn valid_config_parsing_stays_within_the_allocation_budget() {
    let input = configuration();
    let started = std::time::Instant::now();
    let mut config = None;
    let allocations = allocation_counter::measure(|| {
        config = Some(Config::parse(&input).unwrap());
    });
    eprintln!(
        "config bytes={}, elapsed={:?}, {allocations:?}",
        input.len(),
        started.elapsed()
    );
    let config = config.unwrap();
    assert_eq!(config.accounts.len(), 256);
    assert!(
        config
            .accounts
            .iter()
            .all(|account| account.from_identities.len() == 100)
    );
    assert!(
        allocations.bytes_total < 24 * input.len() as u64,
        "{allocations:?}"
    );
}

#[test]
fn config_parse_fast_path_preserves_version_and_migration_error_precedence() {
    let input = configuration();
    let future = input.replacen("version = 1", "version = 999", 1).replacen(
        "accounts = 256",
        "accounts = 0",
        1,
    );
    for future in [
        future,
        String::from("version = 999\nfuture_layout = true\n"),
    ] {
        let error = Config::parse(&future).unwrap_err();
        assert_eq!(error.code, Error::incompatible_schema().code);
        assert_eq!(error.message, Error::incompatible_schema().message);
    }
    let legacy = input.replacen("[limits]\n", "[limits]\nruntime_slots = 1\n", 1);
    let error = Config::parse(&legacy).unwrap_err();
    assert_eq!(error.code, Error::obsolete_runtime_capacity().code);
    assert_eq!(error.message, Error::obsolete_runtime_capacity().message);
}
