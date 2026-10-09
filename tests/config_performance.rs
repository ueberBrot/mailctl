use mailctl::{
    config::{Config, MailboxScope},
    domain::Error,
};
use std::fmt::Write;

fn configuration() -> String {
    let state_dir =
        serde_json::to_string(&std::env::temp_dir().join("mailctl-config-performance")).unwrap();
    let mut input =
        format!("default_grant = 'reader'\nstate_dir = {state_dir}\n[limits]\naccounts = 256\n",);
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
fn config_parse_fast_path_rejects_unknown_fields_and_preserves_migration_guidance() {
    let input = configuration();
    for invalid in [
        format!("unknown_field = true\n{input}"),
        String::from("unknown_field = true\n"),
    ] {
        let error = Config::parse(&invalid).unwrap_err();
        assert_eq!(error.code, Error::setup_required().code);
        assert_eq!(error.message, Error::setup_required().message);
    }
    let legacy = input.replacen("[limits]\n", "[limits]\nruntime_slots = 1\n", 1);
    let error = Config::parse(&legacy).unwrap_err();
    assert_eq!(error.code, Error::obsolete_runtime_capacity().code);
    assert_eq!(error.message, Error::obsolete_runtime_capacity().message);
}

#[test]
fn scope_intersections_preserve_literal_names_and_normalize_only_inbox() {
    let scope =
        |names: &[&str]| MailboxScope::Only(names.iter().map(|name| (*name).to_owned()).collect());
    let pad = |scope: MailboxScope, prefix: &str| {
        let MailboxScope::Only(mut names) = scope else {
            panic!("explicit fixture scope");
        };
        names.extend((0..40).map(|index| format!("{prefix}-{index}")));
        MailboxScope::Only(names)
    };
    let left = pad(
        scope(&[
            "INBOX",
            "inbox",
            "iNbOx",
            "Archive",
            "archive",
            "Ärger",
            "Étage",
            "work/Sub",
            "sub",
            "InboxArchive",
            "ińbox",
            "箱",
        ]),
        "left-only",
    );
    let right = pad(
        scope(&[
            "iNBOX",
            "INBOX",
            "inbox",
            "Archive",
            "Ärger",
            "Étage",
            "work/Sub",
            "SUB",
            "InboxArchive",
            "INBÖX",
            "箱",
            "Other",
        ]),
        "right-only",
    );
    let expected = scope(&[
        "Archive",
        "INBOX",
        "InboxArchive",
        "work/Sub",
        "Ärger",
        "Étage",
        "箱",
    ]);
    assert_eq!(left.intersection(&right), expected);
    assert_eq!(right.intersection(&left), expected);
    assert_eq!(scope(&["inbox"]).intersection(&right), scope(&["INBOX"]));
    assert_eq!(right.intersection(&scope(&["inbox"])), scope(&["INBOX"]));
    let disjoint = MailboxScope::Only((0..12).map(|i| format!("other-{i}")).collect());
    assert_eq!(left.intersection(&disjoint), MailboxScope::Only(vec![]));
    assert_eq!(
        left.intersection(&MailboxScope::Only(vec![])),
        MailboxScope::Only(vec![])
    );
    assert_eq!(
        MailboxScope::All.intersection(&MailboxScope::All),
        MailboxScope::All
    );
    assert_eq!(
        MailboxScope::All.intersection(&left),
        left.intersection(&MailboxScope::All)
    );
}
