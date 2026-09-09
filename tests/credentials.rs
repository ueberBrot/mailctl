use mailctl::{
    config::CredentialSource,
    credentials::{Availability, Secret, SourceError, source_for},
};
use uuid::Uuid;

#[test]
fn authentication_secrets_reject_empty_oversized_and_invalid_utf8_values() {
    for value in [vec![], vec![b'x'; 65_537], vec![0xff]] {
        assert_eq!(Secret::new(value).unwrap_err(), SourceError::InvalidSecret);
    }
    assert_eq!(Secret::new(vec![b'x'; 65_536]).unwrap().len(), 65_536);
    assert_eq!(
        Secret::new("  pässword\r\n".as_bytes().to_vec())
            .unwrap()
            .len(),
        13
    );
}

#[test]
fn formatting_an_owned_secret_never_discloses_its_value() {
    let secret = Secret::new(b"fixture-password-never-print".to_vec()).unwrap();
    assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    assert_eq!(format!("{secret:#?}"), "Secret([REDACTED])");
}

#[test]
fn unattended_session_sources_require_interaction_without_a_mutable_store() {
    let source = source_for(&CredentialSource::Session {});
    let account = Uuid::new_v4();
    assert_eq!(
        source.availability(account),
        Availability::InteractionRequired
    );
    assert_eq!(
        source.resolve(account).unwrap_err(),
        SourceError::InteractionRequired
    );
    assert!(source.mutable_store().is_none());
}

#[test]
fn deferred_external_sources_never_execute_helpers_or_open_credential_files() {
    for configuration in [
        CredentialSource::Systemd {
            path: std::env::temp_dir().join("unprovisioned-secret"),
        },
        CredentialSource::Command {
            executable: std::env::temp_dir().join("unprovisioned-helper"),
            args: vec![],
            working_dir: std::env::temp_dir(),
        },
    ] {
        let source = source_for(&configuration);
        let account = Uuid::new_v4();
        assert_eq!(source.availability(account), Availability::Unavailable);
        assert_eq!(
            source.resolve(account).unwrap_err(),
            SourceError::Unavailable
        );
        assert!(source.mutable_store().is_none());
    }
}
