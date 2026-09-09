#![allow(dead_code)] // Each integration crate uses part of the shared fixture helpers.

mod append_support;
mod imap_support;
mod support;

use append_support::{draft, receive};
use imap_support::*;
use mailctl::{
    draft_journal::{
        DraftJournal, DraftJournalError, DraftOperationIdentity, DraftOperationState,
        PreparedDraftOperation,
    },
    imap::{AppendOutcome, Limits, PreparedDraft, TlsMode, UidWindow},
};
use uuid::Uuid;

fn operation(draft: &PreparedDraft) -> PreparedDraftOperation {
    PreparedDraftOperation {
        identity: DraftOperationIdentity {
            account_id: Uuid::new_v4(),
            account_generation: 1,
            operation_id: Uuid::new_v4(),
        },
        mailbox_identity: "Drafts".into(),
        content_sha256: draft.sha256(),
    }
}

#[tokio::test]
async fn acknowledged_creation_is_durable_before_optional_reference_lookup_fails() {
    let installation = support::Installation::empty();
    let path = installation.config().with_file_name("drafts.sqlite");
    let mime = draft();
    let expected = mime.bytes().to_vec();
    let operation = operation(&mime);
    let lookup_identity = operation.identity.clone();
    let lookup_path = path.clone();
    let mut session = 0;
    let Fixture { mut probe, task } = repeating_fixture(Limits::default(), 2, move |mut wire| {
        session += 1;
        let first = session == 1;
        let expected = expected.clone();
        let path = lookup_path.clone();
        let identity = lookup_identity.clone();
        Box::pin(async move {
            authenticate(&mut wire).await;
            if first {
                let tag = receive(&mut wire, "Drafts", &expected).await;
                write(
                    &mut wire,
                    &format!("{tag} OK draft accepted without UID\r\n"),
                )
                .await;
                dropped(&mut wire).await;
            } else {
                let observer = DraftJournal::open(path).unwrap();
                assert_eq!(
                    observer.inspect(&identity).unwrap().unwrap().state,
                    DraftOperationState::Created {
                        appended_message: None
                    }
                );
                let tag = expect(&mut wire, "EXAMINE Drafts").await;
                write(
                    &mut wire,
                    &format!("{tag} NO optional lookup unavailable\r\n"),
                )
                .await;
                dropped(&mut wire).await;
            }
        })
    })
    .await;
    let mut journal = DraftJournal::open(&path).unwrap();
    journal.prepare(operation.clone()).unwrap();
    journal.begin_dispatch(&operation).unwrap();
    let result = probe
        .append_draft("fixture", "disposable-password", "Drafts", &mime)
        .await
        .unwrap();
    assert_eq!(result.outcome, AppendOutcome::Created { uid: None });
    journal.record_created(&operation.identity, None).unwrap();
    drop(journal);

    assert!(
        probe
            .search(
                "fixture",
                "disposable-password",
                "Drafts",
                UidWindow { first: 1, last: 1 }
            )
            .await
            .is_err()
    );
    let mut reopened = DraftJournal::open(&path).unwrap();
    let created = DraftOperationState::Created {
        appended_message: None,
    };
    assert_eq!(
        reopened
            .inspect(&operation.identity)
            .unwrap()
            .unwrap()
            .state,
        created
    );
    assert_eq!(
        reopened.begin_dispatch(&operation),
        Err(DraftJournalError::NotDispatchable(created))
    );
    task.await.unwrap();
}

#[tokio::test]
async fn lost_acknowledgement_persists_uncertainty_and_refuses_redispatch() {
    let installation = support::Installation::empty();
    let path = installation.config().with_file_name("drafts.sqlite");
    let mime = draft();
    let expected = mime.bytes().to_vec();
    let operation = operation(&mime);
    let Fixture { mut probe, task } =
        fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                receive(&mut wire, "Drafts", &expected).await;
                // The server has the complete message; close before acknowledging it.
            })
        })
        .await;
    let mut journal = DraftJournal::open(&path).unwrap();
    journal.prepare(operation.clone()).unwrap();
    journal.begin_dispatch(&operation).unwrap();
    let result = probe
        .append_draft("fixture", "disposable-password", "Drafts", &mime)
        .await
        .unwrap();
    assert_eq!(result.outcome, AppendOutcome::Unknown);
    journal.record_outcome_unknown(&operation.identity).unwrap();
    drop(journal);
    let mut reopened = DraftJournal::open(&path).unwrap();
    assert_eq!(
        reopened
            .inspect(&operation.identity)
            .unwrap()
            .unwrap()
            .state,
        DraftOperationState::OutcomeUnknown
    );
    assert_eq!(
        reopened.begin_dispatch(&operation),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::OutcomeUnknown
        ))
    );
    task.await.unwrap();
}

#[tokio::test]
async fn cancellation_closes_transport_and_leaves_durable_in_flight_state() {
    let installation = support::Installation::empty();
    let path = installation.config().with_file_name("drafts.sqlite");
    let mime = draft();
    let expected = mime.bytes().to_vec();
    let operation = operation(&mime);
    let (accepted, received) = tokio::sync::oneshot::channel();
    let Fixture { mut probe, task } =
        fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                receive(&mut wire, "Drafts", &expected).await;
                accepted.send(()).unwrap();
                dropped(&mut wire).await;
            })
        })
        .await;
    let mut journal = DraftJournal::open(&path).unwrap();
    journal.prepare(operation.clone()).unwrap();
    journal.begin_dispatch(&operation).unwrap();
    {
        let request = probe.append_draft("fixture", "disposable-password", "Drafts", &mime);
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => panic!("unacknowledged APPEND completed: {result:?}"),
            result = received => result.unwrap(),
        }
    }
    assert_eq!(probe.append_outcome(), Some(AppendOutcome::Unknown));
    drop(journal);
    let mut reopened = DraftJournal::open(&path).unwrap();
    assert_eq!(
        reopened
            .inspect(&operation.identity)
            .unwrap()
            .unwrap()
            .state,
        DraftOperationState::InFlight
    );
    assert_eq!(
        reopened.begin_dispatch(&operation),
        Err(DraftJournalError::NotDispatchable(
            DraftOperationState::InFlight
        ))
    );
    task.await.unwrap();
}
