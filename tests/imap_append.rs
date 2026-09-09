#![allow(dead_code)]
mod append_support;
mod imap_support;
use append_support::*;
use imap_support::*;
use mailctl::imap::{AppendOutcome, AppendUid, Error, Limits, PreparedDraft, TlsMode};
use std::time::Duration;

#[tokio::test]
async fn tagged_acknowledgement_survives_missing_uid_and_connection_close() {
    for (capabilities, code, uid) in [
        (
            "IMAP4rev1 UIDPLUS",
            " [APPENDUID 77 4]",
            Some(AppendUid {
                uid_validity: 77,
                uid: 4,
            }),
        ),
        ("IMAP4rev1", "", None),
    ] {
        let draft = draft();
        let bytes = draft.bytes().to_vec();
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                capability(&mut wire, "IMAP4rev1").await;
                let tag = expect(&mut wire, "LOGIN fixture disposable-password").await;
                write(&mut wire, &format!("{tag} OK authenticated\r\n")).await;
                capability(&mut wire, capabilities).await;
                let tag = receive(&mut wire, "Drafts", &bytes).await;
                write(
                    &mut wire,
                    &format!("* 1 EXISTS\r\n{tag} OK{code} accepted\r\n"),
                )
                .await;
                // Closing immediately makes all optional provider work unavailable.
            })
        })
        .await;
        let result = fixture
            .probe
            .append_draft("fixture", "disposable-password", "Drafts", &draft)
            .await
            .unwrap();
        assert_eq!(result.outcome, AppendOutcome::Created { uid });
        assert_eq!(fixture.probe.append_outcome(), Some(result.outcome));
        assert!(result.metrics.append_wire_bytes > draft.bytes().len());
        fixture.task.await.unwrap();
    }
}

#[test]
fn composition_rejects_malformed_ids_before_mime_encoding() {
    for id in [
        "@example.test",
        "operation@",
        "operation@@example.test",
        "operation\r\nInjected: value@example.test",
    ] {
        let mut input = input();
        input.message_id = id.into();
        assert!(
            matches!(
                PreparedDraft::compose(input, 1024 * 1024),
                Err(Error::InvalidInput)
            ),
            "invalid message ID accepted"
        );
    }
}

#[tokio::test]
async fn tagged_no_and_bad_are_rejections_before_or_after_literal() {
    for sent in [false, true] {
        for status in ["NO [TRYCREATE] target absent", "BAD rejected"] {
            let draft = draft();
            let bytes = draft.bytes().to_vec();
            let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    let tag = if sent {
                        receive(&mut wire, "Drafts", &bytes).await
                    } else {
                        header(&mut wire, "Drafts", bytes.len()).await
                    };
                    write(&mut wire, &format!("{tag} {status}\r\n")).await;
                    dropped(&mut wire).await;
                })
            })
            .await;
            let result = fixture
                .probe
                .append_draft("fixture", "disposable-password", "Drafts", &draft)
                .await
                .unwrap();
            assert_eq!(result.outcome, AppendOutcome::Rejected);
            fixture.task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn lost_or_invalid_acknowledgement_is_unknown() {
    for response in [
        "",
        "* BYE gone\r\n",
        "wrong OK accepted\r\n",
        "garbage\r\n",
        "+ unexpected continuation\r\n",
    ] {
        let draft = draft();
        let bytes = draft.bytes().to_vec();
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                receive(&mut wire, "Drafts", &bytes).await;
                if !response.is_empty() {
                    write(&mut wire, response).await;
                    dropped(&mut wire).await;
                }
            })
        })
        .await;
        let result = fixture
            .probe
            .append_draft("fixture", "disposable-password", "Drafts", &draft)
            .await
            .unwrap();
        assert_eq!(result.outcome, AppendOutcome::Unknown);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn timeout_disposes_uncertain_transport() {
    let draft = draft();
    let bytes = draft.bytes().to_vec();
    let limits = Limits {
        operation_timeout: Duration::from_millis(200),
        ..Limits::default()
    };
    let mut fixture = fixture(TlsMode::Implicit, limits, move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            receive(&mut wire, "Drafts", &bytes).await;
            dropped(&mut wire).await;
        })
    })
    .await;
    assert_eq!(
        fixture
            .probe
            .append_draft("fixture", "disposable-password", "Drafts", &draft)
            .await
            .unwrap()
            .outcome,
        AppendOutcome::Unknown
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn cancellation_before_and_after_literal_closes_transport_and_retains_unknown() {
    for sent in [false, true] {
        let draft = draft();
        let bytes = draft.bytes().to_vec();
        let (reached, ready) = tokio::sync::oneshot::channel();
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                if sent {
                    receive(&mut wire, "Drafts", &bytes).await;
                } else {
                    header(&mut wire, "Drafts", bytes.len()).await;
                }
                reached.send(()).unwrap();
                dropped(&mut wire).await;
            })
        })
        .await;
        {
            let append =
                fixture
                    .probe
                    .append_draft("fixture", "disposable-password", "Drafts", &draft);
            tokio::pin!(append);
            tokio::select! { _ = ready => {}, result = &mut append => panic!("APPEND unexpectedly completed: {result:?}") }
        }
        assert_eq!(fixture.probe.append_outcome(), Some(AppendOutcome::Unknown));
        fixture.task.await.unwrap();
    }
}

#[test]
fn frozen_composition_preserves_bcc_body_and_reply_metadata_with_exact_size_limit() {
    let mut input = input();
    input.in_reply_to = Some("parent@example.test".into());
    input.references = vec!["ancestor@example.test".into(), "parent@example.test".into()];
    let draft = PreparedDraft::compose(input.clone(), 1024 * 1024).unwrap();
    let exact = PreparedDraft::compose(input.clone(), draft.bytes().len()).unwrap();
    assert_eq!(draft.bytes(), exact.bytes());
    assert_eq!(draft.sha256(), exact.sha256());
    assert!(matches!(
        PreparedDraft::compose(input, draft.bytes().len() - 1),
        Err(Error::Limit)
    ));
    let message = mail_parser::MessageParser::default()
        .parse(draft.bytes())
        .unwrap();
    assert_eq!(message.subject(), Some("Unsent fixture"));
    assert_eq!(message.message_id(), Some("operation@example.test"));
    assert_eq!(
        message.bcc().unwrap().first().unwrap().address(),
        Some("hidden@example.test")
    );
    assert_eq!(
        message.body_text(0).unwrap().replace("\r\n", "\n"),
        "First line\nSecond line\n"
    );
    assert_eq!(message.in_reply_to().as_text(), Some("parent@example.test"));
    let text = std::str::from_utf8(draft.bytes()).unwrap();
    assert!(text.contains("References: <ancestor@example.test> <parent@example.test>\r\n"));
    assert!(text.contains("Content-Type: text/plain"));
}

#[test]
fn composition_bounds_recipient_count_subject_body_and_header_injection() {
    let mut accepted = input();
    accepted.to = vec!["reader@example.test".into(); 100];
    accepted.cc.clear();
    accepted.bcc.clear();
    accepted.subject = "s".repeat(8192);
    PreparedDraft::compose(accepted.clone(), 1024 * 1024).unwrap();
    let mut too_many = accepted.clone();
    too_many.to.push("extra@example.test".into());
    assert!(matches!(
        PreparedDraft::compose(too_many, 1024 * 1024),
        Err(Error::Limit)
    ));
    accepted.subject.push('s');
    assert!(matches!(
        PreparedDraft::compose(accepted, 1024 * 1024),
        Err(Error::Limit)
    ));
    let mut huge_body = input();
    huge_body.body = "x".repeat(1025);
    assert!(matches!(
        PreparedDraft::compose(huge_body, 1024),
        Err(Error::Limit)
    ));
    for value in [
        "victim@example.test\r\nBcc: other@example.test",
        "missing-at",
        "two@@example.test",
    ] {
        let mut invalid = input();
        invalid.from = value.into();
        assert!(matches!(
            PreparedDraft::compose(invalid, 1024 * 1024),
            Err(Error::InvalidInput)
        ));
    }
    let mut empty = input();
    empty.to.clear();
    empty.cc.clear();
    empty.bcc.clear();
    empty.subject.clear();
    empty.body.clear();
    PreparedDraft::compose(empty, 1024 * 1024).unwrap();
}

#[tokio::test]
async fn oversized_acknowledgement_keeps_unknown_and_disposes_transport() {
    let draft = draft();
    let bytes = draft.bytes().to_vec();
    let limits = Limits {
        max_response_bytes: 256,
        max_literal_bytes: 256,
        ..Limits::default()
    };
    let mut fixture = fixture(TlsMode::Implicit, limits, move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = receive(&mut wire, "Drafts", &bytes).await;
            write(&mut wire, &format!("{tag} OK {}\r\n", "x".repeat(257))).await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let result = fixture
        .probe
        .append_draft("fixture", "disposable-password", "Drafts", &draft)
        .await
        .unwrap();
    assert_eq!(result.outcome, AppendOutcome::Unknown);
    assert_eq!(result.metrics.max_response_bytes, 256);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn premature_success_is_unknown_without_sending_literal() {
    let draft = draft();
    let length = draft.bytes().len();
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = header(&mut wire, "Drafts", length).await;
            write(&mut wire, &format!("{tag} OK premature\r\n")).await;
            dropped(&mut wire).await;
        })
    })
    .await;
    assert_eq!(
        fixture
            .probe
            .append_draft("fixture", "disposable-password", "Drafts", &draft)
            .await
            .unwrap()
            .outcome,
        AppendOutcome::Unknown
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn authentication_failure_has_no_append_dispatch() {
    let draft = draft();
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            capability(&mut wire, "IMAP4rev1").await;
            let tag = expect(&mut wire, "LOGIN fixture disposable-password").await;
            write(&mut wire, &format!("{tag} NO invalid credentials\r\n")).await;
            dropped(&mut wire).await;
        })
    })
    .await;
    assert!(matches!(
        fixture
            .probe
            .append_draft("fixture", "disposable-password", "Drafts", &draft)
            .await,
        Err(Error::Authentication)
    ));
    assert_eq!(fixture.probe.append_outcome(), None);
    assert_eq!(fixture.probe.metrics().append_wire_bytes, 0);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn mime_and_header_limits_reject_before_network_dispatch() {
    let mut input = input();
    input.body = "b\n".repeat(64 * 1024);
    let draft = PreparedDraft::compose(input, 1024 * 1024).unwrap();
    for limits in [
        Limits {
            max_operation_bytes: 64 * 1024,
            ..Limits::default()
        },
        Limits {
            max_header_bytes: 8,
            ..Limits::default()
        },
    ] {
        let mut probe = mailctl::imap::ImapProbe::new(
            "invalid.test".into(),
            993,
            TlsMode::Implicit,
            tokio_rustls::rustls::RootCertStore::empty(),
            limits,
        )
        .unwrap();
        assert!(matches!(
            probe
                .append_draft("fixture", "disposable-password", "Drafts", &draft)
                .await,
            Err(Error::Limit)
        ));
        assert_eq!(probe.append_outcome(), None);
        assert_eq!(probe.metrics().wire_bytes, 0);
    }
}
