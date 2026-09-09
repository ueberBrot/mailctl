#[allow(dead_code)]
mod attachment_support;
#[allow(dead_code)]
mod imap_support;

use attachment_support::{continuation, metadata, structure};
use imap_support::*;
use mailctl::imap::{
    AttachmentListRequest, AttachmentProgress, AttachmentRequest, Error, Limits, TlsMode,
};
use std::time::Duration;

async fn start(wire: &mut Wire, encoding: &str, size: usize) {
    authenticate(wire).await;
    examine(wire).await;
    metadata(wire, &structure(encoding, size)).await;
}

#[tokio::test]
async fn resumed_attachment_rechecks_uidvalidity_before_returning_buffered_bytes() {
    let mut session = 0;
    let mut fixture = repeating_fixture(
        Limits { max_attachment_chunk_bytes: 4, ..Limits::default() },
        2,
        move |mut wire| {
            session += 1;
            let first = session == 1;
            Box::pin(async move {
                if first {
                    start(&mut wire, "7BIT", 13).await;
                    literal_bytes(&mut wire, "2", 0, 16384, b"Hello, world!").await;
                    logout(&mut wire).await;
                } else {
                    authenticate(&mut wire).await;
                    let tag = expect(&mut wire, "EXAMINE INBOX").await;
                    write(&mut wire, &format!("* 2 EXISTS\r\n* OK [UIDVALIDITY 78] replaced\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                    dropped(&mut wire).await;
                }
            })
        },
    ).await;
    let chunk = fixture
        .probe
        .read_attachment(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentRequest::new(4, 77, "2"),
        )
        .await
        .unwrap();
    let error = fixture
        .probe
        .read_attachment(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentRequest::resume(continuation(chunk)),
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::UnsafeSelection);
    assert_eq!(fixture.probe.metrics().active_transfers, 0);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn malformed_or_oversized_attachment_frames_dispose_the_transport() {
    for (response, expected) in [
        ("* 1 FETCH (UID 4 BODY[2]<0> {4294967295}\r\n", Error::Limit),
        ("* 1 FETCH (UID 5 BODY[2]<0> {1}\r\nx)\r\n", Error::Protocol),
        ("* 1 FETCH (UID 4 BODY[1]<0> {1}\r\nx)\r\n", Error::Protocol),
        ("* 1 FETCH (UID 4 BODY[2]<1> {1}\r\nx)\r\n", Error::Protocol),
        ("* 1 FETCH (UID 4 BODY[2]<0> NIL)\r\n", Error::Protocol),
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                start(&mut wire, "BASE64", 40_000).await;
                expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[2]<0.16384>)").await;
                write(&mut wire, response).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(fixture.probe.metrics().wire_bytes < 4096);
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn cancellation_during_a_literal_releases_the_transport_and_transfer_slot() {
    let (started, received) = tokio::sync::oneshot::channel();
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_transfers: 1,
            ..Limits::default()
        },
        move |mut wire| {
            Box::pin(async move {
                start(&mut wire, "7BIT", 40_000).await;
                expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[2]<0.16384>)").await;
                write(&mut wire, "* 1 FETCH (UID 4 BODY[2]<0> {16384}\r\npartial").await;
                started.send(()).unwrap();
                dropped(&mut wire).await;
            })
        },
    )
    .await;
    {
        let read = fixture.probe.read_attachment(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentRequest::new(4, 77, "2"),
        );
        tokio::pin!(read);
        tokio::select! {
            _ = received => {},
            result = &mut read => panic!("unexpected completion: {result:?}"),
        }
    }
    assert_eq!(fixture.probe.metrics().active_transfers, 0);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn explicit_cancel_and_expiry_release_bounded_transfer_slots() {
    for expire in [false, true] {
        let mut fixture = repeating_fixture(
            Limits {
                max_attachment_chunk_bytes: 4,
                max_transfers: 1,
                max_transfer_lifetime: Duration::from_secs(1),
                ..Limits::default()
            },
            2,
            |mut wire| {
                Box::pin(async move {
                    start(&mut wire, "7BIT", 13).await;
                    literal_bytes(&mut wire, "2", 0, 16384, b"Hello, world!").await;
                    logout(&mut wire).await;
                })
            },
        )
        .await;
        let first = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap();
        assert_eq!(fixture.probe.metrics().active_transfers, 1);
        let token = continuation(first);
        // A full slot rejects new work before opening another connection.
        assert_eq!(
            fixture
                .probe
                .read_attachment(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentRequest::new(4, 77, "2")
                )
                .await
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(fixture.probe.metrics().active_transfers, 1);
        if expire {
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert_eq!(
                fixture
                    .probe
                    .read_attachment(
                        "fixture",
                        "disposable-password",
                        "INBOX",
                        AttachmentRequest::resume(token)
                    )
                    .await
                    .unwrap_err(),
                Error::TransferExpired
            );
        } else {
            fixture.probe.cancel_attachment(token).unwrap();
        }
        let next = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap();
        fixture.probe.cancel_attachment(continuation(next)).unwrap();
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn invalid_resume_input_releases_its_consumed_transfer() {
    for (password, mailbox) in [("", "INBOX"), ("disposable-password", "")] {
        let mut fixture = repeating_fixture(
            Limits {
                max_attachment_chunk_bytes: 4,
                max_transfers: 1,
                ..Limits::default()
            },
            2,
            |mut wire| {
                Box::pin(async move {
                    start(&mut wire, "7BIT", 13).await;
                    literal_bytes(&mut wire, "2", 0, 16384, b"Hello, world!").await;
                    logout(&mut wire).await;
                })
            },
        )
        .await;
        let first = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap();
        assert_eq!(
            fixture
                .probe
                .read_attachment(
                    "fixture",
                    password,
                    mailbox,
                    AttachmentRequest::resume(continuation(first))
                )
                .await
                .unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        let next = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap();
        fixture.probe.cancel_attachment(continuation(next)).unwrap();
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn transfer_expiry_interrupts_authentication_and_incomplete_fetches() {
    for during_fetch in [false, true] {
        let mut fixture = fixture(
            TlsMode::Implicit,
            Limits {
                max_transfer_lifetime: Duration::from_millis(150),
                operation_timeout: Duration::from_secs(3),
                ..Limits::default()
            },
            move |mut wire| {
                Box::pin(async move {
                    if during_fetch {
                        start(&mut wire, "7BIT", 40_000).await;
                        expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[2]<0.16384>)").await;
                        write(&mut wire, "* 1 FETCH (UID 4 BODY[2]<0> {16384}\r\npartial").await;
                    } else {
                        expect(&mut wire, "CAPABILITY").await;
                    }
                    dropped(&mut wire).await;
                })
            },
        )
        .await;
        assert_eq!(
            fixture
                .probe
                .read_attachment(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentRequest::new(4, 77, "2")
                )
                .await
                .unwrap_err(),
            Error::TransferExpired
        );
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn decoder_failure_preserves_observed_transfer_progress() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            start(&mut wire, "BASE64", 7).await;
            literal_bytes(&mut wire, "2", 0, 16384, b"SGVs%%%").await;
            dropped(&mut wire).await;
        })
    })
    .await;
    assert_eq!(
        fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2")
            )
            .await
            .unwrap_err(),
        Error::Protocol
    );
    assert_eq!(fixture.probe.metrics().transfer_wire_bytes, 7);
    assert_eq!(fixture.probe.metrics().transfer_decode_steps, 7);
    assert_eq!(fixture.probe.metrics().transfer_decoded_bytes, 3);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn dropping_or_misdirecting_a_continuation_releases_its_issuing_slot() {
    for mode in [0, 1, 2] {
        let mut fixture = repeating_fixture(
            Limits {
                max_attachment_chunk_bytes: 4,
                max_transfers: 1,
                ..Limits::default()
            },
            2,
            |mut wire| {
                Box::pin(async move {
                    start(&mut wire, "7BIT", 13).await;
                    literal_bytes(&mut wire, "2", 0, 16384, b"Hello, world!").await;
                    logout(&mut wire).await;
                })
            },
        )
        .await;
        let mut other = mailctl::imap::ImapProbe::new(
            "127.0.0.1".to_owned(),
            1,
            TlsMode::Implicit,
            tokio_rustls::rustls::RootCertStore::empty(),
            Limits::default(),
        )
        .unwrap();
        let first = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap();
        match mode {
            0 => drop(first),
            1 => assert_eq!(
                other.cancel_attachment(continuation(first)).unwrap_err(),
                Error::TransferExpired
            ),
            2 => assert_eq!(
                other
                    .read_attachment(
                        "fixture",
                        "disposable-password",
                        "INBOX",
                        AttachmentRequest::resume(continuation(first))
                    )
                    .await
                    .unwrap_err(),
                Error::TransferExpired
            ),
            _ => unreachable!(),
        }
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        let next = fixture
            .probe
            .read_attachment(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentRequest::new(4, 77, "2"),
            )
            .await
            .unwrap();
        drop(next);
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_encodings_fail_without_fabricating_attachment_bytes() {
    for (encoding, payload) in [
        ("BASE64", "SGVsbG8"),
        ("BASE64", "SGVsbG8=trailing"),
        ("BASE64", "SGVsbG8=AAAA"),
        ("BASE64", "%%%"),
        ("QUOTED-PRINTABLE", "=QZ"),
        ("QUOTED-PRINTABLE", "unfinished="),
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                start(&mut wire, encoding, payload.len()).await;
                literal_bytes(&mut wire, "2", 0, 16384, payload.as_bytes()).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        assert_eq!(
            fixture
                .probe
                .read_attachment(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentRequest::new(4, 77, "2")
                )
                .await
                .unwrap_err(),
            Error::Protocol
        );
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn wire_decoded_and_decoder_work_limits_fail_at_the_narrowed_ceiling() {
    for (limits, encoding, payload, count) in [
        (
            Limits {
                max_attachment_wire_bytes: 8,
                ..Limits::default()
            },
            "7BIT",
            b"123456789".as_slice(),
            9,
        ),
        (
            Limits {
                max_attachment_decoded_bytes: 8,
                ..Limits::default()
            },
            "7BIT",
            b"123456789".as_slice(),
            16384,
        ),
        (
            Limits {
                max_decode_steps: 4,
                ..Limits::default()
            },
            "BASE64",
            b"SGVsbG8=".as_slice(),
            16384,
        ),
    ] {
        let mut fixture = fixture(TlsMode::Implicit, limits, move |mut wire| {
            Box::pin(async move {
                start(&mut wire, encoding, payload.len()).await;
                literal_bytes(&mut wire, "2", 0, count, payload).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        assert_eq!(
            fixture
                .probe
                .read_attachment(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentRequest::new(4, 77, "2")
                )
                .await
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(fixture.probe.metrics().active_transfers, 0);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn exact_wire_and_decoded_limits_require_a_bounded_eof_check() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_literal_bytes: 4,
            max_attachment_wire_bytes: 8,
            max_attachment_decoded_bytes: 8,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                start(&mut wire, "7BIT", 8).await;
                literal_bytes(&mut wire, "2", 0, 4, b"1234").await;
                literal_bytes(&mut wire, "2", 4, 4, b"5678").await;
                literal_bytes(&mut wire, "2", 8, 1, b"").await;
                logout(&mut wire).await;
            })
        },
    )
    .await;
    let chunk = fixture
        .probe
        .read_attachment(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentRequest::new(4, 77, "2"),
        )
        .await
        .unwrap();
    assert!(matches!(chunk.progress, AttachmentProgress::Complete(_)));
    let AttachmentProgress::Complete(integrity) = chunk.progress else {
        panic!("expected completion");
    };
    assert_eq!(integrity.total_decoded_bytes, 8);
    assert_eq!(chunk.metrics.transfer_wire_bytes, 8);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn transfer_cannot_resume_with_a_different_authentication_identity() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_attachment_chunk_bytes: 4,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                start(&mut wire, "7BIT", 13).await;
                literal_bytes(&mut wire, "2", 0, 16384, b"Hello, world!").await;
                logout(&mut wire).await;
            })
        },
    )
    .await;
    let chunk = fixture
        .probe
        .read_attachment(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentRequest::new(4, 77, "2"),
        )
        .await
        .unwrap();
    fixture.task.await.unwrap();
    assert_eq!(
        fixture
            .probe
            .read_attachment(
                "another-account",
                "disposable-password",
                "INBOX",
                AttachmentRequest::resume(continuation(chunk))
            )
            .await
            .unwrap_err(),
        Error::TransferExpired
    );
}

#[tokio::test]
async fn attachment_metadata_obeys_mime_part_limits() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_mime_parts: 2,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                start(&mut wire, "BASE64", 50).await;
                dropped(&mut wire).await;
            })
        },
    )
    .await;
    assert_eq!(
        fixture
            .probe
            .list_attachments(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentListRequest {
                    uid: 4,
                    uid_validity: 77
                }
            )
            .await
            .unwrap_err(),
        Error::Limit
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn unsupported_transfer_encodings_are_listed_but_never_fetched() {
    for encoding in ["BINARY", "X-UNKNOWN"] {
        let mut session = 0;
        let mut fixture = repeating_fixture(Limits::default(), 2, move |mut wire| {
            session += 1;
            let listing = session == 1;
            Box::pin(async move {
                start(&mut wire, encoding, 13).await;
                if listing {
                    logout(&mut wire).await;
                } else {
                    dropped(&mut wire).await;
                }
            })
        })
        .await;
        let listing = fixture
            .probe
            .list_attachments(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentListRequest::new(4, 77),
            )
            .await
            .unwrap();
        assert_eq!(listing.attachments.len(), 1);
        assert!(!listing.attachments[0].available);
        assert_eq!(
            fixture
                .probe
                .read_attachment(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentRequest::new(4, 77, "2")
                )
                .await
                .unwrap_err(),
            Error::Unsupported
        );
        fixture.task.await.unwrap();
    }
}
