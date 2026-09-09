#[allow(dead_code)]
mod attachment_support;
#[allow(dead_code)]
mod imap_support;

use imap_support::*;
use mailctl::imap::{AttachmentListRequest, AttachmentRequest, Error, Limits, TlsMode};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const MIXED: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"large.bin\")) NIL NIL) \"MIXED\" (\"BOUNDARY\" \"fixture\") NIL NIL NIL)";

async fn metadata(wire: &mut Wire, structure: &str) {
    let tag = expect(wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
}

#[tokio::test]
async fn supported_encodings_preserve_bytes_across_wire_and_decoded_chunk_boundaries() {
    let cases: &[(&str, &[u8], &[u8])] = &[
        ("BASE64", b"SGVsbG8sIHdvcmxkIQ==", b"Hello, world!"),
        (
            "QUOTED-PRINTABLE",
            b"Hello=2C=20wo=\r\nrld!",
            b"Hello, world!",
        ),
        ("7BIT", b"Hello, world!", b"Hello, world!"),
        ("8BIT", b"Hello, world!", b"Hello, world!"),
    ];
    for &(encoding, payload, expected) in cases {
        let chunks = if matches!(encoding, "BASE64" | "QUOTED-PRINTABLE") {
            5
        } else {
            4
        };
        let position = Arc::new(AtomicUsize::new(0));
        let observed = position.clone();
        let mut session = 0;
        let mut fixture = repeating_fixture(
            Limits {
                max_literal_bytes: 5,
                max_attachment_chunk_bytes: 4,
                ..Limits::default()
            },
            chunks,
            move |mut wire| {
                session += 1;
                let first = session == 1;
                let position = position.clone();
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    examine(&mut wire).await;
                    if first {
                        attachment_support::metadata(
                            &mut wire,
                            &attachment_support::structure(encoding, payload.len()),
                        )
                        .await;
                    }
                    attachment_support::payload_session(&mut wire, payload, &position, 5).await;
                })
            },
        )
        .await;
        let mut request = AttachmentRequest::new(4, 77, "2");
        let mut bytes: Vec<u8> = Vec::new();
        for chunk_number in 0..chunks {
            let chunk = fixture
                .probe
                .read_attachment("fixture", "disposable-password", "INBOX", request)
                .await
                .unwrap();
            assert_eq!(chunk.decoded_offset, bytes.len() as u64, "{encoding}");
            assert!(chunk.bytes.len() <= 4);
            assert!(chunk.metrics.max_literal_bytes <= 5);
            bytes.extend(&chunk.bytes);
            if chunk_number + 1 == chunks {
                assert!(chunk.complete);
                assert!(chunk.continuation.is_none());
                assert_eq!(chunk.total_decoded_bytes, Some(13));
                // SHA-256 of the independent fixture text, not of client output.
                assert_eq!(
                    chunk.sha256,
                    Some([
                        0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4, 0x3b, 0x8a, 0xc0, 0x06,
                        0x4e, 0x4a, 0x01, 0x64, 0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34,
                        0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3,
                    ])
                );
                break;
            }
            assert!(!chunk.complete);
            assert!(chunk.sha256.is_none());
            assert!(chunk.total_decoded_bytes.is_none());
            request = AttachmentRequest::resume(chunk.continuation.unwrap());
        }
        assert_eq!(bytes, expected, "{encoding}");
        assert_eq!(observed.load(Ordering::Relaxed), payload.len());
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn attachment_listing_checks_uidvalidity_before_fetching() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let error = fixture
        .probe
        .list_attachments(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentListRequest {
                uid: 4,
                uid_validity: 78,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::UnsafeSelection);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn binary_attachment_preserves_nul_high_bytes_and_line_endings() {
    for encoding in ["BASE64", "QUOTED-PRINTABLE", "8BIT"] {
        let payload: &[u8] = match encoding {
            "BASE64" => b"AP8NCng=",
            "QUOTED-PRINTABLE" => b"=00=FF\r\nx",
            _ => b"\xff\r\nx",
        };
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                attachment_support::metadata(
                    &mut wire,
                    &attachment_support::structure(encoding, payload.len()),
                )
                .await;
                literal_bytes(&mut wire, "2", 0, 16384, payload).await;
                logout(&mut wire).await;
            })
        })
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
            .unwrap_or_else(|error| panic!("{encoding}: {error:?}"));
        let expected: &[u8] = if encoding == "8BIT" {
            b"\xff\r\nx"
        } else {
            b"\0\xff\r\nx"
        };
        assert_eq!(chunk.bytes, expected, "{encoding}");
        assert!(chunk.complete);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn attachment_listing_reads_structure_without_fetching_any_payload() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            metadata(&mut wire, MIXED).await;
            logout(&mut wire).await;
        })
    })
    .await;
    let listing = fixture
        .probe
        .list_attachments(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentListRequest {
                uid: 4,
                uid_validity: 77,
            },
        )
        .await
        .unwrap();
    assert_eq!(listing.attachments.len(), 1);
    let attachment = &listing.attachments[0];
    assert_eq!(attachment.part, "2");
    assert_eq!(attachment.filename.as_deref(), Some("large.bin"));
    assert_eq!(attachment.media_type, "application/octet-stream");
    assert_eq!(attachment.declared_size, Some(3_000_000));
    assert!(attachment.available);
    assert!(listing.metrics.wire_bytes < 4096);
    assert_eq!(listing.metrics.max_literal_bytes, 0);
    fixture.task.await.unwrap();
}
