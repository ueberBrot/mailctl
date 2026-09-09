#[allow(dead_code)]
mod attachment_support;
#[allow(dead_code)]
mod imap_support;

use imap_support::*;
use mailctl::imap::{AttachmentRequest, Limits, TlsMode};
use std::sync::{Arc, atomic::AtomicUsize};

#[tokio::test]
async fn quoted_printable_discards_raw_line_padding_and_preserves_encoded_whitespace() {
    let payload = b"first \t\r\nsecond=20=09\r\nthird \t=\r\nline\r\nlast \t";
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            attachment_support::metadata(
                &mut wire,
                &attachment_support::structure("QUOTED-PRINTABLE", payload.len()),
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
        .unwrap();
    assert_eq!(chunk.bytes, b"first\r\nsecond \t\r\nthird \tline\r\nlast");
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn quoted_printable_padding_escapes_and_line_endings_survive_split_wire_slices() {
    let payload = b"A \t\r\nB=20=09\r\nC \t= \t\r\nD=0D=0Aend \t";
    for count in 1..=5 {
        let mut fixture = fixture(
            TlsMode::Implicit,
            Limits {
                max_literal_bytes: count,
                ..Limits::default()
            },
            move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    examine(&mut wire).await;
                    attachment_support::metadata(
                        &mut wire,
                        &attachment_support::structure("QUOTED-PRINTABLE", payload.len()),
                    )
                    .await;
                    attachment_support::payload_session(
                        &mut wire,
                        payload,
                        &Arc::new(AtomicUsize::new(0)),
                        count,
                    )
                    .await;
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
        assert_eq!(
            chunk.bytes, b"A\r\nB \t\r\nC \tD\r\nend",
            "wire slice {count}"
        );
        fixture.task.await.unwrap();
    }
}
