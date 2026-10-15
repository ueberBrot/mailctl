mod imap_support;

use imap_support::*;
use mailctl::imap::{AttachmentListRequest, BodyRequest, Error, Limits, TlsMode};

const TEXT: &str =
    "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 2 1 NIL NIL NIL NIL)";
const TEXT_HEADERS: &[u8] =
    b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n";
const MULTIPART_HEADERS: &[u8] =
    b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n";

async fn metadata(wire: &mut Wire, structure: &str) {
    let tag = expect(wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(
        wire,
        &format!(
            "* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n"
        ),
    )
    .await;
}

#[tokio::test]
async fn mime_depth_one_allows_root_leaf_and_protocol_parameters() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_nesting: 1,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(&mut wire, TEXT).await;
                literal_bytes(&mut wire, "HEADER", 0, 16384, TEXT_HEADERS).await;
                literal_bytes(&mut wire, "1", 0, 3, b"ok").await;
                logout(&mut wire).await;
            })
        },
    )
    .await;
    let page = fixture
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .expect("one MIME node remains legal despite FETCH and CHARSET parentheses");
    assert_eq!(page.text, "ok");
    assert_eq!(page.selected_part.as_deref(), Some("1"));
    assert_eq!(page.source_media_type.as_deref(), Some("text/plain"));
    assert!(!page.replacements);
    assert!(!page.truncated);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn multipart_depth_two_requires_two_mime_levels_before_header_or_payload_fetch() {
    for depth in [1, 2] {
        let mut fixture = fixture(
            TlsMode::Implicit,
            Limits {
                max_nesting: depth,
                ..Limits::default()
            },
            move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    examine(&mut wire).await;
                    metadata(&mut wire, &format!("({TEXT} \"MIXED\" NIL NIL NIL NIL)")).await;
                    if depth == 1 {
                        // The complete typed structure is over the MIME depth
                        // ceiling. No header, payload, or LOGOUT may follow.
                        dropped(&mut wire).await;
                    } else {
                        literal_bytes(&mut wire, "HEADER", 0, 16384, MULTIPART_HEADERS).await;
                        literal_bytes(&mut wire, "1", 0, 3, b"ok").await;
                        logout(&mut wire).await;
                    }
                })
            },
        )
        .await;
        let result = fixture
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await;
        if depth == 1 {
            assert_eq!(result.unwrap_err(), Error::Limit);
        } else {
            let page = result.expect("two semantic MIME levels fit a depth-two ceiling");
            assert_eq!(page.text, "ok");
            assert_eq!(page.selected_part.as_deref(), Some("1"));
        }
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn mime_depth_one_allows_attachment_disposition_parameters_without_payload() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_nesting: 1,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(
                    &mut wire,
                    "(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"7BIT\" 2 NIL (\"ATTACHMENT\" (\"FILENAME\" \"fixture.bin\")) NIL NIL)",
                )
                .await;
                logout(&mut wire).await;
            })
        },
    )
    .await;
    let attachments = fixture
        .probe
        .list_attachments(
            "fixture",
            "disposable-password",
            "INBOX",
            AttachmentListRequest::new(4, 77),
        )
        .await
        .expect("disposition parameters do not add semantic MIME levels");
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].part, "1");
    assert_eq!(attachments[0].filename.as_deref(), Some("fixture.bin"));
    assert!(attachments[0].available);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn mime_depth_one_does_not_limit_search_envelope_address_syntax() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_nesting: 1,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                let tag = expect(&mut wire, "UID SEARCH UID 1:10").await;
                write(&mut wire, &format!("* SEARCH 4\r\n{tag} OK searched\r\n")).await;
                let tag = expect(
                    &mut wire,
                    "UID FETCH 4 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)",
                )
                .await;
                write(
                    &mut wire,
                    &format!("* 1 FETCH (UID 4 ENVELOPE (NIL \"Synthetic\" ((\"Sender\" NIL \"sender\" \"example.test\")) NIL NIL NIL NIL NIL NIL NIL) FLAGS () INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 100)\r\n{tag} OK fetched\r\n"),
                )
                .await;
                logout(&mut wire).await;
            })
        },
    )
    .await;
    let page = fixture
        .probe
        .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
        .await
        .expect("an envelope address list does not consume MIME depth");
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].uid, 4);
    assert_eq!(
        page.messages[0].metadata.from.value().unwrap()[0].address,
        "sender@example.test"
    );
    fixture.task.await.unwrap();
}
