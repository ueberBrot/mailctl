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

fn multipart(depth: usize, leaves: usize) -> String {
    assert!(depth >= 2);
    let mut structure = format!("({} \"MIXED\" NIL NIL NIL NIL)", TEXT.repeat(leaves));
    for _ in 2..depth {
        structure = format!("({structure} \"MIXED\" NIL NIL NIL NIL)");
    }
    structure
}

#[tokio::test]
async fn configured_mime_depth_admits_exact_and_rejects_one_over() {
    for ceiling in [7, 8, 20, 40] {
        for depth in [ceiling, ceiling + 1] {
            let structure = multipart(depth, 1);
            let part = std::iter::repeat_n("1", depth - 1)
                .collect::<Vec<_>>()
                .join(".");
            let mut fixture = fixture(
                TlsMode::Implicit,
                Limits {
                    max_nesting: ceiling,
                    ..Limits::default()
                },
                move |mut wire| {
                    Box::pin(async move {
                        authenticate(&mut wire).await;
                        examine(&mut wire).await;
                        metadata(&mut wire, &structure).await;
                        if depth > ceiling {
                            dropped(&mut wire).await;
                        } else {
                            literal_bytes(&mut wire, "HEADER", 0, 16384, MULTIPART_HEADERS).await;
                            literal_bytes(&mut wire, &part, 0, 3, b"ok").await;
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
            if depth > ceiling {
                assert_eq!(result.unwrap_err(), Error::Limit, "depth={depth}");
            } else {
                assert_eq!(result.unwrap().text, "ok", "depth={depth}");
            }
            fixture.task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn embedded_messages_share_the_configured_mime_depth_budget() {
    for ceiling in [20, 40] {
        for depth in [ceiling, ceiling + 1] {
            let mut structure = TEXT.to_owned();
            for level in 1..depth {
                structure = if level % 2 == 0 {
                    format!("({structure} \"MIXED\" NIL NIL NIL NIL)")
                } else {
                    format!(
                        "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 2 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {structure} 1 NIL NIL NIL NIL)"
                    )
                };
            }
            let mut fixture = fixture(
                TlsMode::Implicit,
                Limits {
                    max_nesting: ceiling,
                    ..Limits::default()
                },
                move |mut wire| {
                    Box::pin(async move {
                        authenticate(&mut wire).await;
                        examine(&mut wire).await;
                        metadata(&mut wire, &structure).await;
                        if depth > ceiling {
                            dropped(&mut wire).await;
                        } else {
                            logout(&mut wire).await;
                        }
                    })
                },
            )
            .await;
            let result = fixture
                .probe
                .list_attachments(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentListRequest::new(4, 77),
                )
                .await;
            if depth > ceiling {
                assert_eq!(result.unwrap_err(), Error::Limit, "depth={depth}");
            } else {
                result.expect("embedded messages must preserve the configured depth range");
            }
            fixture.task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn deep_structure_keeps_exact_mime_node_ceilings() {
    for (depth, ceiling) in [(20, 200), (40, 1000)] {
        for nodes in [ceiling, ceiling + 1] {
            let structure = multipart(depth, nodes - depth + 1);
            let mut fixture = fixture(
                TlsMode::Implicit,
                Limits {
                    max_nesting: depth,
                    max_mime_parts: ceiling,
                    max_response_bytes: 256 * 1024,
                    ..Limits::default()
                },
                move |mut wire| {
                    Box::pin(async move {
                        authenticate(&mut wire).await;
                        examine(&mut wire).await;
                        metadata(&mut wire, &structure).await;
                        if nodes > ceiling {
                            dropped(&mut wire).await;
                        } else {
                            logout(&mut wire).await;
                        }
                    })
                },
            )
            .await;
            let result = fixture
                .probe
                .list_attachments(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentListRequest::new(4, 77),
                )
                .await;
            if nodes > ceiling {
                assert_eq!(result.unwrap_err(), Error::Limit, "nodes={nodes}");
            } else {
                assert!(result.unwrap().is_empty(), "nodes={nodes}");
            }
            fixture.task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn deep_structure_keeps_header_admission_before_payload() {
    let mut fixture = fixture(
        TlsMode::Implicit,
        Limits {
            max_nesting: 40,
            max_header_bytes: 4,
            ..Limits::default()
        },
        |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(&mut wire, &multipart(40, 1)).await;
                let _ = expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[HEADER]<0.5>)").await;
                write(&mut wire, "* 1 FETCH (UID 4 BODY[HEADER]<0> {6}\r\n").await;
                dropped(&mut wire).await;
            })
        },
    )
    .await;
    assert_eq!(
        fixture
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77)
            )
            .await
            .unwrap_err(),
        Error::Limit
    );
    assert_eq!(fixture.probe.metrics().max_literal_bytes, 0);
    fixture.task.await.unwrap();
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
