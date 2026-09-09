#![allow(dead_code)] // This route uses only part of the shared transcript fixture helpers.

mod imap_support;

use imap_support::*;
use mailctl::imap::{BodyRequest, Error, Limits, TlsMode};

const ROOT_HEADERS: &str =
    "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n";

fn text_part(subtype: &str, size: usize, disposition: &str) -> String {
    format!(
        "(\"TEXT\" \"{subtype}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" {size} 1 NIL {disposition} NIL NIL)"
    )
}

fn transfer_text_part(transfer_encoding: &str, size: usize) -> String {
    format!(
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"{transfer_encoding}\" {size} 1 NIL NIL NIL NIL)"
    )
}

async fn metadata(wire: &mut Wire, structure: &str, size: usize) {
    let tag = expect(wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(
        wire,
        &format!(
            "* 1 FETCH (UID 4 RFC822.SIZE {size} BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n"
        ),
    )
    .await;
}

async fn complete_body(wire: &mut Wire, part: &str, value: &[u8]) {
    let mut offset = 0;
    while offset < value.len() {
        let count = (16 * 1024).min(value.len() + 1 - offset);
        let end = (offset + count).min(value.len());
        let sent = end - offset;
        literal_bytes(wire, part, offset, count, &value[offset..end]).await;
        offset = end;
        if sent < count {
            return;
        }
    }
    literal_bytes(wire, part, offset, 1, b"").await;
}

async fn selected_prefix(wire: &mut Wire, structure: &str, size: usize) {
    authenticate(wire).await;
    examine(wire).await;
    metadata(wire, structure, size).await;
    literal_bytes(wire, "HEADER", 0, 16 * 1024, ROOT_HEADERS.as_bytes()).await;
}

#[tokio::test]
async fn default_body_budget_reads_an_exact_two_mebibyte_part_in_bounded_chunks() {
    const SIZE: usize = 2 * 1024 * 1024;
    let structure = format!(
        "({} \"MIXED\" NIL NIL NIL NIL)",
        text_part("PLAIN", SIZE, "NIL")
    );
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            selected_prefix(&mut wire, &structure, SIZE + ROOT_HEADERS.len()).await;
            let chunk = vec![b'x'; 16 * 1024];
            for offset in (0..SIZE).step_by(chunk.len()) {
                literal_bytes(&mut wire, "1", offset, chunk.len(), &chunk).await;
            }
            literal_bytes(&mut wire, "1", SIZE, 1, b"").await;
            logout(&mut wire).await;
        })
    })
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
        .unwrap();
    assert_eq!(page.text.len(), Limits::default().max_text_bytes);
    assert!(page.text.bytes().all(|byte| byte == b'x'));
    assert_eq!(page.selected_part.as_deref(), Some("1"));
    assert!(page.metrics.max_literal_bytes <= 16 * 1024);
    assert!(page.truncated);
    assert!(page.metrics.wire_bytes >= SIZE);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn all_mime_nodes_count_even_when_selection_excludes_their_subtrees() {
    let attached = text_part("PLAIN", 3, "(\"ATTACHMENT\" NIL)");
    let nested = text_part("PLAIN", 3, "NIL");
    let message = format!(
        "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 8 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {nested} 1 NIL NIL NIL NIL)"
    );
    let selected = text_part("PLAIN", 2, "NIL");
    let structure = format!("({attached}{message}{selected} \"MIXED\" NIL NIL NIL NIL)");

    let accepted_structure = structure.clone();
    let mut accepted = fixture(
        TlsMode::Implicit,
        Limits {
            max_mime_parts: 5,
            ..Limits::default()
        },
        move |mut wire| {
            let structure = accepted_structure.clone();
            Box::pin(async move {
                selected_prefix(&mut wire, &structure, 100).await;
                literal_bytes(&mut wire, "3", 0, 3, b"ok").await;
                logout(&mut wire).await;
            })
        },
    )
    .await;
    let page = accepted
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .unwrap();
    assert_eq!(page.text, "ok");
    accepted.task.await.unwrap();

    let mut rejected = fixture(
        TlsMode::Implicit,
        Limits {
            max_mime_parts: 4,
            ..Limits::default()
        },
        move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(&mut wire, &structure, 100).await;
                dropped(&mut wire).await;
            })
        },
    )
    .await;
    assert_eq!(
        rejected
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap_err(),
        Error::Limit
    );
    rejected.task.await.unwrap();
}

#[tokio::test]
async fn nested_and_malformed_bodystructures_fail_finitely_at_the_public_route() {
    let leaf = text_part("PLAIN", 2, "NIL");
    let mut within_limit = leaf.clone();
    for _ in 0..6 {
        within_limit = format!("({within_limit} \"MIXED\" NIL NIL NIL NIL)");
    }
    let selected_part = std::iter::repeat_n("1", 6).collect::<Vec<_>>().join(".");
    let accepted_structure = within_limit.clone();
    let mut accepted = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            selected_prefix(&mut wire, &accepted_structure, 100).await;
            literal_bytes(&mut wire, &selected_part, 0, 3, b"ok").await;
            logout(&mut wire).await;
        })
    })
    .await;
    assert_eq!(
        accepted
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap()
            .text,
        "ok"
    );
    accepted.task.await.unwrap();

    let limited_structure = within_limit.clone();
    let mut limited = fixture(
        TlsMode::Implicit,
        Limits {
            max_nesting: 6,
            ..Limits::default()
        },
        move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(&mut wire, &limited_structure, 100).await;
                dropped(&mut wire).await;
            })
        },
    )
    .await;
    assert_eq!(
        limited
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap_err(),
        Error::Limit
    );
    limited.task.await.unwrap();

    // The pinned io-imap codec accepts six multipart wrappers (a text leaf at depth seven) and
    // rejects the seventh wrapper while decoding BODYSTRUCTURE, before our configurable limit.
    let codec_limit = format!("({within_limit} \"MIXED\" NIL NIL NIL NIL)");
    let mut rejected = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            metadata(&mut wire, &codec_limit, 100).await;
            dropped(&mut wire).await;
        })
    })
    .await;
    assert_eq!(
        rejected
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap_err(),
        Error::Protocol
    );
    rejected.task.await.unwrap();

    let mut malformed = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            write(
                &mut wire,
                &format!(
                    "* 1 FETCH (UID 4 RFC822.SIZE 100 BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 2 1)\r\n{tag} OK fetched\r\n"
                ),
            )
            .await;
            dropped(&mut wire).await;
        })
    })
    .await;
    assert_eq!(
        malformed
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap_err(),
        Error::Protocol
    );
    malformed.task.await.unwrap();
}

#[tokio::test]
async fn decoder_and_work_budgets_stop_after_the_selected_literal() {
    let structure = format!(
        "({} \"MIXED\" NIL NIL NIL NIL)",
        text_part("PLAIN", 6, "NIL")
    );
    for limits in [
        Limits {
            max_decoded_bytes: 5,
            ..Limits::default()
        },
        Limits {
            max_decode_steps: 12,
            ..Limits::default()
        },
        Limits {
            max_decode_steps: 40,
            ..Limits::default()
        },
    ] {
        let structure = structure.clone();
        let mut fixture = fixture(TlsMode::Implicit, limits, move |mut wire| {
            Box::pin(async move {
                selected_prefix(&mut wire, &structure, 100).await;
                literal_bytes(&mut wire, "1", 0, 7, b"abcdef").await;
                dropped(&mut wire).await;
            })
        })
        .await;
        assert_eq!(
            fixture
                .probe
                .read_body(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    BodyRequest::new(4, 77),
                )
                .await
                .unwrap_err(),
            Error::Limit
        );
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_transfer_tails_keep_the_decoded_prefix_and_mark_replacement() {
    for (transfer_encoding, wire, expected) in [
        ("BASE64", b"SGVsbG8".as_slice(), "\u{fffd}Hel"),
        ("BASE64", b"TQ=".as_slice(), "\u{fffd}M"),
        ("BASE64", b"SGVs%G8=".as_slice(), "\u{fffd}Hel"),
        ("BASE64", b"SGVsbG8=!".as_slice(), "\u{fffd}Hello"),
        ("BASE64", b"Zh==".as_slice(), "\u{fffd}f"),
        ("QUOTED-PRINTABLE", b"hello=".as_slice(), "\u{fffd}hello"),
        ("QUOTED-PRINTABLE", b"hello=A".as_slice(), "\u{fffd}hello"),
        ("QUOTED-PRINTABLE", b"hello=QZ".as_slice(), "\u{fffd}hello"),
        (
            "QUOTED-PRINTABLE",
            b"hello\rworld".as_slice(),
            "\u{fffd}helloworld",
        ),
    ] {
        let structure = format!(
            "({} \"MIXED\" NIL NIL NIL NIL)",
            transfer_text_part(transfer_encoding, wire.len())
        );
        let mut fixture = fixture(
            TlsMode::Implicit,
            Limits::default(),
            move |mut wire_stream| {
                Box::pin(async move {
                    selected_prefix(&mut wire_stream, &structure, 100).await;
                    complete_body(&mut wire_stream, "1", wire).await;
                    logout(&mut wire_stream).await;
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
            .unwrap();
        assert_eq!(page.text, expected, "{transfer_encoding}/{wire:?}");
        assert!(page.replacements, "{transfer_encoding}/{wire:?}");
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn hostile_html_is_clamped_or_rejected_before_unbounded_rendering() {
    let huge_span = b"<table><tr><td colspan=18446744073709551615 rowspan=18446744073709551615>safe</td></tr></table>";
    let structure = format!(
        "({} \"MIXED\" NIL NIL NIL NIL)",
        text_part("HTML", huge_span.len(), "NIL")
    );
    let mut clamped = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            selected_prefix(&mut wire, &structure, 100).await;
            complete_body(&mut wire, "1", huge_span).await;
            logout(&mut wire).await;
        })
    })
    .await;
    let page = clamped
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .unwrap();
    assert!(page.converted);
    assert!(page.text.contains("safe"));
    assert!(
        page.metrics.decode_steps <= Limits::default().max_decode_steps,
        "{:?}",
        page.metrics
    );
    clamped.task.await.unwrap();

    let excessive_nodes = format!("<body>{}</body>", "<i></i>".repeat(4097));
    let excessive_cells = format!("<table><tr>{}</tr></table>", "<td>x</td>".repeat(129));
    let excessive_source = format!("<p>{}</p>", "x".repeat(64 * 1024));
    for body in [excessive_nodes, excessive_cells, excessive_source] {
        let structure = format!(
            "({} \"MIXED\" NIL NIL NIL NIL)",
            text_part("HTML", body.len(), "NIL")
        );
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                selected_prefix(&mut wire, &structure, 100).await;
                complete_body(&mut wire, "1", body.as_bytes()).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        assert_eq!(
            fixture
                .probe
                .read_body(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    BodyRequest::new(4, 77),
                )
                .await
                .unwrap_err(),
            Error::Limit
        );
        fixture.task.await.unwrap();
    }
}

#[test]
fn huge_html_table_spans_do_not_expand_client_allocations() {
    let body = b"<table><tr><td colspan=18446744073709551615 rowspan=18446744073709551615>safe</td></tr></table>".to_vec();
    let structure = format!(
        "({} \"MIXED\" NIL NIL NIL NIL)",
        text_part("HTML", body.len(), "NIL")
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut probe, server) =
        dedicated_fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                selected_prefix(&mut wire, &structure, 100).await;
                complete_body(&mut wire, "1", &body).await;
                logout(&mut wire).await;
            })
        });
    let allocations = allocation_counter::measure(|| {
        runtime.block_on(async {
            let page = probe
                .read_body(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    BodyRequest::new(4, 77),
                )
                .await
                .unwrap();
            assert!(page.text.contains("safe"));
        });
    });
    server.join().unwrap();
    assert!(allocations.bytes_max < 2 * 1024 * 1024, "{allocations:?}");
    assert!(
        allocations.bytes_total < 16 * 1024 * 1024,
        "{allocations:?}"
    );
}
