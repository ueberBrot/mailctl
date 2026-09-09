#[allow(dead_code)]
mod imap_support;

use imap_support::*;
use mailctl::imap::{BodyRequest, Limits, TlsMode};
use tokio::io::AsyncWriteExt;

const ROOT_HEADERS: &str =
    "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n";
const TEXT_HEADERS: &str =
    "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n";
const LARGE_MIXED: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"large.bin\")) NIL NIL) \"MIXED\" (\"BOUNDARY\" \"fixture\") NIL NIL NIL)";

async fn literal(wire: &mut Wire, section: &str, offset: usize, count: usize, value: &str) {
    literal_bytes(wire, section, offset, count, value.as_bytes()).await;
}

async fn literal_bytes(wire: &mut Wire, section: &str, offset: usize, count: usize, value: &[u8]) {
    let tag = expect(
        wire,
        &format!("UID FETCH 4 (UID BODY.PEEK[{section}]<{offset}.{count}>)"),
    )
    .await;
    write(
        wire,
        &format!(
            "* 1 FETCH (UID 4 BODY[{section}]<{offset}> {{{}}}\r\n",
            value.len()
        ),
    )
    .await;
    wire.write_all(value).await.unwrap();
    write(wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
}

#[tokio::test]
async fn short_body_does_not_download_the_oversized_attachment() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {LARGE_MIXED})\r\n{tag} OK fetched\r\n")).await;
        literal(&mut wire, "HEADER", 0, 16384, ROOT_HEADERS).await;
        literal(&mut wire, "1", 0, 14, "Short body.\r\n").await;
        logout(&mut wire).await;
    })).await;
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
    assert_eq!(page.text, "Short body.\r\n");
    assert_eq!(page.selected_part.as_deref(), Some("1"));
    assert_eq!(page.source_media_type.as_deref(), Some("text/plain"));
    assert!(page.continuation.is_none());
    assert!(page.metrics.wire_bytes < 4096);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn decoded_text_can_exceed_one_page_and_ends_on_a_utf8_boundary() {
    let mut fixture = fixture(TlsMode::Implicit, Limits { max_text_bytes: 4, ..Limits::default() }, |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        let structure = LARGE_MIXED.replace("13 1 NIL", "10 1 NIL");
        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
        literal(&mut wire, "HEADER", 0, 16384, ROOT_HEADERS).await;
        literal(&mut wire, "1", 0, 11, "a🦀éxyz").await;
        logout(&mut wire).await;
    })).await;
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
    assert_eq!(page.text, "a");
    assert!(page.continuation.is_some());
    assert!(page.truncated);
    fixture.task.await.unwrap();
}

fn text_part(
    subtype: &str,
    charset: &str,
    encoding: &str,
    size: usize,
    id: &str,
    disposition: &str,
) -> String {
    format!(
        "(\"TEXT\" \"{subtype}\" (\"CHARSET\" \"{charset}\") {id} NIL \"{encoding}\" {size} 1 NIL {disposition} NIL NIL)"
    )
}

fn mime(subtype: &str, charset: &str, encoding: &str) -> String {
    format!(
        "Content-Type: text/{subtype}; charset={charset}\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n"
    )
}

async fn selected_script(
    wire: &mut Wire,
    structure: &str,
    part: Option<&str>,
    _headers: &str,
    body: &[u8],
) {
    authenticate(wire).await;
    examine(wire).await;
    let tag = expect(wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
    literal(wire, "HEADER", 0, 16384, ROOT_HEADERS).await;
    if let Some(part) = part {
        literal_bytes(wire, part, 0, body.len() + 1, body).await;
    }
    logout(wire).await;
}

async fn read_selected(
    structure: String,
    part: Option<&str>,
    headers: String,
    body: Vec<u8>,
) -> mailctl::imap::BodyPage {
    let part = part.map(str::to_owned);
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            selected_script(&mut wire, &structure, part.as_deref(), &headers, &body).await;
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
    fixture.task.await.unwrap();
    page
}

#[tokio::test]
async fn alternatives_prefer_plain_while_mixed_uses_the_first_eligible_subtree() {
    let plain = text_part("PLAIN", "UTF-8", "7BIT", 5, "NIL", "NIL");
    let html = text_part("HTML", "UTF-8", "7BIT", 12, "NIL", "NIL");
    let attachment = text_part(
        "PLAIN",
        "UTF-8",
        "7BIT",
        9000000,
        "NIL",
        "(\"ATTACHMENT\" NIL)",
    );
    let alternatives = format!("({html}{plain} \"ALTERNATIVE\" NIL NIL NIL NIL)");
    let structure = format!("({attachment}{alternatives}{plain} \"MIXED\" NIL NIL NIL NIL)");
    let page = read_selected(
        structure,
        Some("2.2"),
        mime("plain", "utf-8", "7bit"),
        b"Hello".to_vec(),
    )
    .await;
    assert_eq!(page.text, "Hello");
    assert_eq!(page.selected_part.as_deref(), Some("2.2"));
    assert!(!page.converted);

    let page = read_selected(
        format!("({html}{plain} \"MIXED\" NIL NIL NIL NIL)"),
        Some("1"),
        mime("html", "utf-8", "7bit"),
        b"<p>Hello</p>".to_vec(),
    )
    .await;
    assert_eq!(page.text.trim(), "Hello");
    assert!(page.converted);
    assert_eq!(page.source_media_type.as_deref(), Some("text/html"));
}

#[tokio::test]
async fn html_preserves_inert_link_targets_and_quotes_without_active_content() {
    let body = b"<html><head><script>active-secret</script><style>style-secret</style></head><body><p>Hello <a href=\"https://example.invalid/report\">report</a></p><blockquote>Quoted text</blockquote><img src=\"http://127.0.0.1:1/private\"></body></html>";
    let html = text_part("HTML", "UTF-8", "7BIT", body.len(), "NIL", "NIL");
    let page = read_selected(
        format!("({html} \"ALTERNATIVE\" NIL NIL NIL NIL)"),
        Some("1"),
        mime("html", "utf-8", "7bit"),
        body.to_vec(),
    )
    .await;
    assert!(
        page.text.contains("Hello") && page.text.contains("report"),
        "{:?}",
        page.text
    );
    assert!(page.text.contains("https://example.invalid/report"));
    assert!(page.text.contains("Quoted text"));
    assert!(!page.text.contains("active-secret"));
    assert!(!page.text.contains("style-secret"));
    assert!(page.converted);
    assert!(page.representation_version.contains("html2text-0.17.1"));
    assert!(page.metrics.decode_steps > body.len());
}

#[tokio::test]
async fn related_uses_its_declared_root_and_falls_back_when_the_root_is_absent() {
    let first = text_part("PLAIN", "UTF-8", "7BIT", 5, "\"<first>\"", "NIL");
    let second = text_part("PLAIN", "UTF-8", "7BIT", 6, "\"<second>\"", "NIL");
    for (root, part, body) in [("<second>", "2", "Second"), ("<missing>", "1", "First!")] {
        let body = if part == "1" { "First" } else { body };
        let structure = format!("({first}{second} \"RELATED\" (\"START\" \"{root}\") NIL NIL NIL)");
        let page = read_selected(
            structure,
            Some(part),
            mime("plain", "utf-8", "7bit"),
            body.as_bytes().to_vec(),
        )
        .await;
        assert_eq!(page.text, body);
        assert_eq!(page.selected_part.as_deref(), Some(part));
    }
}

#[tokio::test]
async fn unsupported_and_attached_bodies_return_an_explicit_empty_representation() {
    let plain = text_part("PLAIN", "UTF-8", "7BIT", 5, "NIL", "NIL");
    let message = format!(
        "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 100 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {plain} 2 NIL NIL NIL NIL)"
    );
    let attached = format!("({plain} \"MIXED\" NIL (\"ATTACHMENT\" NIL) NIL NIL)");
    let binary =
        "(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL NIL NIL NIL)";
    let structure = format!("({message}{attached}{binary} \"MIXED\" NIL NIL NIL NIL)");
    let page = read_selected(structure, None, String::new(), vec![]).await;
    assert_eq!(page.text, "");
    assert!(page.selected_part.is_none());
    assert!(page.source_media_type.is_none());
    assert!(!page.truncated);
}

#[tokio::test]
async fn decoding_preserves_plain_quotes_and_marks_malformed_data() {
    let cases: &[(&str, &str, &[u8], &str, bool)] = &[
        ("UTF-8", "BASE64", b"SGVsbG8=", "Hello", false),
        ("UTF-8", "QUOTED-PRINTABLE", b"caf=C3=A9", "café", false),
        ("ISO-8859-1", "8BIT", b"caf\xe9", "café", false),
        (
            "UTF-8",
            "7BIT",
            b"> quoted\r\n\r\nReply",
            "> quoted\r\n\r\nReply",
            false,
        ),
        ("UTF-8", "BASE64", b"%%%bad%%%", "\u{fffd}", true),
        ("UTF-8", "QUOTED-PRINTABLE", b"=QZ", "\u{fffd}", true),
        ("UTF-8", "8BIT", b"bad\xfftext", "\u{fffd}", true),
        ("UNKNOWN-CHARSET", "8BIT", b"text", "\u{fffd}", true),
    ];
    for (charset, encoding, body, expected, replacements) in cases {
        let part = text_part("PLAIN", charset, encoding, body.len(), "NIL", "NIL");
        let page = read_selected(
            format!("({part} \"MIXED\" NIL NIL NIL NIL)"),
            Some("1"),
            mime("plain", charset, encoding),
            body.to_vec(),
        )
        .await;
        if *replacements {
            assert!(
                page.text.contains(expected),
                "{charset}/{encoding}: {:?}",
                page.text
            );
        } else {
            assert_eq!(page.text, *expected);
        }
        assert_eq!(page.replacements, *replacements, "{charset}/{encoding}");
    }
}

#[tokio::test]
async fn continuation_reconstructs_utf8_text_and_rejects_changed_content() {
    let body = "a🦀éxyz";
    let part = text_part("PLAIN", "UTF-8", "8BIT", body.len(), "NIL", "NIL");
    let structure = format!("({part} \"MIXED\" NIL NIL NIL NIL)");
    let mut session = 0;
    let mut fixture = repeating_fixture(
        Limits {
            max_text_bytes: 4,
            ..Limits::default()
        },
        5,
        move |mut wire| {
            session += 1;
            let structure = structure.clone();
            let body = if session == 5 { "b🦀éxyz" } else { body };
            Box::pin(async move {
                selected_script(
                    &mut wire,
                    &structure,
                    Some("1"),
                    &mime("plain", "utf-8", "8bit"),
                    body.as_bytes(),
                )
                .await;
            })
        },
    )
    .await;
    let mut request = BodyRequest::new(4, 77);
    let mut text = String::new();
    let mut first_cursor = None;
    for _ in 0..4 {
        let page = fixture
            .probe
            .read_body("fixture", "disposable-password", "INBOX", request.clone())
            .await
            .unwrap();
        assert!(page.text.len() <= 4);
        text.push_str(&page.text);
        first_cursor = first_cursor.or_else(|| page.continuation.clone());
        request.continuation = page.continuation;
    }
    assert_eq!(text, body);
    assert!(request.continuation.is_none());
    request.continuation = first_cursor;
    assert_eq!(
        fixture
            .probe
            .read_body("fixture", "disposable-password", "INBOX", request)
            .await
            .unwrap_err(),
        mailctl::imap::Error::StaleCursor
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn small_single_part_messages_use_bounded_whole_peek_and_the_same_decoder() {
    for (headers, charset, encoding, body, expected) in [
        (
            mime("plain", "utf-8", "base64"),
            "UTF-8",
            "BASE64",
            "SGVsbG8=",
            "Hello",
        ),
        (
            "\r\n".to_owned(),
            "US-ASCII",
            "7BIT",
            "Ordinary text",
            "Ordinary text",
        ),
    ] {
        let size = headers.len() + body.len();
        let structure = text_part("PLAIN", charset, encoding, body.len(), "NIL", "NIL");
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE {size} BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
            literal(&mut wire, "HEADER", 0, 16384, &headers).await;
            literal(&mut wire, "", 0, size + 1, &format!("{headers}{body}")).await;
            logout(&mut wire).await;
        })).await;
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
        assert_eq!(page.text, expected);
        assert_eq!(page.selected_part.as_deref(), Some("1"));
        assert!(!page.replacements);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn singleton_whole_message_budget_is_independent_of_selected_body_budget() {
    let headers = TEXT_HEADERS;
    let body = "Hello";
    let size = headers.len() + body.len();
    let structure = text_part("PLAIN", "UTF-8", "7BIT", body.len(), "NIL", "NIL");
    let mut fixture = fixture(TlsMode::Implicit, Limits { max_body_wire_bytes: 5, ..Limits::default() }, move |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE {size} BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
        literal(&mut wire, "HEADER", 0, 16384, headers).await;
        literal(&mut wire, "1", 0, 6, body).await;
        logout(&mut wire).await;
    })).await;
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
    assert_eq!(page.text, "Hello");
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn related_can_identify_a_multipart_root_from_its_bounded_mime_headers() {
    let first = text_part("PLAIN", "UTF-8", "7BIT", 5, "\"<first>\"", "NIL");
    let html = text_part("HTML", "UTF-8", "7BIT", 12, "NIL", "NIL");
    let plain = text_part("PLAIN", "UTF-8", "7BIT", 6, "NIL", "NIL");
    let alternatives = format!("({html}{plain} \"ALTERNATIVE\" NIL NIL NIL NIL)");
    let structure =
        format!("({first}{alternatives} \"RELATED\" (\"START\" \"<root>\") NIL NIL NIL)");
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
        literal(&mut wire, "HEADER", 0, 16384, ROOT_HEADERS).await;
        literal(&mut wire, "2.MIME", 0, 16384, "Content-Type: multipart/alternative; boundary=alt\r\nContent-ID: <root>\r\n\r\n").await;
        literal(&mut wire, "2.2", 0, 7, "Second").await;
        logout(&mut wire).await;
    })).await;
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
    assert_eq!(page.text, "Second");
    assert_eq!(page.selected_part.as_deref(), Some("2.2"));
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn greenmail_separator_repair_preserves_payload_and_proves_eof_for_size_hints() {
    let body = "BODY[1]<0>{13}\r\nunchanged";
    for quoted in [false, true] {
        let body = if quoted { "BODY[1]<0>{13}" } else { body };
        let structure = text_part("PLAIN", "UTF-8", "7BIT", body.len() + 40, "NIL", "NIL");
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ({structure} \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
            // GreenMail also omits the final blank line from complete headers.
            literal(&mut wire, "HEADER", 0, 16384, ROOT_HEADERS.strip_suffix("\r\n").unwrap()).await;
            let tag = expect(&mut wire, &format!("UID FETCH 4 (UID BODY.PEEK[1]<0.{}>)", body.len() + 41)).await;
            let value = if quoted { format!(" \"{body}\"") } else { format!("{{{}}}\r\n{body}", body.len()) };
            write(&mut wire, &format!("* 1 FETCH (UID 4 BODY[1]<0>{value})\r\n{tag} OK fetched\r\n")).await;
            logout(&mut wire).await;
        })).await;
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
        assert_eq!(page.text, body);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn separator_repair_keeps_identity_checks_and_reserves_its_extra_byte() {
    for (section, offset, full_frame, expected) in [
        ("2", 0, false, mailctl::imap::Error::Protocol),
        ("1", 1, false, mailctl::imap::Error::Protocol),
        ("1", 0, true, mailctl::imap::Error::Limit),
    ] {
        let limits = Limits {
            max_response_bytes: 512,
            max_literal_bytes: 256,
            ..Limits::default()
        };
        let mut fixture = fixture(TlsMode::Implicit, limits, move |mut wire| Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
            write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {LARGE_MIXED})\r\n{tag} OK fetched\r\n")).await;
            literal(&mut wire, "HEADER", 0, 256, ROOT_HEADERS).await;
            expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[1]<0.14>)").await;
            let mut response = format!("* 1 FETCH (UID 4 BODY[{section}]<{offset}>{{13}}\r\nShort body.\r\n");
            if full_frame {
                response.push_str(" FLAGS (");
                response.push_str(&"X".repeat(512 - response.len() - 4));
                response.push(')');
            }
            response.push_str(")\r\n");
            if full_frame { assert_eq!(response.len(), 512); }
            write(&mut wire, &response).await;
            dropped(&mut wire).await;
        })).await;
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
            expected
        );
        fixture.task.await.unwrap();
    }
}
