use super::*;

#[derive(Clone, Copy, Debug)]
pub enum BodyRoute {
    MixedAlternative,
    MixedHtmlFirst,
    UnselectedRelated {
        subtype: &'static str,
        declared: bool,
    },
    RelatedRoot,
    RelatedMissingRoot,
    RelatedMultipartRoot,
    AlternativeRelatedHtmlRoot,
    AlternativeRelatedPlainRoot,
    UnsupportedAndAttached,
    WholeBase64,
    WholeDefaultText,
    DepthOver,
    Base64,
    Base64Whitespace,
    Base64CompleteGroup,
    QuotedPrintable,
    Latin1,
    PlainQuotes,
    MalformedBase64,
    MalformedQuotedPrintable,
    MalformedUtf8,
    UnknownCharset,
    HtmlLinksAndQuotes,
}

impl ImapServer {
    pub fn expect_body_route(&self, mailbox: &'static str, case: BodyRoute) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::BodyRoute(mailbox, case),
        });
    }
}

fn text(subtype: &str, charset: &str, encoding: &str, size: usize, id: &str) -> String {
    format!(
        "(\"TEXT\" \"{subtype}\" (\"CHARSET\" \"{charset}\") {id} NIL \"{encoding}\" {size} 1 NIL NIL NIL NIL)"
    )
}

/// Every admitted operation has its own exact EXAMINE/PEEK transcript. The
/// deliberately large message size rules out downloading its other MIME parts.
pub async fn serve(wire: &mut imap_support::Wire, mailbox: &str, case: BodyRoute) {
    use BodyRoute::*;
    use imap_support::{expect, logout, write};

    let plain = text("PLAIN", "UTF-8", "7BIT", 5, "NIL");
    let html = text("HTML", "UTF-8", "7BIT", 12, "NIL");
    let mut headers =
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n".to_owned();
    let mut mime_header: Option<(&str, &str)> = None;
    let mut selected = Some("1");
    let mut payload: &[u8] = b"Hello";
    let mut whole = false;
    let structure = match case {
        MixedAlternative => {
            selected = Some("2.2");
            format!(
                "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 9000000 1 NIL (\"ATTACHMENT\" NIL) NIL NIL)({html}{plain} \"ALTERNATIVE\" NIL NIL NIL NIL){plain} \"MIXED\" NIL NIL NIL NIL)"
            )
        }
        MixedHtmlFirst => {
            payload = b"<p>Hello</p>";
            format!("({html}{plain} \"MIXED\" NIL NIL NIL NIL)")
        }
        UnselectedRelated { subtype, declared } => {
            payload = b"Short body.\r\n";
            let first = text("PLAIN", "UTF-8", "7BIT", payload.len(), "\"<selected>\"");
            let parameters = if declared {
                "(\"START\" \"<selected>\")"
            } else {
                "NIL"
            };
            headers = format!(
                "MIME-Version: 1.0\r\nContent-Type: multipart/{}; boundary=fixture{}\r\n\r\n",
                subtype.to_ascii_lowercase(),
                if declared {
                    "; start=\"<selected>\""
                } else {
                    ""
                },
            );
            format!(
                "({first}(({html} \"ALTERNATIVE\" NIL NIL NIL NIL) \"RELATED\" (\"START\" \"<other-root>\") NIL NIL NIL) \"{subtype}\" {parameters} NIL NIL NIL)"
            )
        }
        RelatedRoot | RelatedMissingRoot => {
            let first = text("PLAIN", "UTF-8", "7BIT", 5, "\"<first>\"");
            let second = text("PLAIN", "UTF-8", "7BIT", 6, "\"<second>\"");
            let root = if matches!(case, RelatedRoot) {
                selected = Some("2");
                payload = b"Second";
                "<second>"
            } else {
                payload = b"First";
                "<missing>"
            };
            format!("({first}{second} \"RELATED\" (\"START\" \"{root}\") NIL NIL NIL)")
        }
        RelatedMultipartRoot => {
            let first = text("PLAIN", "UTF-8", "7BIT", 5, "\"<first>\"");
            let second = text("PLAIN", "UTF-8", "7BIT", 6, "NIL");
            selected = Some("2.2");
            payload = b"Second";
            mime_header = Some((
                "2.MIME",
                "Content-Type: multipart/alternative; boundary=alt\r\nContent-ID: <root>\r\n\r\n",
            ));
            format!(
                "({first}({html}{second} \"ALTERNATIVE\" NIL NIL NIL NIL) \"RELATED\" (\"START\" \"<root>\") NIL NIL NIL)"
            )
        }
        AlternativeRelatedHtmlRoot | AlternativeRelatedPlainRoot => {
            let (root, fallback) = if matches!(case, AlternativeRelatedHtmlRoot) {
                selected = Some("3");
                (&html, &plain)
            } else {
                selected = Some("2.2.1");
                (&plain, &html)
            };
            payload = b"Final";
            headers = "Content-Type: multipart/alternative; boundary=outer\r\n\r\n".to_owned();
            mime_header = Some((
                "2.2.MIME",
                "Content-Type: multipart/mixed; boundary=root\r\nContent-ID: <root>\r\n\r\n",
            ));
            format!(
                "({html}({fallback}({root} \"MIXED\" NIL NIL NIL NIL) \"RELATED\" (\"START\" \"<root>\") NIL NIL NIL){plain} \"ALTERNATIVE\" NIL NIL NIL NIL)"
            )
        }
        UnsupportedAndAttached => {
            selected = None;
            format!(
                "((\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 100 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {plain} 2 NIL NIL NIL NIL)({plain} \"MIXED\" NIL (\"ATTACHMENT\" NIL) NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL NIL NIL NIL) \"MIXED\" NIL NIL NIL NIL)"
            )
        }
        WholeBase64 | WholeDefaultText => {
            whole = true;
            let (charset, encoding) = if matches!(case, WholeBase64) {
                headers = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_owned();
                payload = b"SGVsbG8=";
                ("UTF-8", "BASE64")
            } else {
                headers = "\r\n".to_owned();
                payload = b"Ordinary text";
                ("US-ASCII", "7BIT")
            };
            text("PLAIN", charset, encoding, payload.len(), "NIL")
        }
        DepthOver => format!("({plain} \"MIXED\" NIL NIL NIL NIL)"),
        HtmlLinksAndQuotes => {
            payload = b"<html><head><script>active-secret</script><style>style-secret</style></head><body><p>Hello <a href=\"https://example.invalid/report\">report</a></p><blockquote>Quoted text</blockquote><img src=\"http://127.0.0.1:1/private\"></body></html>";
            let part = text("HTML", "UTF-8", "7BIT", payload.len(), "NIL");
            format!("({part} \"ALTERNATIVE\" NIL NIL NIL NIL)")
        }
        Base64
        | Base64Whitespace
        | Base64CompleteGroup
        | QuotedPrintable
        | Latin1
        | PlainQuotes
        | MalformedBase64
        | MalformedQuotedPrintable
        | MalformedUtf8
        | UnknownCharset => {
            let (charset, encoding, value): (&str, &str, &[u8]) = match case {
                Base64 => ("UTF-8", "BASE64", b"SGVsbG8="),
                Base64Whitespace => ("UTF-8", "BASE64", b" Zg==\r\n"),
                Base64CompleteGroup => ("UTF-8", "BASE64", b"Zm9v"),
                QuotedPrintable => ("UTF-8", "QUOTED-PRINTABLE", b"caf=C3=A9"),
                Latin1 => ("ISO-8859-1", "8BIT", b"caf\xe9"),
                PlainQuotes => ("UTF-8", "7BIT", b"> quoted\r\n\r\nReply"),
                MalformedBase64 => ("UTF-8", "BASE64", b"%%%bad%%%"),
                MalformedQuotedPrintable => ("UTF-8", "QUOTED-PRINTABLE", b"=QZ"),
                MalformedUtf8 => ("UTF-8", "8BIT", b"bad\xfftext"),
                UnknownCharset => ("UNKNOWN-CHARSET", "8BIT", b"text"),
                _ => unreachable!(),
            };
            payload = value;
            let part = text("PLAIN", charset, encoding, payload.len(), "NIL");
            format!("({part} \"MIXED\" NIL NIL NIL NIL)")
        }
    };

    let tag = expect(wire, &format!("EXAMINE {}", mailbox_argument(mailbox))).await;
    write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    let tag = expect(wire, "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    let size = if whole {
        headers.len() + payload.len()
    } else {
        3_000_300
    };
    write(
        wire,
        &format!(
            "* 3 FETCH (UID 3 RFC822.SIZE {size} BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n"
        ),
    )
    .await;
    if matches!(case, DepthOver) {
        // One multipart root plus its text child exceeds a MIME depth of one.
        // No header, payload, or LOGOUT is permitted after the structure.
        imap_support::dropped(wire).await;
        return;
    }
    body_literal(wire, "HEADER", 0, 16384, headers.as_bytes()).await;
    if let Some((section, headers)) = mime_header {
        body_literal(wire, section, 0, 16384, headers.as_bytes()).await;
    }
    if let Some(section) = selected {
        if whole {
            let mut value = headers.into_bytes();
            value.extend_from_slice(payload);
            body_literal(wire, "", 0, size + 1, &value).await;
        } else {
            body_literal(wire, section, 0, payload.len() + 1, payload).await;
        }
    }
    logout(wire).await;
}
