use super::*;

async fn read_body_selection_and_representation_routes(executable: &str) {
    use server::body_routes::BodyRoute::*;

    let cases = [
        (MixedAlternative, "Hello", Some("2.2"), false, false),
        (MixedHtmlFirst, "Hello\n", Some("1"), true, false),
        (
            UnselectedRelated {
                subtype: "MIXED",
                declared: false,
            },
            "Short body.\r\n",
            Some("1"),
            false,
            false,
        ),
        (
            UnselectedRelated {
                subtype: "ALTERNATIVE",
                declared: false,
            },
            "Short body.\r\n",
            Some("1"),
            false,
            false,
        ),
        (
            UnselectedRelated {
                subtype: "RELATED",
                declared: false,
            },
            "Short body.\r\n",
            Some("1"),
            false,
            false,
        ),
        (
            UnselectedRelated {
                subtype: "RELATED",
                declared: true,
            },
            "Short body.\r\n",
            Some("1"),
            false,
            false,
        ),
        (RelatedRoot, "Second", Some("2"), false, false),
        (RelatedMissingRoot, "First", Some("1"), false, false),
        (RelatedMultipartRoot, "Second", Some("2.2"), false, false),
        (AlternativeRelatedHtmlRoot, "Final", Some("3"), false, false),
        (
            AlternativeRelatedPlainRoot,
            "Final",
            Some("2.2.1"),
            false,
            false,
        ),
        (UnsupportedAndAttached, "", None, false, false),
        (WholeBase64, "Hello", Some("1"), false, false),
        (WholeDefaultText, "Ordinary text", Some("1"), false, false),
        (Base64, "Hello", Some("1"), false, false),
        (Base64Whitespace, "f", Some("1"), false, false),
        (Base64CompleteGroup, "foo", Some("1"), false, false),
        (QuotedPrintable, "café", Some("1"), false, false),
        (Latin1, "café", Some("1"), false, false),
        (
            PlainQuotes,
            "> quoted\r\n\r\nReply",
            Some("1"),
            false,
            false,
        ),
        (MalformedBase64, "\u{fffd}", Some("1"), false, true),
        (MalformedQuotedPrintable, "\u{fffd}", Some("1"), false, true),
        (
            MalformedUtf8,
            "\u{fffd}bad\u{fffd}text",
            Some("1"),
            false,
            true,
        ),
        (UnknownCharset, "\u{fffd}text", Some("1"), false, true),
        (HtmlLinksAndQuotes, "Quoted text", Some("1"), true, false),
    ];
    for (case, expected, selected, converted, replacements) in cases {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut fixture = Fixture::new(executable);
            let reader = Reader::start(&fixture, executable).await;
            let (mailbox, before) = discover_message(&fixture, &reader).await;
            let message = before["reference"].as_str().unwrap();
            fixture.server.expect_body_route("INBOX", case);
            let result = reader
                .call(
                    &fixture,
                    &["message", "get", "--message", message],
                    "email_get_message",
                    json!({"message": message}),
                )
                .await;
            assert_eq!(result["message_reference"], message, "{case:?}");
            let body = &result["body"];
            assert_eq!(
                body["representation_version"], "mailctl-body/mail-parser-0.11.9/html2text-0.17.1",
                "{case:?}"
            );
            let text = body["text"].as_str().unwrap();
            if matches!(
                case,
                MalformedBase64 | MalformedQuotedPrintable | HtmlLinksAndQuotes
            ) {
                assert!(text.contains(expected), "{case:?}: {body}");
            } else {
                assert_eq!(text, expected, "{case:?}");
            }
            if matches!(case, HtmlLinksAndQuotes) {
                assert!(text.contains("Hello") && text.contains("report"));
                assert!(text.contains("https://example.invalid/report"));
                assert!(!text.contains("active-secret") && !text.contains("style-secret"));
            }
            assert_eq!(body["selected_part"], json!(selected), "{case:?}");
            let media_type = selected.map(|_| if converted { "text/html" } else { "text/plain" });
            assert_eq!(body["source_media_type"], json!(media_type), "{case:?}");
            assert_eq!(body["converted"], converted, "{case:?}");
            assert_eq!(body["replacements"], replacements, "{case:?}");
            assert_eq!(body["truncated"], false, "{case:?}");
            assert_eq!(body["continuation_available"], false, "{case:?}");
            assert!(body["next_cursor"].is_null(), "{case:?}");
            assert_eq!(
                body["empty_reason"],
                json!(selected.is_none().then_some("no_supported_body")),
                "{case:?}",
            );
            // The independent server only permits selected-body reads. Search
            // again before MCP shutdown to check identity/flags and usability.
            assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
            reader.finish().await;
            fixture.server.finish();
        })
        .await
        .unwrap_or_else(|_| panic!("standalone body route deadline: {case:?}"));
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_selects_and_decodes_body_routes_without_unrelated_payloads() {
    read_body_selection_and_representation_routes(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_selects_and_decodes_body_routes_without_unrelated_payloads() {
    read_body_selection_and_representation_routes(support::MAILCTL_MCP).await;
}

async fn enforce_semantic_mime_depth(executable: &str) {
    use server::body_routes::BodyRoute::{DepthOver, WholeBase64};

    for case in [WholeBase64, DepthOver] {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut fixture =
                Fixture::with_limits(executable, "attachment_chunk_bytes = 3\nmime_depth = 1");
            let reader = Reader::start(&fixture, executable).await;
            let (mailbox, before) = discover_message(&fixture, &reader).await;
            let message = before["reference"].as_str().unwrap();
            fixture.server.expect_body_route("INBOX", case);
            let response = reader
                .response(
                    &fixture,
                    &["message", "get", "--message", message],
                    "email_get_message",
                    json!({"message": message}),
                )
                .await;
            if matches!(case, DepthOver) {
                assert_eq!(response["error"]["code"], "response_too_large");
                assert!(response.get("result").is_none(), "{response}");
            } else {
                assert!(response.get("error").is_none(), "{response}");
                let result = &response["result"];
                assert_eq!(result["message_reference"], message);
                let body = &result["body"];
                assert_eq!(body["text"], "Hello");
                assert_eq!(body["selected_part"], "1");
                assert_eq!(body["source_media_type"], "text/plain");
                assert_eq!(body["replacements"], false);
                assert_eq!(body["truncated"], false);
            }
            // This serial provider must observe refusal disposal before it can
            // serve the unchanged search, while the MCP session remains alive.
            assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
            reader.finish().await;
            fixture.server.finish();
        })
        .await
        .unwrap_or_else(|_| panic!("standalone semantic MIME depth deadline: {case:?}"));
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_mime_depth_counts_nodes_instead_of_protocol_parentheses() {
    enforce_semantic_mime_depth(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_mime_depth_counts_nodes_instead_of_protocol_parentheses() {
    enforce_semantic_mime_depth(support::MAILCTL_MCP).await;
}
