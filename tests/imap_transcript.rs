mod imap_support;

use imap_support::*;
use mailctl::imap::{Limits, TlsMode};

#[tokio::test]
async fn all_folder_discovery_preserves_real_names_and_metadata_without_selection() {
    let mut fixture =
        fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "LIST \"\" \"*\"").await;
                write(
                &mut wire,
                &format!(concat!(
                    "* LIST (\\Noselect) \"/\" \"\"\r\n",
                    "* LIST (\\HasNoChildren) \"/\" inbox\r\n",
                        "* LIST (\\Archive \\HasNoChildren) \"/\" \"Later &AOQ- &- Folder\"\r\n",
                        "* LIST (\\Noselect) \"/\" Parent\r\n",
                        "* LIST () \"/\" &AOk-/&2D7dgA-/&AOk-\r\n",
                        "* LIST () \"/\" &,,0-\r\n",
                        "* LIST () \"/\" &2D3eAA-\r\n",
                    "{tag} OK listed\r\n"
                ), tag = tag),
            )
            .await;
                logout(&mut wire).await;
            })
        })
        .await;
    let result = fixture
        .probe
        .discover_all("fixture", "disposable-password")
        .await
        .unwrap();
    assert_eq!(
        result
            .iter()
            .map(|mailbox| mailbox.name.as_str())
            .collect::<Vec<_>>(),
        [
            "INBOX",
            "Later ä & Folder",
            "Parent",
            "é/🦀/é",
            "\u{fffd}",
            "😀"
        ]
    );
    assert!(result[0].selectable);
    assert_eq!(result[1].attributes, ["\\Archive", "\\HasNoChildren"]);
    assert!(!result[2].selectable);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn restricted_discovery_treats_wildcard_characters_as_exact_names() {
    let mut discovery = true;
    let mut fixture = repeating_fixture(Limits::default(), 2, move |mut wire| {
        let list = discovery;
        discovery = false;
        Box::pin(async move {
            authenticate(&mut wire).await;
            if list {
                let tag = expect(&mut wire, "LIST \"\" \"*\"").await;
                write(
                    &mut wire,
                    &format!(
                        "* LIST () \"/\" Hidden\r\n* LIST () \"/\" Rate\r\n\
                         * LIST () \"/\" {{10}}\r\nRate%* Box\r\n{tag} OK listed\r\n"
                    ),
                )
                .await;
            } else {
                let tag = expect(&mut wire, "EXAMINE \"Rate%* Box\"").await;
                write(
                    &mut wire,
                    &format!("* OK [UIDVALIDITY 77] identity\r\n{tag} OK [READ-ONLY] examined\r\n"),
                )
                .await;
                let tag = expect(&mut wire, "UID SEARCH UID 1:2").await;
                write(&mut wire, &format!("* SEARCH\r\n{tag} OK searched\r\n")).await;
            }
            logout(&mut wire).await;
        })
    })
    .await;
    let result = fixture
        .probe
        .discover("fixture", "disposable-password", &["Rate%* Box".into()])
        .await
        .unwrap();
    assert_eq!(
        result
            .iter()
            .map(|row| row.name.as_str())
            .collect::<Vec<_>>(),
        ["Rate%* Box"]
    );
    assert!(
        fixture
            .probe
            .search_window("fixture", "disposable-password", &result[0].name, 77, 1..=2)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn inventory_limits_count_rows_omitted_deduplicated_or_scope_filtered() {
    for restricted in [false, true] {
        let mut fixture = fixture(
            TlsMode::Implicit,
            Limits {
                max_mailboxes: 2,
                ..Limits::default()
            },
            |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    let tag = expect(&mut wire, "LIST \"\" \"*\"").await;
                    write(
                        &mut wire,
                        &format!(
                            "* LIST () \"/\" INBOX\r\n* LIST () \"/\" inbox\r\n\
                         * LIST (\\Noselect) \"/\" \"\"\r\n{tag} OK listed\r\n"
                        ),
                    )
                    .await;
                    dropped(&mut wire).await;
                })
            },
        )
        .await;
        let result = if restricted {
            fixture
                .probe
                .discover("fixture", "disposable-password", &["Literal*".into()])
                .await
        } else {
            fixture
                .probe
                .discover_all("fixture", "disposable-password")
                .await
        };
        assert_eq!(result.unwrap_err(), mailctl::imap::Error::Limit);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn all_folder_discovery_rejects_invalid_names_and_inconsistent_identities() {
    for rows in [
        "* LIST () \"/\" \"\"\r\n".to_owned(),
        format!("* LIST () \"/\" \"{}\"\r\n", "x".repeat(1025)),
        "* LIST () \"/\" {8}\r\nbad\r\nbox\r\n".to_owned(),
        "* LIST () \"/\" \"&broken-\"\r\n".to_owned(),
        "* LIST () \"/\" \"trailing&\"\r\n".to_owned(),
        "* LIST () \"/\" \"&ACU-\"\r\n".to_owned(),
        "* LIST () \"/\" INBOX\r\n* LIST (\\Noselect) \"/\" inbox\r\n".to_owned(),
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "LIST \"\" \"*\"").await;
                write(&mut wire, &format!("{rows}{tag} OK listed\r\n")).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        assert_eq!(
            fixture
                .probe
                .discover_all("fixture", "disposable-password")
                .await
                .unwrap_err(),
            mailctl::imap::Error::Protocol
        );
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn discovery_rejects_lossy_modified_utf7_identities() {
    for restricted in [false, true] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let command = if restricted {
                    "LIST \"\" &,,0-"
                } else {
                    "LIST \"\" \"*\""
                };
                let tag = expect(&mut wire, command).await;
                // UTF-16 D800 is a lone surrogate, not the literal replacement character.
                write(
                    &mut wire,
                    &format!("* LIST () \"/\" &2AA-\r\n{tag} OK listed\r\n"),
                )
                .await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let result = if restricted {
            fixture
                .probe
                .discover("fixture", "disposable-password", &["\u{fffd}".into()])
                .await
        } else {
            fixture
                .probe
                .discover_all("fixture", "disposable-password")
                .await
        };
        assert_eq!(result.unwrap_err(), mailctl::imap::Error::Protocol);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn runtime_all_folder_discovery_applies_the_narrowed_inventory_limit() {
    use mailctl::{
        authentication::{Account, Error, Runtime},
        credentials::{Availability, Secret, SecretSource, SourceError},
    };
    struct FixtureSecret;
    impl SecretSource for FixtureSecret {
        fn availability(&self, _: uuid::Uuid) -> Availability {
            Availability::Configured
        }
        fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
            Secret::new(b"disposable-password".to_vec())
        }
    }
    let fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = expect(&mut wire, "LIST \"\" \"*\"").await;
            write(
                &mut wire,
                &format!("* LIST () \"/\" INBOX\r\n* LIST () \"/\" Later\r\n{tag} OK listed\r\n"),
            )
            .await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let runtime = Runtime::new(mailctl::config::Limits::default(), fixture.roots.clone()).unwrap();
    let account = Account {
        id: uuid::Uuid::new_v4(),
        generation: 1,
        config: serde_json::from_value(serde_json::json!({
            "key":"fixture", "alias":"fixture", "server":"127.0.0.1",
            "port":fixture.port, "username":"fixture", "from_identities":[],
            "credential":{"source":"session"}
        }))
        .unwrap(),
        source: std::sync::Arc::new(FixtureSecret),
    };
    let narrow = mailctl::config::Limits {
        mailbox_inventory: 1,
        mailbox_page: 1,
        ..Default::default()
    };
    assert_eq!(
        runtime.discover_all(&account, &narrow).await,
        Err(Error::Imap(mailctl::imap::Error::Limit))
    );
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn exact_discovery_authenticates_over_verified_tls_and_logs_out_safely() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = expect(&mut wire, "LIST \"\" INBOX").await;
            write(
                &mut wire,
                &format!("* LIST (\\HasNoChildren) \"/\" INBOX\r\n{tag} OK listed\r\n"),
            )
            .await;
            logout(&mut wire).await;
        })
    })
    .await;
    let result = fixture
        .probe
        .discover(
            "fixture",
            "disposable-password",
            &["INBOX".into(), "INBOX".into()],
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "INBOX");
    assert!(result[0].selectable);
    fixture.task.await.unwrap();
    assert_eq!(
        fixture
            .probe
            .discover("", "disposable-password", &["INBOX".into()])
            .await
            .unwrap_err(),
        mailctl::imap::Error::InvalidInput
    );
    let metrics = fixture.probe.metrics();
    assert_eq!(metrics.wire_bytes, 0);
    assert_eq!(metrics.responses, 0);
    assert_eq!(metrics.parser_steps, 0);
}

#[tokio::test]
async fn starttls_refreshes_capabilities_before_login_and_reads_only_bounded_uid_envelopes() {
    let mut fixture = fixture(TlsMode::StartTls, Limits::default(), |mut wire| Box::pin(async move {
        authenticate(&mut wire).await;
        examine(&mut wire).await;
        let tag = expect(&mut wire, "UID SEARCH UID 1:10").await;
        write(&mut wire, &format!("* SEARCH 4 9\r\n{tag} OK searched\r\n")).await;
        let tag = expect(&mut wire, "UID FETCH 4,9 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)").await;
        write(&mut wire, "* 1 FETCH (UID 4 ENVELOPE (NIL \"Synthetic first\" ((\"Sender\" NIL \"sender\" \"example.invalid\")) NIL NIL ((NIL NIL \"reader\" \"example.invalid\")) NIL NIL NIL \"<four@example.invalid>\") FLAGS () INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 412)\r\n").await;
        write(&mut wire, "* 2 FETCH (UID 9 ENVELOPE (NIL \"Synthetic second\" NIL NIL NIL NIL NIL NIL NIL NIL) FLAGS (\\Seen) INTERNALDATE \"02-Sep-2026 12:00:00 +0000\" RFC822.SIZE 819)\r\n").await;
        write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
        logout(&mut wire).await;
    })).await;
    let result = fixture
        .probe
        .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
        .await
        .unwrap();
    assert_eq!(result.position.uid_validity, 77);
    assert_eq!(
        result.messages.iter().map(|e| e.uid).collect::<Vec<_>>(),
        [9, 4]
    );
    assert_eq!(
        result.messages[0]
            .metadata
            .subject
            .value()
            .map(String::as_str),
        Some("Synthetic second")
    );
    assert_eq!(result.messages[0].metadata.flags, ["\\Seen"]);
    assert!(result.messages[1].metadata.flags.is_empty());
    assert_eq!(
        result.messages[1].metadata.from.value().unwrap()[0].address,
        "sender@example.invalid"
    );
    assert_eq!(
        result.messages[1].metadata.to.value().unwrap()[0].address,
        "reader@example.invalid"
    );
    assert_eq!(result.messages[1].metadata.size, 412);
    assert_eq!(
        result.messages[1]
            .metadata
            .message_id
            .value()
            .map(String::as_str),
        Some("<four@example.invalid>")
    );
    assert!(fixture.probe.metrics().wire_bytes < 4096);
    assert!(fixture.probe.metrics().max_response_bytes <= Limits::default().max_response_bytes);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn invalid_envelope_projections_dispose_the_connection() {
    let fields = [
        "UID 4",
        "ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)",
        "FLAGS ()",
        "INTERNALDATE \"01-Sep-2026 12:00:00 +0000\"",
        "RFC822.SIZE 412",
    ];
    let mut cases = Vec::new();
    for index in 0..fields.len() {
        let mut missing = fields.to_vec();
        missing.remove(index);
        cases.push((missing.join(" "), mailctl::imap::Error::Protocol));
        let mut duplicate = fields.to_vec();
        duplicate.push(fields[index]);
        cases.push((duplicate.join(" "), mailctl::imap::Error::Protocol));
    }
    cases.push((
        format!(
            "{} BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 12 1)",
            fields.join(" ")
        ),
        mailctl::imap::Error::Unsupported,
    ));
    for (items, expected) in cases {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                let tag = expect(&mut wire, "UID SEARCH UID 1:10").await;
                write(&mut wire, &format!("* SEARCH 4\r\n{tag} OK searched\r\n")).await;
                expect(
                    &mut wire,
                    "UID FETCH 4 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)",
                )
                .await;
                write(&mut wire, &format!("* 1 FETCH ({items})\r\n")).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
            .await
            .unwrap_err();
        assert_eq!(error.code, mailctl::domain::Error::from(expected).code);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn certificate_hostname_verification_prevents_authentication() {
    let mut fixture = fixture_with_name(
        TlsMode::Implicit,
        Limits::default(),
        "wrong.invalid",
        |_| Box::pin(async { panic!("unverified TLS accepted") }),
    )
    .await;
    let error = fixture
        .probe
        .discover("fixture", "disposable-password", &["INBOX".into()])
        .await
        .unwrap_err();
    assert_eq!(error, mailctl::imap::Error::Tls);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn unsafe_selection_never_reaches_search() {
    for response in [
        "* OK [UIDVALIDITY 77] identity\r\n{tag} OK [READ-WRITE] selected\r\n",
        "{tag} OK [READ-ONLY] selected\r\n",
        "* OK [UIDVALIDITY 77] identity\r\n{tag} OK selected\r\n",
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "EXAMINE INBOX").await;
                write(&mut wire, &response.replace("{tag}", &tag)).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            mailctl::domain::Error::from(mailctl::imap::Error::UnsafeSelection).code
        );
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_referral_and_mismatched_completion_dispose_the_connection() {
    for (response, expected) in [
        ("* bogus malformed\r\n", mailctl::imap::Error::Protocol),
        ("wrongtag OK listed\r\n", mailctl::imap::Error::Protocol),
        (
            "{tag} NO [REFERRAL imap://other.invalid/INBOX] redirected\r\n",
            mailctl::imap::Error::Unsupported,
        ),
        (
            "* LIST () \"/\" Unapproved\r\n{tag} OK listed\r\n",
            mailctl::imap::Error::Protocol,
        ),
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "LIST \"\" INBOX").await;
                write(&mut wire, &response.replace("{tag}", &tag)).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .discover("fixture", "disposable-password", &["INBOX".into()])
            .await
            .unwrap_err();
        assert_eq!(error, expected, "response {response}");
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn starttls_is_required_and_rejection_disposes_the_plaintext_connection() {
    for advertised in [false, true] {
        let mut fixture = plaintext_fixture(Limits::default(), move |mut wire| {
            Box::pin(async move {
                write(&mut wire, "* OK synthetic server ready\r\n").await;
                capability(
                    &mut wire,
                    if advertised {
                        "IMAP4rev1 STARTTLS"
                    } else {
                        "IMAP4rev1"
                    },
                )
                .await;
                if advertised {
                    let tag = expect(&mut wire, "STARTTLS").await;
                    write(&mut wire, &format!("{tag} NO TLS unavailable\r\n")).await;
                }
                dropped(&mut wire).await;
            })
        })
        .await;
        let result = fixture
            .probe
            .discover("fixture", "disposable-password", &["INBOX".into()])
            .await;
        assert!(matches!(
            result,
            Err(mailctl::imap::Error::Unsupported
                | mailctl::imap::Error::Protocol
                | mailctl::imap::Error::Tls)
        ));
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn operation_timeout_disposes_the_connection() {
    let limits = Limits {
        operation_timeout: std::time::Duration::from_secs(1),
        ..Limits::default()
    };
    let mut fixture = fixture(TlsMode::Implicit, limits, |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            expect(&mut wire, "LIST \"\" INBOX").await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let result = fixture
        .probe
        .discover("fixture", "disposable-password", &["INBOX".into()])
        .await;
    assert_eq!(result.unwrap_err(), mailctl::imap::Error::Timeout);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn cancellation_completion_is_observed_by_the_server() {
    let (ready_send, ready_receive) = tokio::sync::oneshot::channel();
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            expect(&mut wire, "LIST \"\" INBOX").await;
            ready_send.send(()).unwrap();
            dropped(&mut wire).await;
        })
    })
    .await;
    let operation = tokio::spawn(async move {
        fixture
            .probe
            .discover("fixture", "disposable-password", &["INBOX".into()])
            .await
    });
    ready_receive.await.unwrap();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn eof_during_a_response_disposes_the_operation() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            expect(&mut wire, "LIST \"\" INBOX").await;
            write(&mut wire, "* LIST () \"/\" {40}\r\npartial").await;
        })
    })
    .await;
    let error = fixture
        .probe
        .discover("fixture", "disposable-password", &["INBOX".into()])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        mailctl::imap::Error::Eof | mailctl::imap::Error::Transport
    ));
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn response_and_parser_work_limits_fail_explicitly() {
    for limits in [
        Limits {
            max_responses: 10,
            ..Limits::default()
        },
        Limits {
            max_parser_steps: 1400,
            ..Limits::default()
        },
        Limits {
            max_response_bytes: 256,
            max_literal_bytes: 128,
            ..Limits::default()
        },
        Limits {
            max_operation_bytes: 512,
            max_response_bytes: 256,
            max_literal_bytes: 128,
            ..Limits::default()
        },
    ] {
        let ceiling = limits.clone();
        let response = if limits.max_response_bytes == 256 && limits.max_operation_bytes != 512 {
            format!("* OK {}\r\n", "progress".repeat(80))
        } else {
            "* OK unsolicited progress\r\n".repeat(24)
        };
        let mut fixture = fixture(TlsMode::Implicit, limits, move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                expect(&mut wire, "LIST \"\" INBOX").await;
                // One write keeps the fault independent of how much input the client accepts.
                write(&mut wire, &response).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .discover("fixture", "disposable-password", &["INBOX".into()])
            .await
            .unwrap_err();
        assert_eq!(error, mailctl::imap::Error::Limit);
        let metrics = fixture.probe.metrics();
        assert!(metrics.max_response_bytes <= ceiling.max_response_bytes);
        assert!(metrics.parser_steps <= ceiling.max_parser_steps);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn parser_limit_metrics_include_the_last_consumed_byte() {
    let limits = Limits {
        max_parser_steps: 1,
        ..Limits::default()
    };
    let mut fixture = fixture(TlsMode::Implicit, limits, |mut wire| {
        Box::pin(async move { dropped(&mut wire).await })
    })
    .await;
    let error = fixture
        .probe
        .discover("fixture", "disposable-password", &["INBOX".into()])
        .await
        .unwrap_err();
    assert_eq!(error, mailctl::imap::Error::Limit);
    let metrics = fixture.probe.metrics();
    assert_eq!(metrics.wire_bytes, 1);
    assert_eq!(metrics.max_response_bytes, 1);
    assert_eq!(metrics.parser_steps, 1);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn missing_or_duplicate_search_data_cannot_claim_an_empty_result() {
    for response in [
        "{tag} OK searched\r\n",
        "* SEARCH 4\r\n* SEARCH\r\n{tag} OK searched\r\n",
        "* SEARCH 11\r\n{tag} OK searched\r\n",
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                let tag = expect(&mut wire, "UID SEARCH UID 1:10").await;
                write(&mut wire, &response.replace("{tag}", &tag)).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            mailctl::domain::Error::from(mailctl::imap::Error::Protocol).code
        );
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn unsolicited_uid_ranges_are_rejected_before_backend_expansion() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            expect(&mut wire, "EXAMINE INBOX").await;
            write(&mut wire, "* VANISHED (EARLIER) 1:4294967295\r\n").await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let error = fixture
        .probe
        .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
        .await
        .unwrap_err();
    assert_eq!(
        error.code,
        mailctl::domain::Error::from(mailctl::imap::Error::Unsupported).code
    );
    assert!(fixture.probe.metrics().max_response_bytes < 256);
    fixture.task.await.unwrap();
}

#[test]
fn client_allocations_remain_bounded_for_discovery_envelopes_and_oversized_literals() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for route in [
        "discovery",
        "all-discovery",
        "envelopes",
        "large-envelope",
        "starttls",
        "oversized-literal",
    ] {
        let (mut probe, server) = dedicated_fixture(
            if route == "starttls" {
                TlsMode::StartTls
            } else {
                TlsMode::Implicit
            },
            Limits::default(),
            move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    if route == "discovery" || route == "all-discovery" {
                        let command = if route == "all-discovery" {
                            "LIST \"\" \"*\""
                        } else {
                            "LIST \"\" INBOX"
                        };
                        let tag = expect(&mut wire, command).await;
                        let rows = if route == "all-discovery" {
                            (0..1000)
                                .map(|index| format!("* LIST () \"/\" Folder{index:04}\r\n"))
                                .collect::<String>()
                        } else {
                            "* LIST () \"/\" INBOX\r\n".into()
                        };
                        write(&mut wire, &format!("{rows}{tag} OK listed\r\n")).await;
                        logout(&mut wire).await;
                    } else {
                        examine(&mut wire).await;
                        let tag = expect(&mut wire, "UID SEARCH UID 1:10").await;
                        write(&mut wire, &format!("* SEARCH 4\r\n{tag} OK searched\r\n")).await;
                        let tag = expect(
                            &mut wire,
                            "UID FETCH 4 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)",
                        )
                        .await;
                        if route == "oversized-literal" {
                            // Announce 32 MiB without sending any literal payload.
                            write(&mut wire, "* 1 FETCH (UID 4 ENVELOPE (NIL {33554432}\r\n").await;
                            dropped(&mut wire).await;
                        } else if route == "large-envelope" {
                            let subject = "s".repeat(60 * 1024);
                            write(&mut wire, &format!("* 1 FETCH (UID 4 ENVELOPE (NIL {{{}}}\r\n{} NIL NIL NIL NIL NIL NIL NIL NIL) FLAGS () INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 65536)\r\n{tag} OK fetched\r\n", subject.len(), subject)).await;
                            logout(&mut wire).await;
                        } else {
                            write(&mut wire, &format!("* 1 FETCH (UID 4 ENVELOPE (NIL \"Synthetic\" NIL NIL NIL NIL NIL NIL NIL NIL) FLAGS () INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 412)\r\n{tag} OK fetched\r\n")).await;
                            logout(&mut wire).await;
                        }
                    }
                })
            },
        );
        let allocations = allocation_counter::measure(|| {
            runtime.block_on(async {
                if route == "all-discovery" {
                    let inventory = probe
                        .discover_all("fixture", "disposable-password")
                        .await
                        .unwrap();
                    assert_eq!(inventory.len(), 1000);
                    assert_eq!(inventory[0].name, "Folder0000");
                    assert_eq!(inventory[999].name, "Folder0999");
                } else if route == "discovery" {
                    assert_eq!(
                        probe
                            .discover("fixture", "disposable-password", &["INBOX".into()])
                            .await
                            .unwrap()
                            .len(),
                        1
                    );
                } else {
                    let result = probe
                        .search_window("fixture", "disposable-password", "INBOX", 77, 1..=10)
                        .await;
                    if route == "oversized-literal" {
                        assert_eq!(
                            result.unwrap_err().code,
                            mailctl::domain::ErrorCode::ResponseTooLarge
                        );
                    } else {
                        let envelope = result.unwrap().messages.remove(0);
                        assert_eq!(envelope.uid, 4);
                        if route == "large-envelope" {
                            assert_eq!(envelope.metadata.subject.value().unwrap().len(), 60 * 1024);
                        }
                    }
                }
            });
        });
        server.join().unwrap();
        let metrics = probe.metrics();
        eprintln!(
            "{route}: allocation_peak={} allocation_total={} allocations={} wire_bytes={} parser_steps={} responses={} largest_response_frame={}",
            allocations.bytes_max,
            allocations.bytes_total,
            allocations.count_total,
            metrics.wire_bytes,
            metrics.parser_steps,
            metrics.responses,
            metrics.max_response_bytes
        );
        assert!(
            allocations.bytes_max < 2 * 1024 * 1024,
            "{route}: {allocations:?}"
        );
        assert!(
            allocations.bytes_total < 16 * 1024 * 1024,
            "{route}: {allocations:?}"
        );
        assert!(allocations.count_total < 100_000);
        if route == "all-discovery" {
            assert!(
                allocations.count_total < 9_000,
                "mailbox discovery must avoid repeated frame allocation: {allocations:?}"
            );
        }
        if route == "large-envelope" {
            assert!(
                allocations.bytes_max < 440 * 1024,
                "large source headers must not retain an extra frame-sized buffer: {allocations:?}"
            );
        }
        assert!(metrics.wire_bytes < 64 * 1024);
        assert!(metrics.parser_steps < 256 * 1024);
        if route == "oversized-literal" {
            assert_eq!(
                metrics.max_literal_bytes, 0,
                "rejected literal was never admitted"
            );
        }
    }
}

#[tokio::test]
async fn exact_discovery_preserves_spaces_ampersands_and_fragmented_responses() {
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = expect(&mut wire, "LIST \"\" \"A&-B Box\"").await;
            let response = format!("* LIST (\\Noselect) \"/\" \"A&-B Box\"\r\n{tag} OK listed\r\n");
            for fragment in response.as_bytes().chunks(2) {
                use tokio::io::AsyncWriteExt;
                wire.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
            logout(&mut wire).await;
        })
    })
    .await;
    let result = fixture
        .probe
        .discover("fixture", "disposable-password", &["A&B Box".into()])
        .await
        .unwrap();
    assert_eq!(result[0].name, "A&B Box");
    assert!(!result[0].selectable);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn excessive_nesting_and_invalid_literal_declarations_dispose_connections() {
    for (response, expected) in [
        (
            format!("* LIST {}\r\n", "(".repeat(50)),
            mailctl::imap::Error::Limit,
        ),
        (
            "* LIST () \"/\" {18446744073709551616}\r\n".into(),
            mailctl::imap::Error::Protocol,
        ),
    ] {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                expect(&mut wire, "LIST \"\" INBOX").await;
                write(&mut wire, &response).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .discover("fixture", "disposable-password", &["INBOX".into()])
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn discovery_inputs_are_bounded_before_mailbox_dispatch() {
    use mailctl::imap::Error;
    let mut cases = ["bad\r\nname", "bad\u{7f}name", "bad\u{85}name"]
        .into_iter()
        .map(|name| (vec![name.into()], Error::Unsupported))
        .collect::<Vec<_>>();
    cases.push((vec![String::new()], Error::InvalidInput));
    cases.push((vec!["x".repeat(1025)], Error::InvalidInput));
    cases.push((vec!["INBOX".into(); 1001], Error::Limit));
    for (names, expected) in cases {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        assert_eq!(
            fixture
                .probe
                .discover("fixture", "disposable-password", &names)
                .await
                .unwrap_err(),
            expected
        );
        fixture.task.await.unwrap();
    }
}
