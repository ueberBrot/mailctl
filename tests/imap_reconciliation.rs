mod append_support;
mod imap_support;
use imap_support::*;
use mailctl::{
    draft::{DraftEvidence, DraftMessageIdentity, DraftVerification},
    imap::{Limits, TlsMode},
};

#[tokio::test]
async fn reconciliation_verifies_frozen_mime_with_only_examine_search_and_peek() {
    let draft = append_support::draft();
    let bytes = draft.bytes().to_vec();
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = expect(&mut wire, "EXAMINE Drafts").await;
            write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 77] incarnation\r\n* OK [UIDNEXT 5] next\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
            let tag = expect(&mut wire, "UID SEARCH UID 1:4 HEADER Message-ID operation@example.test").await;
            write(&mut wire, &format!("* SEARCH 4\r\n{tag} OK found\r\n")).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[]<0.16384>)").await;
            write(&mut wire, &format!("* 1 FETCH (UID 4 BODY[]<0> {{{}}}\r\n", bytes.len())).await;
            use tokio::io::AsyncWriteExt;
            wire.write_all(&bytes).await.unwrap();
            write(&mut wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
            dropped(&mut wire).await;
        })
    }).await;
    let evidence = fixture
        .probe
        .reconcile_draft(
            &DraftVerification {
                uid_validity: 77,
                message_id: "operation@example.test".into(),
                content_sha256: draft.sha256(),
            },
            &Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        evidence,
        DraftEvidence::Verified(DraftMessageIdentity {
            uid_validity: 77,
            uid: 4
        })
    );
    assert_eq!(fixture.probe.metrics().append_wire_bytes, 0);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn reconciliation_scales_fetches_to_a_tight_wire_budget() {
    let draft = append_support::draft();
    let bytes = draft.bytes().to_vec();
    let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = expect(&mut wire, "EXAMINE Drafts").await;
            write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 77] incarnation\r\n* OK [UIDNEXT 5] next\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
            let tag = expect(&mut wire, "UID SEARCH UID 1:4 HEADER Message-ID operation@example.test").await;
            write(&mut wire, &format!("* SEARCH 4\r\n{tag} OK found\r\n")).await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[]<0.2048>)").await;
            write(&mut wire, &format!("* 1 FETCH (UID 4 BODY[]<0> {{{}}}\r\n", bytes.len())).await;
            use tokio::io::AsyncWriteExt;
            wire.write_all(&bytes).await.unwrap();
            write(&mut wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
            dropped(&mut wire).await;
        })
    }).await;
    let limits = mailctl::config::Limits {
        wire_fetch_bytes: 4096,
        ..Default::default()
    };
    let evidence = fixture
        .probe
        .reconcile_draft(
            &DraftVerification {
                uid_validity: 77,
                message_id: "operation@example.test".into(),
                content_sha256: draft.sha256(),
            },
            &limits,
        )
        .await
        .unwrap();
    assert_eq!(
        evidence,
        DraftEvidence::Verified(DraftMessageIdentity {
            uid_validity: 77,
            uid: 4
        })
    );
    assert!(fixture.probe.metrics().wire_bytes <= limits.wire_fetch_bytes);
    fixture.task.await.unwrap();
}

#[tokio::test]
async fn incomplete_or_ambiguous_evidence_never_verifies_a_draft() {
    for scenario in [
        "absent",
        "multiple",
        "substring",
        "hash",
        "stale",
        "budget",
        "header",
        "mime",
        "unsolicited",
        "literal",
        "timeout",
    ] {
        let draft = append_support::draft();
        let mut bytes = draft.bytes().to_vec();
        if scenario == "substring" {
            bytes = String::from_utf8(bytes)
                .unwrap()
                .replace("<operation@example.test>", "<prefixoperation@example.test>")
                .into_bytes();
        }
        if scenario == "hash" {
            bytes.push(b'x');
        }
        let verification_hash = if scenario == "substring" {
            use sha2::Digest;
            sha2::Sha256::digest(&bytes).into()
        } else {
            draft.sha256()
        };
        let mut limits = mailctl::config::Limits::default();
        if scenario == "timeout" {
            limits.initialization_seconds = 1;
            limits.operation_seconds = 1;
            limits.connection_seconds = 1;
        }
        if scenario == "budget" {
            limits.search_windows = 1;
            limits.search_uid_window = 2;
        }
        if scenario == "header" {
            limits.header_bytes = 8;
        }
        if scenario == "mime" {
            limits.draft_mime_bytes = 8;
        }
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                let tag = expect(&mut wire, "EXAMINE Drafts").await;
                let validity = if scenario == "stale" { 88 } else { 77 };
                write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY {validity}] incarnation\r\n* OK [UIDNEXT 5] next\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                if scenario == "stale" { dropped(&mut wire).await; return; }
                let range = if scenario == "budget" { "1:2" } else { "1:4" };
                let tag = expect(&mut wire, &format!("UID SEARCH UID {range} HEADER Message-ID operation@example.test")).await;
                let found = match scenario { "absent" | "budget" => "", "multiple" => " 3 4", "unsolicited" => " 5", _ => " 4" };
                write(&mut wire, &format!("* SEARCH{found}\r\n{tag} OK found\r\n")).await;
                if matches!(scenario, "absent" | "multiple" | "budget" | "unsolicited") { dropped(&mut wire).await; return; }
                let count = if scenario == "mime" { 9 } else { 16384 };
                let tag = expect(&mut wire, &format!("UID FETCH 4 (UID BODY.PEEK[]<0.{count}>)")).await;
                if scenario == "timeout" { dropped(&mut wire).await; return; }
                if scenario == "literal" {
                    write(&mut wire, "* 1 FETCH (UID 4 BODY[]<0> {16385}\r\n").await;
                    dropped(&mut wire).await; return;
                }
                let bytes = &bytes[..bytes.len().min(count)];
                write(&mut wire, &format!("* 1 FETCH (UID 4 BODY[]<0> {{{}}}\r\n", bytes.len())).await;
                use tokio::io::AsyncWriteExt;
                wire.write_all(bytes).await.unwrap();
                write(&mut wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
                dropped(&mut wire).await;
            })
        }).await;
        let result = fixture
            .probe
            .reconcile_draft(
                &DraftVerification {
                    uid_validity: 77,
                    message_id: "operation@example.test".into(),
                    content_sha256: verification_hash,
                },
                &limits,
            )
            .await;
        let expected = match scenario {
            "absent" => Ok(DraftEvidence::Absent),
            "multiple" => Ok(DraftEvidence::Ambiguous),
            "substring" | "hash" => Ok(DraftEvidence::ContentMismatch),
            "stale" => Err(mailctl::imap::Error::StaleReference),
            "unsolicited" => Err(mailctl::imap::Error::Protocol),
            "timeout" => Err(mailctl::imap::Error::Timeout),
            _ => Err(mailctl::imap::Error::Limit),
        };
        assert_eq!(result, expected, "{scenario}");
        assert_eq!(fixture.probe.metrics().append_wire_bytes, 0);
        fixture.task.await.unwrap();
    }
}

#[test]
fn multi_chunk_reconciliation_has_bounded_memory_wire_and_parser_work() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut peaks = Vec::new();
    for size in [16 * 1024, 512 * 1024] {
        let mut input = append_support::input();
        input.body = "x\n".repeat(size / 2);
        let draft = mailctl::draft::PreparedDraft::compose(input, 1024 * 1024).unwrap();
        let bytes = draft.bytes().to_vec();
        let (mut client, server) = dedicated_fixture(
            TlsMode::Implicit,
            Limits::default(),
            move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    let tag = expect(&mut wire, "EXAMINE Drafts").await;
                    write(&mut wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 77] incarnation\r\n* OK [UIDNEXT 5] next\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                    let tag = expect(
                        &mut wire,
                        "UID SEARCH UID 1:4 HEADER Message-ID operation@example.test",
                    )
                    .await;
                    write(&mut wire, &format!("* SEARCH 4\r\n{tag} OK found\r\n")).await;
                    for offset in (0..=bytes.len()).step_by(16384) {
                        let part = &bytes[offset..bytes.len().min(offset + 16384)];
                        let tag = expect(
                            &mut wire,
                            &format!("UID FETCH 4 (UID BODY.PEEK[]<{offset}.16384>)"),
                        )
                        .await;
                        write(
                            &mut wire,
                            &format!("* 1 FETCH (UID 4 BODY[]<{offset}> {{{}}}\r\n", part.len()),
                        )
                        .await;
                        use tokio::io::AsyncWriteExt;
                        wire.write_all(part).await.unwrap();
                        write(&mut wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
                    }
                    dropped(&mut wire).await;
                })
            },
        );
        let expected = DraftVerification {
            uid_validity: 77,
            message_id: "operation@example.test".into(),
            content_sha256: draft.sha256(),
        };
        let limits = mailctl::config::Limits::default();
        let measured = allocation_counter::measure(|| {
            let result = runtime
                .block_on(client.reconcile_draft(&expected, &limits))
                .unwrap();
            assert_eq!(
                result,
                DraftEvidence::Verified(DraftMessageIdentity {
                    uid_validity: 77,
                    uid: 4
                })
            );
        });
        server.join().unwrap();
        let metrics = client.metrics();
        assert!(metrics.max_literal_bytes <= 16384);
        assert!(metrics.max_response_bytes <= 20 * 1024);
        assert!(metrics.wire_bytes <= limits.wire_fetch_bytes);
        assert!(metrics.parser_steps <= metrics.wire_bytes * 4 + 1024);
        assert_eq!(metrics.append_wire_bytes, 0);
        assert!(measured.bytes_max < 512 * 1024, "{measured:?}");
        eprintln!(
            "RECONCILE mime={} wire={} parser_steps={} peak={}",
            draft.bytes().len(),
            metrics.wire_bytes,
            metrics.parser_steps,
            measured.bytes_max
        );
        peaks.push(measured.bytes_max);
    }
    assert!(
        peaks[1] <= peaks[0] + 64 * 1024,
        "MIME-sized allocation: {peaks:?}"
    );
}
