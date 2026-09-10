//! Measure the exact typed search routine used by application requests.
#[allow(dead_code)]
mod imap_support;
use imap_support::*;
use mailctl::{
    config,
    domain::{ErrorCode, SearchCriteria},
    imap::{Limits, TlsMode},
    service::SearchRequest,
};
use tokio::io::AsyncReadExt;

async fn select(wire: &mut Wire, upper: u32) {
    let tag = expect(wire, "EXAMINE INBOX").await;
    write(wire, &format!("* OK [UIDVALIDITY 7] stable\r\n* OK [UIDNEXT {}] next\r\n{tag} OK [READ-ONLY] selected\r\n", upper+1)).await;
}
async fn row(wire: &mut Wire, uid: u32, subject: &str) {
    write(wire, &format!("* {uid} FETCH (UID {uid} ENVELOPE (NIL \"{subject}\" NIL NIL NIL NIL NIL NIL NIL NIL) FLAGS () INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 1)\r\n")).await;
}
async fn line(wire: &mut Wire) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n") {
        bytes.push(wire.read_u8().await.unwrap());
        assert!(bytes.len() <= 1024);
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn maximum_fragmented_search_and_page_have_bounded_client_resources() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let term = format!("{}\r\n", "x".repeat(4094));
    let criteria: SearchCriteria = serde_json::from_value(serde_json::json!(vec![
        serde_json::json!({"field":"text","value":term});
        32
    ]))
    .unwrap();
    let (mut probe, server) =
        dedicated_fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                select(&mut wire, 200).await;
                let initial = line(&mut wire).await;
                let (tag, command) = initial.split_once(' ').unwrap();
                assert_eq!(command, "UID SEARCH UID 1:200 TEXT {4096}\r\n");
                for index in 0..32 {
                    if index > 0 {
                        assert_eq!(line(&mut wire).await, " TEXT {4096}\r\n");
                    }
                    write(&mut wire, "+ continue\r\n").await;
                    let mut literal = vec![0; 4096];
                    wire.read_exact(&mut literal).await.unwrap();
                    assert_eq!(literal, term.as_bytes());
                }
                assert_eq!(line(&mut wire).await, "\r\n");
                let matches = (1..=200)
                    .map(|uid| uid.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                write(
                    &mut wire,
                    &format!("* SEARCH {matches}\r\n{tag} OK searched\r\n"),
                )
                .await;
                let tag = expect(
                    &mut wire,
                    "UID FETCH 1:200 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)",
                )
                .await;
                for uid in 1..=200 {
                    row(&mut wire, uid, "synthetic").await;
                }
                write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
                logout(&mut wire).await;
            })
        });
    let limits = config::Limits {
        search_page: 200,
        ..Default::default()
    };
    let allocations = allocation_counter::measure(|| {
        runtime.block_on(async {
            let batch = probe
                .search_messages(
                    "fixture",
                    "disposable-password",
                    SearchRequest {
                        mailbox: "INBOX",
                        criteria: &criteria,
                        position: None,
                        limit: 200,
                        response_bytes: 1024 * 1024,
                    },
                    &limits,
                )
                .await
                .unwrap();
            assert_eq!(batch.messages.len(), 200);
            assert_eq!(batch.position.next_uid, 0);
        })
    });
    server.join().unwrap();
    let metrics = probe.metrics();
    eprintln!(
        "typed-search peak={} total={} allocations={} wire={} parser={} responses={} largest_frame={}",
        allocations.bytes_max,
        allocations.bytes_total,
        allocations.count_total,
        metrics.wire_bytes,
        metrics.parser_steps,
        metrics.responses,
        metrics.max_response_bytes
    );
    assert!(allocations.bytes_max < 8 * 1024 * 1024, "{allocations:?}");
    assert!(
        allocations.bytes_total < 32 * 1024 * 1024,
        "{allocations:?}"
    );
    assert!(metrics.wire_bytes < 64 * 1024);
    assert!(metrics.parser_steps < 512 * 1024);
    assert!(metrics.responses < 256);
    assert!(metrics.max_response_bytes < 2048);
}

#[test]
fn source_header_limits_precede_normalization_and_remain_separate_from_json() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (header_limit, malformed, extra) in [
        (1024, false, 0),
        (1024, true, 1),
        (256 * 1024, false, 0),
        (256 * 1024, true, 1),
    ] {
        let (mut probe, server) =
            dedicated_fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    select(&mut wire, 1).await;
                    let tag = expect(&mut wire, "UID SEARCH UID 1").await;
                    write(&mut wire, &format!("* SEARCH 1\r\n{tag} OK searched\r\n")).await;
                    let tag = expect(
                        &mut wire,
                        "UID FETCH 1 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)",
                    )
                    .await;
                    let subject = if malformed {
                        format!("{}\u{1}", "x".repeat(header_limit))
                    } else {
                        "\\\\".repeat(header_limit)
                    };
                    row(&mut wire, 1, &subject).await;
                    if extra == 0 {
                        write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
                        logout(&mut wire).await;
                    } else {
                        write(&mut wire, &format!("{tag} OK fetched\r\n")).await;
                        dropped(&mut wire).await;
                    }
                })
            });
        let limits = config::Limits {
            header_bytes: header_limit,
            ..Default::default()
        };
        let criteria = SearchCriteria::default();
        let result = runtime.block_on(probe.search_messages(
            "fixture",
            "disposable-password",
            SearchRequest {
                mailbox: "INBOX",
                criteria: &criteria,
                position: None,
                limit: 1,
                response_bytes: 2 * 1024 * 1024,
            },
            &limits,
        ));
        if extra == 0 {
            assert_eq!(
                result.unwrap().messages[0]
                    .metadata
                    .subject
                    .value()
                    .unwrap()
                    .len(),
                header_limit
            );
        } else {
            assert_eq!(result.err().unwrap().code, ErrorCode::ResponseTooLarge);
        }
        assert!(probe.metrics().max_response_bytes <= 2 * header_limit + 2048);
        server.join().unwrap();
    }
}

#[test]
fn narrow_wire_budget_and_oversized_literals_stop_reading_before_payload_allocation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for literal in [false, true] {
        let (mut probe, server) =
            dedicated_fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    select(&mut wire, 1000).await;
                    let tag = expect(&mut wire, "UID SEARCH UID 1:1000").await;
                    if literal {
                        write(&mut wire, &format!("* SEARCH 1\r\n{tag} OK searched\r\n")).await;
                        expect(
                            &mut wire,
                            "UID FETCH 1 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)",
                        )
                        .await;
                        write(&mut wire, "* 1 FETCH (UID 1 ENVELOPE (NIL {1025}\r\n").await;
                    } else {
                        let matches = (1..=1000)
                            .map(|uid| uid.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        write(
                            &mut wire,
                            &format!("* SEARCH {matches}\r\n{tag} OK searched\r\n"),
                        )
                        .await;
                    }
                    dropped(&mut wire).await;
                })
            });
        let limits = config::Limits {
            header_bytes: 1024,
            wire_fetch_bytes: 1024,
            ..Default::default()
        };
        let criteria = SearchCriteria::default();
        let allocations = allocation_counter::measure(|| {
            runtime.block_on(async {
                let error = probe
                    .search_messages(
                        "fixture",
                        "disposable-password",
                        SearchRequest {
                            mailbox: "INBOX",
                            criteria: &criteria,
                            position: None,
                            limit: 1,
                            response_bytes: 1024 * 1024,
                        },
                        &limits,
                    )
                    .await
                    .err()
                    .unwrap();
                assert_eq!(error.code, ErrorCode::ResponseTooLarge);
            })
        });
        assert!(probe.metrics().wire_bytes <= 1024);
        assert!(allocations.bytes_max < 1024 * 1024, "{allocations:?}");
        server.join().unwrap();
    }
}

#[test]
fn maximum_window_budget_retains_continuation_after_empty_live_queries() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut probe, server) =
        dedicated_fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                select(&mut wire, 1_000_001).await;
                for index in 0..100 {
                    let last = 1_000_001 - index * 10_000;
                    let first = last - 9_999;
                    let tag = expect(&mut wire, &format!("UID SEARCH UID {first}:{last}")).await;
                    write(&mut wire, &format!("* SEARCH\r\n{tag} OK searched\r\n")).await;
                }
                logout(&mut wire).await;
            })
        });
    let limits = config::Limits {
        search_windows: 100,
        search_uid_window: 10_000,
        ..Default::default()
    };
    let criteria = SearchCriteria::default();
    let batch = runtime
        .block_on(probe.search_messages(
            "fixture",
            "disposable-password",
            SearchRequest {
                mailbox: "INBOX",
                criteria: &criteria,
                position: None,
                limit: 1,
                response_bytes: 1024 * 1024,
            },
            &limits,
        ))
        .unwrap();
    assert!(batch.messages.is_empty());
    assert_eq!(batch.position.upper_uid, 1_000_001);
    assert_eq!(batch.position.next_uid, 1);
    assert!(probe.metrics().responses < 220);
    assert!(probe.metrics().parser_steps < 64 * 1024);
    server.join().unwrap();
}
