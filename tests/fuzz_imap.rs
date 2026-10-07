mod fuzz_support;
mod imap_support;

use fuzz_support::{Campaign, MAX_INPUT_BYTES};
use imap_support::*;
use io_imap::{
    codec::{CommandCodec, decode::Decoder},
    types::command::CommandBody,
};
use mailctl::{
    config,
    draft::{DraftEvidence, DraftVerification},
    imap::{BodyRequest, Error, Limits, Metrics, TlsMode},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

// A route byte and NUL precede each raw transcript, preserving binary corpus bytes.
const TRUNCATED_LITERAL: &[u8] = include_bytes!("fuzz_corpus/imap/truncated-literal.imap");
const CORPUS: &[Case] = &[
    Case {
        input: include_bytes!("fuzz_corpus/imap/list.imap"),
        expected: Expected::Listed(&["INBOX"]),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/body.imap"),
        expected: Expected::Read("Short body.\r\n"),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/oversized-literal.imap"),
        expected: Expected::Rejected(Error::Limit),
    },
    Case {
        input: TRUNCATED_LITERAL,
        expected: Expected::Rejected(Error::Eof),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/wrong-tag.imap"),
        expected: Expected::Rejected(Error::Protocol),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/draft-absent.imap"),
        expected: Expected::Draft(DraftEvidence::Absent),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/draft-verified.imap"),
        expected: Expected::Draft(DraftEvidence::Verified(
            mailctl::draft::DraftMessageIdentity {
                uid_validity: 77,
                uid: 4,
            },
        )),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/draft-outside-window.imap"),
        expected: Expected::Rejected(Error::Protocol),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/literal-syntax.imap"),
        expected: Expected::Read("x\r\n* BYE\r\ny\r\n"),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/excessive-nesting.imap"),
        expected: Expected::Rejected(Error::Limit),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/response-flood.imap"),
        expected: Expected::Rejected(Error::Limit),
    },
    Case {
        input: include_bytes!("fuzz_corpus/imap/oversized-line.imap"),
        expected: Expected::Rejected(Error::Limit),
    },
    Case {
        // Reduced from seed 35002, case 0: malformed tagged response disposes TLS.
        input: include_bytes!("fuzz_corpus/imap/malformed-tagged-response.imap"),
        expected: Expected::Rejected(Error::Protocol),
    },
];
const HEADERS: &[u8] = b"Content-Type: multipart/mixed; boundary=fixture\r\n\r\n";
const STRUCTURE: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL) \"MIXED\" (\"BOUNDARY\" \"fixture\") NIL NIL NIL)";
const DRAFT: &[u8] = b"Message-ID: <fuzz-draft@example.invalid>\r\n\r\nUnsent fixture\r\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    List,
    Body,
    Reconcile,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Listed(Vec<String>),
    Read(String),
    Draft(DraftEvidence),
    Rejected(Error),
}

enum Expected {
    Listed(&'static [&'static str]),
    Read(&'static str),
    Draft(DraftEvidence),
    Rejected(Error),
}

struct Case {
    input: &'static [u8],
    expected: Expected,
}

fn limits() -> Limits {
    Limits {
        max_response_bytes: 2048,
        max_operation_bytes: 8192,
        max_literal_bytes: 1024,
        max_responses: 32,
        max_parser_steps: 32 * 1024,
        max_nesting: 8,
        max_mailboxes: 4,
        max_header_bytes: 1024,
        max_body_wire_bytes: 2048,
        max_decoded_bytes: 2048,
        max_text_bytes: 2048,
        max_decode_steps: 8192,
        operation_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        ..Limits::default()
    }
}

fn draft_limits() -> config::Limits {
    config::Limits {
        operation_seconds: 1,
        connection_seconds: 1,
        initialization_seconds: 1,
        wire_fetch_bytes: 8192,
        header_bytes: 1024,
        draft_mime_bytes: 1024,
        search_uid_window: 8,
        search_windows: 1,
        ..Default::default()
    }
}

/// The server checks outgoing commands independently of the production wire guard.
async fn observe_cleanup(wire: &mut Wire, route: Route, commands: &AtomicUsize) {
    let mut verified = false;
    while let Some(command) = observe_command(wire, Duration::from_secs(3)).await {
        commands.fetch_add(1, Ordering::Relaxed);
        match command.body {
            CommandBody::Logout if route != Route::Reconcile => {
                let tag = command.tag.as_ref();
                let reply = format!("* BYE closing\r\n{tag} OK logout\r\n");
                if wire.write_all(reply.as_bytes()).await.is_ok() {
                    let _ = wire.flush().await;
                }
            }
            body if route == Route::Reconcile && !verified => {
                let codec = CommandCodec::new();
                let (_, expected) = codec
                    .decode(b"expected UID FETCH 4 (UID BODY.PEEK[]<0.1025>)\r\n")
                    .unwrap();
                assert!(
                    body == expected.body,
                    "unexpected command or mailbox mutation"
                );
                verified = true;
                let tag = command.tag.as_ref();
                let prefix = format!("* 1 FETCH (UID 4 BODY[]<0> {{{}}}\r\n", DRAFT.len());
                if wire.write_all(prefix.as_bytes()).await.is_err()
                    || wire.write_all(DRAFT).await.is_err()
                    || wire
                        .write_all(format!(")\r\n{tag} OK fetched\r\n").as_bytes())
                        .await
                        .is_err()
                {
                    return;
                }
                let _ = wire.flush().await;
            }
            _ => panic!("unexpected command or mailbox mutation"),
        }
    }
}

async fn send_case(wire: &mut Wire, bytes: &[u8], fragment: usize) {
    for chunk in bytes.chunks(fragment) {
        if wire.write_all(chunk).await.is_err() || wire.flush().await.is_err() {
            return;
        }
        tokio::task::yield_now().await;
    }
}

fn run_case(input: &[u8], index: usize, hold_open: bool) -> Outcome {
    assert!(input.len() <= MAX_INPUT_BYTES, "input ceiling");
    let route = match input.first() {
        Some(b'B') => Route::Body,
        Some(b'D') => Route::Reconcile,
        _ => Route::List,
    };
    let response = input.get(2..).unwrap_or_default().to_vec();
    let fragment = [1, 2, 7, 31, MAX_INPUT_BYTES][index % 5];
    let sent = Arc::new(AtomicUsize::new(0));
    let commands = Arc::new(AtomicUsize::new(0));
    let server_sent = sent.clone();
    let server_commands = commands.clone();
    let bounds = limits();
    let (mut client, server) = dedicated_fixture(TlsMode::Implicit, bounds.clone(), move |wire| {
        let mut wire: Wire = Box::new(CountedWire {
            wire,
            written: server_sent,
        });
        Box::pin(async move {
            let script = async {
                authenticate(&mut wire).await;
                let tag = match route {
                    Route::List => expect(&mut wire, "LIST \"\" INBOX").await,
                    Route::Body => {
                        examine(&mut wire).await;
                        let tag =
                            expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
                        write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000000 BODYSTRUCTURE {STRUCTURE})\r\n{tag} OK fetched\r\n")).await;
                        literal_bytes(&mut wire, "HEADER", 0, 1024, HEADERS).await;
                        expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[1]<0.14>)").await
                    }
                    Route::Reconcile => {
                        let tag = expect(&mut wire, "EXAMINE Drafts").await;
                        write(&mut wire, &format!("* FLAGS (\\Draft)\r\n* 1 EXISTS\r\n* OK [UIDVALIDITY 77] identity\r\n* OK [UIDNEXT 9] upper\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                        expect(
                            &mut wire,
                            "UID SEARCH UID 1:8 HEADER Message-ID fuzz-draft@example.invalid",
                        )
                        .await
                    }
                };
                // Lossy Unicode conversion would change the bytes being fuzzed.
                let mut response = response;
                while let Some(offset) = response.windows(5).position(|bytes| bytes == b"{tag}") {
                    response.splice(offset..offset + 5, tag.bytes());
                }
                send_case(&mut wire, &response, fragment).await;
                // Truncation also exercises EOF, while the retained delayed-literal case
                // keeps the transport open until the operation's deadline disposes it.
                if !hold_open
                    && !response
                        .windows(tag.len())
                        .any(|bytes| bytes == tag.as_bytes())
                {
                    let _ = wire.shutdown().await;
                }
                observe_cleanup(&mut wire, route, &server_commands).await;
            };
            tokio::time::timeout(Duration::from_secs(3), script)
                .await
                .expect("independent server deadline");
        })
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = Instant::now();
    let mut metrics = Metrics::default();
    let mut result = None;
    let measured = allocation_counter::measure(|| {
        runtime.block_on(async {
            let outcome = match route {
                Route::List => client
                    .discover("fixture", "disposable-password", &["INBOX".into()])
                    .await
                    .map(|rows| {
                        assert!(rows.len() <= 1, "exact mailbox inventory");
                        assert!(
                            rows.iter().all(|row| row.name == "INBOX"),
                            "unapproved mailbox"
                        );
                        Outcome::Listed(rows.into_iter().map(|row| row.name).collect())
                    }),
                Route::Body => client
                    .read_body(
                        "fixture",
                        "disposable-password",
                        "INBOX",
                        BodyRequest::new(4, 77),
                    )
                    .await
                    .map(|page| {
                        assert!(
                            page.text.len() <= bounds.max_text_bytes,
                            "text page ceiling"
                        );
                        assert!(
                            page.metrics.decode_steps <= bounds.max_decode_steps,
                            "decode work ceiling"
                        );
                        assert!(
                            page.metrics.decoded_bytes <= bounds.max_decoded_bytes,
                            "decoded byte ceiling"
                        );
                        Outcome::Read(page.text)
                    }),
                Route::Reconcile => client
                    .reconcile_draft(
                        &DraftVerification {
                            uid_validity: 77,
                            message_id: "fuzz-draft@example.invalid".into(),
                            content_sha256: Sha256::digest(DRAFT).into(),
                        },
                        &draft_limits(),
                    )
                    .await
                    .map(Outcome::Draft),
            };
            metrics = client.metrics();
            result = Some(outcome.unwrap_or_else(Outcome::Rejected));
        })
    });
    assert!(
        server.join().is_ok(),
        "case {index}: independent command observation failed"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "case {index}: wall-clock ceiling"
    );
    assert!(
        metrics.wire_bytes <= bounds.max_operation_bytes,
        "case {index}: wire ceiling"
    );
    assert!(
        metrics.wire_bytes <= sent.load(Ordering::Relaxed) + 64,
        "case {index}: independent wire count"
    );
    let response_ceiling = if route == Route::Reconcile {
        draft_limits().wire_fetch_bytes
    } else {
        bounds.max_response_bytes
    };
    assert!(
        metrics.max_response_bytes <= response_ceiling,
        "case {index}: frame ceiling"
    );
    let literal_ceiling = if route == Route::Reconcile {
        response_ceiling
    } else {
        bounds.max_literal_bytes
    };
    assert!(
        metrics.max_literal_bytes <= literal_ceiling,
        "case {index}: literal ceiling"
    );
    let response_work_ceiling = if route == Route::Reconcile {
        Limits::default().max_responses
    } else {
        bounds.max_responses
    };
    assert!(
        metrics.responses <= response_work_ceiling,
        "case {index}: response work ceiling"
    );
    assert!(
        metrics.parser_steps <= bounds.max_parser_steps,
        "case {index}: parser work ceiling"
    );
    assert_eq!(
        metrics.append_wire_bytes, 0,
        "case {index}: no APPEND bytes"
    );
    assert!(
        commands.load(Ordering::Relaxed) <= 2,
        "case {index}: outgoing work ceiling"
    );
    assert!(
        measured.bytes_max < 2 * 1024 * 1024,
        "case {index}: live allocation ceiling"
    );
    assert!(
        measured.bytes_total < 16 * 1024 * 1024,
        "case {index}: total allocation ceiling"
    );
    assert!(
        measured.count_total < 32 * 1024,
        "case {index}: allocation work ceiling"
    );
    result.unwrap()
}

#[test]
fn retained_imap_framing_regressions() {
    for (index, case) in CORPUS.iter().enumerate() {
        match (&case.expected, run_case(case.input, index, false)) {
            (Expected::Listed(expected), Outcome::Listed(actual)) => {
                assert_eq!(actual, *expected, "retained IMAP fixture {index}")
            }
            (Expected::Read(expected), Outcome::Read(actual)) => {
                assert_eq!(actual, *expected, "retained IMAP fixture {index}")
            }
            (Expected::Draft(expected), Outcome::Draft(actual)) => {
                assert_eq!(actual, *expected, "retained IMAP fixture {index}")
            }
            (Expected::Rejected(expected), Outcome::Rejected(actual)) => {
                assert_eq!(actual, *expected, "retained IMAP fixture {index}")
            }
            (_, actual) => panic!("retained IMAP fixture {index}: unexpected result {actual:?}"),
        }
    }
}

#[test]
fn delayed_imap_literal_times_out_and_disposes_transport() {
    assert_eq!(
        run_case(TRUNCATED_LITERAL, 3, true),
        Outcome::Rejected(Error::Timeout)
    );
}

#[test]
#[ignore = "bounded byte-mutation campaign; run explicitly with MAILCTL_FUZZ_CASES and MAILCTL_FUZZ_SEED"]
fn fuzz_imap_framing() {
    let campaign = Campaign::from_env("imap");
    let seeds: Vec<_> = CORPUS.iter().map(|case| case.input).collect();
    for (index, input) in campaign.cases(&seeds) {
        let _ = run_case(&input, index, false);
    }
    campaign.finish();
}
