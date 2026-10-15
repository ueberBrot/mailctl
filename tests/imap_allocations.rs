mod imap_support;

use imap_support::*;
use io_imap::codec::{ResponseCodec, decode::Decoder};
use mailctl::imap::{AttachmentListRequest, Error, Limits, TlsMode};
use std::time::{Duration, Instant};

const LEAF: &str = "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 2 1)";

fn structure(depth: usize, kind: usize, leaf: &str) -> String {
    let mut body = leaf.to_owned();
    for level in 1..depth {
        body = if kind == 1 || (kind == 2 && level % 2 == 0) {
            format!(
                "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 2 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {body} 1)"
            )
        } else {
            format!("({body} \"MIXED\")")
        };
    }
    body
}

#[test]
fn deep_bodystructure_codec_has_finite_work_and_stack() {
    // Unoptimized nom combinators need more stack. Also qualify a 1 MiB stack in
    // optimized builds; request work can run on the calling thread.
    let stack_bytes = if cfg!(debug_assertions) {
        2 * 1024 * 1024
    } else {
        1024 * 1024
    };
    std::thread::Builder::new()
        .stack_size(stack_bytes)
        .spawn(|| {
            for kind in 0..3 {
                for depth in [8, 20, 40, 63, 64, 1000] {
                    for field in ["BODY", "BODYSTRUCTURE"] {
                        for variant in 0..4 {
                            let leaf = match variant {
                                2 => LEAF.replace("2 1", "x 1"),
                                3 => format!(
                                    "{} NIL NIL NIL NIL {}1{})",
                                    &LEAF[..LEAF.len() - 1],
                                    "(".repeat(7),
                                    ")".repeat(7)
                                ),
                                _ => LEAF.to_owned(),
                            };
                            let mut body = structure(depth, kind, &leaf);
                            if variant == 1 {
                                body.pop();
                            }
                            let response = format!("* 1 FETCH ({field} {body})\r\n");
                            let start = Instant::now();
                            let measured = allocation_counter::measure(|| {
                                let result = ResponseCodec::new().decode(response.as_bytes());
                                if depth < 64 && matches!(variant, 0 | 3) {
                                    assert!(
                                        result.is_ok(),
                                        "{field} kind={kind} depth={depth} variant={variant}"
                                    );
                                    assert!(result.unwrap().0.is_empty());
                                } else {
                                    assert!(
                                        result.is_err(),
                                        "{field} kind={kind} depth={depth} variant={variant}"
                                    );
                                }
                            });
                            assert!(start.elapsed() < Duration::from_secs(2));
                            assert!(measured.bytes_max < 512 * 1024, "{measured:?}");
                            assert!(measured.bytes_total < 2 * 1024 * 1024, "{measured:?}");
                            assert!(measured.count_total < 4096, "{measured:?}");
                            eprintln!(
                                "codec field={field} kind={kind} depth={depth} variant={variant} wire={} peak={} total={} allocations={} elapsed_us={}",
                                response.len(), measured.bytes_max, measured.bytes_total,
                                measured.count_total, start.elapsed().as_micros()
                            );
                        }
                    }
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn deep_bodystructure_public_rejection_keeps_allocations_and_parser_work_bounded() {
    for (depth, messages, malformed, expected) in [
        (20, false, false, None),
        (40, false, false, None),
        (40, true, false, None),
        (41, false, false, Some(Error::Limit)),
        (41, true, false, Some(Error::Limit)),
        (40, false, true, Some(Error::Protocol)),
        (40, true, true, Some(Error::Protocol)),
        (63, false, false, Some(Error::Limit)),
        (63, true, false, Some(Error::Limit)),
        (64, false, false, Some(Error::Limit)),
        (1000, true, false, Some(Error::Limit)),
    ] {
        let mut body = structure(depth, usize::from(messages), LEAF);
        if malformed {
            body.pop();
        }
        let limits = Limits {
            max_nesting: 40,
            max_response_bytes: 256 * 1024,
            ..Limits::default()
        };
        let bounds = limits.clone();
        let (mut client, server) = dedicated_fixture(TlsMode::Implicit, limits, move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
                write(&mut wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {body})\r\n{tag} OK fetched\r\n")).await;
                if expected.is_some() {
                    dropped(&mut wire).await;
                } else {
                    logout(&mut wire).await;
                }
            })
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let start = Instant::now();
        let measured = allocation_counter::measure(|| {
            let result = runtime.block_on(client.list_attachments(
                "fixture",
                "disposable-password",
                "INBOX",
                AttachmentListRequest::new(4, 77),
            ));
            if let Some(expected) = expected {
                assert_eq!(result.unwrap_err(), expected);
            } else {
                result.unwrap();
            }
        });
        server.join().unwrap();
        let metrics = client.metrics();
        assert!(metrics.parser_steps <= bounds.max_parser_steps);
        assert!(metrics.wire_bytes <= bounds.max_operation_bytes);
        assert!(metrics.max_response_bytes <= bounds.max_response_bytes);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(measured.bytes_max < 2 * 1024 * 1024, "{measured:?}");
        assert!(measured.bytes_total < 16 * 1024 * 1024, "{measured:?}");
        assert!(measured.count_total < 32 * 1024, "{measured:?}");
        eprintln!(
            "public depth={depth} messages={messages} malformed={malformed} wire={} parser_steps={} peak={} total={} allocations={} elapsed_us={}",
            metrics.wire_bytes,
            metrics.parser_steps,
            measured.bytes_max,
            measured.bytes_total,
            measured.count_total,
            start.elapsed().as_micros()
        );
    }
}
