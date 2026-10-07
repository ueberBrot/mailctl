mod fuzz_support;
mod imap_support;

use fuzz_support::{Campaign, MAX_INPUT_BYTES};
use imap_support::{
    CountedWire, Wire, authenticate, dedicated_fixture, examine, expect, observe_command,
};
use io_imap::types::{
    command::CommandBody,
    fetch::{MacroOrMessageDataItemNames, MessageDataItemName, Section},
    sequence::{SeqOrUid, Sequence},
};
use mailctl::imap::{
    AttachmentData, AttachmentDecoder, BodyPage, BodyRequest, Error, Limits, Metrics, TlsMode,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

const ROOT_HEADERS: &[u8] =
    b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n";
const WIRE_SLICE: usize = 1024;

const CORPUS: &[&[u8]] = &[
    include_bytes!("fuzz_corpus/mime/structure-depth-seven.seed"),
    include_bytes!("fuzz_corpus/mime/structure-depth-eight.seed"),
    include_bytes!("fuzz_corpus/mime/structure-incomplete.seed"),
    include_bytes!("fuzz_corpus/mime/headers-valid.seed"),
    include_bytes!("fuzz_corpus/mime/headers-incomplete.seed"),
    include_bytes!("fuzz_corpus/mime/plain-quoted.seed"),
    include_bytes!("fuzz_corpus/mime/plain-invalid-utf8.seed"),
    include_bytes!("fuzz_corpus/mime/html-active-content.seed"),
    include_bytes!("fuzz_corpus/mime/html-table-span.seed"),
    include_bytes!("fuzz_corpus/mime/body-base64-tail.seed"),
    include_bytes!("fuzz_corpus/mime/body-quoted-printable-tail.seed"),
    include_bytes!("fuzz_corpus/mime/attachment-base64.seed"),
    include_bytes!("fuzz_corpus/mime/attachment-base64-tail.seed"),
    include_bytes!("fuzz_corpus/mime/attachment-quoted-printable.seed"),
    include_bytes!("fuzz_corpus/mime/attachment-quoted-printable-tail.seed"),
    include_bytes!("fuzz_corpus/mime/attachment-raw.seed"),
    // RFC 3501 section 9 excludes NUL from ordinary IMAP literals.
    include_bytes!("fuzz_corpus/mime/attachment-raw-nul.seed"),
];

fn limits() -> Limits {
    Limits {
        max_response_bytes: 32 * 1024,
        max_operation_bytes: 128 * 1024,
        max_literal_bytes: WIRE_SLICE,
        max_responses: 128,
        max_parser_steps: 1024 * 1024,
        max_nesting: 12,
        max_header_bytes: 4096,
        max_mime_parts: 16,
        max_body_wire_bytes: MAX_INPUT_BYTES,
        max_decoded_bytes: 128 * 1024,
        max_text_bytes: 4096,
        max_decode_steps: 256 * 1024,
        max_attachment_decoded_bytes: MAX_INPUT_BYTES,
        max_attachment_wire_bytes: MAX_INPUT_BYTES,
        max_attachment_chunk_bytes: MAX_INPUT_BYTES,
        operation_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(1),
        ..Limits::default()
    }
}

fn text_structure(subtype: &str, encoding: &str, size: usize) -> Vec<u8> {
    format!(
        "((\"TEXT\" \"{subtype}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"{encoding}\" {size} 1 NIL NIL NIL NIL) \"MIXED\" NIL NIL NIL NIL)"
    ).into_bytes()
}

fn attachment_structure(encoding: &str, size: usize) -> Vec<u8> {
    format!(
        "((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 2 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"{encoding}\" {size} NIL (\"ATTACHMENT\" (\"FILENAME\" \"synthetic.bin\")) NIL NIL) \"MIXED\" NIL NIL NIL NIL)"
    ).into_bytes()
}

async fn serve(mut wire: Wire, kind: u8, input: Vec<u8>) {
    authenticate(&mut wire).await;
    examine(&mut wire).await;
    let attachment = matches!(kind, b'B' | b'Q' | b'R');
    let body = if matches!(kind, b'S' | b'H') {
        b"ok".as_slice()
    } else {
        &input
    };
    let structure = match kind {
        b'S' => input.clone(),
        b'M' => text_structure("HTML", "8BIT", body.len()),
        b'T' => text_structure("PLAIN", "BASE64", body.len()),
        b'U' => text_structure("PLAIN", "QUOTED-PRINTABLE", body.len()),
        b'B' => attachment_structure("BASE64", body.len()),
        b'Q' => attachment_structure("QUOTED-PRINTABLE", body.len()),
        b'R' => attachment_structure("8BIT", body.len()),
        _ => text_structure("PLAIN", "8BIT", body.len()),
    };
    let tag = expect(&mut wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    let mut response = b"* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ".to_vec();
    response.extend_from_slice(&structure);
    response.extend_from_slice(format!(")\r\n{tag} OK fetched\r\n").as_bytes());
    if wire.write_all(&response).await.is_err() || wire.flush().await.is_err() {
        return;
    }

    let mut header_offset = 0usize;
    let mut body_offset = 0usize;
    for _ in 0..64 {
        let Some(command) = observe_command(&mut wire, Duration::from_secs(3)).await else {
            return;
        };
        let tag = command.tag.as_ref();
        if matches!(command.body, CommandBody::Logout) {
            let _ = wire
                .write_all(format!("* BYE closing\r\n{tag} OK logout\r\n").as_bytes())
                .await;
            return;
        }
        let CommandBody::Fetch {
            sequence_set,
            macro_or_item_names: MacroOrMessageDataItemNames::MessageDataItemNames(names),
            uid: true,
            modifiers,
        } = &command.body
        else {
            panic!("only read-only synthetic FETCH is allowed");
        };
        assert!(modifiers.is_empty(), "synthetic FETCH modifiers");
        assert!(
            matches!(sequence_set.0.as_ref(), [Sequence::Single(SeqOrUid::Value(uid))] if uid.get() == 4)
        );
        let [
            MessageDataItemName::Uid,
            MessageDataItemName::BodyExt {
                section: Some(section),
                partial: Some((offset, count)),
                peek: true,
            },
        ] = names.as_slice()
        else {
            panic!("only bounded synthetic PEEK is allowed");
        };
        let offset = *offset as usize;
        let count = count.get() as usize;
        assert!(
            (1..=WIRE_SLICE).contains(&count),
            "synthetic wire slice ceiling"
        );
        let (section_name, bytes) = match section {
            Section::Header(None) if !attachment => {
                assert_eq!(offset, header_offset, "synthetic header offset");
                let value = if kind == b'H' {
                    input.as_slice()
                } else {
                    ROOT_HEADERS
                };
                let end = offset.saturating_add(count).min(value.len());
                assert!(offset <= end, "synthetic header progress");
                header_offset = end;
                ("HEADER".to_owned(), &value[offset..end])
            }
            Section::Mime(part) if !attachment && kind == b'S' => {
                assert_eq!(offset, 0, "synthetic related header offset");
                let part = part
                    .0
                    .as_ref()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
                (format!("{part}.MIME"), ROOT_HEADERS)
            }
            Section::Part(part) => {
                let part = part
                    .0
                    .as_ref()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
                if attachment {
                    assert_eq!(part, "2", "synthetic attachment part");
                }
                assert_eq!(offset, body_offset, "synthetic body offset");
                let end = offset.saturating_add(count).min(body.len());
                assert!(offset <= end, "synthetic body progress");
                body_offset = end;
                (part, &body[offset..end])
            }
            _ => panic!("unexpected synthetic PEEK section"),
        };
        let prefix = format!(
            "* 1 FETCH (UID 4 BODY[{section_name}]<{offset}> {{{}}}\r\n",
            bytes.len()
        );
        if wire.write_all(prefix.as_bytes()).await.is_err()
            || wire.write_all(bytes).await.is_err()
            || wire
                .write_all(format!(")\r\n{tag} OK fetched\r\n").as_bytes())
                .await
                .is_err()
            || wire.flush().await.is_err()
        {
            return;
        }
    }
    panic!("synthetic operation command ceiling");
}

enum Outcome {
    Body(Result<BodyPage, Error>),
    Attachment(Result<AttachmentData, Error>),
}

fn assert_metrics(metrics: Metrics, limits: &Limits, case: usize) {
    assert!(
        metrics.wire_bytes <= limits.max_operation_bytes,
        "mime case {case}: wire ceiling"
    );
    assert!(
        metrics.responses <= limits.max_responses,
        "mime case {case}: response ceiling"
    );
    assert!(
        metrics.parser_steps <= limits.max_parser_steps,
        "mime case {case}: parser ceiling"
    );
    assert!(
        metrics.max_response_bytes <= limits.max_response_bytes,
        "mime case {case}: frame ceiling"
    );
    assert!(
        metrics.max_literal_bytes <= WIRE_SLICE,
        "mime case {case}: literal ceiling"
    );
    assert!(
        metrics.decode_steps <= limits.max_decode_steps,
        "mime case {case}: body work ceiling"
    );
    assert!(
        metrics.decoded_bytes <= limits.max_decoded_bytes,
        "mime case {case}: body allocation ceiling"
    );
    assert!(
        metrics.transfer_wire_bytes <= limits.max_attachment_wire_bytes,
        "mime case {case}: transfer wire ceiling"
    );
    assert!(
        metrics.transfer_decoded_bytes <= limits.max_attachment_decoded_bytes,
        "mime case {case}: transfer allocation ceiling"
    );
    assert!(
        metrics.transfer_decode_steps <= limits.max_decode_steps,
        "mime case {case}: transfer work ceiling"
    );
    assert!(
        metrics.max_transfer_state_bytes <= 16 * 1024 + MAX_INPUT_BYTES + 128,
        "mime case {case}: transfer state ceiling"
    );
}

fn run(input: &[u8], case: usize) -> Outcome {
    assert!(
        input.len() <= MAX_INPUT_BYTES,
        "mime case {case}: input ceiling"
    );
    let kind = input.first().copied().unwrap_or(b'P');
    let payload = input.get(2..).unwrap_or_default().to_vec();
    let limits = limits();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server_bytes = Arc::new(AtomicUsize::new(b"* OK synthetic server ready\r\n".len()));
    let counted = server_bytes.clone();
    let (mut probe, server) = dedicated_fixture(TlsMode::Implicit, limits.clone(), move |wire| {
        Box::pin(serve(
            Box::new(CountedWire {
                wire,
                written: counted,
            }),
            kind,
            payload,
        ))
    });
    let mut outcome = None;
    let started = Instant::now();
    let allocations = allocation_counter::measure(|| {
        outcome = Some(runtime.block_on(async {
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                if matches!(kind, b'B' | b'Q' | b'R') {
                    let mut decoder = AttachmentDecoder::new("INBOX", 4, 77, "2", &limits).unwrap();
                    Outcome::Attachment(
                        probe
                            .read_attachment("fixture", "disposable-password", &mut decoder)
                            .await,
                    )
                } else {
                    Outcome::Body(
                        probe
                            .read_body(
                                "fixture",
                                "disposable-password",
                                "INBOX",
                                BodyRequest::new(4, 77),
                            )
                            .await,
                    )
                }
            })
            .await;
            assert_metrics(probe.metrics(), &limits, case);
            result.expect("bounded MIME operation deadline")
        }));
    });
    server.join().expect("bounded synthetic MIME server");
    let server_bytes = server_bytes.load(Ordering::Relaxed);
    assert!(
        server_bytes <= limits.max_operation_bytes,
        "mime case {case}: independent wire ceiling"
    );
    assert!(
        probe.metrics().wire_bytes <= server_bytes,
        "mime case {case}: independently observed wire bytes"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "mime case {case}: elapsed ceiling"
    );
    assert!(
        allocations.bytes_max <= 16 * 1024 * 1024,
        "mime case {case}: peak allocation ceiling"
    );
    assert!(
        allocations.bytes_total <= 64 * 1024 * 1024,
        "mime case {case}: total allocation ceiling"
    );
    assert!(
        allocations.count_total <= 250_000,
        "mime case {case}: allocation work ceiling"
    );
    let outcome = outcome.unwrap();
    match &outcome {
        Outcome::Body(Ok(page)) => {
            assert_eq!(
                page.metrics.wire_bytes, server_bytes,
                "mime case {case}: complete response wire count"
            );
            assert!(
                page.text.len() <= limits.max_text_bytes,
                "mime case {case}: text page ceiling"
            );
            assert_metrics(page.metrics, &limits, case);
        }
        Outcome::Attachment(Ok(chunk)) => {
            assert_eq!(
                probe.metrics().wire_bytes,
                server_bytes,
                "mime case {case}: complete response wire count"
            );
            assert!(
                chunk.bytes.len() <= limits.max_attachment_chunk_bytes,
                "mime case {case}: attachment chunk ceiling"
            );
            assert_eq!(
                chunk.decoded_offset, 0,
                "mime case {case}: initial attachment offset"
            );
            assert!(
                chunk.integrity.is_some(),
                "mime case {case}: bounded input completes transfer"
            );
        }
        Outcome::Body(Err(error)) | Outcome::Attachment(Err(error)) => {
            assert!(
                matches!(
                    error,
                    Error::Protocol
                        | Error::Limit
                        | Error::Eof
                        | Error::Unsupported
                        | Error::Transport
                ),
                "mime case {case}: unexpected error category {error}"
            );
        }
    }
    outcome
}

#[test]
fn retained_mime_inputs_replay_through_bounded_public_reads() {
    for (case, input) in CORPUS.iter().enumerate() {
        match (case, run(input, case)) {
            (0 | 3, Outcome::Body(Ok(page))) => assert_eq!(page.text, "ok"),
            (1 | 4, Outcome::Body(Err(Error::Protocol)))
            | (2, Outcome::Body(Err(Error::Protocol | Error::Eof)))
            | (12 | 14 | 16, Outcome::Attachment(Err(Error::Protocol))) => {}
            (5, Outcome::Body(Ok(page))) => {
                assert_eq!(page.text, "> synthetic quote\r\n\r\nSynthetic reply.")
            }
            (6, Outcome::Body(Ok(page))) => {
                assert!(page.replacements);
                assert!(page.text.contains('\u{fffd}'));
            }
            (7, Outcome::Body(Ok(page))) => {
                assert!(page.converted);
                assert!(page.text.contains("Visible synthetic text"));
                assert!(page.text.contains("Quoted synthetic text"));
                assert!(!page.text.contains("synthetic-active-marker"));
                assert!(!page.text.contains("synthetic-style-marker"));
            }
            (8, Outcome::Body(Ok(page))) => {
                assert!(page.converted);
                assert!(page.text.contains("safe"));
            }
            (9, Outcome::Body(Ok(page))) => {
                assert_eq!(page.text, "\u{fffd}Hello");
                assert!(page.replacements);
            }
            (10, Outcome::Body(Ok(page))) => {
                assert_eq!(page.text, "\u{fffd}hello");
                assert!(page.replacements);
            }
            (11, Outcome::Attachment(Ok(chunk))) => {
                assert_eq!(chunk.bytes, b"Hello");
                assert_integrity(
                    chunk,
                    5,
                    "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
                );
            }
            (13, Outcome::Attachment(Ok(chunk))) => {
                assert_eq!(chunk.bytes, b"first\r\nsecond \t\r\nthird \tline\r\nlast");
                assert_integrity(
                    chunk,
                    34,
                    "c462e3691dd79e9a1d6bcc9e4fdecdec133dda19a9ec9410d832e25e1d2e3dec",
                );
            }
            (15, Outcome::Attachment(Ok(chunk))) => {
                assert_eq!(chunk.bytes, b"Synthetic binary\xfffixture");
                assert_integrity(
                    chunk,
                    24,
                    "a0141c690005b91892d7969436725bd30f76beff4815486a4443293368b92699",
                );
            }
            (_, Outcome::Body(Err(error))) => {
                panic!("mime retained case {case}: unexpected body error {error}")
            }
            (_, Outcome::Attachment(Err(error))) => {
                panic!("mime retained case {case}: unexpected attachment error {error}")
            }
            _ => panic!("mime retained case {case}: unexpected result"),
        }
    }
}

fn assert_integrity(chunk: AttachmentData, expected_len: u64, expected_digest: &str) {
    let integrity = chunk.integrity.unwrap();
    assert_eq!(integrity.total_decoded_bytes, expected_len);
    let digest = integrity
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(digest, expected_digest);
}

#[test]
#[ignore = "explicit bounded synthetic MIME mutation campaign"]
fn fuzz_mime() {
    let campaign = Campaign::from_env("mime");
    for (case, input) in campaign.cases(CORPUS) {
        run(&input, case);
    }
    campaign.finish();
}
