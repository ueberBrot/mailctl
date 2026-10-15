mod attachment_support;
mod imap_support;

use attachment_support::{decoder, metadata, payload_session, structure};
use imap_support::*;
use mailctl::imap::{AttachmentListRequest, Error, Limits, TlsMode};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const GREETING: &[u8] = b"* OK synthetic server ready\r\n";
const WIRE_SLICE: usize = 16 * 1024;
const DECODED_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum Encoding {
    Base64,
    QuotedPrintable,
    Raw,
}

impl Encoding {
    fn name(self) -> &'static str {
        match self {
            Self::Base64 => "BASE64",
            Self::QuotedPrintable => "QUOTED-PRINTABLE",
            Self::Raw => "8BIT",
        }
    }
}

/// The fixture payload is constructed before measurement and then moved wholly to the server
/// thread. The measured client retains only the current returned chunk and continuation token.
fn fixture_payload(encoding: Encoding, decoded_len: usize) -> (Vec<u8>, u64, [u8; 32]) {
    let mut decoded = (0..decoded_len)
        .map(|index| (index.wrapping_mul(31) as u8).wrapping_add(17))
        .collect::<Vec<_>>();
    if matches!(encoding, Encoding::Raw) {
        decoded.fill(b'r');
    }
    if matches!(encoding, Encoding::QuotedPrintable) {
        decoded.fill(b'a');
        // Frequent interior spaces exercise retained padding without allocating per word.
        for index in (1..decoded_len - 1).step_by(8) {
            decoded[index] = b' ';
        }
        // Split the first =3D escape across two 16 KiB PEEK literals.
        for index in (WIRE_SLICE - 1..decoded_len).step_by(WIRE_SLICE) {
            decoded[index] = b'=';
        }
    }
    let digest = Sha256::digest(&decoded).into();
    let encoded = match encoding {
        Encoding::Base64 => base64(&decoded),
        Encoding::QuotedPrintable => quoted_printable(&decoded),
        Encoding::Raw => decoded.clone(),
    };
    (encoded, decoded_len as u64, digest)
}

fn base64(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for bytes in input.chunks(3) {
        output.push(TABLE[(bytes[0] >> 2) as usize]);
        output.push(
            TABLE[((bytes[0] & 0x03) << 4 | bytes.get(1).copied().unwrap_or(0) >> 4) as usize],
        );
        match bytes.get(1) {
            Some(second) => output.push(
                TABLE[((second & 0x0f) << 2 | bytes.get(2).copied().unwrap_or(0) >> 6) as usize],
            ),
            None => output.push(b'='),
        }
        match bytes.get(2) {
            Some(third) => output.push(TABLE[(third & 0x3f) as usize]),
            None => output.push(b'='),
        }
    }
    output
}

fn quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() + input.len() / WIRE_SLICE * 2);
    for &byte in input {
        if byte == b'=' {
            output.extend_from_slice(b"=3D");
        } else {
            output.push(byte);
        }
    }
    output
}

#[test]
fn full_attachment_transfers_have_payload_independent_memory_and_bounded_counters() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let limits = Limits {
        max_literal_bytes: WIRE_SLICE,
        max_attachment_chunk_bytes: DECODED_CHUNK,
        max_attachment_decoded_bytes: 2 * 1024 * 1024,
        max_attachment_wire_bytes: 2 * 1024 * 1024,
        ..Limits::default()
    };
    let cases = [
        (Encoding::Raw, 64 * 1024 + 13),
        (Encoding::Raw, 1024 * 1024 + 13),
        (Encoding::Base64, 64 * 1024 + 13),
        (Encoding::Base64, 1024 * 1024 + 13),
        (Encoding::QuotedPrintable, 64 * 1024 + 13),
        (Encoding::QuotedPrintable, 1024 * 1024 + 13),
    ];
    let mut peaks = Vec::new();

    for (encoding, decoded_len) in cases {
        let (payload, expected_len, expected_digest) = fixture_payload(encoding, decoded_len);
        assert_ne!(
            payload.len() % WIRE_SLICE,
            0,
            "fixture must prove EOF without an extra request"
        );
        let sessions = decoded_len.div_ceil(DECODED_CHUNK);
        let payload_len = payload.len();
        let source: Arc<[u8]> = payload.into();
        let position = Arc::new(AtomicUsize::new(0));
        let server_bytes = Arc::new(AtomicUsize::new(sessions * GREETING.len()));
        let counted = server_bytes.clone();
        let (mut probe, server) =
            dedicated_sessions(TlsMode::Implicit, limits.clone(), sessions, move |wire| {
                let source = source.clone();
                let position = position.clone();
                let counted = counted.clone();
                Box::pin(async move {
                    let mut wire: Wire = Box::new(CountedWire {
                        wire,
                        written: counted,
                    });
                    authenticate(&mut wire).await;
                    examine(&mut wire).await;
                    if position.load(Ordering::Relaxed) == 0 {
                        metadata(&mut wire, &structure(encoding.name(), source.len())).await;
                    }
                    payload_session(&mut wire, &source, &position, WIRE_SLICE).await;
                })
            });

        let mut request = decoder();
        let mut reported_wire = 0usize;
        let mut reported_parser_steps = 0usize;
        let mut observed_offset = 0u64;
        let mut transfers = 0usize;
        let mut final_metrics = None;
        let allocations = allocation_counter::measure(|| {
            runtime.block_on(async {
                loop {
                    let chunk = probe
                        .read_attachment("fixture", "disposable-password", &mut request)
                        .await
                        .unwrap();
                    transfers += 1;
                    assert_eq!(chunk.decoded_offset, observed_offset, "{}", encoding.name());
                    assert!(chunk.bytes.len() <= DECODED_CHUNK, "{}", encoding.name());
                    observed_offset += chunk.bytes.len() as u64;
                    reported_wire += probe.metrics().wire_bytes;
                    reported_parser_steps += probe.metrics().parser_steps;
                    assert!(
                        probe.metrics().max_literal_bytes <= WIRE_SLICE,
                        "{}",
                        encoding.name()
                    );
                    assert!(
                        probe.metrics().max_response_bytes <= limits.max_response_bytes,
                        "{}",
                        encoding.name()
                    );
                    assert!(
                        probe.metrics().parser_steps <= probe.metrics().wire_bytes * 4 + 64,
                        "{}: {:?}",
                        encoding.name(),
                        probe.metrics()
                    );
                    assert!(
                        probe.metrics().max_transfer_state_bytes
                            <= WIRE_SLICE + DECODED_CHUNK + 128,
                        "{}: {:?}",
                        encoding.name(),
                        probe.metrics()
                    );
                    if let Some(integrity) = chunk.integrity {
                        assert_eq!(
                            integrity.total_decoded_bytes,
                            expected_len,
                            "{}",
                            encoding.name()
                        );
                        assert_eq!(integrity.sha256, expected_digest, "{}", encoding.name());
                        assert_eq!(
                            probe.metrics().transfer_wire_bytes,
                            payload_len,
                            "{}",
                            encoding.name()
                        );
                        assert_eq!(
                            probe.metrics().transfer_decoded_bytes,
                            expected_len as usize,
                            "{}",
                            encoding.name()
                        );
                        assert_eq!(
                            probe.metrics().transfer_decode_steps,
                            payload_len,
                            "{}",
                            encoding.name()
                        );

                        final_metrics = Some(probe.metrics());
                        break;
                    }
                }
            });
        });
        server.join().unwrap();

        let metrics = final_metrics.expect("complete transfer metrics");
        assert_eq!(observed_offset, expected_len, "{}", encoding.name());
        assert_eq!(transfers, sessions, "{}", encoding.name());
        assert_eq!(
            reported_wire,
            server_bytes.load(Ordering::Relaxed),
            "{}",
            encoding.name()
        );
        assert!(
            metrics.transfer_wire_bytes <= limits.max_attachment_wire_bytes,
            "{}: {:?}",
            encoding.name(),
            metrics
        );
        assert!(
            metrics.transfer_decoded_bytes <= limits.max_attachment_decoded_bytes,
            "{}: {:?}",
            encoding.name(),
            metrics
        );
        assert!(
            metrics.transfer_decode_steps <= limits.max_attachment_wire_bytes,
            "{}: {:?}",
            encoding.name(),
            metrics
        );
        assert!(
            reported_parser_steps <= reported_wire * 4 + transfers * 64,
            "{}: wire={reported_wire} parser={reported_parser_steps}",
            encoding.name()
        );
        assert!(
            allocations.bytes_max < 512 * 1024,
            "{}: {allocations:?}",
            encoding.name()
        );
        assert!(
            allocations.bytes_total < 128 * 1024 * 1024,
            "{}: {allocations:?}",
            encoding.name()
        );
        if matches!(encoding, Encoding::QuotedPrintable) {
            assert!(
                allocations.count_total < sessions as u64 * 1024,
                "whitespace must not allocate per word: {allocations:?}"
            );
        }
        println!(
            "attachment allocation proof encoding={} decoded={} transfer_wire={} response_wire={} sessions={} peak={} total={} allocations={} state={} parser={}",
            encoding.name(),
            expected_len,
            payload_len,
            reported_wire,
            transfers,
            allocations.bytes_max,
            allocations.bytes_total,
            allocations.count_total,
            metrics.max_transfer_state_bytes,
            reported_parser_steps,
        );
        peaks.push(allocations.bytes_max);
    }
    assert!(
        peaks.iter().all(|peak| *peak < 512 * 1024),
        "payload growth must not grow peak client allocation: {peaks:?}"
    );
}

fn measure_rejected_transfer(
    encoding: Encoding,
    payload: Vec<u8>,
    expected_prefix: usize,
    served_bytes: usize,
    limits: Limits,
    expected_error: Error,
) {
    assert_eq!(expected_prefix % DECODED_CHUNK, 0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let sessions = expected_prefix / DECODED_CHUNK + 1;
    let declared_bytes = payload.len();
    let position = Arc::new(AtomicUsize::new(0));
    let server_bytes = Arc::new(AtomicUsize::new(sessions * GREETING.len()));
    let counted = server_bytes.clone();
    let source: Arc<[u8]> = payload.into();
    let mut session = 0;
    let (mut probe, server) =
        dedicated_sessions(TlsMode::Implicit, limits.clone(), sessions, move |wire| {
            session += 1;
            let initial = session == 1;
            let terminal = session == sessions;
            let source = source.clone();
            let position = position.clone();
            let counted = counted.clone();
            Box::pin(async move {
                let mut wire: Wire = Box::new(CountedWire {
                    wire,
                    written: counted,
                });
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                if initial {
                    metadata(&mut wire, &structure(encoding.name(), source.len())).await;
                }
                if terminal {
                    let offset = position.load(Ordering::Relaxed);
                    for (index, bytes) in
                        source[offset..served_bytes].chunks(WIRE_SLICE).enumerate()
                    {
                        literal_bytes(
                            &mut wire,
                            "2",
                            offset + index * WIRE_SLICE,
                            WIRE_SLICE,
                            bytes,
                        )
                        .await;
                    }
                    dropped(&mut wire).await;
                } else {
                    payload_session(&mut wire, &source, &position, WIRE_SLICE).await;
                }
            })
        });
    let mut request = decoder();
    let mut response_wire = 0;
    let mut parser_steps = 0;
    let allocations = allocation_counter::measure(|| {
        runtime.block_on(async {
            for page in 0..sessions {
                let result = probe
                    .read_attachment("fixture", "disposable-password", &mut request)
                    .await;
                if page + 1 == sessions {
                    assert_eq!(result.unwrap_err(), expected_error, "{}", encoding.name());
                } else {
                    let chunk = result.unwrap();
                    assert_eq!(chunk.decoded_offset, (page * DECODED_CHUNK) as u64);
                    assert_eq!(chunk.bytes.len(), DECODED_CHUNK);
                    assert!(chunk.bytes.iter().all(|byte| *byte == b'x'));
                    assert!(chunk.integrity.is_none());
                }
                let metrics = probe.metrics();
                response_wire += metrics.wire_bytes;
                parser_steps += metrics.parser_steps;
                assert!(metrics.wire_bytes <= limits.max_operation_bytes);
                assert!(metrics.max_literal_bytes <= WIRE_SLICE);
                assert!(metrics.max_response_bytes <= limits.max_response_bytes);
                assert!(metrics.max_transfer_state_bytes <= WIRE_SLICE + DECODED_CHUNK + 128);
            }
        });
    });
    server.join().unwrap();
    let metrics = probe.metrics();
    assert_eq!(response_wire, server_bytes.load(Ordering::Relaxed));
    assert_eq!(metrics.transfer_wire_bytes, served_bytes);
    assert_eq!(metrics.transfer_decode_steps, served_bytes);
    assert_eq!(metrics.transfer_decoded_bytes, expected_prefix);
    // A failing push charges its entire bounded literal before checking the work ceiling.
    assert!(metrics.transfer_decode_steps <= limits.max_decode_steps + WIRE_SLICE);
    assert!(metrics.transfer_wire_bytes <= limits.max_attachment_wire_bytes);
    assert!(parser_steps <= response_wire * 4 + sessions * 64);
    assert!(allocations.bytes_max < 512 * 1024, "{allocations:?}");
    assert!(
        allocations.bytes_total < 128 * 1024 * 1024,
        "{allocations:?}"
    );
    println!(
        "rejected attachment allocation proof encoding={} error={expected_error:?} declared={declared_bytes} transfer_wire={served_bytes} decoded={expected_prefix} response_wire={response_wire} sessions={sessions} peak={} total={} state={} work={}",
        encoding.name(),
        allocations.bytes_max,
        allocations.bytes_total,
        metrics.max_transfer_state_bytes,
        metrics.transfer_decode_steps,
    );
}

#[test]
fn late_malformed_attachment_tails_fail_without_fabricating_completed_bytes() {
    for wire_prefix in [64 * 1024, 1024 * 1024] {
        for encoding in [Encoding::Base64, Encoding::QuotedPrintable] {
            let (mut payload, decoded_prefix, tail) = match encoding {
                Encoding::Base64 => (
                    b"eHh4".repeat(wire_prefix / 4),
                    wire_prefix / 4 * 3,
                    b"eA".as_slice(),
                ),
                Encoding::QuotedPrintable => {
                    (vec![b'x'; wire_prefix], wire_prefix, b"=QZ".as_slice())
                }
                Encoding::Raw => unreachable!(),
            };
            payload.extend_from_slice(tail);
            let served_bytes = payload.len();
            measure_rejected_transfer(
                encoding,
                payload,
                decoded_prefix,
                served_bytes,
                Limits {
                    max_literal_bytes: WIRE_SLICE,
                    max_attachment_chunk_bytes: DECODED_CHUNK,
                    ..Limits::default()
                },
                Error::Protocol,
            );
        }
    }
}

#[test]
fn zero_output_and_retained_whitespace_attachment_prefixes_fail_with_bounded_resources() {
    for size in [64 * 1024, 1024 * 1024] {
        for encoding in [Encoding::Base64, Encoding::QuotedPrintable] {
            let mut payload = match encoding {
                Encoding::Base64 => vec![b' '; size],
                Encoding::QuotedPrintable => b"=\r\n".repeat(size / 3),
                Encoding::Raw => unreachable!(),
            };
            let max_decode_steps = payload.len();
            payload.push(b'x');
            let served_bytes = payload.len();
            measure_rejected_transfer(
                encoding,
                payload,
                0,
                served_bytes,
                Limits {
                    max_decode_steps,
                    max_literal_bytes: WIRE_SLICE,
                    max_attachment_chunk_bytes: DECODED_CHUNK,
                    ..Limits::default()
                },
                Error::Limit,
            );
        }
        let mut whitespace = vec![b' '; size];
        whitespace.push(b'x');
        measure_rejected_transfer(
            Encoding::QuotedPrintable,
            whitespace,
            0,
            3 * WIRE_SLICE,
            Limits {
                max_literal_bytes: WIRE_SLICE,
                max_attachment_chunk_bytes: DECODED_CHUNK,
                ..Limits::default()
            },
            Error::Limit,
        );
    }
}

#[test]
fn huge_declared_attachment_metadata_never_allocates_a_payload() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server_bytes = Arc::new(AtomicUsize::new(GREETING.len()));
    let counted = server_bytes.clone();
    let (mut probe, server) =
        dedicated_fixture(TlsMode::Implicit, Limits::default(), move |wire| {
            Box::pin(async move {
                let mut wire: Wire = Box::new(CountedWire {
                    wire,
                    written: counted,
                });
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(&mut wire, &structure("BASE64", u32::MAX as usize)).await;
                logout(&mut wire).await;
            })
        });
    let mut reported_wire = 0usize;
    let allocations = allocation_counter::measure(|| {
        runtime.block_on(async {
            let listing = probe
                .list_attachments(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    AttachmentListRequest::new(4, 77),
                )
                .await
                .unwrap();
            reported_wire = probe.metrics().wire_bytes;
            assert_eq!(listing[0].declared_size, Some(u32::MAX as u64));
            assert_eq!(probe.metrics().max_literal_bytes, 0);
            assert!(probe.metrics().wire_bytes < 4096, "{:?}", probe.metrics());
        });
    });
    server.join().unwrap();
    assert_eq!(reported_wire, server_bytes.load(Ordering::Relaxed));
    assert!(allocations.bytes_max < 2 * 1024 * 1024, "{allocations:?}");
    assert!(
        allocations.bytes_total < 16 * 1024 * 1024,
        "{allocations:?}"
    );
    println!(
        "attachment metadata allocation proof declared={} wire={} peak={} total={}",
        u32::MAX,
        reported_wire,
        allocations.bytes_max,
        allocations.bytes_total,
    );
}
