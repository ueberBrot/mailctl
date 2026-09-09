#![allow(dead_code)]
mod append_support;
mod imap_support;
use append_support::*;
use imap_support::*;
use mailctl::imap::{AppendOutcome, Limits, PreparedDraft, TlsMode};

#[test]
fn streamed_append_keeps_backend_allocations_independent_of_mime_size() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut peaks = Vec::new();
    for body_len in [16 * 1024, 1024 * 1024] {
        let mut input = input();
        input.body = "x\n".repeat(body_len / 2);
        let draft = PreparedDraft::compose(input, 2 * 1024 * 1024).unwrap();
        let bytes = draft.bytes().to_vec();
        let (mut probe, server) =
            dedicated_fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
                Box::pin(async move {
                    authenticate(&mut wire).await;
                    let tag = receive(&mut wire, "Drafts", &bytes).await;
                    write(&mut wire, &format!("{tag} OK accepted\r\n")).await;
                    dropped(&mut wire).await;
                })
            });
        let mut metrics = None;
        let measured = allocation_counter::measure(|| {
            runtime.block_on(async {
                let result = probe
                    .append_draft("fixture", "disposable-password", "Drafts", &draft)
                    .await
                    .unwrap();
                assert_eq!(result.outcome, AppendOutcome::Created { uid: None });
                metrics = Some(result.metrics);
            })
        });
        server.join().unwrap();
        let metrics = metrics.unwrap();
        assert_eq!(metrics.mime_bytes, draft.bytes().len());
        assert!(metrics.append_wire_bytes <= draft.bytes().len() + 128);
        assert!(metrics.parser_steps <= metrics.wire_bytes * 4 + 128);
        assert!(measured.bytes_max < 512 * 1024, "{measured:?}");
        eprintln!(
            "APPEND mime={} outbound={} inbound={} parser_steps={} peak={} total={} allocations={}",
            draft.bytes().len(),
            metrics.append_wire_bytes,
            metrics.wire_bytes,
            metrics.parser_steps,
            measured.bytes_max,
            measured.bytes_total,
            measured.count_total
        );
        peaks.push(measured.bytes_max);
    }
    assert!(
        peaks[1] <= peaks[0] + 64 * 1024,
        "backend retained a MIME-sized buffer: {peaks:?}"
    );
}

#[test]
fn composition_reuses_normalized_body_within_reserved_mime() {
    for bytes in [16 * 1024, 1024 * 1024] {
        let mut input = input();
        input.body = "é\n".repeat(bytes / 3);
        let measured = allocation_counter::measure(|| {
            let draft = PreparedDraft::compose(input, 2 * 1024 * 1024).unwrap();
            assert!(draft.bytes().len() < 2 * 1024 * 1024);
        });
        eprintln!(
            "COMPOSE input={bytes} peak={} total={} allocations={}",
            measured.bytes_max, measured.bytes_total, measured.count_total
        );
        assert!(
            measured.bytes_total <= 2 * 1024 * 1024 + 128 * 1024,
            "{measured:?}"
        );
    }
}
