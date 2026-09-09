#![allow(dead_code)] // This route uses only part of the shared transcript fixture helpers.

mod imap_support;

use imap_support::*;
use mailctl::imap::{BodyRequest, Error, Limits, TlsMode};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const ROOT_HEADERS: &str =
    "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n";
const TEXT_HEADERS: &str =
    "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n";
const SHORT_BODY: &str = "Short body.\r\n";
const MIXED: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" (\"FILENAME\" \"large.bin\")) NIL NIL) \"MIXED\" (\"BOUNDARY\" \"fixture\") NIL NIL NIL)";

async fn metadata(wire: &mut Wire, response: &str) {
    let tag = expect(wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(wire, &response.replace("{tag}", &tag)).await;
}

async fn literal(wire: &mut Wire, section: &str, offset: usize, count: usize, value: &str) {
    let tag = expect(
        wire,
        &format!("UID FETCH 4 (UID BODY.PEEK[{section}]<{offset}.{count}>)"),
    )
    .await;
    write(
        wire,
        &format!(
            "* 1 FETCH (UID 4 BODY[{section}]<{offset}> {{{}}}\r\n{value})\r\n{tag} OK fetched\r\n",
            value.len()
        ),
    )
    .await;
}

async fn successful_large_attachment_route(wire: &mut Wire, size: u32) {
    authenticate(wire).await;
    examine(wire).await;
    metadata(
        wire,
        &format!(
            "* 1 FETCH (UID 4 RFC822.SIZE {size} BODYSTRUCTURE {})\r\n{{tag}} OK fetched\r\n",
            MIXED.replace("3000000", &size.to_string())
        ),
    )
    .await;
    literal(wire, "HEADER", 0, 16 * 1024, ROOT_HEADERS).await;
    literal(wire, "1", 0, 14, SHORT_BODY).await;
    logout(wire).await;
}

#[tokio::test]
async fn body_read_rejects_uidvalidity_before_any_fetch() {
    let mut validity_fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            let tag = expect(&mut wire, "EXAMINE INBOX").await;
            write(
                &mut wire,
                &format!(
                    "* 2 EXISTS\r\n* OK [UIDVALIDITY 78] replaced\r\n{tag} OK [READ-ONLY] selected\r\n"
                ),
            )
            .await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let error = validity_fixture
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::UnsafeSelection);
    validity_fixture.task.await.unwrap();
}

#[tokio::test]
async fn body_fetch_protocol_identity_faults_dispose_the_connection() {
    let cases = [
        (
            "* 1 FETCH (UID 5 RFC822.SIZE 3000300 BODYSTRUCTURE ".to_owned()
                + MIXED
                + ")\r\n{tag} OK fetched\r\n",
            Error::Protocol,
        ),
        (
            "* 1 FETCH (UID 4 UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ".to_owned()
                + MIXED
                + ")\r\n{tag} OK fetched\r\n",
            Error::Protocol,
        ),
        (
            "* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE ".to_owned()
                + MIXED
                + ")\r\n* 2 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE "
                + MIXED
                + ")\r\n{tag} OK fetched\r\n",
            Error::Protocol,
        ),
    ];
    for (response, expected) in cases {
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(&mut wire, &response).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn body_fetch_rejects_wrong_section_origin_and_nil_payload() {
    for response in [
        "* 1 FETCH (UID 4 BODY[1.MIME]<0> {77}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n)\r\n{tag} OK fetched\r\n",
        "* 1 FETCH (UID 4 BODY[HEADER]<1> {77}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n)\r\n{tag} OK fetched\r\n",
        "* 1 FETCH (UID 4 BODY[HEADER]<0> NIL)\r\n{tag} OK fetched\r\n",
    ] {
        let response = response.to_owned();
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(
                    &mut wire,
                    &format!(
                        "* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {MIXED})\r\n{{tag}} OK fetched\r\n"
                    ),
                )
                .await;
                let tag = expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[HEADER]<0.16384>)").await;
                write(&mut wire, &response.replace("{tag}", &tag)).await;
                dropped(&mut wire).await;
            })
        })
        .await;
        let error = fixture
            .probe
            .read_body(
                "fixture",
                "disposable-password",
                "INBOX",
                BodyRequest::new(4, 77),
            )
            .await
            .unwrap_err();
        assert_eq!(error, Error::Protocol);
        fixture.task.await.unwrap();
    }
}

#[tokio::test]
async fn body_read_enforces_literal_header_body_and_operation_budgets_before_payload() {
    let limits = Limits {
        max_header_bytes: 4,
        ..Limits::default()
    };
    let mut header_fixture = fixture(TlsMode::Implicit, limits, |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            metadata(
                &mut wire,
                &format!(
                    "* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {MIXED})\r\n{{tag}} OK fetched\r\n"
                ),
            )
            .await;
            let tag = expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[HEADER]<0.5>)").await;
            write(&mut wire, "* 1 FETCH (UID 4 BODY[HEADER]<0> {6}\r\n").await;
            dropped(&mut wire).await;
            let _ = tag;
        })
    })
    .await;
    let error = header_fixture
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::Limit);
    assert_eq!(header_fixture.probe.metrics().max_literal_bytes, 0);
    header_fixture.task.await.unwrap();

    let mut validity_fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            metadata(
                &mut wire,
                &format!(
                    "* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {})\r\n{{tag}} OK fetched\r\n",
                    MIXED.replacen(" 13 1", " 2097153 1", 1)
                ),
            )
            .await;
            literal(&mut wire, "HEADER", 0, 16 * 1024, "Content-Type: text/plain; charset=utf-8\r\n\r\n").await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let error = validity_fixture
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::Limit);
    validity_fixture.task.await.unwrap();
}

#[tokio::test]
async fn body_read_rejects_uidvalidity_change_and_cancellation_drops_headers_and_body() {
    let mut uidvalidity_fixture = fixture(TlsMode::Implicit, Limits::default(), |mut wire| {
        Box::pin(async move {
            authenticate(&mut wire).await;
            examine(&mut wire).await;
            metadata(
                &mut wire,
                &format!(
                    "* OK [UIDVALIDITY 78] replaced\r\n* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {MIXED})\r\n{{tag}} OK fetched\r\n"
                ),
            )
            .await;
            dropped(&mut wire).await;
        })
    })
    .await;
    let error = uidvalidity_fixture
        .probe
        .read_body(
            "fixture",
            "disposable-password",
            "INBOX",
            BodyRequest::new(4, 77),
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::UnsafeSelection);
    uidvalidity_fixture.task.await.unwrap();

    for point in ["headers", "body"] {
        let (ready_send, ready_receive) = tokio::sync::oneshot::channel();
        let mut fixture = fixture(TlsMode::Implicit, Limits::default(), move |mut wire| {
            Box::pin(async move {
                authenticate(&mut wire).await;
                examine(&mut wire).await;
                metadata(
                    &mut wire,
                    &format!(
                        "* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {MIXED})\r\n{{tag}} OK fetched\r\n"
                    ),
                )
                .await;
                if point == "headers" {
                    expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[HEADER]<0.16384>)").await;
                    ready_send.send(()).unwrap();
                    dropped(&mut wire).await;
                    return;
                }
                literal(&mut wire, "HEADER", 0, 16 * 1024, ROOT_HEADERS).await;
                let _tag = expect(&mut wire, "UID FETCH 4 (UID BODY.PEEK[1]<0.14>)").await;
                write(&mut wire, "* 1 FETCH (UID 4 BODY[1]<0> {14}\r\n").await;
                // The announced but delayed literal keeps the body route suspended.
                ready_send.send(()).unwrap();
                dropped(&mut wire).await;
            })
        })
        .await;
        let operation = tokio::spawn(async move {
            fixture
                .probe
                .read_body(
                    "fixture",
                    "disposable-password",
                    "INBOX",
                    BodyRequest::new(4, 77),
                )
                .await
        });
        ready_receive.await.unwrap();
        operation.abort();
        assert!(operation.await.unwrap_err().is_cancelled());
        fixture.task.await.unwrap();
    }
}

#[test]
fn selected_body_allocations_do_not_follow_attachment_metadata_size() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut peaks = Vec::new();
    for size in [3_000_300, u32::MAX] {
        let server_bytes = Arc::new(AtomicUsize::new(b"* OK synthetic server ready\r\n".len()));
        let counted = server_bytes.clone();
        let (mut probe, server) =
            dedicated_fixture(TlsMode::Implicit, Limits::default(), move |wire| {
                let mut wire: Wire = Box::new(CountedWire {
                    wire,
                    written: counted,
                });
                Box::pin(async move { successful_large_attachment_route(&mut wire, size).await })
            });
        let mut observed_bytes = 0;
        let allocations = allocation_counter::measure(|| {
            runtime.block_on(async {
                let page = probe
                    .read_body(
                        "fixture",
                        "disposable-password",
                        "INBOX",
                        BodyRequest::new(4, 77),
                    )
                    .await
                    .unwrap();
                assert_eq!(page.text, SHORT_BODY);
                assert!(page.metrics.wire_bytes < 64 * 1024);
                observed_bytes = page.metrics.wire_bytes;
            });
        });
        server.join().unwrap();
        assert_eq!(observed_bytes, server_bytes.load(Ordering::Relaxed));
        assert!(observed_bytes < 4096);
        assert!(allocations.bytes_max < 2 * 1024 * 1024, "{allocations:?}");
        assert!(
            allocations.bytes_total < 16 * 1024 * 1024,
            "{allocations:?}"
        );
        peaks.push(allocations.bytes_max);
    }
    assert!(peaks[0].abs_diff(peaks[1]) < 512 * 1024, "{peaks:?}");
}

/// Measures actual server writes independently of the production counters.
struct CountedWire {
    wire: Wire,
    written: Arc<AtomicUsize>,
}
impl AsyncRead for CountedWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(context, buffer)
    }
}
impl AsyncWrite for CountedWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.wire).poll_write(context, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.written.fetch_add(*count, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.wire).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.wire).poll_shutdown(context)
    }
}
