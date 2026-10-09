//! Apply admission limits around the SDK's STDIO transport.
use crate::{
    config::Limits,
    domain::{Error, ErrorCode},
};
use futures_util::StreamExt;
use rmcp::{
    RoleServer,
    model::{ClientNotification, ClientRequest, GetExtensions, JsonRpcMessage},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{Transport, async_rw::AsyncRwTransport},
};
use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_util::sync::CancellationToken;

type Pending = Arc<Mutex<HashMap<rmcp::model::RequestId, PendingRequest>>>;

struct PendingRequest {
    _permit: OwnedSemaphorePermit,
    cancellation: RequestCancellation,
}

#[derive(Clone)]
pub(super) struct RequestCancellation(CancellationToken);
impl RequestCancellation {
    pub(super) fn new() -> Self {
        Self(CancellationToken::new())
    }

    pub(super) fn token(&self) -> &CancellationToken {
        &self.0
    }
}

/// A fixed reservation for decoding/control traffic stays available even when all
/// request reservations are occupied. These are ceilings, not eagerly allocated buffers.
pub(super) struct Bounds {
    input: usize,
    pub(super) envelope: usize,
    output: usize,
    requests: usize,
    nesting: usize,
    deadline: Duration,
}
impl Bounds {
    pub(super) fn new(
        limits: &Limits,
        response_bound: usize,
        drafts: bool,
        schema_bytes: usize,
    ) -> Result<Self, Error> {
        // Cover the SDK/codec's initial buffers, duplex, and bounded task metadata.
        const FIXED: usize = 64 * 1024;
        let available = limits
            .buffered_bytes
            .checked_sub(FIXED)
            .ok_or_else(Error::setup_required)?;
        let draft_mime = if drafts { limits.draft_mime_bytes } else { 0 };
        let fits = |input, envelope| {
            let (_, control, request) =
                Self::reservations(input, envelope, limits.accounts, draft_mime, schema_bytes);
            control + request <= available
        };
        // Keep room for useful discovery responses before maximizing input.
        // Maximizing draft input against a 1 KiB envelope otherwise consumes
        // the budget and rejects ordinary capabilities on a default grant.
        let reserved_envelope = largest_fitting(
            1024,
            response_bound.min(limits.envelope_bytes).min(64 * 1024),
            |candidate| fits(1024, candidate),
        );
        // Draft bodies and search predicates can expand sixfold in JSON.
        // Reserve bounded input and composition storage before sizing responses.
        let input = largest_fitting(
            1024,
            limits.envelope_bytes.min(if drafts {
                6 * limits.draft_mime_bytes + 256 * 1024
            } else {
                1024 * 1024
            }),
            |candidate| fits(candidate, reserved_envelope),
        );
        let envelope = largest_fitting(0, response_bound.min(limits.envelope_bytes), |candidate| {
            fits(input, candidate)
        });
        if envelope < 1024 {
            return Err(Error::setup_required());
        }
        let (output, control, request) =
            Self::reservations(input, envelope, limits.accounts, draft_mime, schema_bytes);
        let requests = (available - control) / request;
        Ok(Self {
            input,
            envelope,
            output,
            requests: requests.min(limits.active_requests + limits.queued_requests),
            nesting: limits.json_nesting,
            deadline: Duration::from_secs(limits.operation_seconds as u64),
        })
    }

    fn reservations(
        input: usize,
        envelope: usize,
        accounts: usize,
        draft_mime: usize,
        schema_bytes: usize,
    ) -> (usize, usize, usize) {
        // Nonempty identity strings occupy at least three encoded bytes, with
        // at most 100 per discovered account. Count both String/Value descriptors
        // and account/BTree overhead, rather than multiplying all field bytes by
        // a JSON node worst case. Service reserves >=160 bytes per account before
        // cloning; health may include up to 256 accounts independent of page size.
        let structure = 64 * 1024
            + 64 * (accounts * 100).min(envelope / 3)
            + 4096 * accounts.min(envelope / 160)
            + 1024 * 256.min(envelope / 160);
        // MCP contains the envelope once as a Value and once as JSON text.
        // Escaping that already serialized text adds at most one byte per byte.
        // Tool schemas can exceed a small result budget. Reserve their measured size,
        // plus the caller's JSON-RPC id, before admitting the session.
        let output = (3 * envelope + input + 1024)
            .max(schema_bytes + input + 1024)
            .max(32 * 1024);
        // The permanent control allocation covers one decoder, retained client
        // initialization data and ingress scratch. SDK/Tokio encoder capacities
        // remain allocated after a response: each can grow to twice its payload;
        // Tokio's pinned STDIO implementation copies at most 2 MiB per write.
        // The ingress guard caps JSON keys/values at 4096 before SDK decoding.
        // Large frames therefore reserve bounded node overhead instead of
        // treating every string byte as another tiny JSON value. Retain the
        // tighter generic estimate for small frames.
        let control_input = (272 * input).min(12 * input + 4 * 1024 * 1024);
        let request_input = (128 * input).min(4 * input + 2 * 1024 * 1024);
        let control = control_input + 2 * output + 2 * output.min(2 * 1024 * 1024);
        // The input/metadata survives to output completion. Domain-to-Value
        // conversion holds at most two copies of field bytes; Value plus text
        // holds at most three, including String capacity growth.
        let request = request_input + 3 * envelope + structure + 2 * draft_mime;
        (output, control, request)
    }
}

fn largest_fitting(mut lower: usize, mut upper: usize, fits: impl Fn(usize) -> bool) -> usize {
    while lower < upper {
        let candidate = lower + (upper - lower).div_ceil(2);
        if fits(candidate) {
            lower = candidate;
        } else {
            upper = candidate - 1;
        }
    }
    lower
}

pub(super) struct BoundedStdio<W: AsyncWrite = tokio::io::Stdout> {
    sdk: AsyncRwTransport<RoleServer, tokio::io::DuplexStream, W>,
    ingress: JoinHandle<()>,
    slots: Arc<Semaphore>,
    pending: Pending,
    control: Arc<Semaphore>,
    output_limit: usize,
    deadline: Duration,
    receive_expires: Instant,
    initializing: bool,
    staged: Option<(RxJsonRpcMessage<RoleServer>, OwnedSemaphorePermit)>,
}

async fn forward_bounded_input(
    reader: impl AsyncRead + Unpin,
    writer: &mut (impl AsyncWrite + Unpin),
    input_limit: usize,
    nesting_limit: usize,
    deadline: Duration,
) -> Result<(), ErrorCode> {
    let mut lines = FramedRead::new(reader, LinesCodec::new_with_max_length(input_limit));
    for _ in 0..4096 {
        let line = match timeout(deadline, lines.next()).await {
            Ok(Some(Ok(line))) => line,
            Ok(None) => return Ok(()),
            Ok(Some(Err(_))) => return Err(ErrorCode::InvalidRequest),
            Err(_) => return Err(ErrorCode::Timeout),
        };
        crate::encoding::validate_json_bounds(line.as_bytes(), nesting_limit, 4096)
            .map_err(|error| error.code)?;
        let write = async {
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await
        };
        timeout(deadline, write)
            .await
            .map_err(|_| ErrorCode::Timeout)?
            .map_err(|_| ErrorCode::Cancelled)?;
    }
    Ok(())
}

impl BoundedStdio {
    pub(super) fn new(bounds: Bounds, shutdown: CancellationToken) -> Self {
        Self::with_io(bounds, shutdown, tokio::io::stdin(), tokio::io::stdout())
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> BoundedStdio<W> {
    fn with_io(
        bounds: Bounds,
        shutdown: CancellationToken,
        input: impl AsyncRead + Unpin + Send + 'static,
        output: W,
    ) -> Self {
        let (reader, mut writer) = tokio::io::duplex(8192);
        // Validate complete, bounded lines before the SDK can buffer or parse them.
        let ingress = tokio::spawn(async move {
            // The SDK may drain requests after EOF; cancel active work as soon as input closes.
            let _cancel_on_exit = shutdown.drop_guard();
            let _ = forward_bounded_input(
                input,
                &mut writer,
                bounds.input,
                bounds.nesting,
                bounds.deadline,
            )
            .await;
        });
        Self {
            sdk: AsyncRwTransport::new_server(reader, output),
            ingress,
            slots: Arc::new(Semaphore::new(bounds.requests)),
            pending: Default::default(),
            control: Arc::new(Semaphore::new(1)),
            output_limit: bounds.output,
            deadline: bounds.deadline,
            receive_expires: Instant::now() + bounds.deadline,
            initializing: true,
            staged: None,
        }
    }
}

impl<W: AsyncWrite> Drop for BoundedStdio<W> {
    fn drop(&mut self) {
        self.ingress.abort();
    }
}
impl<W: AsyncWrite + Unpin + Send + 'static> Transport<RoleServer> for BoundedStdio<W> {
    type Error = io::Error;
    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let id = match &item {
            JsonRpcMessage::Response(value) => Some(value.id.clone()),
            JsonRpcMessage::Error(value) => value.id.clone(),
            _ => None,
        };
        let cancelled = id.as_ref().is_some_and(|id| {
            self.pending.lock().is_ok_and(|pending| {
                pending
                    .get(id)
                    .is_some_and(|request| request.cancellation.0.is_cancelled())
            })
        });
        let valid = cancelled || crate::encoding::serialized_size(&item, self.output_limit).is_ok();
        let pending = self.pending.clone();
        let send = if cancelled {
            // Release the reservation only after the handler's retained output
            // has been dropped, preserving cancellation's no-response behavior.
            drop(item);
            None
        } else {
            Some(self.sdk.send(item))
        };
        let deadline = self.deadline;
        async move {
            if !valid {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let result = match send {
                Some(send) => timeout(deadline, send)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
                None => Ok(()),
            };
            if let Some(id) = id {
                pending
                    .lock()
                    .map_err(|_| io::ErrorKind::Other)?
                    .remove(&id);
            }
            result
        }
    }
    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            // This parsing uses the permanent control reservation. Transfer ownership
            // to a request reservation before returning to the SDK's task scheduler.
            // Notifications retain it in SDK extensions through their handler's return,
            // so a flood cannot accumulate detached notification tasks. This permit is
            // independent of request saturation; acquire it before consuming any input.
            if self.staged.is_none() {
                let control = self.control.clone().acquire_owned().await.ok()?;
                // SDK receive is cancellation-safe; keep the same deadline when the SDK
                // service loop interrupts it to send a response.
                let item = timeout_at(self.receive_expires, self.sdk.receive())
                    .await
                    .ok()??;
                self.receive_expires = Instant::now() + self.deadline;
                self.staged = Some((item, control));
            }
            let (item, _) = self.staged.as_mut()?;
            if let JsonRpcMessage::Notification(notification) = item
                && let ClientNotification::CancelledNotification(notification) =
                    &notification.notification
                && let Some(request) = notification.params.request_id.as_ref().and_then(|id| {
                    self.pending
                        .lock()
                        .ok()?
                        .get(id)
                        .map(|request| request.cancellation.clone())
                })
            {
                // The SDK drops canceled handler responses before calling send.
                // Keep its response path intact and cancel through the extension,
                // so admission remains occupied through handler and output cleanup.
                request.0.cancel();
                self.staged.take();
                continue;
            }
            if let JsonRpcMessage::Request(request) = item {
                if self.initializing {
                    match &request.request {
                        ClientRequest::InitializeRequest(_) => self.initializing = false,
                        ClientRequest::PingRequest(_) => {}
                        // Newer SDKs also support initialization through per-request
                        // metadata; this server pins the 2025 initialize lifecycle.
                        _ => return None,
                    }
                }
                // A peer can receive a response before its send future releases the
                // request reservation. Keep this one decoded request in the control
                // reservation while waiting; SDK select cancellation must not lose it.
                let permit = timeout_at(self.receive_expires, self.slots.clone().acquire_owned())
                    .await
                    .ok()?
                    .ok()?;
                let mut pending = self.pending.lock().ok()?;
                match pending.entry(request.id.clone()) {
                    Entry::Vacant(entry) => {
                        let cancellation = RequestCancellation::new();
                        request
                            .request
                            .extensions_mut()
                            .insert(cancellation.clone());
                        entry.insert(PendingRequest {
                            _permit: permit,
                            cancellation,
                        });
                    }
                    Entry::Occupied(_) => return None,
                }
            }
            let (mut item, control) = self.staged.take()?;
            if let JsonRpcMessage::Notification(notification) = &mut item {
                notification
                    .notification
                    .extensions_mut()
                    .insert(Arc::new(control));
            }
            return Some(item);
        }
    }
    async fn close(&mut self) -> io::Result<()> {
        self.ingress.abort();
        self.sdk.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fuzz_support, mcp_corpus::MCP};
    use rmcp::{
        ServerHandler, ServiceExt,
        model::{
            CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData,
            ProtocolVersion, RequestId, ServerCapabilities, ServerConfig,
        },
        service::RequestContext,
    };
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, BufReader};

    struct GatedRequests {
        entered: tokio::sync::mpsc::UnboundedSender<RequestId>,
        cancelled: tokio::sync::mpsc::UnboundedSender<RequestId>,
        cleanup: Arc<Semaphore>,
    }

    impl ServerHandler for GatedRequests {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(ServerCapabilities::default())
                .with_protocol_version(ProtocolVersion::V_2025_11_25)
        }

        async fn call_tool(
            &self,
            _: CallToolRequestParams,
            context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, ErrorData> {
            self.entered.send(context.id.clone()).unwrap();
            let cancellation = context
                .extensions
                .get::<RequestCancellation>()
                .map_or(&context.ct, RequestCancellation::token);
            tokio::select! {
                _ = cancellation.cancelled() => {},
                _ = context.ct.cancelled() => {},
            }
            self.cancelled.send(context.id).unwrap();
            // Cancellation has reached the handler, but cleanup still owns its
            // admitted memory. The next request must wait for this gate.
            self.cleanup.acquire().await.unwrap().forget();
            Ok(CallToolResult::success(vec![ContentBlock::text("canceled output")]).into())
        }
    }

    #[tokio::test]
    async fn repeated_cancellation_retains_admission_until_cleanup_and_keeps_stdio_usable() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (input, output) = tokio::io::split(server_io);
        let transport = BoundedStdio::with_io(
            Bounds {
                input: 4096,
                envelope: 1024,
                output: 32 * 1024,
                requests: 1,
                nesting: 32,
                deadline: Duration::from_secs(2),
            },
            CancellationToken::new(),
            input,
            output,
        );
        let slots = transport.slots.clone();
        let pending = transport.pending.clone();
        let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
        let (cancelled, mut cancellations) = tokio::sync::mpsc::unbounded_channel();
        let cleanup = Arc::new(Semaphore::new(0));
        let handler = GatedRequests {
            entered,
            cancelled,
            cleanup: cleanup.clone(),
        };
        let serving = tokio::spawn(async move { handler.serve(transport).await.unwrap() });
        let (reader, mut writer) = tokio::io::split(client_io);
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"cancellation-test\",\"version\":\"1\"}}}\n").await.unwrap();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"],
            0
        );
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        let server = timeout(Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap();

        for id in 1..=3 {
            let request = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"gated\"}}}}\n"
            );
            writer.write_all(request.as_bytes()).await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(2), entries.recv())
                    .await
                    .unwrap(),
                Some(RequestId::Number(id)),
            );
            let cancel = format!(
                "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{id}}}}}\n"
            );
            writer.write_all(cancel.as_bytes()).await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(2), cancellations.recv())
                    .await
                    .unwrap(),
                Some(RequestId::Number(id)),
            );
            assert_eq!(slots.available_permits(), 0);
            assert!(pending.lock().unwrap().contains_key(&RequestId::Number(id)));
            let ping_id = 100 + id;
            let ping = format!("{{\"jsonrpc\":\"2.0\",\"id\":{ping_id},\"method\":\"ping\"}}\n");
            writer.write_all(ping.as_bytes()).await.unwrap();
            line.clear();
            assert!(
                timeout(Duration::from_millis(20), reader.read_line(&mut line))
                    .await
                    .is_err(),
                "canceled work retains its reservation through cleanup",
            );
            cleanup.add_permits(1);
            timeout(Duration::from_secs(2), reader.read_line(&mut line))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"],
                ping_id,
                "the canceled request produces no wire response and the next request succeeds",
            );
            assert!(!pending.lock().unwrap().contains_key(&RequestId::Number(id)));
        }
        server.cancel().await.unwrap();
    }

    fn decoding_case(
        runtime: &tokio::runtime::Runtime,
        input: &[u8],
        case: usize,
    ) -> (bool, Option<ErrorCode>) {
        assert!(
            input.len() <= fuzz_support::MAX_INPUT_BYTES,
            "MCP decoding input ceiling in case {case}"
        );
        // Sessions admit at least 1 KiB; use the production control reservation,
        // which includes decoder scratch and retained SDK buffers.
        let (_, reservation, _) = Bounds::reservations(input.len().max(1024), 1024, 1, 0, 0);
        let started = std::time::Instant::now();
        let mut accepted = false;
        let mut admission_error = None;
        let measured = allocation_counter::measure(|| {
            runtime.block_on(async {
                let input = input.to_vec();
                let (reader, mut writer) = tokio::io::duplex(8192);
                let ingress = tokio::spawn(async move {
                    forward_bounded_input(
                        input.as_slice(),
                        &mut writer,
                        fuzz_support::MAX_INPUT_BYTES,
                        32,
                        Duration::from_secs(2),
                    )
                    .await
                });
                let mut sdk =
                    AsyncRwTransport::<RoleServer, _, _>::new_server(reader, tokio::io::sink());
                let received = timeout(Duration::from_secs(2), sdk.receive()).await;
                let retained = received.as_ref().ok().and_then(Option::as_ref).cloned();
                accepted = retained.is_some();
                ingress.abort();
                let joined = ingress.await;
                admission_error = match joined {
                    Ok(result) => result.err(),
                    Err(error) => {
                        assert!(
                            error.is_cancelled(),
                            "MCP ingress task failed in case {case}"
                        );
                        None
                    }
                };
                assert!(received.is_ok(), "MCP SDK receive deadline in case {case}");
                drop(std::hint::black_box((received, retained)));
            });
        });
        assert!(
            measured.bytes_max as usize <= reservation,
            "MCP decoding control reservation exceeded in case {case}"
        );
        assert!(
            measured.bytes_total <= 16 * 1024 * 1024,
            "MCP decoding total allocation ceiling in case {case}"
        );
        assert!(
            measured.count_total <= 32 * 1024,
            "MCP decoding allocation work ceiling in case {case}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "MCP decoding deadline in case {case}"
        );
        (accepted, admission_error)
    }

    #[test]
    fn mcp_decoding_regressions_fit_reservations_and_work_bounds() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread decoding runtime");
        for (case, input) in MCP.iter().enumerate() {
            let (accepted, _) = decoding_case(&runtime, input, case);
            if case < 2 {
                assert!(accepted, "valid retained MCP request in case {case}");
            }
        }
        for (case, input) in [
            vec![0xff, b'\n'],
            format!("{}0{}\n", "[".repeat(65), "]".repeat(65)).into_bytes(),
            format!("[{}]\n", vec!["0"; 4097].join(",")).into_bytes(),
            vec![b'x'; fuzz_support::MAX_INPUT_BYTES],
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !decoding_case(&runtime, input, MCP.len() + case).0,
                "invalid retained MCP request in case {case}"
            );
        }
        let mut sequence = MCP[0].to_vec();
        sequence.extend_from_slice(format!("{}0{}\n", "[".repeat(65), "]".repeat(65)).as_bytes());
        let (accepted, admission_error) = decoding_case(&runtime, &sequence, MCP.len() + 4);
        assert!(accepted, "valid MCP frame survives a later rejected frame");
        assert_eq!(
            admission_error,
            Some(ErrorCode::InvalidRequest),
            "later MCP frame exceeds the admission bound"
        );
    }

    #[test]
    #[ignore = "explicit bounded mutation campaign"]
    fn fuzz_mcp_decoding() {
        let campaign = fuzz_support::Campaign::from_env("mcp-decoding");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread decoding runtime");
        for (case, input) in campaign.cases(MCP) {
            decoding_case(&runtime, &input, case);
        }
        campaign.finish();
    }

    #[test]
    fn bounded_sdk_decoding_fits_the_input_reservation_for_large_strings_and_many_nodes() {
        for arguments in [
            json!({"mailbox":"mb1.synthetic","criteria":vec![json!({"field":"text","value":"\u{1}".repeat(4096)});32]}),
            json!({"values":vec![json!({"a":0,"b":1});500]}),
        ] {
            let frame = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"email_search_messages","arguments":arguments}})).unwrap();
            crate::encoding::validate_json_bounds(&frame, 32, 4096).unwrap();
            let measured = allocation_counter::measure(|| {
                let decoded: RxJsonRpcMessage<RoleServer> = serde_json::from_slice(&frame).unwrap();
                let retained = decoded.clone();
                std::hint::black_box((decoded, retained));
            });
            let reservation = (128 * frame.len()).min(4 * frame.len() + 2 * 1024 * 1024);
            assert!(measured.bytes_max as usize <= reservation, "{measured:?}");
            eprintln!(
                "MCP input bytes={} peak={} reservation={reservation}",
                frame.len(),
                measured.bytes_max
            );
        }
        let excessive = serde_json::to_vec(&vec![0; 4097]).unwrap();
        assert!(crate::encoding::validate_json_bounds(&excessive, 32, 4096).is_err());
    }
}
