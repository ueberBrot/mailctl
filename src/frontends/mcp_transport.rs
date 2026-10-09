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
    pin::Pin,
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

struct DeferredRequest {
    request: rmcp::model::JsonRpcRequest<ClientRequest>,
    expires: Instant,
}

struct RejectedRequest {
    send: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
    _control: OwnedSemaphorePermit,
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
        if !fits(1024, 1024) {
            return Err(Error::setup_required());
        }
        // Draft bodies and search predicates can expand sixfold in JSON.
        let input_limit = limits.envelope_bytes.min(if drafts {
            6 * limits.draft_mime_bytes + 256 * 1024
        } else {
            1024 * 1024
        });
        // Retain full search arguments while making room for large discovery
        // results. Opaque references use a JSON-safe alphabet; the remaining
        // space covers predicate wrappers and ordinary JSON-RPC metadata.
        let reserved_input = if drafts {
            1024
        } else {
            largest_fitting(
                1024,
                input_limit.min(6 * 32 * 4096 + 2 * limits.token_bytes + 4096),
                |candidate| fits(candidate, 1024),
            )
        };
        // Draft composition keeps input priority while reserving enough output
        // for ordinary capabilities. Read-only sessions also accommodate large
        // configured account inventories within the same fixed byte budget.
        let reserved_envelope = largest_fitting(
            1024,
            response_bound.min(limits.envelope_bytes).min(if drafts {
                64 * 1024
            } else {
                4 * 1024 * 1024
            }),
            |candidate| fits(reserved_input, candidate),
        );
        // Reserve bounded input and composition storage before sizing responses.
        let input = largest_fitting(1024, input_limit, |candidate| {
            fits(candidate, reserved_envelope)
        });
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
        // One decoded request may wait for admission while the decoder continues
        // handling cancellation and other control traffic independently.
        let control = control_input + request_input + 2 * output + 2 * output.min(2 * 1024 * 1024);
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
    deferred: Option<DeferredRequest>,
    rejected: Option<RejectedRequest>,
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
            deferred: None,
            rejected: None,
        }
    }

    fn receive_deadline(&self) -> Instant {
        self.deferred
            .as_ref()
            .map_or(self.receive_expires, |request| {
                self.receive_expires.min(request.expires)
            })
    }

    fn admit_request(
        &self,
        mut request: rmcp::model::JsonRpcRequest<ClientRequest>,
        permit: OwnedSemaphorePermit,
    ) -> Option<RxJsonRpcMessage<RoleServer>> {
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
                Some(JsonRpcMessage::Request(request))
            }
            Entry::Occupied(_) => None,
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
            let expires = self.receive_deadline();
            if let Some(rejected) = &mut self.rejected {
                // SDK select can interrupt receive while output is partially
                // written. Retain this single control response until completion.
                timeout_at(expires, &mut rejected.send).await.ok()?.ok()?;
                self.rejected = None;
            }
            if self
                .deferred
                .as_ref()
                .is_some_and(|request| request.expires <= Instant::now())
            {
                return None;
            }
            // Process decoded control traffic before admitting its canceled
            // request, but keep older waiting work ahead of fresh requests.
            if self
                .staged
                .as_ref()
                .is_none_or(|(item, _)| matches!(item, JsonRpcMessage::Request(_)))
                && self.deferred.is_some()
            {
                match self.slots.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let request = self.deferred.take()?.request;
                        return self.admit_request(request, permit);
                    }
                    Err(tokio::sync::TryAcquireError::NoPermits) => {}
                    Err(tokio::sync::TryAcquireError::Closed) => return None,
                }
            }
            // Decode/control storage is independent of request saturation.
            // Notifications keep its permit through their SDK handler's return,
            // so a flood cannot accumulate detached notification tasks.
            if self.staged.is_none() {
                let slots = self.slots.clone();
                let control = self.control.clone();
                let waiting = self.deferred.is_some();
                let input = async {
                    let control = control.acquire_owned().await.ok()?;
                    // Keep the deadline and SDK decoder scratch across select
                    // interruption by outgoing responses or released admission.
                    let item = timeout_at(expires, self.sdk.receive()).await.ok()??;
                    Some((item, control))
                };
                tokio::select! {
                    biased;
                    permit = timeout_at(expires, slots.acquire_owned()), if waiting => {
                        let permit = permit.ok()?.ok()?;
                        let request = self.deferred.take()?.request;
                        return self.admit_request(request, permit);
                    }
                    item = input => {
                        self.staged = Some(item?);
                        self.receive_expires = Instant::now() + self.deadline;
                    }
                }
                // Released admission belongs to the oldest waiting request,
                // including when a fresh frame was decoded at the same time.
                continue;
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
            if let JsonRpcMessage::Notification(notification) = item
                && let ClientNotification::CancelledNotification(notification) =
                    &notification.notification
                && self.deferred.as_ref().is_some_and(|request| {
                    notification.params.request_id.as_ref() == Some(&request.request.id)
                })
            {
                // This request has never reached a handler or provider.
                self.deferred = None;
                self.staged.take();
                continue;
            }
            if let JsonRpcMessage::Request(request) = item {
                if self.initializing {
                    match &request.request {
                        ClientRequest::InitializeRequest(_) => self.initializing = false,
                        ClientRequest::PingRequest(_) => {}
                        // This server uses the pinned initialize lifecycle.
                        _ => return None,
                    }
                }
                // Never correlate an overload response with an admitted or waiting ID.
                if self.pending.lock().ok()?.contains_key(&request.id)
                    || self
                        .deferred
                        .as_ref()
                        .is_some_and(|waiting| waiting.request.id == request.id)
                {
                    return None;
                }
                let permit = if self.deferred.is_none() {
                    match self.slots.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(tokio::sync::TryAcquireError::NoPermits) => None,
                        Err(tokio::sync::TryAcquireError::Closed) => return None,
                    }
                } else {
                    None
                };
                let (JsonRpcMessage::Request(request), control) = self.staged.take()? else {
                    unreachable!();
                };
                if let Some(permit) = permit {
                    return self.admit_request(request, permit);
                }
                if self.deferred.is_none() {
                    self.deferred = Some(DeferredRequest {
                        request,
                        expires: self.receive_expires,
                    });
                    drop(control);
                    continue;
                }
                // Keep one waiting request without blocking cancellation. Only
                // further excess requests need a response from the control budget.
                let response = TxJsonRpcMessage::<RoleServer>::error(
                    rmcp::model::ErrorData::new(
                        rmcp::model::ErrorCode(-32000),
                        "Request capacity exhausted",
                        Some(serde_json::json!({"code": "rate_limited"})),
                    ),
                    Some(request.id),
                );
                self.rejected = Some(RejectedRequest {
                    send: Box::pin(self.sdk.send(response)),
                    _control: control,
                });
                continue;
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
        // A paused rejection can own the SDK writer lock while output is blocked.
        self.rejected = None;
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

    fn one_request_bounds() -> Bounds {
        Bounds {
            input: 4096,
            envelope: 1024,
            output: 32 * 1024,
            requests: 1,
            nesting: 32,
            deadline: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn discovery_budget_retains_maximally_escaped_search_arguments() {
        let limits = Limits {
            accounts: 40,
            ..Limits::default()
        };
        let bounds = Bounds::new(&limits, limits.envelope_bytes, false, 64 * 1024).unwrap();
        let arguments = json!({
            "mailbox": "m".repeat(limits.token_bytes),
            "cursor": "c".repeat(limits.token_bytes),
            "criteria": (0..32)
                .map(|_| json!({"field": "subject", "value": "\u{1}".repeat(4096)}))
                .collect::<Vec<_>>(),
            "limit": 200,
        });
        serde_json::from_value::<crate::domain::SearchMessagesInput>(arguments.clone()).unwrap();
        let mut request = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "i".repeat(1024),
            "method": "tools/call",
            "params": {"name": "email_search_messages", "arguments": arguments},
        }))
        .unwrap();
        request.push(b'\n');
        let (input, mut writer) = tokio::io::duplex(8192);
        let sending = tokio::spawn(async move { writer.write_all(&request).await.unwrap() });
        let mut transport =
            BoundedStdio::with_io(bounds, CancellationToken::new(), input, tokio::io::sink());
        transport.initializing = false;
        assert!(matches!(
            timeout(Duration::from_secs(2), transport.receive())
                .await
                .unwrap(),
            Some(JsonRpcMessage::Request(_)),
        ));
        sending.await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_ids_do_not_reject_or_release_an_admitted_request() {
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".as_slice(),
            tokio::io::sink(),
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        assert!(transport.receive().await.is_none());
        assert_eq!(transport.slots.available_permits(), 0);
        assert!(transport.rejected.is_none());
        let pending = transport.pending.lock().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&RequestId::Number(1)));
    }

    #[tokio::test]
    async fn duplicate_ids_do_not_reject_or_replace_a_waiting_request() {
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n".as_slice(),
            tokio::io::sink(),
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        assert!(transport.receive().await.is_none());
        assert_eq!(transport.slots.available_permits(), 0);
        assert!(transport.rejected.is_none());
        assert_eq!(
            transport.deferred.as_ref().unwrap().request.id,
            RequestId::Number(2)
        );
        let pending = transport.pending.lock().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&RequestId::Number(1)));
    }

    #[tokio::test]
    async fn cancellation_drops_waiting_requests_before_dispatch() {
        let (input, mut writer) = tokio::io::duplex(8192);
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n").await.unwrap();
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            input,
            tokio::io::sink(),
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .is_err()
        );
        assert_eq!(
            transport.deferred.as_ref().unwrap().request.id,
            RequestId::Number(3)
        );
        assert!(transport.rejected.is_none());
        transport
            .send(TxJsonRpcMessage::<RoleServer>::response(
                rmcp::model::ServerResult::empty(()),
                RequestId::Number(1),
            ))
            .await
            .unwrap();
        let Some(JsonRpcMessage::Request(request)) = transport.receive().await else {
            panic!("uncanceled waiting request remains usable");
        };
        assert_eq!(request.id, RequestId::Number(3));
        let pending = transport.pending.lock().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending.contains_key(&RequestId::Number(2)));
    }

    #[tokio::test]
    async fn decoded_cancellation_precedes_admission_released_at_the_same_time() {
        let (input, mut writer) = tokio::io::duplex(8192);
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n").await.unwrap();
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            input,
            tokio::io::sink(),
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .is_err()
        );
        // Reproduce SDK select interruption after decoding cancellation but
        // before dispatching it, followed by an outgoing response releasing a slot.
        let cancellation = serde_json::from_slice::<RxJsonRpcMessage<RoleServer>>(
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}",
        ).unwrap();
        transport.staged = Some((
            cancellation,
            transport.control.clone().try_acquire_owned().unwrap(),
        ));
        transport
            .send(TxJsonRpcMessage::<RoleServer>::response(
                rmcp::model::ServerResult::empty(()),
                RequestId::Number(1),
            ))
            .await
            .unwrap();
        drop(writer);
        assert!(
            timeout(Duration::from_secs(2), transport.receive())
                .await
                .unwrap()
                .is_none()
        );
        assert!(transport.deferred.is_none());
        assert!(transport.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn control_notifications_do_not_extend_a_waiting_requests_deadline() {
        let (input, mut writer) = tokio::io::duplex(8192);
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n").await.unwrap();
        let mut transport = BoundedStdio::with_io(
            Bounds {
                deadline: Duration::from_millis(100),
                ..one_request_bounds()
            },
            CancellationToken::new(),
            input,
            tokio::io::sink(),
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .is_err()
        );
        let expires = transport.deferred.as_ref().unwrap().expires;
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        let notification = transport.receive().await.unwrap();
        assert!(matches!(notification, JsonRpcMessage::Notification(_)));
        drop(notification);
        assert_eq!(transport.deferred.as_ref().unwrap().expires, expires);
        assert!(transport.receive_expires > expires);
        tokio::time::sleep_until(expires).await;
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn interrupted_overload_output_resumes_once_before_later_cancellation() {
        let (output, reader) = tokio::io::duplex(1);
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n".as_slice(),
            output,
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        let cancellation = transport.pending.lock().unwrap()[&RequestId::Number(1)]
            .cancellation
            .clone();
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .is_err(),
        );
        assert!(transport.rejected.is_some());
        assert!(!cancellation.0.is_cancelled());
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let (received, written) = timeout(Duration::from_secs(2), async {
            tokio::join!(transport.receive(), reader.read_line(&mut line))
        })
        .await
        .unwrap();
        assert!(received.is_none());
        assert!(written.unwrap() > 0);
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], 3);
        assert_eq!(response["error"]["data"]["code"], "rate_limited");
        assert!(transport.rejected.is_none());
        assert!(transport.deferred.is_none());
        assert!(cancellation.0.is_cancelled());
        assert_eq!(transport.slots.available_permits(), 0);
        drop(transport);
        line.clear();
        assert_eq!(reader.read_line(&mut line).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn closing_discards_a_blocked_overload_response_before_closing_the_writer() {
        let (output, _reader) = tokio::io::duplex(1);
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n".as_slice(),
            output,
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .is_err(),
        );
        assert!(transport.rejected.is_some());
        timeout(Duration::from_secs(1), transport.close())
            .await
            .expect("blocked rejection must not keep the writer mutex locked during close")
            .unwrap();
        assert!(transport.rejected.is_none());
    }

    #[tokio::test]
    async fn sequential_requests_wait_for_started_output_to_release_admission() {
        let (output, reader) = tokio::io::duplex(1);
        let (input, mut writer) = tokio::io::duplex(8192);
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n").await.unwrap();
        let mut transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            input,
            output,
        );
        transport.initializing = false;
        assert!(transport.receive().await.is_some());
        let mut send = Box::pin(transport.send(TxJsonRpcMessage::<RoleServer>::response(
            rmcp::model::ServerResult::empty(()),
            RequestId::Number(1),
        )));
        assert!(timeout(Duration::from_millis(20), &mut send).await.is_err(),);
        assert!(
            timeout(Duration::from_millis(20), transport.receive())
                .await
                .is_err(),
        );
        assert!(transport.deferred.is_some());
        assert!(transport.rejected.is_none());
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let (sent, received, written) = timeout(Duration::from_secs(2), async {
            tokio::join!(send, transport.receive(), reader.read_line(&mut line))
        })
        .await
        .unwrap();
        sent.unwrap();
        assert!(written.unwrap() > 0);
        let Some(JsonRpcMessage::Request(request)) = received else {
            panic!("sequential request remains admitted");
        };
        assert_eq!(request.id, RequestId::Number(2));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"],
            1,
        );
        assert!(transport.rejected.is_none());
        let pending = transport.pending.lock().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&RequestId::Number(2)));
    }

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
    async fn saturated_requests_do_not_hide_later_cancellation_notifications() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (input, output) = tokio::io::split(server_io);
        let transport = BoundedStdio::with_io(
            one_request_bounds(),
            CancellationToken::new(),
            input,
            output,
        );
        let slots = transport.slots.clone();
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
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"saturation-test\",\"version\":\"1\"}}}\n").await.unwrap();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        let server = timeout(Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap();
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"gated\"}}\n").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), entries.recv())
                .await
                .unwrap(),
            Some(RequestId::Number(1)),
        );
        // The excess request arrives before cancellation while the admitted
        // handler cannot finish until it receives that cancellation.
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), cancellations.recv())
                .await
                .expect("saturation must leave the cancellation control path available"),
            Some(RequestId::Number(1)),
        );
        assert_eq!(slots.available_permits(), 0);
        line.clear();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], 3);
        assert_eq!(response["error"]["data"]["code"], "rate_limited");
        cleanup.add_permits(1);
        line.clear();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"],
            2,
        );
        server.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn repeated_cancellation_retains_admission_until_cleanup_and_keeps_stdio_usable() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (input, output) = tokio::io::split(server_io);
        let transport = BoundedStdio::with_io(
            one_request_bounds(),
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
            json!({"mailbox":"mb.synthetic","criteria":vec![json!({"field":"text","value":"\u{1}".repeat(4096)});32]}),
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
