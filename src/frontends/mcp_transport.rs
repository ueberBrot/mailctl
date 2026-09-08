//! Apply admission limits around the SDK's STDIO transport.
use crate::{config::Limits, domain::Error};
use futures_util::StreamExt;
use rmcp::{
    RoleServer,
    model::{ClientRequest, GetExtensions, JsonRpcMessage},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{Transport, async_rw::AsyncRwTransport},
};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::codec::{FramedRead, LinesCodec};

type SdkStdio = AsyncRwTransport<RoleServer, tokio::io::DuplexStream, tokio::io::Stdout>;
type Pending = Arc<Mutex<HashMap<rmcp::model::RequestId, OwnedSemaphorePermit>>>;

/// A fixed reservation for decoding/control traffic stays available even when all
/// request reservations are occupied. These are ceilings, not eagerly allocated buffers.
pub(super) struct Bounds {
    input: usize,
    pub(super) output: usize,
    requests: usize,
    nesting: usize,
    deadline: Duration,
}
impl Bounds {
    pub(super) fn new(limits: &Limits) -> Result<Self, Error> {
        // Cover the SDK/codec's initial buffers, duplex, and bounded task metadata.
        const FIXED: usize = 64 * 1024;
        let available = limits
            .buffered_bytes
            .checked_sub(FIXED)
            .ok_or_else(Self::capacity_error)?;
        let input = limits.envelope_bytes.min(64 * 1024).min(available / 1024);
        let output = limits.envelope_bytes.min(1024 * 1024).min(available / 64);
        // 128x covers worst-case tiny JSON Value nodes, BTree entries, SDK
        // deserialization scratch and cloned request metadata. The ingress line,
        // codec/read buffer capacities and duplex coexist with that decoder.
        // Initialization also retains the bounded client description/capabilities
        // for the session after the initialize request reservation is released.
        // The SDK also retains its output encoder's capacity between responses.
        let control = 272 * input + 4 * output;
        // An accepted request can retain input/metadata while its normalized
        // envelope, structured Value, escaped JSON text and SDK encoding coexist.
        // Include task/map overhead and the bounded operation-specific tool schema.
        let request = 128 * input + 32 * output + 16 * 1024;
        let requests = available.saturating_sub(control) / request;
        if input < 1024 || output < 1024 || requests == 0 {
            return Err(Self::capacity_error());
        }
        Ok(Self {
            input,
            output,
            requests: requests.min(limits.active_requests + limits.queued_requests),
            nesting: limits.json_nesting,
            deadline: Duration::from_secs(limits.operation_seconds as u64),
        })
    }

    fn capacity_error() -> Error {
        let mut error = Error::setup_required();
        error.message = "MCP buffer limits cannot admit a request; increase buffered_bytes or envelope_bytes in the selected grant, then run mailctl-mcp setup".into();
        error
    }
}

pub(super) struct BoundedStdio {
    sdk: SdkStdio,
    ingress: JoinHandle<()>,
    slots: Arc<Semaphore>,
    pending: Pending,
    control: Arc<Semaphore>,
    output_limit: usize,
    deadline: Duration,
    receive_expires: Instant,
    initializing: bool,
}

impl BoundedStdio {
    pub(super) fn new(bounds: Bounds) -> Self {
        let (reader, mut writer) = tokio::io::duplex(8192);
        // Validate complete, bounded lines before the SDK can buffer or parse them.
        let ingress = tokio::spawn(async move {
            let mut lines = FramedRead::new(
                tokio::io::stdin(),
                LinesCodec::new_with_max_length(bounds.input),
            );
            for _ in 0..4096 {
                let Ok(Some(Ok(line))) = timeout(bounds.deadline, lines.next()).await else {
                    break;
                };
                if crate::encoding::validate_json_depth(line.as_bytes(), bounds.nesting).is_err() {
                    break;
                }
                let write = async {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\n").await
                };
                if !matches!(timeout(bounds.deadline, write).await, Ok(Ok(()))) {
                    break;
                }
            }
        });
        Self {
            sdk: AsyncRwTransport::new_server(reader, tokio::io::stdout()),
            ingress,
            slots: Arc::new(Semaphore::new(bounds.requests)),
            pending: Default::default(),
            control: Arc::new(Semaphore::new(1)),
            output_limit: bounds.output,
            deadline: bounds.deadline,
            receive_expires: Instant::now() + bounds.deadline,
            initializing: true,
        }
    }
}
impl Drop for BoundedStdio {
    fn drop(&mut self) {
        self.ingress.abort();
    }
}
impl Transport<RoleServer> for BoundedStdio {
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
        let valid = crate::encoding::serialized_size(&item, self.output_limit).is_ok();
        let pending = self.pending.clone();
        let send = self.sdk.send(item);
        let deadline = self.deadline;
        async move {
            if !valid {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let result = timeout(deadline, send)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
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
        // This parsing uses the permanent control reservation. Transfer ownership
        // to a request reservation before returning to the SDK's task scheduler.
        // Notifications retain it in SDK extensions through their handler's return,
        // so a flood cannot accumulate detached notification tasks. This permit is
        // independent of request saturation; acquire it before consuming any input.
        let control = self.control.clone().acquire_owned().await.ok()?;
        // SDK receive is cancellation-safe; keep the same deadline when the SDK
        // service loop interrupts it to send a response.
        let mut item = timeout_at(self.receive_expires, self.sdk.receive())
            .await
            .ok()??;
        self.receive_expires = Instant::now() + self.deadline;
        if let JsonRpcMessage::Request(request) = &item {
            if self.initializing {
                match &request.request {
                    ClientRequest::InitializeRequest(_) => self.initializing = false,
                    ClientRequest::PingRequest(_) => {}
                    // Newer SDKs also support initialization through per-request
                    // metadata; this server pins the 2025 initialize lifecycle.
                    _ => return None,
                }
            }
            // Keep cancellation notifications readable when all request slots are occupied.
            let permit = self.slots.clone().try_acquire_owned().ok()?;
            let mut pending = self.pending.lock().ok()?;
            if pending.contains_key(&request.id) {
                return None;
            }
            pending.insert(request.id.clone(), permit);
        }
        if let JsonRpcMessage::Notification(notification) = &mut item {
            notification
                .notification
                .extensions_mut()
                .insert(Arc::new(control));
        }
        Some(item)
    }
    async fn close(&mut self) -> io::Result<()> {
        self.ingress.abort();
        self.sdk.close().await
    }
}
