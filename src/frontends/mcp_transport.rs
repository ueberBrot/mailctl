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
    pub(super) envelope: usize,
    output: usize,
    requests: usize,
    nesting: usize,
    deadline: Duration,
}
impl Bounds {
    pub(super) fn new(limits: &Limits, response_bound: usize) -> Result<Self, Error> {
        // Cover the SDK/codec's initial buffers, duplex, and bounded task metadata.
        const FIXED: usize = 64 * 1024;
        let available = limits
            .buffered_bytes
            .checked_sub(FIXED)
            .ok_or_else(Error::setup_required)?;
        let fits = |input, envelope| {
            let (_, control, request) = Self::reservations(input, envelope, limits.accounts);
            control + request <= available
        };
        // Preserve the complete application allowance whenever a reservation
        // fits. A large response takes precedence over a larger input frame;
        // only the configured memory ceiling may narrow the response budget.
        let mut envelope = 0;
        let mut upper = response_bound.min(limits.envelope_bytes);
        while envelope < upper {
            let candidate = envelope + (upper - envelope).div_ceil(2);
            if fits(1024, candidate) {
                envelope = candidate;
            } else {
                upper = candidate - 1;
            }
        }
        if envelope < 1024 {
            return Err(Error::setup_required());
        }
        let mut input = 1024;
        let mut upper = limits.envelope_bytes.min(64 * 1024);
        while input < upper {
            let candidate = input + (upper - input).div_ceil(2);
            if fits(candidate, envelope) {
                input = candidate;
            } else {
                upper = candidate - 1;
            }
        }
        let (output, control, request) = Self::reservations(input, envelope, limits.accounts);
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

    fn reservations(input: usize, envelope: usize, accounts: usize) -> (usize, usize, usize) {
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
        // Account for the caller's JSON-RPC id and fixed protocol/tool schemas.
        let output = (3 * envelope + input + 1024).max(16 * 1024);
        // The permanent control allocation covers one decoder, retained client
        // initialization data and ingress scratch. SDK/Tokio encoder capacities
        // remain allocated after a response: each can grow to twice its payload;
        // Tokio's pinned STDIO implementation copies at most 2 MiB per write.
        let control = 272 * input + 2 * output + 2 * output.min(2 * 1024 * 1024);
        // The input/metadata survives to output completion. Domain-to-Value
        // conversion holds at most two copies of field bytes; Value plus text
        // holds at most three, including String capacity growth.
        let request = 128 * input + 3 * envelope + structure;
        (output, control, request)
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
