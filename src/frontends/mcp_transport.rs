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
    collections::{HashMap, hash_map::Entry},
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
        // A full search can contain 32 four-KiB strings, each JSON-escaped to six
        // bytes per source byte. Reserve its frame before sizing the response.
        let mut input = 1024;
        let mut upper = limits.envelope_bytes.min(1024 * 1024);
        while input < upper {
            let candidate = input + (upper - input).div_ceil(2);
            if fits(candidate, 1024) {
                input = candidate;
            } else {
                upper = candidate - 1;
            }
        }
        let mut envelope = 0;
        let mut upper = response_bound.min(limits.envelope_bytes);
        while envelope < upper {
            let candidate = envelope + (upper - envelope).div_ceil(2);
            if fits(input, candidate) {
                envelope = candidate;
            } else {
                upper = candidate - 1;
            }
        }
        if envelope < 1024 {
            return Err(Error::setup_required());
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
        let output = (3 * envelope + input + 1024).max(32 * 1024);
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
        let request = request_input + 3 * envelope + structure;
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
    staged: Option<(RxJsonRpcMessage<RoleServer>, OwnedSemaphorePermit)>,
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
                if validate_frame(line.as_bytes(), bounds.nesting).is_err() {
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
            staged: None,
        }
    }
}

fn validate_frame(bytes: &[u8], nesting: usize) -> Result<(), Error> {
    crate::encoding::validate_json_depth(bytes, nesting)?;
    let mut quoted = false;
    let mut escaped = false;
    let mut nodes = 1usize;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' | b',' | b':' => {
                    nodes += 1;
                    if nodes > 4096 {
                        return Err(Error::new(crate::domain::ErrorCode::InvalidRequest));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
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
        let (item, _) = self.staged.as_ref()?;
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
                    entry.insert(permit);
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
        Some(item)
    }
    async fn close(&mut self) -> io::Result<()> {
        self.ingress.abort();
        self.sdk.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bounded_sdk_decoding_fits_the_input_reservation_for_large_strings_and_many_nodes() {
        for arguments in [
            json!({"mailbox":"mb1.synthetic","criteria":vec![json!({"field":"text","value":"\u{1}".repeat(4096)});32]}),
            json!({"values":vec![json!({"a":0,"b":1});500]}),
        ] {
            let frame = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"email_search_messages","arguments":arguments}})).unwrap();
            validate_frame(&frame, 32).unwrap();
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
        assert!(validate_frame(&excessive, 32).is_err());
    }
}
