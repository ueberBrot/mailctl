//! Apply admission limits around the SDK's STDIO transport.
use futures_util::StreamExt;
use rmcp::{
    RoleServer,
    model::JsonRpcMessage,
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
    time::timeout,
};
use tokio_util::codec::{FramedRead, LinesCodec};

pub(super) const OUTPUT_LIMIT: usize = 1024 * 1024;
const INPUT_LIMIT: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
type SdkStdio = AsyncRwTransport<RoleServer, tokio::io::DuplexStream, tokio::io::Stdout>;
type Pending = Arc<Mutex<HashMap<rmcp::model::RequestId, OwnedSemaphorePermit>>>;

pub(super) struct BoundedStdio {
    sdk: SdkStdio,
    ingress: JoinHandle<()>,
    slots: Arc<Semaphore>,
    pending: Pending,
}

impl BoundedStdio {
    pub(super) fn new() -> Self {
        let (reader, mut writer) = tokio::io::duplex(8192);
        // Validate complete, bounded lines before the SDK can buffer or parse them.
        let ingress = tokio::spawn(async move {
            let mut lines = FramedRead::new(
                tokio::io::stdin(),
                LinesCodec::new_with_max_length(INPUT_LIMIT),
            );
            for _ in 0..4096 {
                let Ok(Some(Ok(line))) = timeout(DEADLINE, lines.next()).await else {
                    break;
                };
                if crate::ipc::validate_json_depth(line.as_bytes(), 32).is_err() {
                    break;
                }
                let write = async {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\n").await
                };
                if !matches!(timeout(DEADLINE, write).await, Ok(Ok(()))) {
                    break;
                }
            }
        });
        Self {
            sdk: AsyncRwTransport::new_server(reader, tokio::io::stdout()),
            ingress,
            slots: Arc::new(Semaphore::new(8)),
            pending: Default::default(),
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
        let valid = crate::ipc::serialized_size(&item, OUTPUT_LIMIT).is_ok();
        let pending = self.pending.clone();
        let send = self.sdk.send(item);
        async move {
            if !valid {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let result = timeout(DEADLINE, send)
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
        let permit = timeout(DEADLINE, self.slots.clone().acquire_owned())
            .await
            .ok()?
            .ok()?;
        let item = self.sdk.receive().await?;
        if let JsonRpcMessage::Request(request) = &item {
            let mut pending = self.pending.lock().ok()?;
            if pending.contains_key(&request.id) {
                return None;
            }
            pending.insert(request.id.clone(), permit);
        }
        Some(item)
    }
    async fn close(&mut self) -> io::Result<()> {
        self.ingress.abort();
        self.sdk.close().await
    }
}
