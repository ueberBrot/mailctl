//! Authenticated local broker transport with bounded framing and admission.

use crate::{
    domain::{Envelope, Error, ErrorCode, Operation},
    policy::Narrowing,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    path::Path,
};

/// Count serialized bytes without allocating an output buffer.
pub fn serialized_size<T: Serialize>(value: &T, maximum: usize) -> Result<usize, Error> {
    struct Counter {
        length: usize,
        maximum: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.maximum.saturating_sub(self.length) {
                return Err(io::Error::other("response bound"));
            }
            self.length += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { length: 0, maximum };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
    Ok(counter.length)
}

/// Serialize without ever growing the payload beyond the configured ceiling.
pub fn serialize_bounded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, Error> {
    struct Bounded {
        bytes: Vec<u8>,
        maximum: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
                return Err(io::Error::other("response bound"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let length = serialized_size(value, maximum)?;
    let mut output = Bounded {
        bytes: Vec::with_capacity(length),
        maximum: length,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
    Ok(output.bytes)
}

#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    #[serde(default)]
    narrowing: Narrowing,
    #[serde(default)]
    client_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub version: u32,
    pub effective: serde_json::Value,
}

#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Message {
    Request {
        request_id: String,
        request: Operation,
        #[serde(default)]
        narrowing: Narrowing,
    },
    Cancel {
        request_id: String,
        target_request_id: String,
    },
}

/// Check nesting before the JSON decoder allocates nested values.
pub fn validate_json_depth(bytes: &[u8], maximum_depth: usize) -> Result<(), Error> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
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
            match *byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > maximum_depth {
                        return Err(Error::new(ErrorCode::InvalidRequest));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8], maximum_depth: usize) -> Result<T, Error> {
    validate_json_depth(bytes, maximum_depth)?;
    serde_json::from_slice(bytes).map_err(|_| Error::new(ErrorCode::InvalidRequest))
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::{
        config::{Config, Limits, ListenerConfig},
        service::Service,
    };
    use std::{
        collections::{HashMap, HashSet},
        fs::{self, File},
        future::Future,
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        path::PathBuf,
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
        task::JoinSet,
        time::{Instant, timeout},
    };

    fn unavailable() -> Error {
        Error::new(ErrorCode::BrokerUnavailable)
    }
    fn denied() -> Error {
        Error::new(ErrorCode::PermissionDenied)
    }
    fn limited() -> Error {
        Error::new(ErrorCode::RateLimited)
    }

    /// A protected directory is owned by this identity and inaccessible to others.
    fn protected_directory(path: &Path, uid: u32) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !path.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || fs::canonicalize(path).map_err(|_| denied())? != path
        {
            return Err(denied());
        }
        Ok(())
    }

    fn endpoint_identity(path: &Path, uid: u32) -> Result<(), Error> {
        protected_directory(path.parent().ok_or_else(denied)?, uid)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(denied());
        }
        Ok(())
    }

    struct Endpoint {
        path: PathBuf,
        device: u64,
        inode: u64,
    }
    impl Drop for Endpoint {
        fn drop(&mut self) {
            if let Ok(metadata) = fs::symlink_metadata(&self.path)
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    struct StateLock(File);
    impl StateLock {
        fn acquire(path: &Path) -> Result<Self, Error> {
            let uid = rustix::process::geteuid().as_raw();
            protected_directory(path, uid)?;
            let fd = rustix::fs::open(
                path.join("broker.lock"),
                rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|_| denied())?;
            let file = File::from(fd);
            let metadata = file.metadata().map_err(|_| denied())?;
            if !metadata.is_file()
                || metadata.uid() != uid
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(denied());
            }
            file.try_lock().map_err(|_| unavailable())?;
            Ok(Self(file))
        }
    }
    impl Drop for StateLock {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }

    struct Budget {
        clients: Arc<Semaphore>,
        handshakes: Arc<Semaphore>,
        active: Arc<Semaphore>,
        queued: Arc<Semaphore>,
        bytes: Arc<Semaphore>,
    }
    impl Budget {
        fn new(limits: &Limits) -> Self {
            Self {
                clients: Arc::new(Semaphore::new(limits.clients)),
                handshakes: Arc::new(Semaphore::new(limits.handshakes)),
                active: Arc::new(Semaphore::new(limits.active_requests)),
                queued: Arc::new(Semaphore::new(limits.queued_requests)),
                bytes: Arc::new(Semaphore::new(limits.buffered_bytes)),
            }
        }
    }
    struct Reservation {
        _global: OwnedSemaphorePermit,
        _listener: OwnedSemaphorePermit,
    }
    fn reserve(
        global: &Arc<Semaphore>,
        listener: &Arc<Semaphore>,
        count: usize,
    ) -> Result<Reservation, Error> {
        let count = u32::try_from(count).map_err(|_| limited())?;
        let global = global
            .clone()
            .try_acquire_many_owned(count)
            .map_err(|_| limited())?;
        let listener = listener
            .clone()
            .try_acquire_many_owned(count)
            .map_err(|_| limited())?;
        Ok(Reservation {
            _global: global,
            _listener: listener,
        })
    }
    struct Frame {
        bytes: Vec<u8>,
        _reservation: Reservation,
    }
    async fn read_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
        limits: &Limits,
        global: &Budget,
        local: &Budget,
    ) -> Result<Frame, Error> {
        let length = reader.read_u32().await.map_err(|_| unavailable())? as usize;
        if length == 0 || length > limits.ipc_frame_bytes {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let reservation = reserve(&global.bytes, &local.bytes, length * 2)?;
        let mut bytes = vec![0; length];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| unavailable())?;
        Ok(Frame {
            bytes,
            _reservation: reservation,
        })
    }
    async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
        writer: &mut W,
        value: &T,
        maximum: usize,
    ) -> Result<(), Error> {
        let bytes = serialize_bounded(value, maximum)?;
        writer
            .write_u32(bytes.len() as u32)
            .await
            .map_err(|_| unavailable())?;
        writer.write_all(&bytes).await.map_err(|_| unavailable())?;
        writer.flush().await.map_err(|_| unavailable())
    }

    /// One broker holds the state lock and every successfully bound listener.
    pub struct Broker {
        service: Arc<Service>,
        listeners: Vec<(UnixListener, ListenerConfig, Endpoint)>,
        global: Arc<Budget>,
        _state: StateLock,
    }
    impl Broker {
        pub fn bind(config: Config) -> Result<Self, Error> {
            config.validate()?;
            if matches!(config.deployment, crate::config::Deployment::Isolated) {
                return Err(Error::new(ErrorCode::UnsupportedCapability));
            }
            let state = StateLock::acquire(&config.state_dir)?;
            let uid = rustix::process::geteuid().as_raw();
            // Validate every existing endpoint before allowing a healthy listener to serve.
            for listener in &config.listeners {
                match protected_directory(listener.endpoint.parent().ok_or_else(denied)?, uid) {
                    Err(error) if error.code == ErrorCode::BrokerUnavailable => continue,
                    result => result?,
                }
                match fs::symlink_metadata(&listener.endpoint) {
                    Ok(_) => endpoint_identity(&listener.endpoint, uid)?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err(denied()),
                }
            }
            let service = Service::open(config)?;
            let mut listeners = Vec::new();
            for listener in service.config().listeners.clone() {
                if fs::symlink_metadata(&listener.endpoint).is_ok() {
                    let probe = rustix::net::socket(
                        rustix::net::AddressFamily::UNIX,
                        rustix::net::SocketType::STREAM,
                        None,
                    )
                    .map_err(|_| unavailable())?;
                    rustix::fs::fcntl_setfl(&probe, rustix::fs::OFlags::NONBLOCK)
                        .map_err(|_| unavailable())?;
                    rustix::io::fcntl_setfd(&probe, rustix::io::FdFlags::CLOEXEC)
                        .map_err(|_| unavailable())?;
                    let address = rustix::net::SocketAddrUnix::new(&listener.endpoint)
                        .map_err(|_| unavailable())?;
                    if rustix::net::connect(&probe, &address) != Err(rustix::io::Errno::CONNREFUSED)
                    {
                        service.mark_listener_unavailable(&listener.name);
                        continue;
                    }
                    fs::remove_file(&listener.endpoint).map_err(|_| unavailable())?;
                }
                match UnixListener::bind(&listener.endpoint) {
                    Ok(socket) => {
                        fs::set_permissions(&listener.endpoint, fs::Permissions::from_mode(0o600))
                            .map_err(|_| denied())?;
                        endpoint_identity(&listener.endpoint, uid)?;
                        let metadata =
                            fs::symlink_metadata(&listener.endpoint).map_err(|_| denied())?;
                        let endpoint = Endpoint {
                            path: listener.endpoint.clone(),
                            device: metadata.dev(),
                            inode: metadata.ino(),
                        };
                        listeners.push((socket, listener, endpoint));
                    }
                    Err(_) => service.mark_listener_unavailable(&listener.name),
                }
            }
            if listeners.is_empty() {
                return Err(unavailable());
            }
            let global = Arc::new(Budget::new(&service.config().limits));
            Ok(Self {
                service: Arc::new(service),
                listeners,
                global,
                _state: state,
            })
        }

        pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
            let Self {
                service,
                listeners,
                global,
                _state,
            } = self;
            let mut tasks = JoinSet::new();
            for (socket, listener, endpoint) in listeners {
                let service = service.clone();
                let global = global.clone();
                tasks.spawn(async move {
                    let _endpoint = endpoint;
                    let local = Arc::new(Budget::new(&listener.limits));
                    let listener = Arc::new(listener);
                    let mut connections = JoinSet::new();
                    loop {
                        tokio::select! {
                            accepted = socket.accept() => {
                                let Ok((stream, _)) = accepted else { break; };
                                let Ok(peer) = stream.peer_cred() else { continue; };
                                if !listener.peer_uids.contains(&peer.uid()) { continue; }
                                let Ok(clients) = reserve(&global.clients, &local.clients, 1) else { continue; };
                                let Ok(handshakes) = reserve(&global.handshakes, &local.handshakes, 1) else { continue; };
                                let (service, global, local, listener) = (service.clone(), global.clone(), local.clone(), listener.clone());
                                connections.spawn(async move {
                                    let _clients = clients;
                                    let lifetime = Duration::from_secs(listener.limits.connection_lifetime_seconds as u64);
                                    let _ = timeout(lifetime, connection(stream, service, listener, global, local, handshakes)).await;
                                });
                            }
                            _ = connections.join_next(), if !connections.is_empty() => {}
                        }
                    }
                });
            }
            tokio::pin!(shutdown);
            tokio::select! {
                _ = &mut shutdown => {},
                _ = tasks.join_next() => return Err(unavailable()),
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            drop(_state);
            Ok(())
        }
    }

    fn intersect(session: &Narrowing, request: Narrowing) -> Narrowing {
        let accounts = match (&session.accounts, request.accounts) {
            (Some(session), Some(request)) => Some(
                request
                    .into_iter()
                    .filter(|key| session.contains(key))
                    .collect(),
            ),
            (Some(session), None) => Some(session.clone()),
            (None, request) => request,
        };
        Narrowing {
            read_only: session.read_only || request.read_only,
            accounts,
        }
    }

    async fn connection(
        mut stream: UnixStream,
        service: Arc<Service>,
        listener: Arc<ListenerConfig>,
        global: Arc<Budget>,
        local: Arc<Budget>,
        handshakes: Reservation,
    ) -> Result<(), Error> {
        let limits = &listener.limits;
        let handshake = async {
            let frame = read_frame(&mut stream, limits, &global, &local).await?;
            let hello: Hello = parse(&frame.bytes, limits.json_nesting)?;
            if hello.kind != "hello"
                || hello
                    .client_name
                    .as_ref()
                    .is_some_and(|name| name.len() > 256)
            {
                return Err(Error::new(ErrorCode::InvalidRequest));
            }
            if hello.version != 1 {
                return Err(Error::new(ErrorCode::ProtocolMismatch));
            }
            let context = service.context(&listener.name, &hello.narrowing)?;
            let effective = service.execute(&context, Operation::Capabilities)?;
            let _output = reserve(&global.bytes, &local.bytes, limits.ipc_frame_bytes)?;
            write_frame(
                &mut stream,
                &Welcome {
                    version: 1,
                    effective,
                },
                limits.ipc_frame_bytes,
            )
            .await?;
            Ok::<_, Error>(hello.narrowing)
        };
        let narrowing = match timeout(
            Duration::from_secs(limits.handshake_seconds as u64),
            handshake,
        )
        .await
        {
            Ok(Ok(narrowing)) => narrowing,
            Ok(Err(error)) => {
                let _output = reserve(&global.bytes, &local.bytes, limits.ipc_frame_bytes)?;
                let _ = timeout(
                    Duration::from_secs(limits.handshake_seconds as u64),
                    write_frame(
                        &mut stream,
                        &Envelope::from_result("handshake".into(), Err(error.clone())),
                        limits.ipc_frame_bytes,
                    ),
                )
                .await;
                return Err(error);
            }
            Err(_) => return Err(Error::new(ErrorCode::Timeout)),
        };
        drop(handshakes);
        let (mut reader, mut writer) = stream.into_split();
        let (incoming, mut frames) = mpsc::channel(1);
        let (read_global, read_local, read_listener) =
            (global.clone(), local.clone(), listener.clone());
        let mut reader_task = JoinSet::new();
        reader_task.spawn(async move {
            loop {
                let frame = timeout(
                    Duration::from_secs(read_listener.limits.operation_seconds as u64),
                    read_frame(
                        &mut reader,
                        &read_listener.limits,
                        &read_global,
                        &read_local,
                    ),
                )
                .await
                .map_err(|_| Error::new(ErrorCode::Timeout))
                .and_then(|frame| frame);
                let failed = frame.is_err();
                if incoming.send(frame).await.is_err() || failed {
                    break;
                }
            }
        });
        let mut requests = JoinSet::new();
        let mut cancellations: HashMap<String, oneshot::Sender<()>> = HashMap::new();
        let mut seen = HashSet::new();
        let mut identifiers = Vec::new();
        loop {
            let (envelope, (mut frame, output, active)) = tokio::select! {
                frame = frames.recv() => {
                    let Some(frame) = frame else { break; };
                    let frame = frame?;
                    let message: Message = parse(&frame.bytes, limits.json_nesting)?;
                    let request_id = match &message { Message::Request { request_id, .. } | Message::Cancel { request_id, .. } => request_id };
                    if request_id.is_empty() || request_id.len() > 64 || !request_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                        || seen.len() >= 4096 || seen.contains(request_id) {
                        return Err(Error::new(ErrorCode::InvalidRequest));
                    }
                    identifiers.push(reserve(&global.bytes, &local.bytes, request_id.len() + 128)?);
                    seen.insert(request_id.clone());
                    let output = reserve(&global.bytes, &local.bytes, limits.ipc_frame_bytes)?;
                    match message {
                        Message::Cancel { request_id, target_request_id } => {
                            let result = if let Some(cancel) = cancellations.remove(&target_request_id) {
                                let _: Result<(), ()> = cancel.send(());
                                Ok(serde_json::json!({"cancelled": true}))
                            } else { Err(Error::new(ErrorCode::InvalidRequest)) };
                            (Envelope::from_result(request_id, result), (frame, output, None))
                        }
                        Message::Request { request_id, request, narrowing: request_narrowing } => {
                            let queue = reserve(&global.queued, &local.queued, 1);
                            match queue {
                                Err(error) => (Envelope::from_result(request_id, Err(error)), (frame, output, None)),
                                Ok(queue) => {
                                    let context = service.context(&listener.name, &intersect(&narrowing, request_narrowing));
                                    let (cancel, cancelled) = oneshot::channel::<()>();
                                    cancellations.insert(request_id.clone(), cancel);
                                    let (global, local, service) = (global.clone(), local.clone(), service.clone());
                                    let deadline = Instant::now() + Duration::from_secs(limits.operation_seconds as u64);
                                    requests.spawn(async move {
                                        let (result, active) = tokio::select! {
                                            _ = cancelled => (Err(Error::new(ErrorCode::Cancelled)), None),
                                            result = tokio::time::timeout_at(deadline, async {
                                                let _local_active = local.active.clone().acquire_owned().await.map_err(|_| limited())?;
                                                let _global_active = global.active.clone().acquire_owned().await.map_err(|_| limited())?;
                                                drop(queue);
                                                let result = context.and_then(|context| service.execute(&context, request));
                                                Ok::<_, Error>((result, Some((_local_active, _global_active))))
                                            }) => match result {
                                                Ok(Ok(result)) => result,
                                                Ok(Err(error)) => (Err(error), None),
                                                Err(_) => (Err(Error::new(ErrorCode::Timeout)), None),
                                            },
                                        };
                                        (Envelope::from_result(request_id, result), (frame, output, active))
                                    });
                                    continue;
                                }
                            }
                        }
                    }
                }
                response = requests.join_next(), if !requests.is_empty() => {
                    let Some(Ok(response)) = response else { return Err(Error::new(ErrorCode::InternalError)); };
                    cancellations.remove(&response.0.request_id);
                    response
                }
            };
            // Retain the reservation through the write, but release the raw payload
            // before allocating the serialized response beside the normalized result.
            frame.bytes = Vec::new();
            let _resources = (frame, output, active);
            let write = async {
                match write_frame(&mut writer, &envelope, limits.ipc_frame_bytes).await {
                    Err(error) if error.code == ErrorCode::ResponseTooLarge => {
                        write_frame(
                            &mut writer,
                            &Envelope::from_result(envelope.request_id, Err(error)),
                            limits.ipc_frame_bytes,
                        )
                        .await
                    }
                    result => result,
                }
            };
            timeout(Duration::from_secs(limits.operation_seconds as u64), write)
                .await
                .map_err(|_| Error::new(ErrorCode::Timeout))??;
        }
        Ok(())
    }

    /// Authenticates the server identity before sending application requests.
    pub struct Client {
        stream: UnixStream,
        pub effective: serde_json::Value,
        limits: Limits,
    }
    impl Client {
        pub async fn connect(
            endpoint: &Path,
            expected_uid: u32,
            narrowing: Narrowing,
        ) -> Result<Self, Error> {
            endpoint_identity(endpoint, expected_uid)?;
            let limits = Limits::default();
            let mut stream = timeout(
                Duration::from_secs(limits.connection_seconds as u64),
                UnixStream::connect(endpoint),
            )
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?
            .map_err(|_| unavailable())?;
            let peer = stream.peer_cred().map_err(|_| denied())?;
            if peer.uid() != expected_uid {
                return Err(denied());
            }
            let global = Budget::new(&limits);
            let local = Budget::new(&limits);
            let welcome: Welcome = timeout(
                Duration::from_secs(limits.handshake_seconds as u64),
                async {
                    write_frame(
                        &mut stream,
                        &Hello {
                            kind: "hello".into(),
                            version: 1,
                            narrowing,
                            client_name: None,
                        },
                        limits.ipc_frame_bytes,
                    )
                    .await?;
                    let frame = read_frame(&mut stream, &limits, &global, &local).await?;
                    parse(&frame.bytes, limits.json_nesting)
                },
            )
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))??;
            if welcome.version != 1 {
                return Err(Error::new(ErrorCode::ProtocolMismatch));
            }
            Ok(Self {
                stream,
                effective: welcome.effective,
                limits,
            })
        }
        pub async fn request(
            &mut self,
            request_id: &str,
            request: Operation,
        ) -> Result<Envelope, Error> {
            let message = Message::Request {
                request_id: request_id.into(),
                request,
                narrowing: Narrowing::default(),
            };
            let global = Budget::new(&self.limits);
            let local = Budget::new(&self.limits);
            timeout(
                Duration::from_secs(self.limits.operation_seconds as u64),
                async {
                    write_frame(&mut self.stream, &message, self.limits.ipc_frame_bytes).await?;
                    let frame = read_frame(&mut self.stream, &self.limits, &global, &local).await?;
                    let envelope: Envelope = parse(&frame.bytes, self.limits.json_nesting)?;
                    if envelope.request_id != request_id || envelope.schema_version != 1 {
                        return Err(Error::new(ErrorCode::ProtocolMismatch));
                    }
                    Ok(envelope)
                },
            )
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?
        }
    }
}

#[cfg(unix)]
pub use unix::{Broker, Client};

#[cfg(not(unix))]
pub struct Broker;
#[cfg(not(unix))]
impl Broker {
    pub fn bind(_: crate::config::Config) -> Result<Self, Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    pub async fn run(self, _: impl std::future::Future<Output = ()>) -> Result<(), Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
}
#[cfg(not(unix))]
pub struct Client {
    pub effective: serde_json::Value,
}
#[cfg(not(unix))]
impl Client {
    pub async fn connect(_: &Path, _: u32, _: Narrowing) -> Result<Self, Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
    pub async fn request(&mut self, _: &str, _: Operation) -> Result<Envelope, Error> {
        Err(Error::new(ErrorCode::UnsupportedCapability))
    }
}
