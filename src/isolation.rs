//! Native macOS IPC for the explicitly provisioned isolated topology.
use crate::{
    config::Limits,
    domain::{Envelope, Error, ErrorCode, Operation, OperationResult},
    encoding::{serialize_bounded, validate_json_bounds},
    policy::Narrowing,
};
#[cfg(feature = "isolated")]
use crate::{
    config::{Config, MAX_BYTES},
    domain::IsolationCapacity,
    service::Service,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "isolated")]
use std::{
    collections::HashMap,
    fs::File,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    process::ExitCode,
    sync::Arc,
};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
    time::timeout,
};
#[cfg(feature = "isolated")]
use tokio::{net::UnixListener, sync::Semaphore, task::JoinSet};

const ROUTE: &str = "/Library/Application Support/mailctl-isolated/route.json";
const SOCKET: &str = "/Library/Application Support/mailctl-isolated/run/socket";
#[cfg(feature = "isolated")]
const SERVICE_HOME: &str = "/var/db/mailctl-isolated";
#[cfg(feature = "isolated")]
const CONFIG: &str = "/var/db/mailctl-isolated/config.toml";
const ROUTE_BYTES: usize = 64 * 1024;
const REQUEST_BYTES: usize = 64 * 1024;
#[cfg(feature = "isolated")]
const SESSIONS: usize = 4;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    version: u32,
    service_uid: u32,
    socket: PathBuf,
    callers: Vec<Caller>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Caller {
    uid: u32,
    grant: String,
}

impl Route {
    fn load() -> Result<Self, Error> {
        let bytes = read_root_file(Path::new(ROUTE), ROUTE_BYTES)?;
        let route: Self =
            serde_json::from_slice(&bytes).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
        if route.version != 1
            || route.service_uid == 0
            || route.socket != Path::new(SOCKET)
            || route.callers.len() > 256
        {
            return Err(Error::new(ErrorCode::BrokerUnavailable));
        }
        let mut callers = HashSet::new();
        if route.callers.iter().any(|caller| {
            caller.uid == 0
                || caller.uid == route.service_uid
                || caller.grant.is_empty()
                || caller.grant.len() > 128
                || !callers.insert(caller.uid)
        }) {
            return Err(Error::new(ErrorCode::BrokerUnavailable));
        }
        Ok(route)
    }

    fn grant(&self, uid: u32) -> Option<&str> {
        self.callers
            .iter()
            .find(|caller| caller.uid == uid)
            .map(|caller| caller.grant.as_str())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientFrame {
    Hello {
        version: u32,
        narrowing: Narrowing,
    },
    Operation {
        operation: Operation,
        response_limit: usize,
    },
    Doctor {
        check_account: bool,
        response_limit: usize,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ServerFrame {
    Hello {
        version: u32,
        limits: Limits,
        response_bound: usize,
    },
    Result {
        envelope: Envelope,
    },
}

/// A client for one authenticated native isolated session.
pub struct Client {
    stream: Mutex<Option<UnixStream>>,
    limits: Limits,
    response_bound: usize,
}

impl Client {
    pub async fn connect(narrowing: Narrowing) -> Result<Self, Error> {
        let route = Route::load()?;
        let caller = rustix::process::geteuid().as_raw();
        if caller == 0 || caller == route.service_uid || route.grant(caller).is_none() {
            return Err(Error::new(ErrorCode::PermissionDenied));
        }
        let (stream, limits, response_bound) = timeout(Duration::from_secs(5), async {
            let mut stream = UnixStream::connect(&route.socket)
                .await
                .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
            if stream
                .peer_cred()
                .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?
                .uid()
                != route.service_uid
            {
                return Err(Error::new(ErrorCode::BrokerUnavailable));
            }
            write_frame(
                &mut stream,
                &ClientFrame::Hello {
                    version: 1,
                    narrowing,
                },
                REQUEST_BYTES,
            )
            .await?;
            let ServerFrame::Hello {
                version,
                limits,
                response_bound,
            } = read_frame(&mut stream, REQUEST_BYTES, 32).await?
            else {
                return Err(Error::new(ErrorCode::ProtocolMismatch));
            };
            if version != 1 {
                return Err(Error::new(ErrorCode::ProtocolMismatch));
            }
            Ok((stream, limits, response_bound))
        })
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))??;
        if limits.validate().is_err()
            || response_bound < 1024
            || response_bound > limits.envelope_bytes
        {
            return Err(Error::new(ErrorCode::ProtocolMismatch));
        }
        Ok(Self {
            stream: Mutex::new(Some(stream)),
            limits,
            response_bound,
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn response_bound(&self) -> usize {
        self.response_bound
    }

    pub fn with_response_limit(mut self, maximum: usize) -> Self {
        self.limit_response(maximum);
        self
    }

    pub(crate) fn limit_response(&mut self, maximum: usize) {
        self.response_bound = self.response_bound.min(maximum);
    }

    pub async fn execute(&self, operation: Operation) -> Result<OperationResult, Error> {
        self.exchange(ClientFrame::Operation {
            operation,
            response_limit: self.response_bound,
        })
        .await
    }

    pub async fn doctor(&self, check_account: bool) -> Result<OperationResult, Error> {
        self.exchange(ClientFrame::Doctor {
            check_account,
            response_limit: self.response_bound,
        })
        .await
    }

    async fn exchange(&self, request: ClientFrame) -> Result<OperationResult, Error> {
        // Cancellation drops the taken stream, so no subsequent operation can
        // receive a response that belonged to the cancelled request.
        let mut retained = self.stream.lock().await;
        let mut stream = retained
            .take()
            .ok_or_else(|| Error::new(ErrorCode::BrokerUnavailable))?;
        let response = timeout(
            Duration::from_secs(self.limits.operation_seconds as u64),
            async {
                write_frame(&mut stream, &request, REQUEST_BYTES).await?;
                read_frame(&mut stream, self.response_bound, 32).await
            },
        )
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))??;
        match response {
            ServerFrame::Result { envelope } => {
                *retained = Some(stream);
                envelope.into_result()
            }
            ServerFrame::Hello { .. } => Err(Error::new(ErrorCode::ProtocolMismatch)),
        }
    }
}

#[cfg(feature = "isolated")]
pub fn run_server() -> ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!("mailctl-isolated: invalid request");
        return ExitCode::from(2);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return unavailable(),
    };
    match runtime.block_on(server()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => ExitCode::from(error.exit_code()),
    }
}

#[cfg(feature = "isolated")]
fn unavailable() -> ExitCode {
    eprintln!("mailctl-isolated: unavailable");
    ExitCode::from(8)
}

#[cfg(feature = "isolated")]
async fn server() -> Result<(), Error> {
    let route = Route::load()?;
    let service_uid = rustix::process::geteuid().as_raw();
    if service_uid == 0 || service_uid != route.service_uid {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    verify_root_path(
        &std::env::current_exe().map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?,
        false,
    )?;
    let home = verify_service_home(service_uid)?;
    let config = load_service_config(service_uid)?;
    verify_service_state(&config, &home, service_uid)?;
    let session_cap = SESSIONS.min(config.limits.active_requests);
    let expected =
        serde_json::to_vec(&config).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    let service = Arc::new(Service::open_checked(config, || {
        let current = load_service_config(service_uid)?;
        if serde_json::to_vec(&current).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?
            != expected
        {
            return Err(Error::new(ErrorCode::OperationConflict));
        }
        Ok(())
    })?);
    let run = prepare_run_directory(service_uid)?;
    let lock = singleton_lock(&run, service_uid)?;
    remove_stale_socket()?;
    let listener =
        UnixListener::bind(SOCKET).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666))
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;

    let permits = Arc::new(Semaphore::new(session_cap));
    let mut grant_permits = HashMap::new();
    for caller in &route.callers {
        let context = service.context(&caller.grant, &Narrowing::default())?;
        let cap = service.limits(&context)?.active_requests.min(session_cap);
        grant_permits
            .entry(caller.grant.as_str())
            .or_insert_with(|| (Arc::new(Semaphore::new(cap)), cap));
    }
    let mut sessions = JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        while sessions.try_join_next().is_some() {}
        tokio::select! {
            _ = &mut shutdown => break,
            _ = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let Ok(peer) = stream.peer_cred() else { continue; };
                let caller = peer.uid();
                let Some(grant) = route.grant(caller) else { continue; };
                let (grant_slots, cap) = &grant_permits[grant];
                let Ok(grant_permit) = grant_slots.clone().try_acquire_owned() else { continue; };
                let cap = *cap;
                let grant = grant.to_owned();
                let service = service.clone();
                sessions.spawn(async move {
                    let (_permit, _grant_permit) = (permit, grant_permit);
                    let _ = serve_session(stream, service, grant, cap).await;
                });
            }
        }
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    let _ = fs::remove_file(SOCKET);
    drop(lock);
    Ok(())
}

#[cfg(feature = "isolated")]
async fn serve_session(
    mut stream: UnixStream,
    service: Arc<Service>,
    grant: String,
    session_cap: usize,
) -> Result<(), Error> {
    let base = service.context(&grant, &Narrowing::default())?;
    let (base_limits, _) = session_limits(service.limits(&base)?)?;
    let ClientFrame::Hello {
        version: 1,
        narrowing,
    } = timeout(
        Duration::from_secs(base_limits.initialization_seconds as u64),
        read_frame(&mut stream, REQUEST_BYTES, base_limits.json_nesting),
    )
    .await
    .map_err(|_| Error::new(ErrorCode::Timeout))??
    else {
        return Err(Error::new(ErrorCode::ProtocolMismatch));
    };
    let context = service.context(&grant, &narrowing)?;
    drop(narrowing);
    let (limits, response_bound) = session_limits(service.limits(&context)?)?;
    write_frame(
        &mut stream,
        &ServerFrame::Hello {
            version: 1,
            limits: limits.clone(),
            response_bound,
        },
        REQUEST_BYTES,
    )
    .await?;
    let session = Duration::from_secs(limits.connection_lifetime_seconds as u64);
    timeout(session, async {
        loop {
            let request = timeout(
                Duration::from_secs(limits.operation_seconds as u64),
                read_frame(&mut stream, REQUEST_BYTES, limits.json_nesting),
            )
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))??;
            let client_bound = match &request {
                ClientFrame::Operation { response_limit, .. }
                | ClientFrame::Doctor { response_limit, .. } => *response_limit,
                ClientFrame::Hello { .. } => return Err(Error::new(ErrorCode::ProtocolMismatch)),
            };
            if client_bound < 1024 || client_bound > response_bound {
                return Err(Error::new(ErrorCode::InvalidRequest));
            }
            let narrowed = context
                .clone()
                .with_response_limit(client_bound.saturating_sub(256));
            let operation_deadline = Duration::from_secs(limits.operation_seconds as u64);
            let result = timeout(operation_deadline, async {
                match request {
                    ClientFrame::Operation { operation, .. } => {
                        service.execute(&narrowed, operation).await
                    }
                    ClientFrame::Doctor { check_account, .. } => service
                        .doctor(&narrowed, check_account)
                        .await
                        .map(OperationResult::Doctor),
                    ClientFrame::Hello { .. } => Err(Error::new(ErrorCode::ProtocolMismatch)),
                }
            })
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?;
            timeout(
                operation_deadline,
                write_result(
                    &mut stream,
                    isolated_capacity(result, &limits, session_cap),
                    client_bound,
                ),
            )
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))??;
        }
    })
    .await
    .map_err(|_| Error::new(ErrorCode::Timeout))?
}

#[cfg(feature = "isolated")]
fn session_limits(configured: &Limits) -> Result<(Limits, usize), Error> {
    let mut limits = configured.clone();
    limits.operation_seconds = limits.operation_seconds.min(30);
    limits.initialization_seconds = limits.initialization_seconds.min(5);
    limits.connection_lifetime_seconds = limits.connection_lifetime_seconds.min(300);
    limits.active_requests = 1;
    limits.json_nesting = limits.json_nesting.min(32);
    // Internally tagged ClientFrame buffers generic serde Content before typed
    // field bounds reject unknown or oversized fields. Reserve generic JSON
    // decoding space, including vector growth and scratch, for every wire byte.
    // Sixteen response-sized units separately cover result fields, serialization
    // growth, framed output, and bounded task metadata.
    let response_bound = limits.envelope_bytes.min(
        limits
            .buffered_bytes
            .saturating_div(SESSIONS)
            .saturating_sub(128 * REQUEST_BYTES)
            .saturating_div(16),
    );
    if response_bound < 1024 {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    Ok((limits, response_bound))
}

#[cfg(feature = "isolated")]
fn isolated_capacity(
    result: Result<OperationResult, Error>,
    limits: &Limits,
    session_cap: usize,
) -> Result<OperationResult, Error> {
    let mut result = result?;
    if let OperationResult::Capabilities(capabilities) = &mut result {
        capabilities.capacity.per_process.active_requests = session_cap as u64;
        capabilities.capacity.per_process.queued_requests = 0;
        capabilities.capacity.isolation = Some(IsolationCapacity {
            sessions: session_cap as u64,
            active_requests_per_session: 1,
            request_bytes: REQUEST_BYTES as u64,
            session_seconds: limits.connection_lifetime_seconds as u64,
        });
    }
    Ok(result)
}

#[cfg(feature = "isolated")]
async fn write_result(
    stream: &mut UnixStream,
    result: Result<OperationResult, Error>,
    maximum: usize,
) -> Result<(), Error> {
    let frame = ServerFrame::Result {
        envelope: Envelope::from_result(uuid::Uuid::new_v4().to_string(), result),
    };
    let bytes = match serialize_bounded(&frame, maximum) {
        Ok(bytes) => bytes,
        Err(_) => serialize_bounded(
            &ServerFrame::Result {
                envelope: Envelope::from_result(
                    uuid::Uuid::new_v4().to_string(),
                    Err(Error::new(ErrorCode::ResponseTooLarge)),
                ),
            },
            maximum,
        )?,
    };
    write_bytes(stream, &bytes).await
}

async fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    maximum: usize,
    nesting: usize,
) -> Result<T, Error> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))? as usize;
    if length == 0 || length > maximum {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    validate_json_bounds(&bytes, nesting, usize::MAX)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::new(ErrorCode::InvalidRequest))
}

async fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    maximum: usize,
) -> Result<(), Error> {
    let bytes = serialize_bounded(value, maximum)?;
    write_bytes(stream, &bytes).await
}

async fn write_bytes(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
    stream
        .write_u32(length)
        .await
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))
}

fn read_root_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Error> {
    verify_root_path(path, false)?;
    read_private_file(path, maximum, 0, 0o022)
}

#[cfg(feature = "isolated")]
fn load_service_config(uid: u32) -> Result<Config, Error> {
    let bytes = read_private_file(Path::new(CONFIG), MAX_BYTES, uid, 0o077)?;
    let text = String::from_utf8(bytes).map_err(|_| Error::setup_required())?;
    Config::parse(&text)
}

fn read_private_file(
    path: &Path,
    maximum: usize,
    owner: u32,
    writable: u32,
) -> Result<Vec<u8>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & writable != 0
        || metadata.len() > maximum as u64
    {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if bytes.len() > maximum {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    Ok(bytes)
}

fn verify_root_path(path: &Path, directory: bool) -> Result<(), Error> {
    let canonical = fs::canonicalize(path).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if canonical != path {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    for ancestor in canonical.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || !(metadata.is_dir() || ancestor == canonical && !directory && metadata.is_file())
        {
            return Err(Error::new(ErrorCode::BrokerUnavailable));
        }
    }
    Ok(())
}

#[cfg(feature = "isolated")]
fn verify_service_home(uid: u32) -> Result<PathBuf, Error> {
    let home =
        fs::canonicalize(SERVICE_HOME).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if home != Path::new("/private/var/db/mailctl-isolated") {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    verify_private_directory(&home, uid)?;
    Ok(home)
}

#[cfg(feature = "isolated")]
fn verify_service_state(config: &Config, home: &Path, uid: u32) -> Result<(), Error> {
    let state = fs::canonicalize(&config.state_dir)
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if !state.starts_with(home) {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    verify_private_directory(&state, uid)
}

#[cfg(feature = "isolated")]
fn verify_private_directory(path: &Path, uid: u32) -> Result<(), Error> {
    for ancestor in path.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(Error::new(ErrorCode::BrokerUnavailable));
        }
    }
    let metadata = fs::metadata(path).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    Ok(())
}

#[cfg(feature = "isolated")]
fn prepare_run_directory(uid: u32) -> Result<PathBuf, Error> {
    let run = PathBuf::from("/Library/Application Support/mailctl-isolated/run");
    let parent = run
        .parent()
        .ok_or_else(|| Error::new(ErrorCode::BrokerUnavailable))?;
    verify_root_path(parent, true)?;
    let metadata =
        fs::symlink_metadata(&run).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o001 == 0
    {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    Ok(run)
}

#[cfg(feature = "isolated")]
fn singleton_lock(run: &Path, uid: u32) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(run.join("server.lock"))
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::new(ErrorCode::BrokerUnavailable))?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(Error::new(ErrorCode::BrokerUnavailable));
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::new(ErrorCode::RateLimited))?;
    Ok(file)
}

#[cfg(feature = "isolated")]
fn remove_stale_socket() -> Result<(), Error> {
    match fs::symlink_metadata(SOCKET) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(SOCKET).map_err(|_| Error::new(ErrorCode::BrokerUnavailable))
        }
        Ok(_) => Err(Error::new(ErrorCode::BrokerUnavailable)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::new(ErrorCode::BrokerUnavailable)),
    }
}

#[cfg(feature = "isolated")]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        return;
    };
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
}

#[cfg(all(test, feature = "isolated"))]
mod tests {
    use super::*;

    #[test]
    fn rejected_tagged_json_fits_the_session_request_reservation() {
        let (limits, response_bound) = session_limits(&Limits::default()).unwrap();
        limits.validate().unwrap();
        let request_reservation = limits.buffered_bytes / SESSIONS - 16 * response_bound;
        let payload = format!(
            r#"{{"type":"hello","version":1,"narrowing":{{}},"padding":[{}0]}}"#,
            "0,".repeat(32_000),
        );
        assert!(payload.len() <= REQUEST_BYTES);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut sender, mut receiver) = {
            let _runtime = runtime.enter();
            UnixStream::pair().unwrap()
        };
        let allocations = allocation_counter::measure(|| {
            runtime.block_on(async {
                let (sent, received) = tokio::join!(
                    write_bytes(&mut sender, payload.as_bytes()),
                    read_frame::<ClientFrame>(&mut receiver, REQUEST_BYTES, limits.json_nesting),
                );
                sent.unwrap();
                assert_eq!(received.err().unwrap().code, ErrorCode::InvalidRequest);
            });
        });
        assert!(
            allocations.bytes_max <= request_reservation as u64,
            "tagged JSON allocation exceeds its session reservation: {allocations:?}"
        );
    }

    #[test]
    fn session_admission_requires_space_for_generic_json_decoding() {
        let limits = Limits {
            envelope_bytes: 1024,
            buffered_bytes: 1024 * 1024,
            ..Limits::default()
        };
        limits.validate().unwrap();
        assert_eq!(
            session_limits(&limits).unwrap_err().code,
            ErrorCode::BrokerUnavailable
        );
        assert!(session_limits(&Limits::default()).unwrap().1 >= 1024);
    }
}
