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
        if route.service_uid == 0 || route.socket != Path::new(SOCKET) || route.callers.len() > 256
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
                &ClientFrame::Hello { narrowing },
                REQUEST_BYTES,
            )
            .await?;
            let ServerFrame::Hello {
                limits,
                response_bound,
            } = read_frame(&mut stream, REQUEST_BYTES, 32).await?
            else {
                return Err(Error::new(ErrorCode::ProtocolMismatch));
            };
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
        let expires =
            tokio::time::Instant::now() + Duration::from_secs(self.limits.operation_seconds as u64);
        let bytes = serialize_bounded(&request, REQUEST_BYTES)?;
        let (draft_identity, uncertain_on_interrupt) = match request {
            ClientFrame::Operation {
                operation: Operation::DraftStatus(input),
                ..
            } => (
                Some(crate::domain::DraftOperationDetails {
                    identity: input.identity(),
                    mailbox: input.mailbox,
                    uid_validity: None,
                }),
                input.reconcile,
            ),
            ClientFrame::Operation { operation, .. } => (operation.draft_outcome_identity(), true),
            _ => (None, false),
        };
        // Cancellation drops the taken stream, so no subsequent operation can
        // receive a response that belonged to the cancelled request.
        let mut retained = tokio::time::timeout_at(expires, self.stream.lock())
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?;
        let mut stream = retained
            .take()
            .ok_or_else(|| Error::new(ErrorCode::BrokerUnavailable))?;
        let envelope = tokio::time::timeout_at(expires, async {
            write_bytes(&mut stream, &bytes).await?;
            read_frame(&mut stream, self.response_bound, 32).await
        })
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))
        .flatten()
        .and_then(|response| match response {
            ServerFrame::Result { envelope } => Ok(envelope),
            ServerFrame::Hello { .. } => Err(Error::new(ErrorCode::ProtocolMismatch)),
        })
        .map_err(|error| match &draft_identity {
            Some(identity) if uncertain_on_interrupt => {
                Error::draft_outcome(ErrorCode::OutcomeUnknown, identity.clone())
            }
            _ => error,
        })?;
        *retained = Some(stream);
        envelope.into_result().map_err(|mut error| {
            if matches!(
                error.code,
                ErrorCode::OutcomeUnknown | ErrorCode::OperationInProgress
            ) && error.draft_operation.is_none()
            {
                error.draft_operation = draft_identity.map(Box::new);
            }
            error
        })
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
        // Isolated CLI/MCP sessions also decode bounded typed MIME structures.
        .thread_stack_size(8 * 1024 * 1024)
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
    let ClientFrame::Hello { narrowing } = timeout(
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
    let context = context.with_operation_limit(limits.operation_seconds);
    write_frame(
        &mut stream,
        &ServerFrame::Hello {
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
            let narrowed = context.clone().with_response_limit(client_bound);
            let operation_deadline = Duration::from_secs(limits.operation_seconds as u64);
            // The application owns the narrowed deadline and retains draft
            // uncertainty when cancellation follows dispatch or reconciliation.
            let result = match request {
                ClientFrame::Operation { operation, .. } => {
                    service.execute(&narrowed, operation).await
                }
                ClientFrame::Doctor { check_account, .. } => service
                    .doctor(&narrowed, check_account)
                    .await
                    .map(OperationResult::Doctor),
                ClientFrame::Hello { .. } => Err(Error::new(ErrorCode::ProtocolMismatch)),
            };
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
    let fallback = match &result {
        Err(error)
            if matches!(
                error.code,
                ErrorCode::OutcomeUnknown | ErrorCode::OperationInProgress
            ) =>
        {
            error.code
        }
        _ => ErrorCode::ResponseTooLarge,
    };
    let frame = ServerFrame::Result {
        envelope: Envelope::from_result(uuid::Uuid::new_v4().to_string(), result),
    };
    let bytes = match serialize_bounded(&frame, maximum) {
        Ok(bytes) => bytes,
        Err(_) => serialize_bounded(
            &ServerFrame::Result {
                envelope: Envelope::from_result(
                    uuid::Uuid::new_v4().to_string(),
                    Err(Error::new(fallback)),
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
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
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
    // Reserve the EOF probe so an unchanged file needs no buffer growth.
    let mut bytes = Vec::with_capacity((metadata.len() as usize).saturating_add(1));
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(Error::new(ErrorCode::BrokerUnavailable)),
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

    struct PrivateFileFixture(PathBuf);
    impl PrivateFileFixture {
        fn new(label: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "mailctl-isolation-{label}-{}",
                uuid::Uuid::new_v4()
            )))
        }
    }
    impl Drop for PrivateFileFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn private_ipc_file_reader_rejects_fifos_without_waiting_for_a_writer() {
        const CHILD_PATH: &str = "MAILCTL_ISOLATION_FIFO_TEST_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            assert_eq!(
                read_private_file(
                    Path::new(&path),
                    ROUTE_BYTES,
                    rustix::process::geteuid().as_raw(),
                    0o077,
                )
                .unwrap_err()
                .code,
                ErrorCode::BrokerUnavailable
            );
            return;
        }
        let fixture = PrivateFileFixture::new("fifo");
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .args(["-m", "600"])
                .arg(&fixture.0)
                .status()
                .unwrap()
                .success()
        );
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "isolation::tests::private_ipc_file_reader_rejects_fifos_without_waiting_for_a_writer",
                "--nocapture",
            ])
            .env(CHILD_PATH, &fixture.0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "private FIFO rejection child failed: {status}"
                );
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("private IPC file reader blocked opening a FIFO without a writer");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn private_ipc_file_reader_preserves_size_owner_permissions_and_symlink_checks() {
        let fixture = PrivateFileFixture::new("boundaries");
        let link = PrivateFileFixture::new("symlink");
        crate::file_storage::replace(&fixture.0, b"fixture").unwrap();
        let owner = rustix::process::geteuid().as_raw();
        assert_eq!(
            read_private_file(&fixture.0, 7, owner, 0o077).unwrap(),
            b"fixture"
        );
        for (maximum, uid) in [(6, owner), (7, owner.wrapping_add(1))] {
            assert_eq!(
                read_private_file(&fixture.0, maximum, uid, 0o077)
                    .unwrap_err()
                    .code,
                ErrorCode::BrokerUnavailable
            );
        }
        std::os::unix::fs::symlink(&fixture.0, &link.0).unwrap();
        assert_eq!(
            read_private_file(&link.0, 7, owner, 0o077)
                .unwrap_err()
                .code,
            ErrorCode::BrokerUnavailable
        );
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_private_file(&fixture.0, 7, owner, 0o077)
                .unwrap_err()
                .code,
            ErrorCode::BrokerUnavailable
        );
        // Root route files use the narrower write prohibition; public read bits remain allowed.
        assert_eq!(
            read_private_file(&fixture.0, 7, owner, 0o022).unwrap(),
            b"fixture"
        );
        crate::file_storage::replace(&fixture.0, b"").unwrap();
        assert!(
            read_private_file(&fixture.0, 0, owner, 0o077)
                .unwrap()
                .is_empty()
        );
    }

    fn client_pair() -> (Client, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        (
            Client {
                stream: Mutex::new(Some(stream)),
                limits: Limits {
                    operation_seconds: 1,
                    ..Limits::default()
                },
                response_bound: REQUEST_BYTES,
            },
            peer,
        )
    }

    fn draft(body: String) -> Operation {
        Operation::SaveDraft(crate::domain::SaveDraftInput {
            account_id: uuid::Uuid::new_v4(),
            account_generation: 1,
            operation_id: uuid::Uuid::new_v4(),
            mailbox: "Drafts".into(),
            draft: Box::new(crate::domain::DraftContent {
                body,
                ..Default::default()
            }),
        })
    }

    #[tokio::test]
    async fn oversized_draft_is_rejected_before_writing_and_preserves_the_session() {
        let (client, mut peer) = client_pair();
        let error = client
            .execute(draft("x".repeat(REQUEST_BYTES)))
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResponseTooLarge);
        assert!(error.draft_operation.is_none());
        let reply = async {
            let request: ClientFrame = read_frame(&mut peer, REQUEST_BYTES, 32).await.unwrap();
            assert!(matches!(request, ClientFrame::Doctor { .. }));
            write_frame(
                &mut peer,
                &ServerFrame::Result {
                    envelope: Envelope::from_result(
                        "fixture".into(),
                        Err(Error::new(ErrorCode::UnsupportedCapability)),
                    ),
                },
                REQUEST_BYTES,
            )
            .await
            .unwrap();
        };
        let (result, ()) = tokio::join!(client.doctor(false), reply);
        assert_eq!(result.unwrap_err().code, ErrorCode::UnsupportedCapability);
    }

    #[tokio::test]
    async fn unexpected_hello_after_draft_dispatch_preserves_the_uncertain_operation() {
        let (client, mut peer) = client_pair();
        let Operation::SaveDraft(input) = draft("frozen body".into()) else {
            unreachable!();
        };
        let identity = input.operation_details();
        let reply = async {
            let request: ClientFrame = read_frame(&mut peer, REQUEST_BYTES, 32).await.unwrap();
            assert!(matches!(
                request,
                ClientFrame::Operation {
                    operation: Operation::SaveDraft(_),
                    ..
                }
            ));
            write_frame(
                &mut peer,
                &ServerFrame::Hello {
                    limits: Limits::default(),
                    response_bound: REQUEST_BYTES,
                },
                REQUEST_BYTES,
            )
            .await
            .unwrap();
        };
        let (result, ()) = tokio::join!(client.execute(Operation::SaveDraft(input)), reply);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::OutcomeUnknown);
        assert_eq!(error.draft_operation.as_deref(), Some(&identity));
        assert!(client.stream.lock().await.is_none());
        assert_eq!(
            client.doctor(false).await.unwrap_err().code,
            ErrorCode::BrokerUnavailable,
        );
    }

    #[tokio::test]
    async fn interrupted_reconciliation_preserves_identity_but_a_journal_read_does_not() {
        for reconcile in [true, false] {
            let (client, mut peer) = client_pair();
            let Operation::SaveDraft(input) = draft(String::new()) else {
                unreachable!();
            };
            let identity = input.operation_details();
            let operation = Operation::DraftStatus(crate::domain::DraftStatusInput {
                account_id: input.account_id,
                account_generation: input.account_generation,
                operation_id: input.operation_id,
                mailbox: input.mailbox,
                reconcile,
            });
            let disconnect = async {
                let request: ClientFrame = read_frame(&mut peer, REQUEST_BYTES, 32).await.unwrap();
                assert!(matches!(
                    request,
                    ClientFrame::Operation {
                        operation: Operation::DraftStatus(_),
                        ..
                    }
                ));
                drop(peer);
            };
            let (result, ()) = tokio::join!(client.execute(operation), disconnect);
            let error = result.unwrap_err();
            if reconcile {
                assert_eq!(error.code, ErrorCode::OutcomeUnknown);
                assert_eq!(error.draft_operation.as_deref(), Some(&identity));
            } else {
                assert_eq!(error.code, ErrorCode::BrokerUnavailable);
                assert!(error.draft_operation.is_none());
            }
            assert!(client.stream.lock().await.is_none());
        }
    }

    #[tokio::test]
    async fn compact_uncertain_errors_restore_the_callers_draft_identity() {
        for reconcile in [true, false] {
            for code in [ErrorCode::OutcomeUnknown, ErrorCode::OperationInProgress] {
                let (client, mut peer) = client_pair();
                let Operation::SaveDraft(input) = draft(String::new()) else {
                    unreachable!();
                };
                let identity = input.operation_details();
                let operation = Operation::DraftStatus(crate::domain::DraftStatusInput {
                    account_id: input.account_id,
                    account_generation: input.account_generation,
                    operation_id: input.operation_id,
                    mailbox: input.mailbox,
                    reconcile,
                });
                let reply = async {
                    let _: ClientFrame = read_frame(&mut peer, REQUEST_BYTES, 32).await.unwrap();
                    write_frame(
                        &mut peer,
                        &ServerFrame::Result {
                            envelope: Envelope::from_result(
                                "fixture".into(),
                                Err(Error::new(code)),
                            ),
                        },
                        REQUEST_BYTES,
                    )
                    .await
                    .unwrap();
                };
                let (result, ()) = tokio::join!(client.execute(operation), reply);
                let error = result.unwrap_err();
                assert_eq!(error.code, code);
                assert_eq!(error.draft_operation.as_deref(), Some(&identity));
                assert!(client.stream.lock().await.is_some());
            }
        }
    }

    #[tokio::test]
    async fn unexpected_hello_after_a_read_remains_a_protocol_mismatch() {
        let (client, mut peer) = client_pair();
        let reply = async {
            let request: ClientFrame = read_frame(&mut peer, REQUEST_BYTES, 32).await.unwrap();
            assert!(matches!(request, ClientFrame::Doctor { .. }));
            write_frame(
                &mut peer,
                &ServerFrame::Hello {
                    limits: Limits::default(),
                    response_bound: REQUEST_BYTES,
                },
                REQUEST_BYTES,
            )
            .await
            .unwrap();
        };
        let (result, ()) = tokio::join!(client.doctor(false), reply);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolMismatch);
        assert!(error.draft_operation.is_none());
        assert!(client.stream.lock().await.is_none());
    }

    #[tokio::test]
    async fn draft_waiting_for_the_session_times_out_without_claiming_dispatch() {
        let (client, _peer) = client_pair();
        let retained = client.stream.lock().await;
        let error = timeout(Duration::from_secs(2), client.execute(draft(String::new())))
            .await
            .expect("queue acquisition exceeded the operation deadline")
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Timeout);
        assert!(error.draft_operation.is_none());
        assert!(retained.is_some());
    }

    #[tokio::test]
    async fn queued_time_counts_toward_the_draft_response_deadline() {
        let (client, mut peer) = client_pair();
        let retained = client.stream.lock().await;
        let release = async {
            tokio::time::sleep(Duration::from_millis(800)).await;
            drop(retained);
            let request: ClientFrame = read_frame(&mut peer, REQUEST_BYTES, 32).await.unwrap();
            assert!(matches!(
                request,
                ClientFrame::Operation {
                    operation: Operation::SaveDraft(_),
                    ..
                }
            ));
        };
        let operation = timeout(
            Duration::from_millis(1500),
            client.execute(draft(String::new())),
        );
        let (result, ()) = tokio::join!(operation, release);
        let error = result
            .expect("dispatch restarted the operation deadline")
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutcomeUnknown);
        assert!(error.draft_operation.is_some());
        assert!(client.stream.lock().await.is_none());
    }

    struct DraftInstallation(Config);
    impl DraftInstallation {
        fn new() -> Self {
            let directory = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("mailctl-isolation-drafts-{}", uuid::Uuid::new_v4()));
            Self(
                Config::parse(&format!(
                    r#"default_grant = "reader"
state_dir = {state}
[limits]
operation_seconds = 120
account_connections = 1
active_requests = 1
[[accounts]]
key = "fixture"
alias = "fixture"
server = "imap.example.test"
username = "fixture@example.test"
mailboxes = ["Drafts"]
from_identities = ["fixture@example.test"]
drafts_mailbox = "Drafts"
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["fixture"]
[[grants]]
name = "writer"
profile = "drafts_only"
accounts = ["fixture"]
"#,
                    state = serde_json::to_string(&directory.join("state")).unwrap(),
                ))
                .unwrap(),
            )
        }
    }
    impl Drop for DraftInstallation {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.state_dir.parent().unwrap());
        }
    }

    async fn draft_session(
        service: Arc<Service>,
    ) -> (
        UnixStream,
        tokio::task::JoinHandle<Result<(), Error>>,
        Limits,
        usize,
    ) {
        let (mut caller, server) = UnixStream::pair().unwrap();
        let session = tokio::spawn(serve_session(server, service, "writer".into(), 4));
        write_frame(
            &mut caller,
            &ClientFrame::Hello {
                narrowing: Narrowing::default(),
            },
            REQUEST_BYTES,
        )
        .await
        .unwrap();
        let ServerFrame::Hello {
            limits,
            response_bound,
        } = read_frame(&mut caller, REQUEST_BYTES, 32).await.unwrap()
        else {
            panic!("isolated session hello");
        };
        (caller, session, limits, response_bound)
    }

    #[tokio::test]
    async fn isolated_drafts_use_the_advertised_deadline_and_preserve_dispatch_uncertainty() {
        use crate::{
            domain::{DraftStatusInput, SaveDraftInput},
            draft_journal::{DraftJournal, DraftOperationState},
            service::{DraftAppend, DraftBackend, DraftPreparation, MailboxTarget},
        };
        use std::{
            future::{Future, pending},
            pin::Pin,
            sync::atomic::{AtomicBool, Ordering},
        };
        use tokio::{sync::Notify, time::Instant};

        struct Backend {
            dispatched: bool,
            entered: Notify,
            dropped: Arc<AtomicBool>,
        }
        struct PendingResource(Arc<AtomicBool>);
        impl Drop for PendingResource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl DraftBackend for Backend {
            fn prepare<'a>(
                &'a self,
                _: MailboxTarget<'a>,
                _: &'a str,
                _: &'a Limits,
            ) -> DraftPreparation<'a> {
                Box::pin(async move {
                    if !self.dispatched {
                        let _resource = PendingResource(self.dropped.clone());
                        self.entered.notify_one();
                        pending::<()>().await;
                    }
                    Ok(Box::new(Append(self)) as Box<dyn DraftAppend>)
                })
            }
            fn reconcile<'a>(
                &'a self,
                _: MailboxTarget<'a>,
                _: &'a str,
                _: &'a crate::draft::DraftVerification,
                _: &'a Limits,
            ) -> Pin<Box<dyn Future<Output = Result<crate::draft::DraftEvidence, Error>> + Send + 'a>>
            {
                Box::pin(async { panic!("deadline checks must not reconcile") })
            }
        }
        struct Append<'a>(&'a Backend);
        impl DraftAppend for Append<'_> {
            fn uid_validity(&self) -> u32 {
                77
            }
            fn append<'a>(
                self: Box<Self>,
                _: &'a crate::draft::PreparedDraft,
                _: &'a Limits,
            ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AppendOutcome, Error>> + Send + 'a>>
            where
                Self: 'a,
            {
                Box::pin(async move {
                    let _resource = PendingResource(self.0.dropped.clone());
                    self.0.entered.notify_one();
                    pending().await
                })
            }
        }

        async fn check(dispatched: bool) {
            let installation = DraftInstallation::new();
            let config = &installation.0;
            Service::setup(config.clone()).unwrap();
            let backend = Arc::new(Backend {
                dispatched,
                entered: Notify::new(),
                dropped: Arc::new(AtomicBool::new(false)),
            });
            let service = Arc::new(
                Service::open(config.clone())
                    .unwrap()
                    .with_draft_backend(backend.clone()),
            );
            let context = service.context("writer", &Narrowing::default()).unwrap();
            let OperationResult::Accounts(accounts) = service
                .execute(&context, Operation::ListAccounts(Default::default()))
                .await
                .unwrap()
            else {
                panic!("fixture account discovery");
            };
            let input = SaveDraftInput {
                account_id: accounts.accounts[0].account_id.parse().unwrap(),
                account_generation: accounts.accounts[0].generation,
                operation_id: uuid::Uuid::new_v4(),
                mailbox: "Drafts".into(),
                draft: Box::new(crate::domain::DraftContent {
                    body: "Synthetic isolated draft deadline.".into(),
                    ..Default::default()
                }),
            };
            let identity = input.identity();
            let (mut caller, session, limits, response_bound) =
                draft_session(service.clone()).await;
            assert_eq!(limits.operation_seconds, 30);
            let started = Instant::now();
            write_frame(
                &mut caller,
                &ClientFrame::Operation {
                    operation: Operation::SaveDraft(input),
                    response_limit: response_bound,
                },
                REQUEST_BYTES,
            )
            .await
            .unwrap();
            timeout(Duration::from_secs(3), backend.entered.notified())
                .await
                .expect("synthetic backend did not reach its pending stage");
            let response = timeout(
                Duration::from_secs(35),
                read_frame::<ServerFrame>(&mut caller, response_bound, 32),
            )
            .await;
            if response.is_err() {
                session.abort();
                let _ = session.await;
                panic!(
                    "isolated draft exceeded its advertised 30-second deadline; dispatched={dispatched}"
                );
            }
            let ServerFrame::Result { envelope } = response.unwrap().unwrap() else {
                panic!("isolated draft result");
            };
            assert!(started.elapsed() >= Duration::from_secs(29));
            let error = envelope.into_result().unwrap_err();
            assert_eq!(
                error.code,
                if dispatched {
                    ErrorCode::OutcomeUnknown
                } else {
                    ErrorCode::Timeout
                },
            );
            if dispatched {
                let operation = error.draft_operation.unwrap();
                assert_eq!(operation.identity, identity);
                assert_eq!(operation.mailbox, "Drafts");
                assert_eq!(operation.uid_validity, Some(77));
            } else {
                assert!(error.draft_operation.is_none());
            }
            assert!(backend.dropped.load(Ordering::SeqCst));

            // The response follows cancellation cleanup: quota and writer ownership
            // are available, and a dispatched operation remains durably uncertain.
            let writer = crate::file_storage::open(
                &config
                    .state_dir
                    .join(format!("draft-{}.lock", identity.account_id)),
                OpenOptions::new().read(true).write(true),
            )
            .unwrap();
            writer.try_lock().expect("draft writer ownership leaked");
            drop(writer);
            let recorded = DraftJournal::open_existing(config.state_dir.join("drafts.sqlite"))
                .unwrap()
                .inspect(&identity)
                .unwrap();
            if dispatched {
                assert_eq!(recorded.unwrap().state, DraftOperationState::OutcomeUnknown);
            } else {
                assert!(recorded.is_none());
            }
            write_frame(
                &mut caller,
                &ClientFrame::Operation {
                    operation: Operation::DraftStatus(DraftStatusInput {
                        account_id: identity.account_id,
                        account_generation: identity.account_generation,
                        operation_id: identity.operation_id,
                        mailbox: "Drafts".into(),
                        reconcile: false,
                    }),
                    response_limit: response_bound,
                },
                REQUEST_BYTES,
            )
            .await
            .unwrap();
            let ServerFrame::Result { envelope } = timeout(
                Duration::from_secs(3),
                read_frame(&mut caller, response_bound, 32),
            )
            .await
            .expect("cancelled draft retained request admission")
            .unwrap() else {
                panic!("isolated draft status result");
            };
            assert_eq!(
                envelope.into_result().unwrap_err().code,
                if dispatched {
                    ErrorCode::OutcomeUnknown
                } else {
                    ErrorCode::OperationNotFound
                },
            );
            drop(caller);
            session.await.unwrap().unwrap_err();
        }

        tokio::join!(check(false), check(true));
    }

    #[test]
    fn rejected_tagged_json_fits_the_session_request_reservation() {
        let (limits, response_bound) = session_limits(&Limits::default()).unwrap();
        limits.validate().unwrap();
        let request_reservation = limits.buffered_bytes / SESSIONS - 16 * response_bound;
        let payload = format!(
            r#"{{"type":"hello","narrowing":{{}},"padding":[{}0]}}"#,
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

    #[tokio::test]
    async fn small_isolated_responses_retain_uncertainty_and_its_guidance() {
        for code in [ErrorCode::OutcomeUnknown, ErrorCode::OperationInProgress] {
            let error = Error::draft_outcome(
                code,
                crate::domain::DraftOperationDetails {
                    identity: crate::domain::DraftIdentity {
                        account_id: uuid::Uuid::new_v4(),
                        account_generation: 1,
                        operation_id: uuid::Uuid::new_v4(),
                    },
                    mailbox: "a".repeat(900),
                    uid_validity: Some(77),
                },
            );
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let (sent, frame) = tokio::join!(
                write_result(&mut sender, Err(error), 1024),
                read_frame::<ServerFrame>(&mut receiver, 1024, 32)
            );
            sent.unwrap();
            let ServerFrame::Result { envelope } = frame.unwrap() else {
                panic!("result frame")
            };
            let error = envelope.into_result().unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(error.message, Error::new(code).message);
            assert!(!error.retryable);
        }
    }

    #[tokio::test]
    async fn minimum_isolated_response_accepts_an_ordinary_created_receipt() {
        let installation = DraftInstallation::new();
        let config = &installation.0;
        Service::setup(config.clone()).unwrap();
        let backend = Arc::new(crate::service::MemoryDrafts::default());
        backend.set("fixture", "Drafts", 77);
        let service = Arc::new(
            Service::open(config.clone())
                .unwrap()
                .with_draft_backend(backend),
        );
        let context = service.context("writer", &Default::default()).unwrap();
        let OperationResult::Accounts(accounts) = service
            .execute(&context, Operation::ListAccounts(Default::default()))
            .await
            .unwrap()
        else {
            panic!("fixture account")
        };
        let (mut caller, session, _, _) = draft_session(service).await;
        write_frame(
            &mut caller,
            &ClientFrame::Operation {
                operation: Operation::SaveDraft(crate::domain::SaveDraftInput {
                    account_id: accounts.accounts[0].account_id.parse().unwrap(),
                    account_generation: 1,
                    operation_id: uuid::Uuid::new_v4(),
                    mailbox: "Drafts".into(),
                    draft: Box::new(crate::domain::DraftContent {
                        body: "Synthetic minimum response.".into(),
                        ..Default::default()
                    }),
                }),
                response_limit: 1024,
            },
            REQUEST_BYTES,
        )
        .await
        .unwrap();
        let frame = read_frame::<ServerFrame>(&mut caller, 1024, 32)
            .await
            .unwrap();
        assert!(serialize_bounded(&frame, 1024).is_ok());
        let ServerFrame::Result { envelope } = frame else {
            panic!("result frame")
        };
        let OperationResult::Draft(receipt) = envelope.into_result().unwrap() else {
            panic!("created receipt")
        };
        assert_eq!(
            receipt.state,
            crate::domain::DraftState::CreatedReferenceUnavailable
        );
        drop(caller);
        session.await.unwrap().unwrap_err();
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
