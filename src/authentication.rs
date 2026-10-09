//! Process-local authentication admission, credential work, and IMAP connections.

use crate::{
    cleanup::{CleanupOwner, CleanupTasks},
    config::{AccountConfig, Limits, TlsMode},
    credentials::{Availability, ResolutionLimits, Secret, SecretSource, SourceError},
    imap::{self, AuthenticatedConnection, ImapEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::{Notify, watch},
    time::Instant,
};
use tokio_rustls::rustls::RootCertStore;
use tracing::Instrument;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Source(SourceError),
    Imap(imap::Error),
    RateLimited,
    Timeout,
    InvalidInput,
}

#[derive(Clone)]
pub struct Account {
    pub id: Uuid,
    pub generation: u64,
    pub config: AccountConfig,
    pub source: Arc<dyn SecretSource>,
}

/// Authentication borrows immutable routing without copying authorization inventories.
pub(crate) struct BorrowedAccount<'a> {
    pub id: Uuid,
    pub generation: u64,
    pub config: &'a AccountConfig,
    pub source: &'a Arc<dyn SecretSource>,
}
impl<'a> From<&'a Account> for BorrowedAccount<'a> {
    fn from(account: &'a Account) -> Self {
        Self {
            id: account.id,
            generation: account.generation,
            config: &account.config,
            source: &account.source,
        }
    }
}

pub struct Runtime {
    limits: Limits,
    roots: Arc<RootCertStore>,
    workers: Arc<Gate>,
    flights: Mutex<HashMap<(Uuid, u64, WorkKind), Weak<Flight>>>,
    accounts: Mutex<HashMap<Uuid, Arc<Pool>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum WorkKind {
    Inspect,
    Resolve(ResolutionLimits),
}
#[derive(Clone)]
enum Work {
    Availability(Availability),
    Secret(Arc<Secret>),
}
struct Flight {
    result: watch::Receiver<Option<Result<Work, Error>>>,
    // None closes queued work to new waiters before its worker reservation is dropped.
    waiters: Mutex<Option<usize>>,
    abandoned: Notify,
}
impl Flight {
    fn join(&self) -> bool {
        let mut waiters = self.waiters.lock().unwrap();
        let Some(count) = waiters.as_mut() else {
            return false;
        };
        *count += 1;
        true
    }

    fn abandon_if_unobserved(&self) -> bool {
        let mut waiters = self.waiters.lock().unwrap();
        if *waiters == Some(0) {
            *waiters = None;
        }
        waiters.is_none()
    }

    async fn cancelled(&self) {
        loop {
            let abandoned = self.abandoned.notified();
            if self.abandon_if_unobserved() {
                return;
            }
            abandoned.await;
        }
    }
}
struct Waiter(Arc<Flight>);
impl Drop for Waiter {
    fn drop(&mut self) {
        let mut waiters = self.0.waiters.lock().unwrap();
        let count = waiters.as_mut().expect("live credential waiter");
        *count -= 1;
        if *count == 0 {
            self.0.abandoned.notify_one();
        }
    }
}

struct Pool {
    state: Mutex<PoolState>,
    gate: Arc<Gate>,
    expiry_changed: Arc<Notify>,
    expiry_tasks: CleanupTasks,
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.expiry_changed.notify_waiters();
    }
}
impl Pool {
    fn start_expiry(self: &Arc<Self>) -> Arc<CleanupOwner> {
        self.expiry_tasks.start(|owner| {
            // Construct before spawn so cancellation also cleans an unpolled task.
            let guard = PoolExpiry {
                pool: Arc::downgrade(self),
                owner,
            };
            let pool = Arc::downgrade(self);
            let changed = self.expiry_changed.clone();
            async move {
                let _guard = guard;
                Self::expire_idle(pool, changed).await;
            }
        })
    }
    async fn expire_idle(pool: Weak<Self>, changed: Arc<Notify>) {
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let Some(pool) = pool.upgrade() else { return };
            let next_expiry = {
                let mut state = pool.state.lock().unwrap();
                state.idle.retain(|idle| idle.expires_at > Instant::now());
                state.idle.iter().map(|idle| idle.expires_at).min()
            };
            // The expiration task must not retain the process-local pool while it waits.
            drop(pool);
            match next_expiry {
                Some(expiry) => tokio::select! {
                    _ = tokio::time::sleep_until(expiry) => {},
                    _ = notified => {},
                },
                None => notified.await,
            }
        }
    }
}
struct PoolExpiry {
    pool: Weak<Pool>,
    owner: Arc<CleanupOwner>,
}
impl Drop for PoolExpiry {
    fn drop(&mut self) {
        // Release can race executor shutdown, including outside any Tokio context.
        self.owner.stop();
        if let Some(pool) = self.pool.upgrade() {
            pool.state
                .lock()
                .unwrap()
                .idle
                .retain(|idle| !Arc::ptr_eq(&idle.owner, &self.owner));
            pool.expiry_changed.notify_waiters();
        }
    }
}
struct PoolState {
    idle: Vec<Idle>,
    last_doctor: Option<Instant>,
}
struct Idle {
    generation: u64,
    connection: AuthenticatedConnection,
    established: Instant,
    expires_at: Instant,
    owner: Arc<CleanupOwner>,
}

/// Dropping a lease disposes its connection. Return it only at a clean operation boundary.
pub struct Lease {
    idle: Idle,
    admission: Admission,
    pool: Arc<Pool>,
    capacity: usize,
}
impl Lease {
    pub(crate) async fn draft_target(
        mut self,
        mailbox: &str,
        limits: &crate::imap::Limits,
    ) -> Result<(Self, u32), crate::imap::Error> {
        let (connection, validity) = self
            .idle
            .connection
            .select_draft_target(mailbox, limits, &mut crate::imap::Metrics::default())
            .await?;
        self.idle.connection = connection;
        Ok((self, validity))
    }
    pub(crate) async fn with_connection<T>(
        self,
        operation: impl AsyncFnOnce(AuthenticatedConnection) -> T,
    ) -> T {
        let Self {
            idle,
            admission: _admission,
            ..
        } = self;
        operation(idle.connection).await
    }
    pub fn release(self) {
        let mut state = self.pool.state.lock().unwrap();
        if self.idle.owner.is_alive()
            && self.idle.expires_at > Instant::now()
            && state.idle.len() + self.admission.gate.state.lock().unwrap().active <= self.capacity
        {
            state.idle.push(self.idle);
            self.pool.expiry_changed.notify_waiters();
        }
    }
}

#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
}
#[derive(Default)]
struct GateState {
    active: usize,
    waiting: VecDeque<GateWaiter>,
    next_ticket: u64,
}
struct GateWaiter {
    ticket: u64,
    active_limit: usize,
    changed: Arc<Notify>,
}
impl GateState {
    fn next_notification(&self) -> Option<Arc<Notify>> {
        self.waiting
            .front()
            .filter(|waiter| self.active < waiter.active_limit)
            .map(|waiter| waiter.changed.clone())
    }
}
struct Admission {
    gate: Arc<Gate>,
    ticket: Option<(u64, Arc<Notify>)>,
}
impl Drop for Admission {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        if let Some((ticket, _)) = &self.ticket {
            state.waiting.retain(|entry| entry.ticket != *ticket);
        } else {
            state.active -= 1;
        }
        let changed = state.next_notification();
        drop(state);
        if let Some(changed) = changed {
            changed.notify_one();
        }
    }
}
impl Gate {
    fn reserve(self: Arc<Self>, active: usize, pending: usize) -> Result<Admission, Error> {
        let ticket = {
            let mut state = self.state.lock().unwrap();
            if state.waiting.is_empty() && state.active < active {
                state.active += 1;
                None
            } else {
                if state.waiting.len() >= pending {
                    return Err(Error::RateLimited);
                }
                let ticket = state.next_ticket;
                state.next_ticket = state.next_ticket.wrapping_add(1);
                let changed = Arc::new(Notify::new());
                state.waiting.push_back(GateWaiter {
                    ticket,
                    active_limit: active,
                    changed: changed.clone(),
                });
                Some((ticket, changed))
            }
        };
        Ok(Admission { gate: self, ticket })
    }
    async fn admit(self: Arc<Self>, active: usize, pending: usize) -> Result<Admission, Error> {
        Ok(self.reserve(active, pending)?.wait().await)
    }
}
impl Admission {
    async fn wait(mut self) -> Self {
        let Some((ticket, notification)) = self
            .ticket
            .as_ref()
            .map(|(ticket, changed)| (*ticket, changed.clone()))
        else {
            return self;
        };
        loop {
            let changed = notification.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.gate.state.lock().unwrap();
                if state.waiting.front().is_some_and(|entry| {
                    entry.ticket == ticket && state.active < entry.active_limit
                }) {
                    state.waiting.pop_front();
                    state.active += 1;
                    self.ticket = None;
                    let next = state.next_notification();
                    drop(state);
                    if let Some(next) = next {
                        next.notify_one();
                    }
                    return self;
                }
            }
            changed.await;
        }
    }
}

impl Runtime {
    pub fn new(limits: Limits, roots: RootCertStore) -> Result<Self, Error> {
        limits.validate().map_err(|_| Error::InvalidInput)?;
        Ok(Self {
            workers: Arc::new(Gate::default()),
            limits,
            roots: Arc::new(roots),
            flights: Mutex::new(HashMap::new()),
            accounts: Mutex::new(HashMap::new()),
        })
    }

    pub async fn inspect(
        &self,
        id: Uuid,
        generation: u64,
        source: Arc<dyn SecretSource>,
    ) -> Result<Availability, Error> {
        self.inspect_with_limits(id, generation, source, &self.limits)
            .await
    }

    pub async fn inspect_with_limits(
        &self,
        id: Uuid,
        generation: u64,
        source: Arc<dyn SecretSource>,
        limits: &Limits,
    ) -> Result<Availability, Error> {
        self.validate_limits(limits)?;
        match self
            .work(id, generation, source, WorkKind::Inspect, limits)
            .await?
        {
            Work::Availability(availability) => Ok(availability),
            Work::Secret(_) => unreachable!(),
        }
    }

    /// Checks one explicitly authorized email account, then disconnects without mailbox work.
    pub async fn doctor(&self, account: &Account, limits: &Limits) -> Result<(), Error> {
        self.doctor_borrowed(account.into(), limits).await
    }

    pub(crate) async fn doctor_borrowed(
        &self,
        account: BorrowedAccount<'_>,
        limits: &Limits,
    ) -> Result<(), Error> {
        self.validate_limits(limits)?;
        let pool = self.pool(account.id)?;
        {
            let mut state = pool.state.lock().unwrap();
            let interval = Duration::from_secs_f64(60.0 / limits.doctor_checks_per_minute as f64);
            if state
                .last_doctor
                .is_some_and(|last| last.elapsed() < interval)
            {
                return Err(Error::RateLimited);
            }
            state.last_doctor = Some(Instant::now());
        }
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            async {
                self.acquire_inner(account, limits, pool, true)
                    .await?
                    .with_connection(AuthenticatedConnection::disconnect)
                    .await
                    .map_err(Error::Imap)
            },
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    /// Discover the bounded provider inventory on one admitted connection, then log out.
    pub async fn discover_all(
        &self,
        account: &Account,
        limits: &Limits,
    ) -> Result<Vec<imap::Mailbox>, Error> {
        self.discover_inventory(account.into(), None, limits).await
    }

    /// Discover exact approved names on one admitted connection, then log out.
    pub async fn discover(
        &self,
        account: &Account,
        names: &[String],
        limits: &Limits,
    ) -> Result<Vec<imap::Mailbox>, Error> {
        self.discover_inventory(account.into(), Some(names), limits)
            .await
    }

    pub(crate) async fn discover_inventory(
        &self,
        account: BorrowedAccount<'_>,
        names: Option<&[String]>,
        limits: &Limits,
    ) -> Result<Vec<imap::Mailbox>, Error> {
        self.validate_limits(limits)?;
        if let Some(names) = names {
            if names.len() > limits.mailbox_inventory {
                return Err(Error::Imap(imap::Error::Limit));
            }
            for name in names {
                imap::mailbox(name).map_err(Error::Imap)?;
            }
        }
        let pool = self.pool(account.id)?;
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            async {
                self.acquire_inner(account, limits, pool, true)
                    .await?
                    .with_connection(async |connection| {
                        let imap_limits = imap::Limits {
                            max_mailboxes: limits.mailbox_inventory,
                            ..Default::default()
                        };
                        let mut metrics = imap::Metrics::default();
                        match names {
                            Some(names) => {
                                connection.discover(names, &imap_limits, &mut metrics).await
                            }
                            None => connection.discover_all(&imap_limits, &mut metrics).await,
                        }
                    })
                    .await
                    .map_err(Error::Imap)
            },
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn acquire(&self, account: &Account, limits: &Limits) -> Result<Lease, Error> {
        self.acquire_borrowed(account.into(), limits).await
    }

    pub(crate) async fn acquire_borrowed(
        &self,
        account: BorrowedAccount<'_>,
        limits: &Limits,
    ) -> Result<Lease, Error> {
        self.validate_limits(limits)?;
        let pool = self.pool(account.id)?;
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            self.acquire_inner(account, limits, pool, false),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    fn validate_limits(&self, limits: &Limits) -> Result<(), Error> {
        limits.validate().map_err(|_| Error::InvalidInput)?;
        if limits.attachment_decoded_bytes > self.limits.attachment_decoded_bytes
            || limits.attachment_wire_bytes > self.limits.attachment_wire_bytes
            || limits.attachment_chunk_bytes > self.limits.attachment_chunk_bytes
            || limits.transfer_seconds > self.limits.transfer_seconds
            || limits.transfers_per_account > self.limits.transfers_per_account
            || limits.text_page_bytes > self.limits.text_page_bytes
            || limits.mime_depth > self.limits.mime_depth
            || limits.mime_parts > self.limits.mime_parts
            || limits.mailbox_inventory > self.limits.mailbox_inventory
            || limits.search_page > self.limits.search_page
            || limits.search_uid_window > self.limits.search_uid_window
            || limits.search_windows > self.limits.search_windows
            || limits.header_bytes > self.limits.header_bytes
            || limits.wire_fetch_bytes > self.limits.wire_fetch_bytes
            || limits.account_connections > self.limits.account_connections
            || limits.account_pending_requests > self.limits.account_pending_requests
            || limits.command_stderr_bytes > self.limits.command_stderr_bytes
            || limits.secret_command_seconds > self.limits.secret_command_seconds
            || limits.secret_bytes > self.limits.secret_bytes
            || limits.operation_seconds > self.limits.operation_seconds
            || limits.connection_seconds > self.limits.connection_seconds
            || limits.connection_lifetime_seconds > self.limits.connection_lifetime_seconds
            || limits.doctor_checks_per_minute > self.limits.doctor_checks_per_minute
            || limits.credential_workers > self.limits.credential_workers
            || limits.queued_credentials > self.limits.queued_credentials
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    fn pool(&self, id: Uuid) -> Result<Arc<Pool>, Error> {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(pool) = accounts.get(&id) {
            pool.start_expiry();
            return Ok(pool.clone());
        }
        if accounts.len() == self.limits.accounts {
            return Err(Error::RateLimited);
        }
        let pool = Arc::new(Pool {
            state: Mutex::new(PoolState {
                idle: Vec::new(),
                last_doctor: None,
            }),
            gate: Arc::new(Gate::default()),
            expiry_changed: Arc::new(Notify::new()),
            expiry_tasks: CleanupTasks::default(),
        });
        pool.start_expiry();
        accounts.insert(id, pool.clone());
        Ok(pool)
    }

    async fn acquire_inner(
        &self,
        account: BorrowedAccount<'_>,
        limits: &Limits,
        pool: Arc<Pool>,
        fresh: bool,
    ) -> Result<Lease, Error> {
        let admission = pool
            .gate
            .clone()
            .admit(limits.account_connections, limits.account_pending_requests)
            .await?;
        let lifetime = Duration::from_secs(limits.connection_lifetime_seconds as u64);
        let idle = {
            let mut state = pool.state.lock().unwrap();
            state.idle.retain(|idle| {
                idle.owner.is_alive()
                    && idle.expires_at > Instant::now()
                    && idle.established.elapsed() < lifetime
            });
            let spare = limits
                .account_connections
                .saturating_sub(pool.gate.state.lock().unwrap().active);
            let selected = if fresh {
                None
            } else {
                state
                    .idle
                    .iter()
                    .rposition(|idle| idle.generation == account.generation)
                    .map(|position| state.idle.swap_remove(position))
            };
            // A new connection also consumes capacity when no matching lease exists.
            state.idle.truncate(spare);
            selected
        };
        let idle = match idle {
            Some(mut idle) => {
                idle.expires_at = idle.expires_at.min(idle.established + lifetime);
                idle
            }
            None => {
                let Work::Secret(secret) = self
                    .work(
                        account.id,
                        account.generation,
                        account.source.clone(),
                        WorkKind::Resolve(
                            ResolutionLimits::try_from(limits).map_err(Error::Source)?,
                        ),
                        limits,
                    )
                    .await?
                else {
                    unreachable!()
                };
                if secret.len() > limits.secret_bytes {
                    return Err(Error::Source(SourceError::InvalidSecret));
                }
                let endpoint = self.endpoint(account.config, limits)?;
                let connection = endpoint
                    .connect_authenticated(
                        &account.config.username,
                        secret.expose(),
                        &mut imap::Metrics::default(),
                    )
                    .await
                    .map_err(Error::Imap)?;
                let established = Instant::now();
                Idle {
                    generation: account.generation,
                    connection,
                    established,
                    expires_at: established + lifetime,
                    owner: pool.start_expiry(),
                }
            }
        };
        Ok(Lease {
            idle,
            admission,
            pool,
            capacity: limits.account_connections,
        })
    }

    fn endpoint(&self, account: &AccountConfig, limits: &Limits) -> Result<ImapEndpoint, Error> {
        ImapEndpoint::new_with_shared_roots(
            account.server.clone(),
            account.port,
            match account.tls {
                TlsMode::Implicit => imap::TlsMode::Implicit,
                TlsMode::Starttls => imap::TlsMode::StartTls,
            },
            self.roots.clone(),
            imap::Limits {
                operation_timeout: Duration::from_secs(limits.operation_seconds as u64),
                connect_timeout: Duration::from_secs(limits.connection_seconds as u64),
                ..Default::default()
            },
        )
        .map_err(Error::Imap)
    }

    async fn work(
        &self,
        id: Uuid,
        generation: u64,
        source: Arc<dyn SecretSource>,
        kind: WorkKind,
        limits: &Limits,
    ) -> Result<Work, Error> {
        let flight = {
            let mut flights = self.flights.lock().unwrap();
            flights.retain(|_, flight| flight.strong_count() > 0);
            let key = (id, generation, kind);
            if let Some(flight) = flights
                .get(&key)
                .and_then(Weak::upgrade)
                .filter(|flight| flight.result.borrow().is_none() && flight.join())
            {
                flight
            } else {
                let admission = self
                    .workers
                    .clone()
                    .reserve(limits.credential_workers, limits.queued_credentials)?;
                let (sender, receiver) = watch::channel(None);
                let flight = Arc::new(Flight {
                    result: receiver,
                    waiters: Mutex::new(Some(1)),
                    abandoned: Notify::new(),
                });
                flights.insert(key, Arc::downgrade(&flight));
                let deadline = Duration::from_secs(limits.operation_seconds as u64);
                let running = flight.clone();
                tokio::spawn(
                    async move {
                        let admission = tokio::select! {
                            _ = running.cancelled() => return,
                            result = tokio::time::timeout(deadline, admission.wait()) => result,
                        };
                        let admission = match admission {
                            Ok(admission) => admission,
                            Err(_) => {
                                let _ = sender.send(Some(Err(Error::Timeout)));
                                return;
                            }
                        };
                        if running.abandon_if_unobserved() {
                            return;
                        }
                        let span = tracing::Span::current();
                        let result = tokio::task::spawn_blocking(move || {
                            span.in_scope(|| {
                                let _worker = admission;
                                match kind {
                                    WorkKind::Inspect => {
                                        Ok(Work::Availability(source.availability(id)))
                                    }
                                    WorkKind::Resolve(resolution_limits) => source
                                        .resolve_with_limits(id, &resolution_limits)
                                        .map(|secret| Work::Secret(Arc::new(secret)))
                                        .map_err(Error::Source),
                                }
                            })
                        })
                        .await
                        .unwrap_or(Err(Error::Source(SourceError::Internal)));
                        let _ = sender.send(Some(result));
                    }
                    .in_current_span(),
                );
                flight
            }
        };
        let waiter = Waiter(flight);
        let mut receiver = waiter.0.result.clone();
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            async {
                receiver
                    .wait_for(Option::is_some)
                    .await
                    .map_err(|_| Error::Source(SourceError::Internal))?
                    .clone()
                    .expect("completed credential work")
            },
        )
        .await
        .map_err(|_| Error::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::{Gate, Runtime};
    use crate::config::{AccountConfig, CredentialSource, Limits, TlsMode};
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };
    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn releasing_worker_capacity_wakes_only_the_next_waiter() {
        let gate = Arc::new(Gate::default());
        let active = gate.clone().reserve(1, 32).unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut queued = (0..32)
            .map(|_| Box::pin(gate.clone().reserve(1, 32).unwrap().wait()))
            .collect::<Vec<_>>();
        for request in &mut queued {
            assert!(request.as_mut().poll(&mut context).is_pending());
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(active);
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "only one credential worker or connection can claim the released capacity"
        );
    }

    #[test]
    fn cancelling_a_blocked_worker_head_wakes_the_newly_eligible_waiter() {
        let gate = Arc::new(Gate::default());
        let _active = gate.clone().reserve(2, 2).unwrap();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut blocked = Box::pin(gate.clone().reserve(1, 2).unwrap().wait());
        let mut eligible = Box::pin(gate.reserve(2, 2).unwrap().wait());
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        assert!(eligible.as_mut().poll(&mut context).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(blocked);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(eligible.as_mut().poll(&mut context).is_ready());
    }

    #[test]
    fn repeated_endpoints_do_not_copy_the_runtime_trust_inventory() {
        let cert =
            rcgen::generate_simple_self_signed(vec!["synthetic.example.test".into()]).unwrap();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        for _ in 0..256 {
            roots.add(cert.cert.der().clone()).unwrap();
        }
        let limits = Limits::default();
        let runtime = Runtime::new(limits.clone(), roots).unwrap();
        let account = AccountConfig {
            key: "synthetic".into(),
            alias: "synthetic".into(),
            server: "synthetic.example.test".into(),
            port: 993,
            tls: TlsMode::Implicit,
            username: "synthetic@example.test".into(),
            mailboxes: vec!["INBOX".into()].into(),
            from_identities: vec!["synthetic@example.test".into()],
            drafts_mailbox: None,
            credential: CredentialSource::Session {},
            retain_history: false,
        };
        drop(runtime.endpoint(&account, &limits).unwrap());
        let allocations = allocation_counter::measure(|| {
            for _ in 0..16 {
                std::hint::black_box(runtime.endpoint(&account, &limits).unwrap());
            }
        });
        println!(
            "16 endpoints with 256 roots: {} allocations, {} allocated bytes",
            allocations.count_total, allocations.bytes_total
        );
        assert!(
            allocations.bytes_total <= 512 * 1024,
            "endpoints copied {} bytes of immutable TLS trust",
            allocations.bytes_total
        );
        assert_eq!(allocations.bytes_current, 0);
    }
}
