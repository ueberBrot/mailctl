//! Process-local authentication admission, credential work, and IMAP connections.

use crate::{
    config::{AccountConfig, Limits, TlsMode},
    credentials::{Availability, Secret, SecretSource, SourceError},
    imap::{self, AuthenticatedConnection, ImapProbe},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, watch},
    time::Instant,
};
use tokio_rustls::rustls::RootCertStore;
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

pub struct Runtime {
    limits: Limits,
    roots: RootCertStore,
    workers: Arc<Gate>,
    flights: Mutex<HashMap<(Uuid, u64, WorkKind), Weak<Flight>>>,
    accounts: Mutex<HashMap<Uuid, Arc<Pool>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum WorkKind {
    Inspect,
    Resolve,
}
#[derive(Clone)]
enum Work {
    Availability(Availability),
    Secret(Arc<Secret>),
}
struct Flight {
    result: watch::Receiver<Option<Result<Work, Error>>>,
    waiters: AtomicUsize,
    abandoned: Notify,
}
impl Flight {
    async fn cancelled(&self) {
        loop {
            let abandoned = self.abandoned.notified();
            if self.waiters.load(Ordering::Acquire) == 0 {
                return;
            }
            abandoned.await;
        }
    }
}
struct Waiter(Arc<Flight>);
impl Drop for Waiter {
    fn drop(&mut self) {
        if self.0.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.abandoned.notify_one();
        }
    }
}

struct Pool {
    state: Mutex<PoolState>,
    gate: Arc<Gate>,
    expiry_changed: Arc<Notify>,
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.expiry_changed.notify_one();
    }
}
impl Pool {
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
struct PoolState {
    generation: u64,
    idle: Vec<Idle>,
    last_doctor: Option<Instant>,
}
struct Idle {
    connection: AuthenticatedConnection,
    established: Instant,
    expires_at: Instant,
}

/// Dropping a lease disposes its connection. Return it only at a clean operation boundary.
pub struct Lease {
    idle: Option<Idle>,
    admission: Admission,
    pool: Arc<Pool>,
    generation: u64,
    capacity: usize,
}
impl Lease {
    pub fn release(mut self) {
        let Some(idle) = self.idle.take() else { return };
        let mut state = self.pool.state.lock().unwrap();
        if state.generation == self.generation
            && idle.expires_at > Instant::now()
            && state.idle.len() + self.admission.gate.state.lock().unwrap().active <= self.capacity
        {
            state.idle.push(idle);
            self.pool.expiry_changed.notify_one();
        }
    }
}

#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Notify,
}
#[derive(Default)]
struct GateState {
    active: usize,
    waiting: VecDeque<u64>,
    next_ticket: u64,
}
struct Admission {
    gate: Arc<Gate>,
    ticket: Option<u64>,
}
impl Drop for Admission {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        if let Some(ticket) = self.ticket {
            state.waiting.retain(|entry| *entry != ticket);
        } else {
            state.active -= 1;
        }
        drop(state);
        self.gate.changed.notify_waiters();
    }
}
impl Gate {
    fn reserve(self: Arc<Self>, active: usize, pending: usize) -> Result<Admission, Error> {
        let ticket = {
            let mut state = self.state.lock().unwrap();
            if state.waiting.is_empty() && state.active < active {
                state.active += 1;
                return Ok(Admission {
                    gate: self.clone(),
                    ticket: None,
                });
            }
            if state.waiting.len() >= pending {
                return Err(Error::RateLimited);
            }
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.wrapping_add(1);
            state.waiting.push_back(ticket);
            ticket
        };
        Ok(Admission {
            gate: self,
            ticket: Some(ticket),
        })
    }
    async fn admit(self: Arc<Self>, active: usize, pending: usize) -> Result<Admission, Error> {
        Ok(self.reserve(active, pending)?.wait(active).await)
    }
}
impl Admission {
    async fn wait(mut self, active: usize) -> Self {
        let Some(ticket) = self.ticket else {
            return self;
        };
        let gate = self.gate.clone();
        loop {
            let changed = gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = gate.state.lock().unwrap();
                if state.waiting.front() == Some(&ticket) && state.active < active {
                    state.waiting.pop_front();
                    state.active += 1;
                    self.ticket = None;
                    drop(state);
                    gate.changed.notify_waiters();
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
            roots,
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
        self.validate_limits(limits)?;
        let pool = self.pool(account.id, account.generation)?;
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
                let mut lease = self.acquire_inner(account, limits, pool, true).await?;
                let connection = lease.idle.take().unwrap().connection;
                connection
                    .disconnect(Duration::from_secs(limits.operation_seconds as u64))
                    .await
                    .map_err(Error::Imap)
            },
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn acquire(&self, account: &Account, limits: &Limits) -> Result<Lease, Error> {
        self.validate_limits(limits)?;
        let pool = self.pool(account.id, account.generation)?;
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            self.acquire_inner(account, limits, pool, false),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    fn validate_limits(&self, limits: &Limits) -> Result<(), Error> {
        limits.validate().map_err(|_| Error::InvalidInput)?;
        if limits.account_connections > self.limits.account_connections
            || limits.account_pending_requests > self.limits.account_pending_requests
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

    fn pool(&self, id: Uuid, generation: u64) -> Result<Arc<Pool>, Error> {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(pool) = accounts.get(&id) {
            let mut state = pool.state.lock().unwrap();
            if generation < state.generation {
                return Err(Error::InvalidInput);
            }
            if generation != state.generation {
                state.generation = generation;
                state.idle.clear();
            }
            return Ok(pool.clone());
        }
        if accounts.len() == self.limits.accounts {
            return Err(Error::RateLimited);
        }
        let pool = Arc::new(Pool {
            state: Mutex::new(PoolState {
                generation,
                idle: Vec::new(),
                last_doctor: None,
            }),
            gate: Arc::new(Gate::default()),
            expiry_changed: Arc::new(Notify::new()),
        });
        tokio::spawn(Pool::expire_idle(
            Arc::downgrade(&pool),
            pool.expiry_changed.clone(),
        ));
        accounts.insert(id, pool.clone());
        Ok(pool)
    }

    async fn acquire_inner(
        &self,
        account: &Account,
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
            if state.generation != account.generation {
                return Err(Error::InvalidInput);
            }
            state.idle.retain(|idle| {
                idle.expires_at > Instant::now() && idle.established.elapsed() < lifetime
            });
            let spare = limits
                .account_connections
                .saturating_sub(pool.gate.state.lock().unwrap().active);
            state.idle.truncate(spare + usize::from(!fresh));
            if fresh { None } else { state.idle.pop() }
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
                        WorkKind::Resolve,
                        limits,
                    )
                    .await?
                else {
                    unreachable!()
                };
                if secret.len() > limits.secret_bytes {
                    return Err(Error::Source(SourceError::InvalidSecret));
                }
                let mut probe = ImapProbe::new(
                    account.config.server.clone(),
                    account.config.port,
                    match account.config.tls {
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
                .map_err(Error::Imap)?;
                let connection = probe
                    .connect_authenticated(&account.config.username, secret.expose())
                    .await
                    .map_err(Error::Imap)?;
                let established = Instant::now();
                Idle {
                    connection,
                    established,
                    expires_at: established + lifetime,
                }
            }
        };
        Ok(Lease {
            idle: Some(idle),
            admission,
            pool,
            generation: account.generation,
            capacity: limits.account_connections,
        })
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
                .filter(|flight| flight.result.borrow().is_none())
            {
                flight.waiters.fetch_add(1, Ordering::AcqRel);
                flight
            } else {
                let admission = self
                    .workers
                    .clone()
                    .reserve(limits.credential_workers, limits.queued_credentials)?;
                let (sender, receiver) = watch::channel(None);
                let flight = Arc::new(Flight {
                    result: receiver,
                    waiters: AtomicUsize::new(1),
                    abandoned: Notify::new(),
                });
                flights.insert(key, Arc::downgrade(&flight));
                let deadline = Duration::from_secs(limits.operation_seconds as u64);
                let active = limits.credential_workers;
                let running = flight.clone();
                tokio::spawn(async move {
                    let admission = tokio::select! {
                        _ = running.cancelled() => return,
                        result = tokio::time::timeout(deadline, admission.wait(active)) => result,
                    };
                    let admission = match admission {
                        Ok(admission) => admission,
                        Err(_) => {
                            let _ = sender.send(Some(Err(Error::Timeout)));
                            return;
                        }
                    };
                    if running.waiters.load(Ordering::Acquire) == 0 {
                        return;
                    }
                    let result = tokio::task::spawn_blocking(move || {
                        let _worker = admission;
                        match kind {
                            WorkKind::Inspect => Ok(Work::Availability(source.availability(id))),
                            WorkKind::Resolve => source
                                .resolve(id)
                                .map(|secret| Work::Secret(Arc::new(secret)))
                                .map_err(Error::Source),
                        }
                    })
                    .await
                    .unwrap_or(Err(Error::Source(SourceError::Internal)));
                    let _ = sender.send(Some(result));
                });
                flight
            }
        };
        let waiter = Waiter(flight);
        let mut receiver = waiter.0.result.clone();
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            async {
                loop {
                    if let Some(result) = receiver.borrow_and_update().clone() {
                        return result;
                    }
                    receiver
                        .changed()
                        .await
                        .map_err(|_| Error::Source(SourceError::Internal))?;
                }
            },
        )
        .await
        .map_err(|_| Error::Timeout)?
    }
}
