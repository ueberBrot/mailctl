//! Transfer reservations own quota, checkout, expiry, and session cleanup.
use super::{AttachmentReader, Error, ErrorCode, Limits, MessageReference, expired};
use crate::cleanup::CleanupTasks;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Default)]
pub(in crate::service) struct Transfers(Arc<Store>);
#[derive(Default)]
struct Store {
    slots: Mutex<HashMap<Uuid, Slot>>,
    expiry_changed: Arc<Notify>,
    expiry_tasks: CleanupTasks,
    has_idle: AtomicBool,
}
impl Drop for Store {
    fn drop(&mut self) {
        self.expiry_changed.notify_waiters();
    }
}
impl Store {
    async fn expire_idle(store: Weak<Self>, changed: Arc<Notify>) {
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let Some(store) = store.upgrade() else { return };
            let next_expiry = {
                let mut slots = store.slots.lock().unwrap();
                let now = Instant::now();
                // Active reads own their reservation until completion/cancellation.
                slots.retain(|_, slot| slot.entry.is_none() || slot.expires > now);
                let next = slots
                    .values()
                    .filter(|slot| slot.entry.is_some())
                    .map(|slot| slot.expires)
                    .min();
                store.has_idle.store(next.is_some(), Ordering::Release);
                next
            };
            // Sleeping cleanup must not keep the process-local transfer store alive.
            drop(store);
            match next_expiry {
                Some(expiry) => tokio::select! {
                    _ = tokio::time::sleep_until(expiry) => {},
                    _ = notified => {},
                },
                None => notified.await,
            }
        }
    }
    fn start_expiry(self: &Arc<Self>) {
        self.expiry_tasks
            .start(|_| Self::expire_idle(Arc::downgrade(self), self.expiry_changed.clone()));
    }
    fn observe_idle(&self, slots: &HashMap<Uuid, Slot>) {
        self.has_idle.store(
            slots.values().any(|slot| slot.entry.is_some()),
            Ordering::Release,
        );
    }
}
struct Slot {
    session: Uuid,
    account: String,
    expires: Instant,
    entry: Option<Entry>,
}
pub(super) struct Entry {
    pub resource: MessageReference,
    pub reference: String,
    pub scope: String,
    pub offset: u64,
    pub reader: Box<dyn AttachmentReader>,
}
// A checked-out slot remains admitted until its request completes or is dropped.
pub(super) struct Reservation {
    store: Arc<Store>,
    id: Uuid,
    expires: Instant,
    retained: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.retained {
            self.store.slots.lock().unwrap().remove(&self.id);
        }
    }
}
impl Reservation {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn expires(&self) -> Instant {
        self.expires
    }
    pub fn retain(mut self, entry: Entry) -> Result<(), Error> {
        let mut store = self.store.slots.lock().unwrap();
        let slot = store.get_mut(&self.id).ok_or_else(expired)?;
        if slot.expires <= Instant::now() {
            return Err(expired());
        }
        slot.entry = Some(entry);
        self.store.has_idle.store(true, Ordering::Release);
        self.retained = true;
        drop(store);
        self.store.start_expiry();
        self.store.expiry_changed.notify_waiters();
        Ok(())
    }
}
impl Transfers {
    fn live(&self) -> MutexGuard<'_, HashMap<Uuid, Slot>> {
        let mut store = self.0.slots.lock().unwrap();
        let now = Instant::now();
        store.retain(|_, slot| slot.entry.is_none() || slot.expires > now);
        self.0.observe_idle(&store);
        store
    }
    pub(in crate::service) fn restart_expiry(&self) {
        if !self.0.has_idle.load(Ordering::Acquire)
            || tokio::runtime::Handle::try_current().is_err()
        {
            return;
        }
        // Recheck under the slot lock so metadata calls never start an empty timer.
        let _slots = self.0.slots.lock().unwrap();
        if self.0.has_idle.load(Ordering::Relaxed) {
            self.0.start_expiry();
        }
    }
    pub(super) fn reserve(
        &self,
        session: Uuid,
        account: &str,
        limits: &Limits,
        started: Instant,
    ) -> Result<Reservation, Error> {
        let mut store = self.live();
        if store
            .values()
            .filter(|slot| slot.account == account)
            .count()
            >= limits.transfers_per_account
        {
            return Err(Error::new(ErrorCode::RateLimited));
        }
        let id = Uuid::new_v4();
        // Equal operation and transfer limits must share an exact deadline.
        let expires = started + Duration::from_secs(limits.transfer_seconds as u64);
        store.insert(
            id,
            Slot {
                session,
                account: account.into(),
                expires,
                entry: None,
            },
        );
        Ok(Reservation {
            store: self.0.clone(),
            id,
            expires,
            retained: false,
        })
    }
    pub(super) fn checkout(
        &self,
        session: Uuid,
        id: Uuid,
        scope: &str,
        offset: u64,
        authorize: impl FnOnce(&Entry) -> Result<(), Error>,
    ) -> Result<(Reservation, Entry), Error> {
        let mut store = self.live();
        let slot = store.get_mut(&id).ok_or_else(expired)?;
        if slot.session != session {
            return Err(expired());
        }
        let entry = slot.entry.as_ref().ok_or_else(expired)?;
        if entry.scope != scope || entry.offset != offset {
            return Err(expired());
        }
        authorize(entry)?;
        let entry = slot.entry.take().ok_or_else(expired)?;
        let expires = slot.expires;
        self.0.observe_idle(&store);
        Ok((
            Reservation {
                store: self.0.clone(),
                id,
                expires,
                retained: false,
            },
            entry,
        ))
    }
    pub(in crate::service) fn session(&self) -> Arc<TransferSession> {
        Arc::new(TransferSession {
            id: Uuid::new_v4(),
            store: Arc::downgrade(&self.0),
        })
    }
}
#[derive(Debug)]
pub(crate) struct TransferSession {
    pub id: Uuid,
    store: Weak<Store>,
}
impl Drop for TransferSession {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            let mut slots = store.slots.lock().unwrap();
            slots.retain(|_, slot| slot.session != self.id);
            store.observe_idle(&slots);
            drop(slots);
            store.expiry_changed.notify_waiters();
        }
    }
}
