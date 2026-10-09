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
    slots: Mutex<Slots>,
    expiry_changed: Arc<Notify>,
    expiry_tasks: CleanupTasks,
    has_idle: AtomicBool,
}
#[derive(Default)]
struct Slots {
    entries: HashMap<Uuid, Slot>,
    idle: usize,
    // Checkout can leave an earlier deadline here; expiry refreshes the bound.
    next_expiry: Option<Instant>,
    #[cfg(test)]
    expiry_inspections: usize,
}
impl Drop for Store {
    fn drop(&mut self) {
        self.expiry_changed.notify_waiters();
    }
}
impl Slots {
    fn expire_due(&mut self, now: Instant) {
        if self.next_expiry.is_none_or(|expiry| expiry > now) {
            return;
        }
        let mut idle = 0;
        let mut next_expiry = None;
        // Active reads keep quota until completion/cancellation, even past expiry.
        self.entries.retain(|_, slot| {
            #[cfg(test)]
            {
                self.expiry_inspections += 1;
            }
            if slot.entry.is_none() {
                return true;
            }
            if slot.expires <= now {
                return false;
            }
            idle += 1;
            next_expiry =
                Some(next_expiry.map_or(slot.expires, |next: Instant| next.min(slot.expires)));
            true
        });
        self.idle = idle;
        self.next_expiry = next_expiry;
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
                slots.expire_due(Instant::now());
                if slots.idle == 0 {
                    // A later retain must wake cleanup if it went back to waiting.
                    slots.next_expiry = None;
                }
                store.observe_idle(&slots);
                slots.next_expiry
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
    fn observe_idle(&self, slots: &Slots) {
        self.has_idle.store(slots.idle > 0, Ordering::Release);
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
            self.store.slots.lock().unwrap().entries.remove(&self.id);
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
        let slot = store.entries.get_mut(&self.id).ok_or_else(expired)?;
        if slot.expires <= Instant::now() {
            return Err(expired());
        }
        slot.entry = Some(entry);
        let expires = slot.expires;
        let changed = store.next_expiry.is_none_or(|previous| expires < previous);
        store.next_expiry = Some(
            store
                .next_expiry
                .map_or(expires, |previous| previous.min(expires)),
        );
        store.idle += 1;
        self.store.observe_idle(&store);
        self.retained = true;
        drop(store);
        self.store.start_expiry();
        if changed {
            self.store.expiry_changed.notify_waiters();
        }
        Ok(())
    }
}
impl Transfers {
    fn live(&self) -> MutexGuard<'_, Slots> {
        let mut store = self.0.slots.lock().unwrap();
        store.expire_due(Instant::now());
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
            .entries
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
        store.entries.insert(
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
        let slot = store.entries.get_mut(&id).ok_or_else(expired)?;
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
        store.idle -= 1;
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
    pub(in crate::service) fn session(&self) -> TransferSession {
        TransferSession {
            id: Uuid::new_v4(),
            store: Arc::downgrade(&self.0),
        }
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
            let mut idle = 0;
            let mut next_expiry = None;
            slots.entries.retain(|_, slot| {
                if slot.session == self.id {
                    return false;
                }
                if slot.entry.is_some() {
                    idle += 1;
                    next_expiry = Some(
                        next_expiry.map_or(slot.expires, |next: Instant| next.min(slot.expires)),
                    );
                }
                true
            });
            slots.idle = idle;
            slots.next_expiry = next_expiry;
            store.observe_idle(&slots);
            drop(slots);
            store.expiry_changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AttachmentReader, Entry, Error, Limits, MessageReference, Transfers};
    use std::{future::Future, pin::Pin};
    use tokio::time::Instant;
    use uuid::Uuid;

    struct Unread;
    impl AttachmentReader for Unread {
        fn next<'a>(
            &'a mut self,
            _: &'a Limits,
        ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AttachmentData, Error>> + Send + 'a>>
        {
            panic!("bookkeeping probe must not read a payload")
        }
    }

    fn entry(account: &str) -> Entry {
        Entry {
            resource: MessageReference {
                account: account.into(),
                generation: 1,
                mailbox: "INBOX".into(),
                uid_validity: 1,
                uid: 1,
            },
            reference: "synthetic-attachment".into(),
            scope: "synthetic-scope".into(),
            offset: 0,
            reader: Box::new(Unread),
        }
    }

    #[test]
    fn continued_transfers_do_not_revisit_unexpired_other_accounts() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _context = runtime.enter();
        let transfers = Transfers::default();
        let limits = Limits {
            accounts: 256,
            transfers_per_account: 4,
            transfer_seconds: 600,
            ..Limits::default()
        };
        let session = Uuid::new_v4();
        let started = Instant::now();
        let mut first = None;
        for index in 0..1024 {
            let account = format!("synthetic-account-{}", index / 4);
            let reservation = transfers
                .reserve(session, &account, &limits, started)
                .unwrap();
            first.get_or_insert(reservation.id());
            reservation.retain(entry(&account)).unwrap();
        }
        transfers.0.slots.lock().unwrap().expiry_inspections = 0;
        for _ in 0..100 {
            let (reservation, entry) = transfers
                .checkout(session, first.unwrap(), "synthetic-scope", 0, |_| Ok(()))
                .unwrap();
            reservation.retain(entry).unwrap();
        }
        let inspections = transfers.0.slots.lock().unwrap().expiry_inspections;
        println!("100 continuations with 1,024 live slots: {inspections} expiry inspections");
        assert_eq!(
            inspections, 0,
            "future transfer deadlines must not cause an inventory scan for each chunk"
        );
    }

    #[test]
    #[ignore = "native performance probe; run explicitly on a quiet host"]
    fn continuation_bookkeeping_with_many_accounts() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _context = runtime.enter();
        let limits = Limits {
            accounts: 256,
            transfers_per_account: 4,
            transfer_seconds: 600,
            ..Limits::default()
        };
        limits.validate().unwrap();
        for count in [1, 1024, 1, 1024] {
            let transfers = Transfers::default();
            let session = Uuid::new_v4();
            let started = Instant::now();
            let mut first = None;
            for index in 0..count {
                let account = format!("synthetic-account-{}", index / 4);
                let reservation = transfers
                    .reserve(session, &account, &limits, started)
                    .unwrap();
                first.get_or_insert(reservation.id());
                reservation.retain(entry(&account)).unwrap();
            }
            let id = first.unwrap();
            let start = std::time::Instant::now();
            for _ in 0..20_000 {
                let (reservation, entry) = transfers
                    .checkout(session, id, "synthetic-scope", 0, |_| Ok(()))
                    .unwrap();
                reservation.retain(entry).unwrap();
            }
            println!(
                "{{\"slots\":{count},\"continuations\":20000,\"elapsed_ns\":{}}}",
                start.elapsed().as_nanos()
            );
        }
    }
}
