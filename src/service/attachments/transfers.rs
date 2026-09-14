//! Transfer reservations own quota, checkout, expiry, and session cleanup.
use super::{AttachmentReader, Error, ErrorCode, Limits, MessageReference, expired};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Default)]
pub(in crate::service) struct Transfers(Arc<Mutex<HashMap<Uuid, Slot>>>);
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
    store: Arc<Mutex<HashMap<Uuid, Slot>>>,
    id: Uuid,
    expires: Instant,
    retained: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.retained {
            self.store.lock().unwrap().remove(&self.id);
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
        let mut store = self.store.lock().unwrap();
        let slot = store.get_mut(&self.id).ok_or_else(expired)?;
        if slot.expires <= Instant::now() {
            return Err(expired());
        }
        slot.entry = Some(entry);
        self.retained = true;
        Ok(())
    }
}
impl Transfers {
    fn live(&self) -> MutexGuard<'_, HashMap<Uuid, Slot>> {
        let mut store = self.0.lock().unwrap();
        let now = Instant::now();
        store.retain(|_, slot| slot.entry.is_none() || slot.expires > now);
        store
    }
    pub(super) fn reserve(
        &self,
        session: Uuid,
        account: &str,
        limits: &Limits,
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
        let expires = Instant::now() + Duration::from_secs(limits.transfer_seconds as u64);
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
        Ok((
            Reservation {
                store: self.0.clone(),
                id,
                expires: slot.expires,
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
    store: Weak<Mutex<HashMap<Uuid, Slot>>>,
}
impl Drop for TransferSession {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            store
                .lock()
                .unwrap()
                .retain(|_, slot| slot.session != self.id);
        }
    }
}
