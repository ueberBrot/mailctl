//! Process-local admission keeps account waits out of active request capacity.
use crate::{
    config::Limits,
    domain::{Error, ErrorCode},
};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Requests {
    state: Mutex<State>,
    changed: Notify,
}
#[derive(Default)]
struct State {
    reserved: usize,
    active: usize,
    accounts: HashMap<String, usize>,
    queue: Vec<Waiting>,
    next: u64,
}
struct Waiting {
    ticket: u64,
    account: String,
    active_limit: usize,
    account_limit: usize,
}
impl State {
    fn next_eligible(&self) -> Option<u64> {
        let mut accounts = HashSet::new();
        self.queue
            .iter()
            .find(|entry| {
                accounts.insert(&entry.account)
                    && self.active < entry.active_limit
                    && self.accounts.get(&entry.account).copied().unwrap_or(0) < entry.account_limit
            })
            .map(|entry| entry.ticket)
    }
    fn rotate(&mut self, account: &str) {
        self.queue.sort_by_key(|entry| entry.account == account);
    }
}
pub(super) struct Reservation<'a>(&'a Requests);
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().reserved -= 1;
    }
}
pub(super) struct Admission<'a> {
    requests: &'a Requests,
    account: &'a str,
    ticket: Option<u64>,
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        let mut state = self.requests.state.lock().unwrap();
        if let Some(ticket) = self.ticket {
            state.queue.retain(|entry| entry.ticket != ticket);
        } else {
            state.active -= 1;
            let count = state.accounts.get_mut(self.account).unwrap();
            *count -= 1;
            if *count == 0 {
                state.accounts.remove(self.account);
            }
            state.rotate(self.account);
        }
        drop(state);
        self.requests.changed.notify_waiters();
    }
}
impl Requests {
    pub fn reserve(&self, limits: &Limits) -> Result<Reservation<'_>, Error> {
        let mut state = self.state.lock().unwrap();
        if state.reserved >= limits.active_requests + limits.queued_requests {
            return Err(Error::new(ErrorCode::RateLimited));
        }
        state.reserved += 1;
        Ok(Reservation(self))
    }

    pub async fn admit<'a>(
        &'a self,
        account: &'a str,
        limits: &Limits,
    ) -> Result<Admission<'a>, Error> {
        let ticket = {
            let mut state = self.state.lock().unwrap();
            let account_active = state.accounts.get(account).copied().unwrap_or(0);
            let waiting = state
                .queue
                .iter()
                .filter(|entry| entry.account == account)
                .count();
            let account_limit = if account.is_empty() {
                limits.active_requests
            } else {
                limits.account_connections
            };
            let must_wait = state.active >= limits.active_requests
                || account_active >= account_limit
                || waiting > 0
                || state.next_eligible().is_some();
            if must_wait
                && (waiting >= limits.account_pending_requests
                    || state.queue.len() >= limits.queued_requests)
            {
                return Err(Error::new(ErrorCode::RateLimited));
            }
            let ticket = state.next;
            state.next = state.next.wrapping_add(1);
            state.queue.push(Waiting {
                ticket,
                account: account.into(),
                active_limit: limits.active_requests,
                account_limit,
            });
            ticket
        };
        let mut admission = Admission {
            requests: self,
            account,
            ticket: Some(ticket),
        };
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                if state.next_eligible() == Some(ticket) {
                    state.queue.retain(|entry| entry.ticket != ticket);
                    state.active += 1;
                    *state.accounts.entry(account.into()).or_default() += 1;
                    // Keep FIFO within each account and move its remaining work
                    // behind other accounts after every admission.
                    state.rotate(account);
                    admission.ticket = None;
                    drop(state);
                    self.changed.notify_waiters();
                    return Ok(admission);
                }
            }
            changed.await;
        }
    }
}
