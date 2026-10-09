//! Process-local admission keeps account waits out of active request capacity.
use crate::{
    config::Limits,
    domain::{Error, ErrorCode},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Requests {
    state: Mutex<State>,
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
    changed: Arc<Notify>,
}
impl State {
    fn next_eligible(&self) -> Option<&Waiting> {
        let mut accounts = HashSet::new();
        self.queue.iter().find(|entry| {
            accounts.insert(&entry.account)
                && self.active < entry.active_limit
                && self.accounts.get(&entry.account).copied().unwrap_or(0) < entry.account_limit
        })
    }
    fn rotate(&mut self, account: &str) {
        self.queue.sort_by_key(|entry| entry.account == account);
    }
    fn next_notification(&self) -> Option<Arc<Notify>> {
        self.next_eligible().map(|entry| entry.changed.clone())
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
        let changed = state.next_notification();
        drop(state);
        if let Some(changed) = changed {
            changed.notify_one();
        }
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
        let (ticket, notification) = {
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
            if !must_wait {
                state.active += 1;
                *state.accounts.entry(account.into()).or_default() += 1;
                return Ok(Admission {
                    requests: self,
                    account,
                    ticket: None,
                });
            }
            if waiting >= limits.account_pending_requests
                || state.queue.len() >= limits.queued_requests
            {
                return Err(Error::new(ErrorCode::RateLimited));
            }
            let ticket = state.next;
            state.next = state.next.wrapping_add(1);
            let changed = Arc::new(Notify::new());
            state.queue.push(Waiting {
                ticket,
                account: account.into(),
                active_limit: limits.active_requests,
                account_limit,
                changed: changed.clone(),
            });
            (ticket, changed)
        };
        let mut admission = Admission {
            requests: self,
            account,
            ticket: Some(ticket),
        };
        loop {
            let changed = notification.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                if state
                    .next_eligible()
                    .is_some_and(|entry| entry.ticket == ticket)
                {
                    state.queue.retain(|entry| entry.ticket != ticket);
                    state.active += 1;
                    *state.accounts.entry(account.into()).or_default() += 1;
                    // Keep FIFO within each account and move its remaining work
                    // behind other accounts after every admission.
                    state.rotate(account);
                    admission.ticket = None;
                    let next = state.next_notification();
                    drop(state);
                    if let Some(next) = next {
                        next.notify_one();
                    }
                    return Ok(admission);
                }
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Requests;
    use crate::config::Limits;
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn uncontended_admission_does_not_allocate_queue_bookkeeping() {
        let requests = Requests::default();
        let limits = Limits::default();
        let mut context = Context::from_waker(Waker::noop());
        let mut admit = || {
            let mut request = std::pin::pin!(requests.admit("synthetic-account", &limits));
            let Poll::Ready(Ok(admission)) = request.as_mut().poll(&mut context) else {
                panic!("uncontended admission must complete without waiting");
            };
            drop(admission);
        };
        // Warm retained map storage before measuring per-request bookkeeping.
        admit();
        let allocations = allocation_counter::measure(|| {
            for _ in 0..1_000 {
                admit();
            }
        });
        assert!(
            allocations.count_total <= 1_000,
            "uncontended admission allocated {} times for 1,000 requests",
            allocations.count_total
        );
    }

    #[test]
    fn releasing_capacity_wakes_only_the_next_eligible_request() {
        let requests = Requests::default();
        let limits = Limits {
            active_requests: 1,
            account_connections: 1,
            account_pending_requests: 64,
            queued_requests: 64,
            ..Limits::default()
        };
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut active = std::pin::pin!(requests.admit("synthetic-account", &limits));
        let Poll::Ready(Ok(active)) = active.as_mut().poll(&mut context) else {
            panic!("first request must be admitted");
        };
        let mut queued = (0..64)
            .map(|_| Box::pin(requests.admit("synthetic-account", &limits)))
            .collect::<Vec<_>>();
        for request in &mut queued {
            assert!(request.as_mut().poll(&mut context).is_pending());
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(active);
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "only one queued request can use the released capacity"
        );
    }

    #[test]
    fn cancelling_a_blocked_account_head_wakes_newly_eligible_work() {
        let requests = Requests::default();
        let broad = Limits {
            active_requests: 3,
            account_connections: 2,
            ..Limits::default()
        };
        let narrow = Limits {
            account_connections: 1,
            ..broad
        };
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut active = std::pin::pin!(requests.admit("synthetic-account", &broad));
        let Poll::Ready(Ok(_active)) = active.as_mut().poll(&mut context) else {
            panic!("first request must be admitted");
        };
        let mut blocked = Box::pin(requests.admit("synthetic-account", &narrow));
        let mut eligible = Box::pin(requests.admit("synthetic-account", &broad));
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        assert!(eligible.as_mut().poll(&mut context).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(blocked);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            eligible.as_mut().poll(&mut context),
            Poll::Ready(Ok(_))
        ));
    }
}
