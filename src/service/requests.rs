//! Process-local admission keeps account waits out of active request capacity.
use crate::{
    config::Limits,
    domain::{Error, ErrorCode},
};
use std::{
    collections::HashMap,
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
    account_head: bool,
    active_limit: usize,
    account_limit: usize,
    changed: Arc<Notify>,
}
impl State {
    fn next_eligible(&self) -> Option<&Waiting> {
        self.queue.iter().find(|entry| {
            entry.account_head
                && self.active < entry.active_limit
                && self.accounts.get(&entry.account).copied().unwrap_or(0) < entry.account_limit
        })
    }
    fn remove_waiting(&mut self, ticket: u64) -> Waiting {
        let position = self
            .queue
            .iter()
            .position(|entry| entry.ticket == ticket)
            .expect("live request ticket");
        let removed = self.queue.remove(position);
        if removed.account_head
            && let Some(next) = self
                .queue
                .iter_mut()
                .find(|entry| entry.account == removed.account)
        {
            next.account_head = true;
        }
        removed
    }
    fn rotate(&mut self, account: &str) {
        let Some(first) = self.queue.iter().position(|entry| entry.account == account) else {
            return;
        };
        let group = self.queue[first..]
            .iter()
            .take_while(|entry| entry.account == account)
            .count();
        if self.queue[first + group..]
            .iter()
            .all(|entry| entry.account != account)
        {
            // After the first round, pending work is usually already grouped.
            self.queue[first..].rotate_left(group);
            return;
        }
        fn partition(queue: &mut [Waiting], account: &str) -> usize {
            if queue.len() <= 1 {
                return usize::from(queue.first().is_some_and(|entry| entry.account != account));
            }
            let middle = queue.len() / 2;
            let (left, right) = queue.split_at_mut(middle);
            let left_others = partition(left, account);
            let right_others = partition(right, account);
            // Join each half's other-account prefix without changing either
            // account's FIFO order or allocating the stable sort's scratch.
            queue[left_others..middle + right_others].rotate_left(middle - left_others);
            left_others + right_others
        }
        partition(&mut self.queue, account);
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
            state.remove_waiting(ticket);
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
                account_head: waiting == 0,
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
                    let waiting = state.remove_waiting(ticket);
                    state.active += 1;
                    *state.accounts.entry(waiting.account).or_default() += 1;
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
    fn draining_a_contended_account_does_not_allocate_eligibility_scratch() {
        let requests = Requests::default();
        let limits = Limits {
            active_requests: 1,
            account_connections: 1,
            account_pending_requests: 64,
            queued_requests: 64,
            ..Limits::default()
        };
        let mut context = Context::from_waker(Waker::noop());
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
        let allocations = allocation_counter::measure(|| {
            drop(active);
            for request in &mut queued {
                let Poll::Ready(Ok(admission)) = request.as_mut().poll(&mut context) else {
                    panic!("the next FIFO request must use the released capacity");
                };
                drop(admission);
            }
        });
        println!(
            "draining 64 queued requests: {} allocations, {} allocated bytes",
            allocations.count_total, allocations.bytes_total
        );
        // The queue already owns each account key and eligibility metadata.
        assert_eq!(
            allocations.count_total, 0,
            "draining admitted work must reuse its account keys and queue storage"
        );
    }

    #[test]
    fn draining_a_mixed_account_queue_does_not_allocate_rotation_scratch() {
        let requests = Requests::default();
        let limits = Limits {
            active_requests: 1,
            account_connections: 1,
            account_pending_requests: 64,
            queued_requests: 256,
            ..Limits::default()
        };
        let accounts = (0..4)
            .map(|index| format!("synthetic-account-{index}"))
            .collect::<Vec<_>>();
        let mut context = Context::from_waker(Waker::noop());
        let mut active = std::pin::pin!(requests.admit(&accounts[0], &limits));
        let Poll::Ready(Ok(active)) = active.as_mut().poll(&mut context) else {
            panic!("first request must be admitted");
        };
        let mut queued = (0..256)
            .map(|index| Box::pin(requests.admit(&accounts[index % 4], &limits)))
            .collect::<Vec<_>>();
        for request in &mut queued {
            assert!(request.as_mut().poll(&mut context).is_pending());
        }
        let allocations = allocation_counter::measure(|| {
            drop(active);
            // Rotation preserves FIFO within each account and gives each other
            // account one admission before returning to the same account.
            for index in
                (0..64).flat_map(|round| [1, 2, 3, 0].map(move |account| round * 4 + account))
            {
                let Poll::Ready(Ok(admission)) = queued[index].as_mut().poll(&mut context) else {
                    panic!("account round robin must admit request {index}");
                };
                drop(admission);
            }
        });
        println!(
            "draining 256 queued requests across four accounts: {} allocations, {} allocated bytes",
            allocations.count_total, allocations.bytes_total
        );
        assert_eq!(
            allocations.count_total, 0,
            "account rotation must reuse queued account keys and queue storage"
        );
    }

    #[test]
    fn arbitrary_account_arrivals_preserve_fifo_and_round_robin() {
        use std::collections::VecDeque;
        let accounts = ["synthetic-a", "synthetic-b", "synthetic-c", "synthetic-d"];
        let limits = Limits {
            active_requests: 1,
            account_connections: 1,
            account_pending_requests: 64,
            queued_requests: 64,
            ..Limits::default()
        };
        for seed in 1..=16_u64 {
            let requests = Requests::default();
            let mut order = (0..64).map(|index| index % 4).collect::<Vec<_>>();
            let mut random = seed;
            for index in (1..order.len()).rev() {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                order.swap(index, (random % (index + 1) as u64) as usize);
            }
            let mut context = Context::from_waker(Waker::noop());
            let mut active = std::pin::pin!(requests.admit(accounts[0], &limits));
            let Poll::Ready(Ok(active)) = active.as_mut().poll(&mut context) else {
                panic!("first request must be admitted");
            };
            let mut queued = order
                .iter()
                .map(|account| Box::pin(requests.admit(accounts[*account], &limits)))
                .collect::<Vec<_>>();
            let mut per_account = std::array::from_fn::<_, 4, _>(|_| VecDeque::new());
            let mut round_robin = VecDeque::new();
            for (index, request) in queued.iter_mut().enumerate() {
                assert!(request.as_mut().poll(&mut context).is_pending());
                let account = order[index];
                per_account[account].push_back(index);
                if account != 0 && !round_robin.contains(&account) {
                    round_robin.push_back(account);
                }
            }
            // Releasing the original account gives the other waiting accounts
            // their first turn, then rotates only accounts that still have work.
            round_robin.push_back(0);
            drop(active);
            while let Some(account) = round_robin.pop_front() {
                let index = per_account[account].pop_front().unwrap();
                let Poll::Ready(Ok(admission)) = queued[index].as_mut().poll(&mut context) else {
                    panic!("seed {seed}: account {account} must admit its FIFO request {index}");
                };
                drop(admission);
                if !per_account[account].is_empty() {
                    round_robin.push_back(account);
                }
            }
            assert!(per_account.iter().all(VecDeque::is_empty));
        }
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

    #[test]
    fn cancelling_a_non_head_does_not_bypass_the_narrowed_account_head() {
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
        let mut context = Context::from_waker(Waker::noop());
        let mut active = std::pin::pin!(requests.admit("synthetic-account", &broad));
        let Poll::Ready(Ok(_active)) = active.as_mut().poll(&mut context) else {
            panic!("first request must be admitted");
        };
        let mut head = Box::pin(requests.admit("synthetic-account", &narrow));
        let mut middle = Box::pin(requests.admit("synthetic-account", &broad));
        let mut tail = Box::pin(requests.admit("synthetic-account", &broad));
        assert!(head.as_mut().poll(&mut context).is_pending());
        assert!(middle.as_mut().poll(&mut context).is_pending());
        assert!(tail.as_mut().poll(&mut context).is_pending());
        drop(middle);
        assert!(tail.as_mut().poll(&mut context).is_pending());
        drop(head);
        assert!(matches!(
            tail.as_mut().poll(&mut context),
            Poll::Ready(Ok(_))
        ));
    }
}
