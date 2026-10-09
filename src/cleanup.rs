//! Expiry tasks follow each Tokio executor without retaining their resource store.
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{runtime, task::AbortHandle};

#[derive(Default)]
pub(crate) struct CleanupTasks(Mutex<HashMap<runtime::Id, Task>>);
struct Task {
    handle: AbortHandle,
    owner: Arc<CleanupOwner>,
}
pub(crate) struct CleanupOwner(AtomicBool);
impl CleanupOwner {
    pub(crate) fn is_alive(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(crate) fn stop(&self) {
        self.0.store(false, Ordering::Release);
    }
}
struct OwnerGuard(Arc<CleanupOwner>);
impl Drop for OwnerGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}
impl CleanupTasks {
    pub(crate) fn start<F>(&self, task: impl FnOnce(Arc<CleanupOwner>) -> F) -> Arc<CleanupOwner>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let runtime = runtime::Handle::current();
        let mut tasks = self.0.lock().unwrap();
        tasks.retain(|_, task| !task.handle.is_finished() && task.owner.is_alive());
        tasks
            .entry(runtime.id())
            .or_insert_with(|| {
                let owner = Arc::new(CleanupOwner(AtomicBool::new(true)));
                let guard = OwnerGuard(owner.clone());
                let future = task(owner.clone());
                let handle = runtime
                    .spawn(async move {
                        let _guard = guard;
                        future.await;
                    })
                    .abort_handle();
                Task { handle, owner }
            })
            .owner
            .clone()
    }
}
