mod support;

use mailctl::{
    config::{Config, Limits},
    domain::{Error, ErrorCode, Operation, OperationResult, SaveDraftInput},
    service::{DraftBackend, DraftPreparation, MailboxTarget, MemoryDrafts, Service},
};
use rusqlite::ffi;
use std::{
    ffi::{CStr, c_char, c_int},
    fs::OpenOptions,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    ptr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

static ORIGINAL: AtomicPtr<ffi::sqlite3_vfs> = AtomicPtr::new(ptr::null_mut());
static OBSERVATION: OnceLock<Observation> = OnceLock::new();

struct Observation {
    wal: PathBuf,
    writer: PathBuf,
    held: AtomicUsize,
    released: AtomicUsize,
    errors: AtomicUsize,
}

// This binary has one test so replacing the default VFS cannot affect concurrent
// tests. Only this disposable journal's WAL deletion is observed; all I/O still
// goes through SQLite's original VFS. Registration is scoped to this test.
#[allow(
    unsafe_code,
    reason = "observe the actual SQLite close boundary via its VFS API"
)]
mod vfs {
    use super::*;

    pub(super) struct Observer(*mut ffi::sqlite3_vfs);

    impl Observer {
        pub(super) fn install() -> Self {
            // SAFETY: SQLite owns the original VFS for the process lifetime. The
            // copied table and static name remain live for the process lifetime,
            // including detached blocking work if a test assertion unwinds.
            unsafe {
                let original = ffi::sqlite3_vfs_find(ptr::null());
                assert!(!original.is_null());
                assert!((*original).xDelete.is_some());
                ORIGINAL.store(original, Ordering::SeqCst);
                let wrapper = Box::into_raw(Box::new(ptr::read(original)));
                (*wrapper).zName = c"mailctl-draft-close-test".as_ptr();
                (*wrapper).pNext = ptr::null_mut();
                (*wrapper).xDelete = Some(observe_delete);
                assert_eq!(ffi::sqlite3_vfs_register(wrapper, 1), ffi::SQLITE_OK);
                Self(wrapper)
            }
        }
    }

    impl Drop for Observer {
        fn drop(&mut self) {
            // SAFETY: both VFS tables remain valid for the process lifetime.
            // Unregistering leaves any existing connection's table usable.
            unsafe {
                ffi::sqlite3_vfs_register(ORIGINAL.load(Ordering::SeqCst), 1);
                ffi::sqlite3_vfs_unregister(self.0);
            }
        }
    }

    unsafe extern "C" fn observe_delete(
        _: *mut ffi::sqlite3_vfs,
        name: *const c_char,
        sync: c_int,
    ) -> c_int {
        // SAFETY: SQLite supplies a valid C filename for the callback duration.
        let path = (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) });
        if let Some(observation) = OBSERVATION.get()
            && path.and_then(|path| path.to_str().ok()).map(Path::new)
                == Some(observation.wal.as_path())
        {
            // Record failures instead of panicking across the C boundary.
            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(&observation.writer)
            {
                Ok(file) => match file.try_lock() {
                    Ok(()) => {
                        observation.released.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(std::fs::TryLockError::WouldBlock) => {
                        observation.held.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        observation.errors.fetch_add(1, Ordering::SeqCst);
                    }
                },
                Err(_) => {
                    observation.errors.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let original = ORIGINAL.load(Ordering::SeqCst);
        // SAFETY: registration retains the original VFS, including xDelete;
        // forward its original context and SQLite's unchanged arguments.
        match unsafe { (*original).xDelete } {
            Some(delete) => unsafe { delete(original, name, sync) },
            None => ffi::SQLITE_IOERR_DELETE,
        }
    }
}

#[derive(Default)]
struct InterruptedDrafts {
    entered: Notify,
    panic: AtomicBool,
}

impl DraftBackend for InterruptedDrafts {
    fn prepare<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a Limits,
    ) -> DraftPreparation<'a> {
        Box::pin(async move {
            assert!(
                !self.panic.load(Ordering::SeqCst),
                "synthetic preparation panic"
            );
            self.entered.notify_one();
            std::future::pending().await
        })
    }

    fn reconcile<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a mailctl::draft::DraftVerification,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<mailctl::draft::DraftEvidence, Error>> + Send + 'a>>
    {
        Box::pin(async { Err(Error::new(ErrorCode::UnsupportedCapability)) })
    }
}

async fn save(service: &Service, input: SaveDraftInput) -> Result<OperationResult, Error> {
    let context = service.context("writer", &Default::default()).unwrap();
    service.execute(&context, Operation::SaveDraft(input)).await
}

#[tokio::test]
async fn writer_remains_held_through_sqlite_close_on_success_error_cancellation_and_panic() {
    let installation = support::Installation::two_accounts();
    let mut config =
        Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.accounts[0].from_identities = vec!["work@example.test".into()];
    Service::setup(config.clone()).unwrap();
    let backend = Arc::new(MemoryDrafts::default());
    backend.set("work", "Drafts", 77);
    let service = Service::open(config.clone())
        .unwrap()
        .with_draft_backend(backend);
    let context = service.context("writer", &Default::default()).unwrap();
    let OperationResult::Accounts(accounts) = service
        .execute(&context, Operation::ListAccounts(Default::default()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let input = SaveDraftInput {
        account_id: accounts.accounts[0].account_id.parse().unwrap(),
        account_generation: accounts.accounts[0].generation,
        operation_id: uuid::Uuid::new_v4(),
        mailbox: "Drafts".into(),
        draft: Default::default(),
    };
    let observation = OBSERVATION.get_or_init(|| Observation {
        wal: config.state_dir.join("drafts.sqlite-wal"),
        writer: config
            .state_dir
            .join(format!("draft-{}.lock", input.account_id)),
        held: AtomicUsize::new(0),
        released: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
    });
    let interrupted = Arc::new(InterruptedDrafts::default());
    let interrupted_service = Arc::new(
        Service::open(config)
            .unwrap()
            .with_draft_backend(interrupted.clone()),
    );
    let _observer = vfs::Observer::install();

    for exit in ["success", "error", "cancellation", "panic"] {
        observation.held.store(0, Ordering::SeqCst);
        observation.released.store(0, Ordering::SeqCst);
        let mut input = input.clone();
        input.operation_id = uuid::Uuid::new_v4();
        match exit {
            "success" => {
                save(&service, input).await.unwrap();
            }
            "error" => {
                input.draft.from = Some("unapproved@example.test".into());
                assert_eq!(
                    save(&service, input).await.unwrap_err().code,
                    ErrorCode::InvalidRequest
                );
            }
            _ => {
                interrupted.panic.store(exit == "panic", Ordering::SeqCst);
                let service = interrupted_service.clone();
                let task = tokio::spawn(async move { save(&service, input).await });
                if exit == "cancellation" {
                    tokio::time::timeout(Duration::from_secs(5), interrupted.entered.notified())
                        .await
                        .unwrap();
                    task.abort();
                }
                let error = tokio::time::timeout(Duration::from_secs(5), task)
                    .await
                    .unwrap()
                    .unwrap_err();
                assert_eq!(error.is_cancelled(), exit == "cancellation");
                assert_eq!(error.is_panic(), exit == "panic");
            }
        }
        assert_eq!(
            observation.errors.load(Ordering::SeqCst),
            0,
            "{exit}: lock probe failed"
        );
        assert_eq!(
            observation.released.load(Ordering::SeqCst),
            0,
            "{exit}: writer released before SQLite deleted WAL"
        );
        assert!(
            observation.held.load(Ordering::SeqCst) > 0,
            "{exit}: actual WAL deletion must be observed with the writer held"
        );
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&observation.writer)
            .unwrap()
            .try_lock()
            .expect("writer released after journal close");
    }
}
