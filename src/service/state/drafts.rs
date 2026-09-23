//! Journal initialization shares installation maintenance; writers hold short OS leases.
use super::*;
use crate::draft_journal::DraftJournal;
use std::fs::OpenOptions;

const JOURNAL: &str = "drafts.sqlite";
const MARKER: &str = "drafts.initialized";

fn enabled(config: &Config) -> bool {
    config
        .grants
        .iter()
        .any(|grant| grant.profile != crate::policy::Profile::ReadOnly)
}
pub(super) fn needs_initialization(config: &Config, directory: &Path) -> bool {
    enabled(config) && !directory.join(MARKER).exists()
}
pub(super) fn initialize(config: &Config, directory: &Path) {
    if !needs_initialization(config, directory) {
        return;
    }
    // A persistent marker prevents missing history from becoming an empty journal.
    let result = (|| -> Result<(), Error> {
        private_files(directory)?;
        crate::file_storage::replace(&directory.join(MARKER), b"pending")
            .map_err(|_| unavailable())?;
        let path = directory.join(JOURNAL);
        let _file = crate::file_storage::open(
            &path,
            OpenOptions::new().read(true).write(true).create(true),
        )
        .map_err(|_| unavailable())?;
        let _journal = DraftJournal::open(&path).map_err(|_| unavailable())?;
        crate::file_storage::replace(&directory.join(MARKER), b"2").map_err(|_| unavailable())
    })();
    // Draft storage degradation must leave healthy reads available.
    let _ = result;
}
fn unavailable() -> Error {
    Error::new(ErrorCode::JournalUnavailable)
}
fn private_files(directory: &Path) -> Result<(), Error> {
    for name in [JOURNAL, "drafts.sqlite-wal", "drafts.sqlite-shm", MARKER] {
        match crate::file_storage::open(&directory.join(name), OpenOptions::new().read(true)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}
impl AccountRegistry {
    pub(in crate::service) fn draft_journal(&self) -> Result<DraftJournal, Error> {
        let directory = &self.lease.as_ref().ok_or_else(unavailable)?.directory;
        private_files(directory)?;
        if crate::file_storage::read(&directory.join(MARKER), 8)
            .map_err(|_| unavailable())?
            .as_deref()
            != Some(b"2")
        {
            return Err(unavailable());
        }
        DraftJournal::open_existing_nowait(directory.join(JOURNAL)).map_err(|_| unavailable())
    }
    pub(in crate::service) async fn draft_writer(
        &self,
        account: Uuid,
        seconds: usize,
    ) -> Result<File, Error> {
        let directory = &self.lease.as_ref().ok_or_else(unavailable)?.directory;
        let file = storage::open_lock(directory, &format!("draft-{account}.lock"))
            .map_err(|_| unavailable())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds as u64);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(Error::new(ErrorCode::RateLimited));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(_) => return Err(unavailable()),
            }
        }
    }
}
