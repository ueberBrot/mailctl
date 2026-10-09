//! Journal initialization shares installation maintenance; writers hold short OS leases.
use super::*;
use crate::draft_journal::{DraftJournal, DraftJournalError};
use std::{fs::OpenOptions, io::Write};

const JOURNAL: &str = "drafts.sqlite";
const MARKER: &str = "drafts.initialized";

pub(super) fn enabled(config: &Config) -> bool {
    config
        .grants
        .iter()
        .any(|grant| grant.profile != crate::policy::Profile::ReadOnly)
}
pub(super) fn initialize(directory: &Path) -> Result<(), Error> {
    if directory.join(MARKER).exists() {
        return Ok(());
    }
    // A persistent marker prevents missing history from becoming an empty journal.
    private_files(directory)?;
    crate::file_storage::replace(&directory.join(MARKER), b"pending").map_err(|_| unavailable())?;
    let path = directory.join(JOURNAL);
    let _file = crate::file_storage::open(
        &path,
        OpenOptions::new().read(true).write(true).create_new(true),
    )
    .map_err(|_| unavailable())?;
    let _journal = DraftJournal::open(&path).map_err(|_| unavailable())?;
    crate::file_storage::replace(&directory.join(MARKER), b"r").map_err(|_| unavailable())
}
fn unavailable() -> Error {
    Error::new(ErrorCode::JournalUnavailable)
}
pub(super) fn private_files(directory: &Path) -> Result<(), Error> {
    for name in [
        JOURNAL,
        "drafts.sqlite-wal",
        "drafts.sqlite-shm",
        MARKER,
        "drafts.suspended",
    ] {
        // Closing an extra descriptor can release SQLite's process-scoped Unix locks,
        // including the shared-memory lock that prevents another process truncating WAL state.
        match crate::file_storage::inspect(&directory.join(name)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}
/// Recovery state has no automatic transition back to dispatch eligibility.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Recovery {
    Restoring,
    Suspended,
}
impl Recovery {
    pub(super) fn read(directory: &Path) -> Result<Option<Self>, Error> {
        let recovery = match crate::file_storage::read(&directory.join("drafts.suspended"), 32)
            .map_err(|_| unavailable())?
            .as_deref()
        {
            None => None,
            Some(b"restoring") => Some(Self::Restoring),
            Some(b"suspended") => Some(Self::Suspended),
            _ => return Err(unavailable()),
        };
        if recovery != Some(Self::Restoring)
            && crate::file_storage::read(&directory.join(MARKER), 8)
                .map_err(|_| unavailable())?
                .as_deref()
                == Some(b"!")
        {
            return Ok(Some(Self::Suspended));
        }
        Ok(recovery)
    }

    pub(super) fn persist(self, directory: &Path) -> Result<(), Error> {
        let value: &[u8] = match self {
            Self::Restoring => b"restoring",
            Self::Suspended => b"suspended",
        };
        match crate::file_storage::replace(&directory.join("drafts.suspended"), value) {
            Ok(()) => Ok(()),
            Err(_) if self == Self::Suspended && !directory.join("drafts.suspended").exists() => {
                // Existing allocated storage remains usable when new-file creation
                // fails. Never truncate or replace the initialization marker.
                let mut marker = crate::file_storage::open(
                    &directory.join(MARKER),
                    OpenOptions::new().write(true),
                )
                .map_err(|_| unavailable())?;
                if marker.metadata().map_err(|_| unavailable())?.len() != 1 {
                    return Err(unavailable());
                }
                marker
                    .write_all(b"!")
                    .and_then(|()| marker.sync_all())
                    .map_err(|_| unavailable())
            }
            Err(_) => Err(unavailable()),
        }
    }
}

/// Installation-aware journal access owns the durable response to corrupt history.
/// Callers retain their account-writer or exclusive maintenance lease throughout.
pub(in crate::service) struct DraftHistory {
    directory: PathBuf,
    journal: DraftJournal,
    _lease: Option<std::sync::Arc<Lease>>,
}
impl DraftHistory {
    pub(super) fn open(directory: &Path) -> Result<Self, Error> {
        private_files(directory)?;
        if Recovery::read(directory)? == Some(Recovery::Restoring) {
            return Err(unavailable());
        }
        if !matches!(
            crate::file_storage::read(&directory.join(MARKER), 8)
                .map_err(|_| unavailable())?
                .as_deref(),
            Some(b"r" | b"!")
        ) || !directory.join(JOURNAL).exists()
        {
            let _ = Recovery::Suspended.persist(directory);
            return Err(unavailable());
        }
        let journal =
            DraftJournal::open_existing_nowait(directory.join(JOURNAL)).map_err(|error| {
                if error == DraftJournalError::Busy {
                    return Error::new(ErrorCode::RateLimited);
                }
                if error == DraftJournalError::InvalidDatabase {
                    let _ = Recovery::Suspended.persist(directory);
                }
                unavailable()
            })?;
        Ok(Self {
            directory: directory.to_owned(),
            journal,
            _lease: None,
        })
    }
    pub(in crate::service) fn access<T>(
        &mut self,
        operation: impl FnOnce(&mut DraftJournal) -> Result<T, DraftJournalError>,
    ) -> Result<T, DraftJournalError> {
        let result = operation(&mut self.journal);
        if matches!(result, Err(DraftJournalError::InvalidDatabase)) {
            let _ = Recovery::Suspended.persist(&self.directory);
        }
        result
    }
}
impl AccountRegistry {
    pub(in crate::service) fn draft_writer_available(&self, account: &str) -> bool {
        let Some(lease) = &self.lease else {
            return false;
        };
        match crate::file_storage::inspect(&lease.directory.join(format!("draft-{account}.lock"))) {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
    }

    pub(in crate::service) fn draft_creation_allowed(&self) -> Result<(), Error> {
        let directory = &self.lease.as_ref().ok_or_else(unavailable)?.directory;
        if Recovery::read(directory)?.is_some() {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(in crate::service) fn absent_draft(&self) -> Error {
        self.draft_creation_allowed()
            .err()
            .unwrap_or_else(|| Error::new(ErrorCode::OperationNotFound))
    }

    pub(in crate::service) fn draft_journal(&self) -> Result<DraftHistory, Error> {
        let lease = self.lease.as_ref().ok_or_else(unavailable)?;
        let mut history = DraftHistory::open(&lease.directory)?;
        history._lease = Some(lease.clone());
        Ok(history)
    }
    pub(in crate::service) async fn wait_for_draft_journal(
        &self,
        seconds: usize,
    ) -> Result<DraftHistory, Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds as u64);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::new(ErrorCode::RateLimited));
            }
            match self.draft_journal() {
                Err(error) if error.code == ErrorCode::RateLimited => {
                    tokio::time::sleep_until(
                        (tokio::time::Instant::now() + Duration::from_millis(10)).min(deadline),
                    )
                    .await;
                }
                result => return result,
            }
        }
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
                    tokio::time::sleep_until(
                        (tokio::time::Instant::now() + Duration::from_millis(10)).min(deadline),
                    )
                    .await;
                }
                Err(_) => return Err(unavailable()),
            }
        }
    }
}
