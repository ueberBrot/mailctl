//! Private installation files and crash-released OS leases.
use crate::domain::{Error, ErrorCode};
use crate::file_storage::{self, redirected};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

pub(super) const MAX_BYTES: usize = 4 * 1024 * 1024;
pub(super) fn invalid() -> Error {
    Error::setup_required()
}
fn busy() -> Error {
    Error::new(ErrorCode::RateLimited)
}

pub(super) fn directory(path: &Path, create: bool) -> Result<PathBuf, Error> {
    if create {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).map_err(|_| invalid())?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !path.is_absolute() || !metadata.is_dir() || redirected(&metadata) {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    for ancestor in path.ancestors() {
        if redirected(&fs::symlink_metadata(ancestor).map_err(|_| invalid())?) {
            return Err(invalid());
        }
    }
    let canonical = fs::canonicalize(path).map_err(|_| invalid())?;
    #[cfg(unix)]
    if canonical != path {
        return Err(invalid());
    }
    Ok(canonical)
}

pub(super) fn open_lock(directory: &Path, name: &str) -> Result<File, Error> {
    file_storage::open(
        &directory.join(name),
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
    )
    .map_err(|_| invalid())
}
#[derive(Clone, Copy)]
pub(super) enum LockMode {
    Shared,
    Exclusive,
}
pub(super) fn lock(file: &File, mode: LockMode, deadline: Instant) -> Result<(), Error> {
    loop {
        let result = match mode {
            LockMode::Shared => file.try_lock_shared(),
            LockMode::Exclusive => file.try_lock(),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(busy());
                }
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Err(TryLockError::Error(_)) => return Err(invalid()),
        }
    }
}
pub(super) fn read(directory: &Path) -> Result<Option<Vec<u8>>, Error> {
    file_storage::read(&directory.join("accounts.json"), MAX_BYTES).map_err(|_| invalid())
}

pub(super) fn persist(directory: &Path, registry: &impl Serialize) -> Result<(), Error> {
    let bytes = crate::encoding::serialize_bounded(registry, MAX_BYTES).map_err(|_| invalid())?;
    file_storage::replace(&directory.join("accounts.json"), &bytes).map_err(|_| invalid())
}

pub(super) fn initialization_marker(file: &mut File) -> Result<Vec<u8>, Error> {
    let mut marker = Vec::new();
    file.take(37)
        .read_to_end(&mut marker)
        .map_err(|_| invalid())?;
    if marker.len() > 36 {
        return Err(invalid());
    }
    Ok(marker)
}
pub(super) fn mark_initialized(file: &mut File, installation: &str) -> Result<(), Error> {
    file.rewind().map_err(|_| invalid())?;
    file.write_all(installation.as_bytes())
        .map_err(|_| invalid())?;
    file.sync_all().map_err(|_| invalid())
}
