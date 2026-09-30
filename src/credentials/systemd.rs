use super::{Availability, ResolutionLimits, Secret, SecretSource, SourceError};
use crate::config::{Limits, systemd_credential_name};
use rustix::fs::{Mode, OFlags, fgetxattr, open, openat};
use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Component, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct SystemdSource {
    name: String,
    directory: Option<PathBuf>,
}

impl SystemdSource {
    pub(super) fn new(name: String) -> Self {
        Self {
            name,
            directory: std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
        }
    }

    fn open(&self) -> Result<File, SourceError> {
        if !systemd_credential_name(&self.name) {
            return Err(SourceError::AccessDenied);
        }
        let path = self.directory.as_ref().ok_or(SourceError::Unavailable)?;
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(SourceError::Unavailable);
        }
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = File::from(open("/", flags, Mode::empty()).map_err(failure)?);
        let uid = rustix::process::geteuid().as_raw();
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(SourceError::AccessDenied);
            };
            directory =
                File::from(openat(&directory, name, flags, Mode::empty()).map_err(failure)?);
            let metadata = directory.metadata().map_err(failure)?;
            let sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if (metadata.uid() != 0 && metadata.uid() != uid)
                || (metadata.mode() & 0o022 != 0 && !sticky)
            {
                return Err(SourceError::AccessDenied);
            }
        }
        let metadata = directory.metadata().map_err(failure)?;
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o550 {
                return Err(SourceError::AccessDenied);
            }
            // O_PATH descriptors cannot read xattrs. Open the pinned directory,
            // keeping validation independent of later path replacements.
            let readable = File::from(
                openat(
                    &directory,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(failure)?,
            );
            if !service_user_acl(&readable, uid, 5) {
                return Err(SourceError::AccessDenied);
            }
        }
        let file = File::from(
            openat(
                &directory,
                &self.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(failure)?,
        );
        let metadata = file.metadata().map_err(failure)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || !((metadata.uid() == uid && metadata.mode() & 0o777 == 0o400)
                || (metadata.uid() == 0
                    && metadata.mode() & 0o777 == 0o440
                    && service_user_acl(&file, uid, 4)))
        {
            return Err(SourceError::AccessDenied);
        }
        Ok(file)
    }
}

impl SecretSource for SystemdSource {
    fn prerequisite(&self) -> Option<&'static str> {
        Some(
            "Launch explicitly through systemd with LoadCredential= or LoadCredentialEncrypted= and User=; the manager owns provisioning and supplies private read-only files through CREDENTIALS_DIRECTORY. Restart every consuming unit after rotation; existing provider sessions require separate revocation",
        )
    }

    fn availability(&self, _: Uuid) -> Availability {
        self.open()
            .map(|_| Availability::Configured)
            .unwrap_or_else(Availability::from)
    }

    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
        self.resolve_with_limits(account, &ResolutionLimits::try_from(&Limits::default())?)
    }

    fn resolve_with_limits(
        &self,
        _: Uuid,
        limits: &ResolutionLimits,
    ) -> Result<Secret, SourceError> {
        let file = self.open()?;
        let limit = limits.secret_bytes();
        if file.metadata().map_err(failure)?.len() > limit as u64 {
            return Err(SourceError::InvalidSecret);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        if bytes.len() > limit {
            return Err(SourceError::InvalidSecret);
        }
        Secret::new(std::mem::take(&mut *bytes))
    }
}

fn service_user_acl(file: &File, uid: u32, permissions: u16) -> bool {
    // systemd grants the service UID access through a POSIX ACL. The ACL mask
    // appears as group mode bits even though the owning group has no access.
    // Accept only owner + service UID, with no other user or group grants.
    let mut acl = [0_u8; 44];
    if fgetxattr(file, "system.posix_acl_access", &mut acl).ok() != Some(acl.len())
        || acl[..4] != 2_u32.to_le_bytes()
    {
        return false;
    }
    // Linux POSIX ACL xattr entries: USER_OBJ, USER, GROUP_OBJ, MASK, OTHER.
    let entries = [
        (1_u16, permissions, u32::MAX),
        (2, permissions, uid),
        (4, 0, u32::MAX),
        (16, permissions, u32::MAX),
        (32, 0, u32::MAX),
    ];
    acl[4..]
        .as_chunks::<8>()
        .0
        .iter()
        .zip(entries)
        .all(|(entry, (tag, permissions, id))| {
            entry[..2] == tag.to_le_bytes()
                && entry[2..4] == permissions.to_le_bytes()
                && entry[4..] == id.to_le_bytes()
        })
}

fn failure(error: impl Into<io::Error>) -> SourceError {
    let error = error.into();
    match error.kind() {
        io::ErrorKind::NotFound => SourceError::Missing,
        io::ErrorKind::PermissionDenied => SourceError::AccessDenied,
        _ if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
            SourceError::AccessDenied
        }
        _ => SourceError::Unavailable,
    }
}
