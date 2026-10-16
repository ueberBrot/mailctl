use super::{cleanup_failed, failed};
use crate::domain::{Error, ErrorCode};
use rustix::fs::{self, AtFlags, CloneFlags, Mode, OFlags};
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

pub(super) struct NativeFile {
    root: File,
    root_path: PathBuf,
    file: File,
    partial: Option<String>,
    name: String,
    unreported_destination: bool,
}
impl NativeFile {
    pub(super) fn create(root: &Path, name: &str) -> Result<Self, Error> {
        let directory = open_root(root)?;
        let partial = format!(".mailctl-{}.partial", uuid::Uuid::new_v4());
        let file = fs::openat(
            &directory,
            &partial,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| failed())?;
        Ok(Self {
            root: directory,
            root_path: root.to_owned(),
            file,
            partial: Some(partial),
            name: name.into(),
            unreported_destination: false,
        })
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.file.write_all(bytes).map_err(|_| failed())
    }
    pub(super) fn publish(&mut self) -> Result<(PathBuf, String), Error> {
        self.publish_with(|file, root, name| {
            fs::fclonefileat(file, root, name, CloneFlags::NOOWNERCOPY)
        })
    }
    fn publish_with(
        &mut self,
        mut clone_file: impl FnMut(&File, &File, &str) -> Result<(), rustix::io::Errno>,
    ) -> Result<(PathBuf, String), Error> {
        self.file.sync_all().map_err(|_| failed())?;
        // A later rename must not redefine the approved destination path.
        let directory = PathBuf::from(OsString::from_vec(
            fs::getpath(&self.root).map_err(|_| failed())?.into_bytes(),
        ));
        let current = open_root(&self.root_path)?;
        let held = fs::fstat(&self.root).map_err(|_| failed())?;
        let now = fs::fstat(&current).map_err(|_| failed())?;
        if held.st_dev != now.st_dev || held.st_ino != now.st_ino {
            return Err(failed());
        }
        let partial = self.partial.as_ref().ok_or_else(failed)?;
        let file = fs::fstat(&self.file).map_err(|_| failed())?;
        let named =
            fs::statat(&self.root, partial, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| failed())?;
        if file.st_dev != named.st_dev || file.st_ino != named.st_ino || file.st_nlink != 1 {
            return Err(failed());
        }
        for suffix in 0..1000 {
            let name = if suffix == 0 {
                &self.name
            } else {
                &format!("{}-{suffix}", self.name)
            };
            match clone_file(&self.file, &self.root, name) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => continue,
                Err(_) => return Err(failed()),
            }
            self.unreported_destination = true;
            let output = fs::openat(
                &self.root,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|_| failed())?;
            let metadata = fs::fstat(&output).map_err(|_| failed())?;
            if metadata.st_mode & 0o777 != 0o600
                || metadata.st_uid != held.st_uid
                || metadata.st_nlink != 1
                || metadata.st_size != file.st_size
            {
                return Err(failed());
            }
            output.sync_all().map_err(|_| failed())?;
            let actual = PathBuf::from(OsString::from_vec(
                fs::getpath(&output).map_err(|_| failed())?.into_bytes(),
            ));
            if actual != directory.join(name) {
                return Err(failed());
            }
            self.remove_partial()?;
            self.root.sync_all().map_err(|_| failed())?;
            self.unreported_destination = false;
            return Ok((actual, format!("macos:{}", held.st_dev)));
        }
        Err(failed())
    }

    pub fn abort(&mut self) -> Result<(), Error> {
        let cleanup = self.remove_partial();
        if self.unreported_destination {
            return Err(Error::new(ErrorCode::ExportFinalizationFailed));
        }
        cleanup
    }

    fn remove_partial(&mut self) -> Result<(), Error> {
        if let Some(name) = &self.partial {
            match fs::statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(named) => {
                    let held = fs::fstat(&self.file).map_err(|_| cleanup_failed())?;
                    if named.st_dev != held.st_dev || named.st_ino != held.st_ino {
                        return Err(cleanup_failed());
                    }
                }
                Err(rustix::io::Errno::NOENT) => {
                    self.partial = None;
                    return Ok(());
                }
                Err(_) => return Err(cleanup_failed()),
            }
            match fs::unlinkat(&self.root, name, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => self.partial = None,
                Err(_) => return Err(cleanup_failed()),
            }
        }
        Ok(())
    }
}
impl Drop for NativeFile {
    fn drop(&mut self) {
        if self.abort().is_err() {
            tracing::error!(target: "mailctl::diagnostic", event = "export_cleanup_failed");
        }
    }
}

fn open_root(path: &Path) -> Result<File, Error> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
        return Err(failed());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(fs::open("/", flags, Mode::empty()).map_err(|_| failed())?);
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = fs::openat(&directory, name, flags, Mode::empty())
                    .map(File::from)
                    .map_err(|_| failed())?;
            }
            _ => return Err(failed()),
        }
    }
    let metadata = fs::fstat(&directory).map_err(|_| failed())?;
    if metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_mode & 0o077 != 0 {
        return Err(failed());
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs as std_fs, os::unix::fs::PermissionsExt};

    #[test]
    fn a_root_renamed_during_publication_never_returns_a_successful_receipt() {
        let parent = std::env::temp_dir().join(format!("mailctl-export-{}", uuid::Uuid::new_v4()));
        std_fs::create_dir(&parent).unwrap();
        // Resolve macOS's temporary-directory aliases before opening without symlinks.
        let parent = parent.canonicalize().unwrap();
        let root = parent.join("approved");
        let moved = parent.join("moved");
        std_fs::create_dir(&root).unwrap();
        std_fs::set_permissions(&root, std_fs::Permissions::from_mode(0o700)).unwrap();
        let mut file = NativeFile::create(&root, "a").unwrap();
        file.write_bytes(b"abc").unwrap();
        let result = file.publish_with(|file, directory, name| {
            std_fs::rename(&root, &moved).unwrap();
            fs::fclonefileat(file, directory, name, CloneFlags::NOOWNERCOPY)
        });
        assert!(
            result.is_err(),
            "export escaped the approved root: {result:?}"
        );
        assert_eq!(
            file.abort().unwrap_err().code,
            ErrorCode::ExportFinalizationFailed
        );
        assert_eq!(std_fs::read(moved.join("a")).unwrap(), b"abc");
        assert_eq!(std_fs::read_dir(&moved).unwrap().count(), 1);
        drop(file);
        std_fs::remove_dir_all(parent).unwrap();
    }
}
