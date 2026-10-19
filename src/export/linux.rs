use super::{cleanup_failed, failed};
use crate::domain::{Error, ErrorCode};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::{
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
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
        self.publish_with(link_file)
    }

    fn publish_with(
        &mut self,
        mut link_file: impl FnMut(&File, &File, &str) -> Result<(), rustix::io::Errno>,
    ) -> Result<(PathBuf, String), Error> {
        self.file.sync_all().map_err(|_| failed())?;
        let root = self.check_root()?;
        let partial = self.partial.as_ref().ok_or_else(failed)?;
        let file = fs::fstat(&self.file).map_err(|_| failed())?;
        let named =
            fs::statat(&self.root, partial, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| failed())?;
        if !same_file(&file, &named)
            || !FileType::from_raw_mode(file.st_mode).is_file()
            || file.st_uid != root.st_uid
            || file.st_nlink != 1
        {
            return Err(failed());
        }
        for suffix in 0..1000 {
            let name = if suffix == 0 {
                self.name.clone()
            } else {
                format!("{}-{suffix}", self.name)
            };
            match link_file(&self.file, &self.root, &name) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => continue,
                Err(_) => return Err(failed()),
            }
            self.unreported_destination = true;
            let output = fs::openat(
                &self.root,
                &name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|_| failed())?;
            let metadata = fs::fstat(&output).map_err(|_| failed())?;
            if !same_file(&file, &metadata)
                || !FileType::from_raw_mode(metadata.st_mode).is_file()
                || metadata.st_mode & 0o7777 != 0o600
                || metadata.st_uid != root.st_uid
                || metadata.st_nlink != 2
                || metadata.st_size != file.st_size
            {
                return Err(failed());
            }
            let actual = descriptor_path(&output)?;
            if actual != self.root_path.join(&name) {
                return Err(failed());
            }
            self.check_root()?;
            self.remove_partial()?;
            output.sync_all().map_err(|_| failed())?;
            self.root.sync_all().map_err(|_| failed())?;
            self.check_root()?;
            let metadata = fs::fstat(&output).map_err(|_| failed())?;
            let named =
                fs::statat(&self.root, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| failed())?;
            if !same_file(&file, &metadata)
                || !same_file(&file, &named)
                || metadata.st_mode & 0o7777 != 0o600
                || metadata.st_uid != root.st_uid
                || metadata.st_nlink != 1
                || metadata.st_size != file.st_size
                || descriptor_path(&output)? != actual
            {
                return Err(failed());
            }
            self.unreported_destination = false;
            return Ok((actual, format!("linux:{}", root.st_dev)));
        }
        Err(failed())
    }

    pub(super) fn abort(&mut self) -> Result<(), Error> {
        let cleanup = self.remove_partial();
        if self.unreported_destination {
            return Err(Error::new(ErrorCode::ExportFinalizationFailed));
        }
        cleanup
    }

    fn check_root(&self) -> Result<fs::Stat, Error> {
        let current = open_root(&self.root_path)?;
        let held = fs::fstat(&self.root).map_err(|_| failed())?;
        let now = fs::fstat(&current).map_err(|_| failed())?;
        if !same_file(&held, &now) || descriptor_path(&self.root)? != self.root_path {
            return Err(failed());
        }
        Ok(held)
    }

    fn remove_partial(&mut self) -> Result<(), Error> {
        if let Some(name) = &self.partial {
            match fs::statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(named) => {
                    let held = fs::fstat(&self.file).map_err(|_| cleanup_failed())?;
                    if !same_file(&named, &held) {
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

fn link_file(file: &File, root: &File, name: &str) -> Result<(), rustix::io::Errno> {
    fs::linkat(
        fs::CWD,
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        root,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )
}

fn descriptor_path(file: &File) -> Result<PathBuf, Error> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| failed())
}

fn same_file(left: &fs::Stat, right: &fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
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

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("mailctl-export-{}", uuid::Uuid::new_v4()));
            std_fs::create_dir(&path).unwrap();
            std_fs::set_permissions(&path, std_fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            let root = self.0.join("approved");
            std_fs::create_dir(&root).unwrap();
            std_fs::set_permissions(&root, std_fs::Permissions::from_mode(0o700)).unwrap();
            root
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            std_fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn a_root_renamed_during_publication_never_returns_a_successful_receipt() {
        let directory = Directory::new();
        let root = directory.root();
        let moved = directory.0.join("moved");
        let mut file = NativeFile::create(&root, "a").unwrap();
        file.write_bytes(b"abc").unwrap();
        assert!(
            file.publish_with(|file, held, name| {
                std_fs::rename(&root, &moved).unwrap();
                link_file(file, held, name)
            })
            .is_err()
        );
        assert_eq!(
            file.abort().unwrap_err().code,
            ErrorCode::ExportFinalizationFailed
        );
        assert_eq!(std_fs::read(moved.join("a")).unwrap(), b"abc");
        assert_eq!(std_fs::read_dir(&moved).unwrap().count(), 1);
    }

    #[test]
    fn publication_uses_the_held_file_if_the_partial_name_is_replaced() {
        let directory = Directory::new();
        let root = directory.root();
        let mut file = NativeFile::create(&root, "a").unwrap();
        file.write_bytes(b"abc").unwrap();
        let partial = root.join(file.partial.as_ref().unwrap());
        let moved = directory.0.join("original");
        assert!(
            file.publish_with(|file, held, name| {
                std_fs::rename(&partial, &moved).unwrap();
                std_fs::write(&partial, b"foreign").unwrap();
                link_file(file, held, name)
            })
            .is_err()
        );
        assert_eq!(
            file.abort().unwrap_err().code,
            ErrorCode::ExportFinalizationFailed
        );
        assert_eq!(std_fs::read(root.join("a")).unwrap(), b"abc");
        assert_eq!(std_fs::read(&partial).unwrap(), b"foreign");
        std_fs::remove_file(&partial).unwrap();
    }

    #[test]
    fn a_different_inode_at_the_published_name_never_receives_a_receipt() {
        let directory = Directory::new();
        let root = directory.root();
        let moved = directory.0.join("published");
        let mut file = NativeFile::create(&root, "a").unwrap();
        file.write_bytes(b"abc").unwrap();
        assert!(
            file.publish_with(|file, held, name| {
                link_file(file, held, name)?;
                std_fs::rename(root.join(name), &moved).unwrap();
                std_fs::write(root.join(name), b"foreign").unwrap();
                Ok(())
            })
            .is_err()
        );
        assert_eq!(
            file.abort().unwrap_err().code,
            ErrorCode::ExportFinalizationFailed
        );
        assert_eq!(std_fs::read(&moved).unwrap(), b"abc");
        assert_eq!(std_fs::read(root.join("a")).unwrap(), b"foreign");
        assert_eq!(std_fs::read_dir(&root).unwrap().count(), 1);
    }
}
