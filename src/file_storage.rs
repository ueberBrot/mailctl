//! Bounded private files and durable replacement shared by configuration and state.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub(crate) fn create_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

pub(crate) fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

pub(crate) fn open(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Inspect reparse points themselves instead of following their targets.
        options.custom_flags(0x00200000);
        for ancestor in path
            .ancestors()
            .skip(1)
            .filter(|path| !path.as_os_str().is_empty())
        {
            if redirected(&fs::symlink_metadata(ancestor)?) {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || redirected(&metadata) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(file)
}

pub(crate) fn read(path: &Path, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let file = match open(path, OpenOptions::new().read(true)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > maximum as u64 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(bytes))
}

pub(crate) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_file_name(format!(".mailctl-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = open(&temporary, OpenOptions::new().write(true).create_new(true))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
