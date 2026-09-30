#![allow(
    unsafe_code,
    reason = "Windows export requires handle-relative opens and same-handle rename/deletion"
)]
use super::{cleanup_failed, failed};
use crate::{
    domain::{Error, ErrorCode},
    file_storage::windows as security,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION,
            FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
            FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformation, FileRenameInformation,
            NtCreateFile, NtSetInformationFile,
        },
    },
    Win32::{
        Foundation::{
            OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ,
            FILE_TRAVERSE, FILE_WRITE_DATA, GetFileInformationByHandle, GetFinalPathNameByHandleW,
            READ_CONTROL, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

pub(super) struct NativeFile {
    // Retaining every directory prevents ancestor renames and reparse mutation.
    directories: Vec<File>,
    file: Option<File>,
    name: String,
    unreported_destination: bool,
}

impl NativeFile {
    pub(super) fn create(root: &Path, name: &str) -> Result<Self, Error> {
        let directories = open_root(root).map_err(|_| failed())?;
        let directory = directories.last().ok_or_else(failed)?;
        security::inspect(directory).map_err(|_| failed())?;
        let descriptor = security::private_descriptor().map_err(|_| failed())?;
        let partial = format!(".mailctl-{}.partial", uuid::Uuid::new_v4());
        let file = open(
            Some(directory),
            OsStr::new(&partial),
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            Some(&descriptor),
        )
        .map_err(|_| failed())?;
        let mut export = Self {
            directories,
            file: Some(file),
            name: name.to_owned(),
            unreported_destination: false,
        };
        if export.validate_file().is_err() {
            export.abort()?;
            return Err(failed());
        }
        Ok(export)
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.file
            .as_mut()
            .ok_or_else(failed)?
            .write_all(bytes)
            .map_err(|_| failed())
    }

    pub(super) fn publish(&mut self) -> Result<(PathBuf, String), Error> {
        let file = self.file.as_ref().ok_or_else(failed)?;
        file.sync_all().map_err(|_| failed())?;
        let root = self.directories.last().ok_or_else(failed)?;
        security::inspect(root).map_err(|_| failed())?;
        self.validate_file().map_err(|_| failed())?;
        let root_path = final_path(root).map_err(|_| failed())?;
        for suffix in 0..1000 {
            let name = if suffix == 0 {
                &self.name
            } else {
                &format!("{}-{suffix}", self.name)
            };
            match rename(file, name) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(failed()),
            }
            self.unreported_destination = true;
            let actual = final_path(file).map_err(|_| failed())?;
            let information = self.validate_file().map_err(|_| failed())?;
            if actual != root_path.join(name) {
                return Err(failed());
            }
            file.sync_all().map_err(|_| failed())?;
            self.unreported_destination = false;
            self.file.take();
            self.directories.clear();
            return Ok((
                actual,
                format!("windows:{:08X}", information.dwVolumeSerialNumber),
            ));
        }
        Err(failed())
    }

    pub(super) fn abort(&mut self) -> Result<(), Error> {
        if let Some(file) = self.file.as_ref() {
            let cleanup_error = || {
                if self.unreported_destination {
                    Error::new(ErrorCode::ExportFinalizationFailed)
                } else {
                    cleanup_failed()
                }
            };
            if information(file)
                .map_err(|_| cleanup_error())?
                .nNumberOfLinks
                != 1
            {
                // Removing this name cannot establish cleanup of an extra alias.
                return Err(cleanup_error());
            }
            let information = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
            let mut status = IO_STATUS_BLOCK::default();
            let result = unsafe {
                NtSetInformationFile(
                    file.as_raw_handle(),
                    &mut status,
                    ptr::addr_of!(information).cast(),
                    size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                    FileDispositionInformation,
                )
            };
            if result < 0 {
                return Err(cleanup_error());
            }
            self.file.take();
            self.unreported_destination = false;
            self.directories.clear();
        }
        Ok(())
    }

    fn validate_file(&self) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        let file = self.file.as_ref().ok_or(io::ErrorKind::NotFound)?;
        let information = security::inspect(file)?;
        if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
            || information.nNumberOfLinks != 1
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(information)
    }
}

impl Drop for NativeFile {
    fn drop(&mut self) {
        if self.abort().is_err() {
            tracing::error!(target: "mailctl::diagnostic", event = "export_cleanup_failed");
        }
    }
}

fn open_root(path: &Path) -> io::Result<Vec<File>> {
    let spelling = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || path.as_os_str().encode_wide().take(4097).count() > 4096
        || spelling.contains(&0)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // Path::components normalizes interior dots; inspect the original spelling too.
    if spelling
        .split(|character| matches!(*character, b'/' | b'\\'))
        .any(|part| part == b"." || part == b"..")
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut parts = path.components();
    let drive = match parts.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        },
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    if parts.next() != Some(Component::RootDir) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let volume = format!("\\??\\{}:\\", char::from(drive));
    let first = open_directory(None, OsStr::new(&volume))?;
    let mut directories = vec![first];
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let spelling = name.as_encoded_bytes();
        if matches!(spelling.last(), Some(b' ' | b'.')) || spelling.contains(&b':') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let directory = open_directory(directories.last(), name)?;
        directories.push(directory);
    }
    Ok(directories)
}

fn open_directory(parent: Option<&File>, name: &OsStr) -> io::Result<File> {
    let directory = open(
        parent,
        name,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
        None,
    )?;
    let attributes = information(&directory)?.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(directory)
}

fn open(
    parent: Option<&File>,
    name: &OsStr,
    access: u32,
    disposition: u32,
    kind: u32,
    descriptor: Option<&security::Descriptor>,
) -> io::Result<File> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let bytes = wide
        .len()
        .checked_mul(2)
        .ok_or(io::ErrorKind::InvalidInput)?;
    let length = u16::try_from(bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(ptr::null_mut(), AsRawHandle::as_raw_handle),
        ObjectName: &name,
        // The drive prefix resolves through the DOS namespace; subsequent names
        // are single segments beneath already held filesystem handles.
        Attributes: OBJ_CASE_INSENSITIVE
            | if parent.is_some() {
                OBJ_DONT_REPARSE
            } else {
                0
            },
        SecurityDescriptor: descriptor.map_or(ptr::null(), |value| value.as_ptr().cast()),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = ptr::null_mut();
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            if kind == FILE_DIRECTORY_FILE {
                FILE_SHARE_READ
            } else {
                0
            },
            disposition,
            kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if result < 0 {
        return Err(nt_error(result));
    }
    // Ownership passes to File only after NtCreateFile returns a valid handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn rename(file: &File, name: &str) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let length = size_of::<FILE_RENAME_INFORMATION>() + wide.len() * 2;
    // usize storage aligns the variable-length native structure on both targets.
    let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut status = IO_STATUS_BLOCK::default();
    unsafe {
        (*information).FileNameLength = (wide.len() * 2) as u32;
        ptr::copy_nonoverlapping(
            wide.as_ptr(),
            buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
            wide.len(),
        );
        // NULL RootDirectory plus a basename renames within the file's current
        // parent. ReplaceIfExists stays false; no pathname is reopened.
        let result = NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            information.cast(),
            length as u32,
            FileRenameInformation,
        );
        if result < 0 {
            return Err(nt_error(result));
        }
    }
    Ok(())
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 4097];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= buffer.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if !path.is_absolute() || path.to_str().is_none() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(path)
}

fn nt_error(status: i32) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}
