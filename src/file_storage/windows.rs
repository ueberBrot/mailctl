//! Native private-directory creation and handle-based discretionary ACL checks.
#![allow(
    unsafe_code,
    reason = "Windows security descriptors and token ownership require Win32 FFI"
)]
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        *,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        GetFileInformationByHandle,
    },
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub(crate) struct Descriptor(*mut c_void);
impl Descriptor {
    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct CurrentUser(Vec<usize>);
impl CurrentUser {
    fn new() -> io::Result<Self> {
        unsafe {
            let mut handle = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = OwnedHandle::from_raw_handle(handle);
            let mut size = 0;
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut size,
            );
            if size == 0 || size > 65536 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
            if GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(buffer))
        }
    }
    fn sid(&self) -> PSID {
        // The aligned allocation owns the TOKEN_USER and the SID it points into.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
    fn sid_string(&self) -> io::Result<String> {
        unsafe {
            let current = self.sid();
            let mut sid_string = ptr::null_mut();
            if Authorization::ConvertSidToStringSidW(current, &mut sid_string) == 0 {
                return Err(io::Error::last_os_error());
            }
            let _sid_allocation = Descriptor(sid_string.cast());
            let mut length = 0;
            while *sid_string.add(length) != 0 {
                length += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(sid_string, length))
                .map_err(|_| io::ErrorKind::InvalidData.into())
        }
    }
}

fn trusted(sid: PSID, current: PSID) -> bool {
    unsafe {
        !sid.is_null()
            && IsValidSid(sid) != 0
            && (EqualSid(sid, current) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0)
    }
}

pub(crate) fn inspect(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    unsafe {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if GetFileInformationByHandle(file.as_raw_handle(), &mut information) == 0 {
            return Err(io::Error::last_os_error());
        }
        if information.nNumberOfLinks > 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let user = CurrentUser::new()?;
        let current = user.sid();
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let error = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let _descriptor = Descriptor(descriptor);
        if !trusted(owner, current) || acl.is_null() || IsValidAcl(acl) == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        for index in 0..(*acl).AceCount {
            let mut entry = ptr::null_mut();
            if GetAce(acl, index as u32, &mut entry) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*entry.cast::<ACE_HEADER>();
            // Reject unreviewed object/callback grants rather than guessing their effect.
            match header.AceType as u32 {
                ACCESS_ALLOWED_ACE_TYPE => {
                    let ace = &*entry.cast::<ACCESS_ALLOWED_ACE>();
                    let sid = ptr::addr_of!(ace.SidStart).cast_mut().cast();
                    if ace.Mask != 0 && !trusted(sid, current) {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                }
                ACCESS_DENIED_ACE_TYPE => {}
                _ => return Err(io::ErrorKind::PermissionDenied.into()),
            }
        }
        Ok(information)
    }
}

pub(crate) fn private_descriptor() -> io::Result<Descriptor> {
    let user = CurrentUser::new()?;
    let sid = user.sid_string()?;
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Descriptor(descriptor))
}

pub(super) fn directory(path: &Path) -> io::Result<()> {
    super::inspect_ancestors(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let information = inspect(&file)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

pub(super) fn create_directory(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return directory(path);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && !parent.exists()
    {
        create_directory(parent)?;
    }
    match create_new_directory(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => directory(path),
        result => result,
    }
}

pub(super) fn create_new_directory(path: &Path) -> io::Result<()> {
    super::inspect_ancestors(path)?;
    unsafe {
        let descriptor = private_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if path_wide[..path_wide.len() - 1].contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if CreateDirectoryW(path_wide.as_ptr(), &attributes) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    directory(path)
}
