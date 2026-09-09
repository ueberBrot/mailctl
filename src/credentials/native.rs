use super::{Availability, MutableSecretStore, SERVICE_NAME, Secret, SecretSource, SourceError};
use apple_native_keyring_store::keychain::Store;
use keyring_core::{Entry, api::CredentialStoreApi};
use security_framework::{
    base::Error as PlatformError,
    os::macos::keychain::{KeychainUserInteractionLock, SecKeychain},
};
use std::{
    collections::HashMap,
    ffi::OsString,
    io::{ErrorKind, Read},
    os::{fd::AsFd, unix::ffi::OsStringExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroize;

/// The Apple native store selected once for both executable entry points.
pub struct NativeSource {
    store: Result<Arc<Store>, SourceError>,
}

impl NativeSource {
    pub fn shared() -> Arc<dyn SecretSource> {
        static SOURCE: OnceLock<Arc<NativeSource>> = OnceLock::new();
        SOURCE
            .get_or_init(|| {
                Arc::new(Self {
                    store: disable_interaction().and_then(|()| Store::new().map_err(source_error)),
                })
            })
            .clone()
    }

    fn store(&self) -> Result<&Store, SourceError> {
        disable_interaction()?;
        self.store.as_deref().map_err(|error| *error)
    }

    fn entry(&self, account: Uuid) -> Result<Entry, SourceError> {
        self.store()?
            .build(SERVICE_NAME, &account.to_string(), None)
            .map_err(source_error)
    }
}

impl SecretSource for NativeSource {
    fn availability(&self, account: Uuid) -> Availability {
        let inspect = || -> Result<Availability, SourceError> {
            let account = account.to_string();
            // get_credential retrieves password bytes in this Apple adapter;
            // search loads only entry attributes, so status does not fetch secrets.
            let entries = self
                .store()?
                .search(&HashMap::from([
                    ("service", SERVICE_NAME),
                    ("user", account.as_str()),
                ]))
                .map_err(source_error)?;
            Ok(if entries.is_empty() {
                Availability::Missing
            } else {
                Availability::Available
            })
        };
        inspect().unwrap_or_else(Availability::from)
    }

    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
        Secret::new(self.entry(account)?.get_secret().map_err(source_error)?)
    }

    fn mutable_store(&self) -> Option<&dyn MutableSecretStore> {
        Some(self)
    }
}

impl MutableSecretStore for NativeSource {
    fn set(&self, account: Uuid, secret: &Secret) -> Result<(), SourceError> {
        if self.availability(account) == Availability::Missing {
            create_shared_entry(account)?;
        }
        self.entry(account)?
            .set_secret(secret.expose().as_bytes())
            .map_err(source_error)
    }

    fn delete(&self, account: Uuid) -> Result<(), SourceError> {
        self.entry(account)?
            .delete_credential()
            .map_err(source_error)
    }
}

/// Must precede every in-process Keychain operation, including TLS trust loading.
pub(super) fn disable_interaction() -> Result<(), SourceError> {
    // Retained until process exit. Dropping a per-call guard would allow another
    // credential worker or trust-store enumeration to open a dialog.
    static NONINTERACTIVE: OnceLock<Result<KeychainUserInteractionLock, SourceError>> =
        OnceLock::new();
    NONINTERACTIVE
        .get_or_init(|| SecKeychain::disable_user_interaction().map_err(platform_error))
        .as_ref()
        .map(|_| ())
        .map_err(|error| *error)
}

fn create_shared_entry(account: Uuid) -> Result<(), SourceError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let keychain = default_user_keychain(deadline)?;
    if Instant::now() >= deadline {
        return Err(SourceError::Unavailable);
    }
    // Create only empty metadata with the cooperative same-login access policy.
    // Password bytes enter Keychain through keyring-core afterward. Omitting -U
    // makes a concurrent creator fail safely without changing an existing ACL.
    let mut child = security_command()
        .args([
            "add-generic-password",
            "-A",
            "-s",
            SERVICE_NAME,
            "-a",
            &account.to_string(),
            "-w",
            "",
        ])
        .arg(keychain)
        .stdout(Stdio::null())
        .spawn()
        .map_err(|_| SourceError::Unavailable)?;
    wait_for_security(&mut child, deadline).and_then(|status| {
        status
            .success()
            .then_some(())
            .ok_or(SourceError::Unavailable)
    })
}

const DEFAULT_KEYCHAIN_OUTPUT_BYTES: usize = 8 * 1024;

fn default_user_keychain(deadline: Instant) -> Result<PathBuf, SourceError> {
    if Instant::now() >= deadline {
        return Err(SourceError::Unavailable);
    }
    let mut child = security_command()
        .args(["default-keychain", "-d", "user"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| SourceError::Unavailable)?;
    let Some(mut stdout) = child.stdout.take() else {
        terminate_security(&mut child);
        return Err(SourceError::Unavailable);
    };
    if set_nonblocking(&stdout).is_err() {
        terminate_security(&mut child);
        return Err(SourceError::Unavailable);
    }
    let (status, output) = match collect_stdout(&mut child, &mut stdout, deadline) {
        Ok(result) => result,
        Err(error) => {
            terminate_security(&mut child);
            return Err(error);
        }
    };
    if !status.success() {
        return Err(SourceError::Unavailable);
    }
    parse_default_keychain(&output)
}

fn security_command() -> Command {
    let mut command = Command::new("/usr/bin/security");
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn set_nonblocking(stdout: &ChildStdout) -> Result<(), SourceError> {
    let flags = rustix::fs::fcntl_getfl(stdout.as_fd()).map_err(|_| SourceError::Unavailable)?;
    rustix::fs::fcntl_setfl(stdout.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| SourceError::Unavailable)
}

fn collect_stdout(
    child: &mut Child,
    stdout: &mut ChildStdout,
    deadline: Instant,
) -> Result<(ExitStatus, Vec<u8>), SourceError> {
    let mut output = Vec::new();
    let mut exceeded_limit = false;
    let mut exited = None;
    let mut eof = false;
    let mut buffer = [0; 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(SourceError::Unavailable);
        }
        while !eof {
            if Instant::now() >= deadline {
                return Err(SourceError::Unavailable);
            }
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    let remaining = DEFAULT_KEYCHAIN_OUTPUT_BYTES.saturating_sub(output.len());
                    output.extend_from_slice(&buffer[..count.min(remaining)]);
                    exceeded_limit |= count > remaining;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(SourceError::Unavailable),
            }
        }
        if exited.is_none() {
            exited = child.try_wait().map_err(|_| SourceError::Unavailable)?;
        }
        if let Some(status) = exited
            && eof
        {
            return (!exceeded_limit)
                .then_some((status, output))
                .ok_or(SourceError::Unavailable);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_security(child: &mut Child, deadline: Instant) -> Result<ExitStatus, SourceError> {
    loop {
        if Instant::now() >= deadline {
            terminate_security(child);
            return Err(SourceError::Unavailable);
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(_) => {
                terminate_security(child);
                return Err(SourceError::Unavailable);
            }
        }
    }
}

fn terminate_security(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn parse_default_keychain(output: &[u8]) -> Result<PathBuf, SourceError> {
    let output = output.strip_suffix(b"\n").unwrap_or(output);
    let output = output.strip_suffix(b"\r").unwrap_or(output);
    let mut output = output;
    while matches!(output.first(), Some(b' ' | b'\t')) {
        output = &output[1..];
    }
    let Some(keychain) = output
        .strip_prefix(b"\"")
        .and_then(|value| value.strip_suffix(b"\""))
    else {
        return Err(SourceError::Unavailable);
    };
    let keychain = OsString::from_vec(keychain.to_vec());
    if keychain.is_empty()
        || keychain.as_encoded_bytes().iter().any(u8::is_ascii_control)
        || !Path::new(&keychain).is_absolute()
    {
        return Err(SourceError::Unavailable);
    }
    Ok(PathBuf::from(keychain))
}

fn source_error(error: keyring_core::Error) -> SourceError {
    match error {
        keyring_core::Error::NoEntry => SourceError::Missing,
        keyring_core::Error::PlatformFailure(error)
        | keyring_core::Error::NoStorageAccess(error) => error
            .downcast_ref::<PlatformError>()
            .map_or(SourceError::Unavailable, |error| {
                platform_code(error.code())
            }),
        keyring_core::Error::BadEncoding(mut bytes)
        | keyring_core::Error::BadDataFormat(mut bytes, _) => {
            bytes.zeroize();
            SourceError::InvalidSecret
        }
        keyring_core::Error::TooLong(..) | keyring_core::Error::Invalid(..) => {
            SourceError::InvalidSecret
        }
        keyring_core::Error::NoDefaultStore | keyring_core::Error::NotSupportedByStore(_) => {
            SourceError::Unavailable
        }
        _ => SourceError::Internal,
    }
}

fn platform_error(error: PlatformError) -> SourceError {
    platform_code(error.code())
}

fn platform_code(code: i32) -> SourceError {
    match code {
        -25300 => SourceError::Missing,
        // macOS uses the same code for a locked keychain and an item whose
        // access policy needs a prompt. Preserve that uncertainty.
        -25308 | -25315 => SourceError::InteractionRequired,
        -61 | -128 | -25293 | -25244 | -25292 => SourceError::AccessDenied,
        -25291 | -25294 | -25295 => SourceError::Unavailable,
        _ => SourceError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_default_keychain;
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

    #[test]
    fn default_keychain_output_preserves_a_quoted_raw_path() {
        assert_eq!(
            parse_default_keychain(
                b"    \"/Users/fixture/Library/Keychains/with\\slash-and\"quote.keychain-db\"\n",
            )
            .unwrap(),
            PathBuf::from(OsString::from_vec(
                b"/Users/fixture/Library/Keychains/with\\slash-and\"quote.keychain-db".to_vec()
            ))
        );
        for output in [
            br#""relative.keychain-db""#.as_slice(),
            b"    \"/Users/fixture/one\"\n    \"/Users/fixture/two\"\n".as_slice(),
            br#"["/Users/fixture/one"]"#.as_slice(),
            b"\"/Users/fixture/one\n\"".as_slice(),
        ] {
            assert!(parse_default_keychain(output).is_err());
        }
    }
}
