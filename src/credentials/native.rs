use super::{Availability, MutableSecretStore, SERVICE_NAME, Secret, SecretSource, SourceError};
use apple_native_keyring_store::keychain::Store;
use keyring_core::{Entry, api::CredentialStoreApi};
use security_framework::{
    base::Error as PlatformError,
    os::macos::keychain::{KeychainUserInteractionLock, SecKeychain},
};
use std::{
    collections::HashMap,
    process::{Command, Stdio},
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
    // Create only empty metadata with the cooperative same-login access policy.
    // Password bytes enter Keychain through keyring-core afterward. Omitting -U
    // makes a concurrent creator fail safely without changing an existing ACL.
    let mut child = Command::new("/usr/bin/security")
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
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| SourceError::Unavailable)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(SourceError::Unavailable),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SourceError::Unavailable);
            }
        }
    }
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
