//! Credential sources expose safe status separately from secret resolution.

use crate::config::{CredentialSource, Limits};
pub use crate::domain::{CredentialFailure as SourceError, SourceAvailability as Availability};
use std::{fmt, sync::Arc};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
mod command;

#[cfg(target_os = "linux")]
mod systemd;

#[cfg(target_os = "macos")]
mod native;
#[cfg(windows)]
#[path = "credentials/windows.rs"]
mod native;
#[cfg(any(target_os = "macos", windows))]
pub use native::NativeSource;

pub const SERVICE_NAME: &str = "mailctl";
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsFd) -> Result<(), SourceError> {
    let flags = rustix::fs::fcntl_getfl(pipe).map_err(|_| SourceError::Unavailable)?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| SourceError::Unavailable)
}

/// Suppress native dialogs before credential or TLS trust-store access.
#[cfg_attr(
    not(target_os = "macos"),
    allow(
        clippy::unnecessary_wraps,
        reason = "macOS setup can fail through this shared interface"
    )
)]
pub(crate) fn prepare_native_access() -> Result<(), SourceError> {
    #[cfg(target_os = "macos")]
    return native::disable_interaction();
    #[cfg(not(target_os = "macos"))]
    Ok(())
}

/// Owned authentication material. Debug output contains no secret bytes.
///
/// Secret values cannot enter a serialized result:
///
/// ```compile_fail
/// use mailctl::credentials::Secret;
/// let secret = Secret::new(b"synthetic-password".to_vec()).unwrap();
/// serde_json::to_string(&secret).unwrap();
/// ```
///
/// Borrowing the secret value is internal to the crate:
///
/// ```compile_fail
/// use mailctl::credentials::Secret;
/// let secret = Secret::new(b"synthetic-password".to_vec()).unwrap();
/// let password = secret.expose();
/// ```
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, SourceError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            bytes.zeroize();
            return Err(SourceError::InvalidSecret);
        }
        String::from_utf8(bytes)
            .map(|text| Self(Zeroizing::new(text)))
            .map_err(|error| {
                error.into_bytes().zeroize();
                SourceError::InvalidSecret
            })
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl From<SourceError> for Availability {
    fn from(error: SourceError) -> Self {
        match error {
            SourceError::Missing => Self::Missing,
            SourceError::Locked => Self::Locked,
            SourceError::AccessDenied => Self::AccessDenied,
            SourceError::Unavailable => Self::Unavailable,
            SourceError::InteractionRequired => Self::InteractionRequired,
            SourceError::InvalidSecret | SourceError::Internal => Self::Unknown,
        }
    }
}

/// Validated ceilings shared by credential execution and concurrent resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResolutionLimits {
    secret_bytes: usize,
    stderr_bytes: usize,
    timeout: std::time::Duration,
}
impl ResolutionLimits {
    pub fn secret_bytes(&self) -> usize {
        self.secret_bytes
    }
    pub fn stderr_bytes(&self) -> usize {
        self.stderr_bytes
    }
    pub fn timeout(&self) -> std::time::Duration {
        self.timeout
    }
}
impl TryFrom<&Limits> for ResolutionLimits {
    type Error = SourceError;
    fn try_from(limits: &Limits) -> Result<Self, Self::Error> {
        limits.validate().map_err(|_| SourceError::Unavailable)?;
        Ok(Self {
            secret_bytes: limits.secret_bytes,
            stderr_bytes: limits.command_stderr_bytes,
            timeout: std::time::Duration::from_secs(
                limits.secret_command_seconds.min(limits.operation_seconds) as u64,
            ),
        })
    }
}

/// Blocking operations run on the application's bounded credential workers.
pub trait SecretSource: Send + Sync {
    /// Safe provisioning or platform requirements, without inspecting the source.
    fn prerequisite(&self) -> Option<&'static str> {
        None
    }
    /// Inspects metadata without authentication, secret retrieval, or prompting.
    fn availability(&self, account: Uuid) -> Availability;
    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError>;
    /// Resolution uses the caller's effective resource ceilings.
    fn resolve_with_limits(
        &self,
        account: Uuid,
        limits: &ResolutionLimits,
    ) -> Result<Secret, SourceError> {
        let secret = self.resolve(account)?;
        if secret.len() > limits.secret_bytes {
            return Err(SourceError::InvalidSecret);
        }
        Ok(secret)
    }
    fn mutable_store(&self) -> Option<&dyn MutableSecretStore> {
        None
    }
}

pub trait MutableSecretStore: Send + Sync {
    fn set(&self, account: Uuid, secret: &Secret) -> Result<(), SourceError>;
    fn delete(&self, account: Uuid) -> Result<(), SourceError>;
}

/// Selects a source without inspecting the store or contacting a provider.
pub fn source_for(source: &CredentialSource) -> Arc<dyn SecretSource> {
    match source {
        CredentialSource::Native {} => native_source(),
        CredentialSource::Session {} => Arc::new(DeferredSource {
            failure: SourceError::InteractionRequired,
            prerequisite: "Session credentials require mailctl --interactive in an operator terminal without --json",
        }),
        #[cfg(target_os = "linux")]
        CredentialSource::Systemd { name } => Arc::new(systemd::SystemdSource::new(name.clone())),
        #[cfg(not(target_os = "linux"))]
        CredentialSource::Systemd { .. } => Arc::new(DeferredSource {
            failure: SourceError::Unavailable,
            prerequisite: "Systemd credentials require Linux and explicit provisioning with LoadCredential= for the execution identity",
        }),
        #[cfg(unix)]
        CredentialSource::Command(config) => Arc::new(command::CommandSource::new(config.clone())),
        #[cfg(not(unix))]
        CredentialSource::Command(_) => Arc::new(DeferredSource {
            failure: SourceError::Unavailable,
            prerequisite: "Trusted credential commands require a supported Unix execution environment",
        }),
    }
}

#[cfg(any(target_os = "macos", windows))]
fn native_source() -> Arc<dyn SecretSource> {
    NativeSource::shared()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn native_source() -> Arc<dyn SecretSource> {
    Arc::new(DeferredSource {
        failure: SourceError::Unavailable,
        prerequisite: "Native credential resolution in this build requires macOS or Windows",
    })
}

// Sources unsupported by this build still expose safe provisioning status.
struct DeferredSource {
    failure: SourceError,
    prerequisite: &'static str,
}

impl SecretSource for DeferredSource {
    fn prerequisite(&self) -> Option<&'static str> {
        Some(self.prerequisite)
    }

    fn availability(&self, _: Uuid) -> Availability {
        self.failure.into()
    }

    fn resolve(&self, _: Uuid) -> Result<Secret, SourceError> {
        Err(self.failure)
    }
}

#[cfg(any(target_os = "macos", windows))]
fn keyring_error(
    error: keyring_core::Error,
    platform: impl FnOnce(&(dyn std::error::Error + Send + Sync + 'static)) -> SourceError,
) -> SourceError {
    match error {
        keyring_core::Error::NoEntry => SourceError::Missing,
        keyring_core::Error::PlatformFailure(error)
        | keyring_core::Error::NoStorageAccess(error) => platform(error.as_ref()),
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
