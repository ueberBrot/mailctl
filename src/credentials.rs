//! Credential sources expose safe status separately from secret resolution.

use crate::config::CredentialSource;
pub use crate::domain::{CredentialFailure as SourceError, SourceAvailability as Availability};
use std::{fmt, sync::Arc};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
mod native;
#[cfg(target_os = "macos")]
pub use native::NativeSource;

pub const SERVICE_NAME: &str = "mailctl";
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Suppress native dialogs before credential or TLS trust-store access.
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

/// Blocking operations run on the application's bounded credential workers.
pub trait SecretSource: Send + Sync {
    /// Safe provisioning or platform requirements, without inspecting the source.
    fn prerequisite(&self) -> Option<&'static str> {
        None
    }
    /// Inspects metadata without authentication, secret retrieval, or prompting.
    fn availability(&self, account: Uuid) -> Availability;
    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError>;
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
            prerequisite: "Foreground session credential resolution is unavailable in this build",
        }),
        CredentialSource::Systemd { .. } => Arc::new(DeferredSource {
            failure: SourceError::Unavailable,
            prerequisite: "Systemd credentials need provisioning for the execution identity; source resolution is unavailable in this build",
        }),
        CredentialSource::Command { .. } => Arc::new(DeferredSource {
            failure: SourceError::Unavailable,
            prerequisite: "Trusted credential commands need a provisioned helper; source execution is unavailable in this build",
        }),
    }
}

#[cfg(target_os = "macos")]
fn native_source() -> Arc<dyn SecretSource> {
    NativeSource::shared()
}

#[cfg(not(target_os = "macos"))]
fn native_source() -> Arc<dyn SecretSource> {
    Arc::new(DeferredSource {
        failure: SourceError::Unavailable,
        prerequisite: "Native credential resolution in this build requires macOS",
    })
}

// Platform qualification and external-source execution belong to later slices.
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
