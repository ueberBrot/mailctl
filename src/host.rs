//! Host dependencies selected by the executable before accepting operations.
use crate::{
    config::CredentialSource,
    credentials::{self, SecretSource, SourceError},
};
use std::sync::Arc;
use tokio_rustls::rustls::RootCertStore;

/// Credential routing and TLS trust for one application runtime.
/// Source selection returns promptly without prompting or retrieving secrets.
/// TLS trust loading runs on a blocking worker. Secret resolution still uses
/// the application's credential workers, deadlines, and secret limits.
pub trait HostEnvironment: Send + Sync {
    fn credential_source(&self, reference: &CredentialSource) -> Arc<dyn SecretSource>;
    fn tls_roots(&self) -> Result<RootCertStore, SourceError>;
}

/// The configured credential sources and native TLS trust used by shipped launchers.
pub struct NativeEnvironment;
impl HostEnvironment for NativeEnvironment {
    fn credential_source(&self, reference: &CredentialSource) -> Arc<dyn SecretSource> {
        credentials::source_for(reference)
    }
    fn tls_roots(&self) -> Result<RootCertStore, SourceError> {
        credentials::prepare_native_access()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        Ok(roots)
    }
}
