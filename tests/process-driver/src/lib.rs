//! Synthetic host dependencies used only by the process-test launchers.
use mailctl::{
    config::CredentialSource,
    credentials::{Availability, Secret, SecretSource, SourceError},
    host::HostEnvironment,
};
use std::{io::Read, sync::Arc};
use tokio_rustls::rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};

pub struct FixtureHost;
impl HostEnvironment for FixtureHost {
    fn credential_source(&self, source: &CredentialSource) -> Arc<dyn SecretSource> {
        Arc::new(FixtureSecret(matches!(source, CredentialSource::Native {})))
    }
    fn tls_roots(&self) -> Result<RootCertStore, SourceError> {
        let path = std::env::var_os("MAILCTL_FIXTURE_CA").ok_or(SourceError::Unavailable)?;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| SourceError::Unavailable)?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| SourceError::Unavailable)?;
        if bytes.len() > 65536 {
            return Err(SourceError::Unavailable);
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(&bytes).map_err(|_| SourceError::Unavailable)?)
            .map_err(|_| SourceError::Unavailable)?;
        Ok(roots)
    }
}
struct FixtureSecret(bool);
impl SecretSource for FixtureSecret {
    fn availability(&self, _: uuid::Uuid) -> Availability {
        assert!(
            !tracing::Span::current().is_disabled(),
            "credential availability must retain the request span"
        );
        if self.0 {
            Availability::Available
        } else {
            Availability::Unavailable
        }
    }
    fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
        if !self.0 {
            return Err(SourceError::Unavailable);
        }
        Secret::new(b"disposable-password".to_vec())
    }
}
