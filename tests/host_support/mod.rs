//! Host dependencies for exercising the application's production IMAP adapter.
use mailctl::{
    config::CredentialSource,
    credentials::{Availability, Secret, SecretSource, SourceError},
    host::HostEnvironment,
};
use std::sync::Arc;
use tokio_rustls::rustls::RootCertStore;

pub struct Host {
    roots: RootCertStore,
    password: &'static [u8],
}
impl Host {
    pub fn new(roots: RootCertStore, password: &'static [u8]) -> Arc<Self> {
        Arc::new(Self { roots, password })
    }
}
impl HostEnvironment for Host {
    fn credential_source(&self, _: &CredentialSource) -> Arc<dyn SecretSource> {
        Arc::new(Password(self.password))
    }
    fn tls_roots(&self) -> Result<RootCertStore, SourceError> {
        Ok(self.roots.clone())
    }
}
struct Password(&'static [u8]);
impl SecretSource for Password {
    fn availability(&self, _: uuid::Uuid) -> Availability {
        Availability::Available
    }
    fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
        Secret::new(self.0.to_vec())
    }
}
