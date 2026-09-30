use super::{Availability, MutableSecretStore, SERVICE_NAME, Secret, SecretSource, SourceError};
use keyring_core::{Entry, api::CredentialStoreApi};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use uuid::Uuid;
use windows_native_keyring_store::Store;

pub struct NativeSource {
    store: Result<Arc<Store>, SourceError>,
}
impl NativeSource {
    pub fn shared() -> Arc<dyn SecretSource> {
        static SOURCE: OnceLock<Arc<NativeSource>> = OnceLock::new();
        SOURCE
            .get_or_init(|| {
                Arc::new(Self {
                    store: Store::new().map_err(source_error),
                })
            })
            .clone()
    }
    fn entry(&self, account: Uuid) -> Result<Entry, SourceError> {
        self.store
            .as_ref()
            .map_err(|error| *error)?
            .build(
                SERVICE_NAME,
                &account.to_string(),
                Some(&HashMap::from([("persistence", "Local")])),
            )
            .map_err(source_error)
    }
}
impl SecretSource for NativeSource {
    fn availability(&self, account: Uuid) -> Availability {
        // This returns only attributes. The native adapter wipes the credential
        // blob supplied by Windows before freeing its allocation.
        self.entry(account)
            .and_then(|entry| entry.get_attributes().map_err(source_error))
            .map(|_| Availability::Available)
            .unwrap_or_else(Availability::from)
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
fn source_error(error: keyring_core::Error) -> SourceError {
    // The adapter keeps its platform error type private. Do not infer a more
    // specific category by parsing its diagnostic text.
    super::keyring_error(error, |_| SourceError::Unavailable)
}
