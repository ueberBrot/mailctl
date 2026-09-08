//! Shared installation identity, configuration revision, and maintenance leases.
mod storage;
use crate::{
    config::{AccountConfig, Config, CredentialSource, TlsMode},
    domain::{Error, ErrorCode},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use storage::{LockMode, invalid};
use uuid::Uuid;

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AccountHistory {
    account_id: String,
    generations: Vec<Generation>,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Generation {
    generation: u64,
    server: String,
    port: u16,
    tls: TlsMode,
    username: String,
    credential: Option<CredentialSource>,
}
impl Generation {
    fn matches(&self, account: &AccountConfig) -> bool {
        self.server == account.server
            && self.port == account.port
            && self.tls == account.tls
            && self.username == account.username
    }
    fn from_account(account: &AccountConfig, generation: u64) -> Self {
        Self {
            generation,
            server: account.server.clone(),
            port: account.port,
            tls: account.tls,
            username: account.username.clone(),
            credential: Some(account.credential.clone()),
        }
    }
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    installation: String,
    installation_key: [u8; 32],
    configuration_revision: String,
    accounts: BTreeMap<String, AccountHistory>,
}
impl Registry {
    fn new(configuration_revision: String) -> Result<Self, Error> {
        let mut installation_key = [0; 32];
        getrandom::fill(&mut installation_key).map_err(|_| invalid())?;
        Ok(Self {
            version: 1,
            installation: Uuid::new_v4().to_string(),
            installation_key,
            configuration_revision,
            accounts: BTreeMap::new(),
        })
    }
    fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || Uuid::parse_str(&self.installation).is_err()
            || self.installation_key == [0; 32]
            || self.configuration_revision.len() != 64
            || !self
                .configuration_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid());
        }
        let mut identities = HashSet::new();
        for history in self.accounts.values() {
            if Uuid::parse_str(&history.account_id).is_err()
                || !identities.insert(&history.account_id)
                || history.generations.is_empty()
                || history
                    .generations
                    .iter()
                    .enumerate()
                    .any(|(index, generation)| generation.generation != index as u64 + 1)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn reconcile(&mut self, config: &Config) -> Result<(), Error> {
        self.validate()?;
        for (key, history) in &mut self.accounts {
            if !config.accounts.iter().any(|account| &account.key == key) {
                for generation in &mut history.generations {
                    generation.credential = None;
                }
            }
        }
        for account in &config.accounts {
            let history =
                self.accounts
                    .entry(account.key.clone())
                    .or_insert_with(|| AccountHistory {
                        account_id: Uuid::new_v4().to_string(),
                        generations: Vec::new(),
                    });
            if !account.retain_history {
                for generation in &mut history.generations {
                    generation.credential = None;
                }
            }
            match history.generations.last_mut() {
                Some(current) if current.matches(account) => {
                    current.credential = Some(account.credential.clone())
                }
                _ => history.generations.push(Generation::from_account(
                    account,
                    history.generations.len() as u64 + 1,
                )),
            }
        }
        Ok(())
    }
}

struct Lease {
    directory: PathBuf,
    _maintenance: File,
}

struct Initialization {
    directory: PathBuf,
    config: Config,
    revision: String,
    marker: Vec<u8>,
    registry: Registry,
    maintenance: File,
    _initialization: File,
    exclusive: bool,
    changed: bool,
}

impl Initialization {
    fn acquire(config: &Config, exclusive: bool) -> Result<Self, Error> {
        let directory = storage::directory(&config.state_dir, exclusive)?;
        let mut canonical = config.clone();
        canonical.state_dir = directory.clone();
        let revision = fingerprint(&canonical)?;
        let deadline =
            Instant::now() + Duration::from_secs(config.limits.initialization_seconds as u64);
        let mut initialization = storage::open_lock(&directory, "initialization.lock")?;
        storage::lock(&initialization, LockMode::Exclusive, deadline)?;
        let marker = storage::initialization_marker(&mut initialization)?;
        let persisted = load(&directory)?;
        if persisted.is_none() && !marker.is_empty() {
            return Err(invalid());
        }
        let changed = persisted
            .as_ref()
            .is_none_or(|registry| registry.configuration_revision != revision);
        let maintenance = storage::open_lock(&directory, "maintenance.lock")?;
        let exclusive = exclusive || changed;
        storage::lock(
            &maintenance,
            if exclusive {
                LockMode::Exclusive
            } else {
                LockMode::Shared
            },
            deadline,
        )?;
        let registry = match persisted {
            Some(registry) => registry,
            None => Registry::new(revision.clone())?,
        };
        if !registry.installation.as_bytes().starts_with(&marker) {
            return Err(invalid());
        }
        // An unchanged configuration must retain every account's existing identity.
        if !changed
            && config
                .accounts
                .iter()
                .any(|account| !registry.accounts.contains_key(&account.key))
        {
            return Err(invalid());
        }
        Ok(Self {
            directory,
            config: canonical,
            revision,
            marker,
            registry,
            maintenance,
            _initialization: initialization,
            exclusive,
            changed,
        })
    }

    fn reconcile<T>(
        &mut self,
        update_configuration: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        // Prepare bounded state before allowing the configuration to be replaced.
        let bytes = if self.changed {
            self.registry.configuration_revision = self.revision.clone();
            self.registry.reconcile(&self.config)?;
            Some(
                crate::encoding::serialize_bounded(&self.registry, storage::MAX_BYTES)
                    .map_err(|_| invalid())?,
            )
        } else {
            None
        };
        let updated = update_configuration()?;
        if let Some(bytes) = bytes {
            storage::persist(&self.directory, &bytes)?;
        }
        if self.marker.len() != self.registry.installation.len() {
            storage::mark_initialized(&mut self._initialization, &self.registry.installation)?;
        }
        Ok(updated)
    }

    fn downgrade_to_shared(&mut self) -> Result<(), Error> {
        if self.exclusive {
            let deadline = Instant::now()
                + Duration::from_secs(self.config.limits.initialization_seconds as u64);
            self.maintenance.unlock().map_err(|_| invalid())?;
            storage::lock(&self.maintenance, LockMode::Shared, deadline)?;
            self.exclusive = false;
        }
        Ok(())
    }
}

pub(super) struct AccountRegistry {
    registry: Registry,
    lease: Option<Lease>,
}
impl AccountRegistry {
    pub(super) fn in_memory(config: &Config) -> Result<Self, Error> {
        let mut registry = Registry::new(fingerprint(config)?)?;
        registry.reconcile(config)?;
        Ok(Self {
            registry,
            lease: None,
        })
    }
    pub(super) fn open_checked(
        config: &Config,
        confirm_configuration: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let mut initialization = Initialization::acquire(config, false)?;
        initialization.reconcile(confirm_configuration)?;
        initialization.downgrade_to_shared()?;
        let Initialization {
            directory,
            registry,
            maintenance,
            ..
        } = initialization;
        Ok(Self {
            registry,
            lease: Some(Lease {
                directory,
                _maintenance: maintenance,
            }),
        })
    }
    pub(super) fn maintain<T>(
        config: &Config,
        update_configuration: impl FnOnce() -> Result<T, Error>,
    ) -> Result<(Self, T), Error> {
        let mut initialization = Initialization::acquire(config, true)?;
        let updated = initialization.reconcile(update_configuration)?;
        let registry = Self {
            registry: initialization.registry,
            lease: None,
        };
        Ok((registry, updated))
    }
    pub(super) fn check_revision(&self) -> Result<(), Error> {
        let Some(lease) = &self.lease else {
            return Ok(());
        };
        storage::directory(&lease.directory, false)?;
        let persisted = load(&lease.directory)?.ok_or_else(invalid)?;
        if persisted != self.registry {
            return Err(Error::new(ErrorCode::OperationConflict));
        }
        Ok(())
    }
    pub(super) fn identity(&self, key: &str) -> (&str, u64) {
        let account = &self.registry.accounts[key];
        (&account.account_id, account.generations.len() as u64)
    }
    pub(super) fn installation(&self) -> &str {
        &self.registry.installation
    }
    pub(super) fn revision(&self) -> &str {
        &self.registry.configuration_revision
    }
}

fn fingerprint(config: &Config) -> Result<String, Error> {
    let bytes =
        crate::encoding::serialize_bounded(config, storage::MAX_BYTES).map_err(|_| invalid())?;
    use std::fmt::Write;
    let mut revision = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(revision, "{byte:02x}");
    }
    Ok(revision)
}

fn load(directory: &Path) -> Result<Option<Registry>, Error> {
    let Some(bytes) = storage::read(directory)? else {
        return Ok(None);
    };
    let registry: Registry = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    registry.validate()?;
    Ok(Some(registry))
}
