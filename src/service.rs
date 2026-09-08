//! Account discovery and broker authorization through one application interface.
use crate::{
    backend::InMemoryBackend,
    config::{AccountConfig, Config, CredentialSource, TlsMode},
    domain::{
        Account, AccountDiscovery, AccountHealth, Capabilities, Error, ErrorCode, Health, Operation,
    },
    policy::{Narrowing, RequestContext},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::Mutex,
};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountHistory {
    account_id: String,
    generations: Vec<Generation>,
}
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    installation: String,
    accounts: BTreeMap<String, AccountHistory>,
}
impl Registry {
    fn new() -> Self {
        Self {
            version: 1,
            installation: Uuid::new_v4().to_string(),
            accounts: BTreeMap::new(),
        }
    }
    fn reconcile(&mut self, config: &Config) -> Result<(), Error> {
        if self.version != 1 || Uuid::parse_str(&self.installation).is_err() {
            return Err(unavailable());
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
                return Err(unavailable());
            }
        }
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

pub struct Service {
    config: Config,
    registry: Registry,
    backend: InMemoryBackend,
    unavailable_listeners: Mutex<HashSet<String>>,
    context_id: String,
}
impl Service {
    /// Open persisted account identities after the broker has acquired its state lock.
    pub fn open(config: Config) -> Result<Self, Error> {
        config.validate()?;
        check_private_path(&config.state_dir, true)?;
        let path = config.state_dir.join("accounts.json");
        let mut registry = if path.try_exists().map_err(|_| unavailable())? {
            check_private_path(&path, false)?;
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            }
            let file = options.open(&path).map_err(|_| unavailable())?;
            let mut bytes = Vec::new();
            file.take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| unavailable())?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(unavailable());
            }
            serde_json::from_slice(&bytes).map_err(|_| unavailable())?
        } else {
            Registry::new()
        };
        registry.reconcile(&config)?;
        persist(&config.state_dir, &registry)?;
        Ok(Self::build(config, registry))
    }
    pub fn in_memory(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let mut registry = Registry::new();
        registry.reconcile(&config)?;
        Ok(Self::build(config, registry))
    }
    fn build(config: Config, registry: Registry) -> Self {
        Self {
            config,
            registry,
            backend: InMemoryBackend,
            unavailable_listeners: Mutex::new(HashSet::new()),
            context_id: Uuid::new_v4().to_string(),
        }
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn mark_listener_unavailable(&self, name: &str) {
        if let Ok(mut listeners) = self.unavailable_listeners.lock() {
            listeners.insert(name.to_owned());
        }
    }
    /// The transport supplies the authenticated listener; client metadata never selects it.
    pub fn context(
        &self,
        listener_name: &str,
        narrowing: &Narrowing,
    ) -> Result<RequestContext, Error> {
        let listener = self
            .config
            .listeners
            .iter()
            .find(|listener| listener.name == listener_name)
            .ok_or_else(denied)?;
        if narrowing.accounts.as_ref().is_some_and(|accounts| {
            accounts.len() > self.config.limits.accounts
                || accounts.iter().any(|account| account.len() > 1024)
        }) {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let accounts = listener
            .accounts
            .iter()
            .filter(|key| {
                narrowing.accounts.as_ref().is_none_or(|selected| {
                    self.config
                        .accounts
                        .iter()
                        .any(|account| &account.key == *key && selected.contains(&account.alias))
                })
            })
            .cloned()
            .collect();
        Ok(RequestContext {
            installation: self.context_id.clone(),
            listener: listener_name.into(),
            accounts,
            permissions: listener.profile.permissions(narrowing.read_only),
        })
    }
    pub fn execute(&self, context: &RequestContext, operation: Operation) -> Result<Value, Error> {
        if context.installation != self.context_id {
            return Err(denied());
        }
        let listener = self
            .config
            .listeners
            .iter()
            .find(|listener| listener.name == context.listener)
            .ok_or_else(denied)?;
        let permissions = context.permissions.clone();
        let accounts = || {
            self.config
                .accounts
                .iter()
                .filter(|account| context.accounts.contains(&account.key))
        };
        let operations = vec![
            "list_accounts".to_string(),
            "capabilities".to_string(),
            "health".to_string(),
        ];
        let result = match operation {
            Operation::ListAccounts(input) => {
                let limit = input.limit.unwrap_or(listener.limits.accounts);
                if limit == 0 || limit > listener.limits.accounts {
                    return Err(Error::new(ErrorCode::InvalidRequest));
                }
                // Count encoded field bytes before cloning operator-controlled labels.
                let mut ordered = accounts().collect::<Vec<_>>();
                ordered.sort_by_key(|account| &self.registry.accounts[&account.key].account_id);
                let complete = ordered.len() <= limit;
                ordered.truncate(limit);
                let mut budget =
                    OutputBudget::new(listener.limits.ipc_frame_bytes.saturating_sub(512));
                budget.reserve(32)?;
                for account in &ordered {
                    budget.reserve(256)?;
                    budget.count(&account.alias)?;
                    budget.count(&account.from_identities)?;
                }
                let visible = ordered
                    .into_iter()
                    .map(|account| {
                        let history = &self.registry.accounts[&account.key];
                        Account {
                            alias: account.alias.clone(),
                            account_id: history.account_id.clone(),
                            generation: history.generations.len() as u64,
                            from_identities: account.from_identities.clone(),
                            capabilities: operations.clone(),
                            availability: self.backend.availability(),
                        }
                    })
                    .collect::<Vec<_>>();
                serde_json::to_value(AccountDiscovery {
                    accounts: visible,
                    complete,
                })
            }
            Operation::Capabilities => serde_json::to_value(Capabilities {
                operations,
                permissions,
                health: self.health(context, listener.limits.ipc_frame_bytes)?,
            }),
            Operation::Health => {
                serde_json::to_value(self.health(context, listener.limits.ipc_frame_bytes)?)
            }
        }
        .map_err(|_| Error::new(ErrorCode::InternalError))?;
        if serde_json::to_vec(&result)
            .map_err(|_| Error::new(ErrorCode::InternalError))?
            .len()
            > listener.limits.ipc_frame_bytes.saturating_sub(512)
        {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        Ok(result)
    }
    fn health(&self, context: &RequestContext, frame_bytes: usize) -> Result<Health, Error> {
        let unavailable = self
            .unavailable_listeners
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))?;
        let status = if unavailable.contains(&context.listener) {
            "unavailable"
        } else {
            "ready"
        };
        let mut budget = OutputBudget::new(frame_bytes.saturating_sub(512));
        budget.reserve(256 + context.accounts.len() * 160)?;
        let mut accounts = self
            .config
            .accounts
            .iter()
            .filter(|account| context.accounts.contains(&account.key))
            .map(|account| {
                let history = &self.registry.accounts[&account.key];
                AccountHealth {
                    account_id: history.account_id.clone(),
                    generation: history.generations.len() as u64,
                    availability: self.backend.availability(),
                }
            })
            .collect::<Vec<_>>();
        accounts.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        Ok(Health {
            status: status.into(),
            listener: context.listener.clone(),
            accounts,
        })
    }
}
fn denied() -> Error {
    Error::new(ErrorCode::PermissionDenied)
}
fn unavailable() -> Error {
    Error::new(ErrorCode::BrokerUnavailable)
}
fn check_private_path(path: &Path, directory: bool) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(unavailable());
        }
    }
    Ok(())
}
fn persist(directory: &Path, registry: &Registry) -> Result<(), Error> {
    let bytes = serde_json::to_vec(registry).map_err(|_| unavailable())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(unavailable());
    }
    let temporary = directory.join(format!(".accounts-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|_| unavailable())?;
        file.write_all(&bytes).map_err(|_| unavailable())?;
        file.sync_all().map_err(|_| unavailable())?;
        std::fs::rename(&temporary, directory.join("accounts.json")).map_err(|_| unavailable())?;
        #[cfg(unix)]
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Counts serialization work without retaining bytes; excess output fails before cloning labels.
struct OutputBudget {
    remaining: usize,
}
impl OutputBudget {
    fn new(remaining: usize) -> Self {
        Self { remaining }
    }
    fn reserve(&mut self, bytes: usize) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| Error::new(ErrorCode::ResponseTooLarge))?;
        Ok(())
    }
    fn count(&mut self, value: &impl Serialize) -> Result<(), Error> {
        serde_json::to_writer(self, value).map_err(|_| Error::new(ErrorCode::ResponseTooLarge))
    }
}
impl Write for OutputBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.reserve(bytes.len()).map_err(std::io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
