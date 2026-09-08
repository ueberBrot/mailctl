//! Versioned operator configuration. Parsing validates authority and resource ceilings.
use crate::{
    domain::{Error, ErrorCode},
    policy::Profile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
};

fn invalid() -> Error {
    Error::new(ErrorCode::InvalidRequest)
}
macro_rules! limits {
    ($($name:ident: $default:expr => $max:expr),+ $(,)?) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct Limits { $(pub $name: usize,)+ }
        impl Default for Limits { fn default() -> Self { Self { $($name: $default,)+ } } }
        #[derive(Clone, Debug, Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct LimitOverrides { $($name: Option<usize>,)+ }
        impl LimitOverrides {
            fn resolve(self, ceiling: &Limits) -> Result<Limits, Error> {
                let resolved = Limits { $($name: self.$name.unwrap_or(ceiling.$name),)+ };
                if $(resolved.$name > ceiling.$name)||+ { return Err(invalid()); }
                resolved.validate()?;
                Ok(resolved)
            }
        }
        impl Limits {
            pub fn validate(&self) -> Result<(), Error> {
                if $(self.$name == 0 || self.$name > $max)||+ { return Err(invalid()); }
                if self.buffered_bytes < self.ipc_frame_bytes * 3 + 192 || self.ipc_frame_bytes < 1024
                    || self.handshakes > self.clients || self.active_requests > self.clients
                    || self.connection_seconds > self.operation_seconds
                    || self.handshake_seconds > self.operation_seconds
                    || self.mailbox_page > self.mailbox_inventory { return Err(invalid()); }
                Ok(())
            }
        }
    }
}
limits! {
    ipc_frame_bytes: 16 * 1024 * 1024 => 64 * 1024 * 1024,
    json_nesting: 32 => 64,
    search_page: 50 => 200,
    search_uid_window: 1000 => 10000,
    search_windows: 10 => 100,
    mailbox_page: 200 => 1000,
    mailbox_inventory: 1000 => 1000,
    text_page_bytes: 256 * 1024 => 2 * 1024 * 1024,
    wire_fetch_bytes: 2 * 1024 * 1024 => 8 * 1024 * 1024,
    header_bytes: 64 * 1024 => 256 * 1024,
    mime_depth: 20 => 40,
    mime_parts: 200 => 1000,
    attachment_decoded_bytes: 10 * 1024 * 1024 => 32 * 1024 * 1024,
    attachment_wire_bytes: 16 * 1024 * 1024 => 64 * 1024 * 1024,
    attachment_chunk_bytes: 64 * 1024 => 256 * 1024,
    transfer_seconds: 300 => 600,
    transfers_per_account: 2 => 4,
    token_bytes: 2048 => 8192,
    draft_mime_bytes: 1024 * 1024 => 8 * 1024 * 1024,
    operation_seconds: 30 => 120,
    connection_seconds: 10 => 30,
    account_connections: 2 => 4,
    account_pending_requests: 16 => 64,
    secret_bytes: 16 * 1024 => 64 * 1024,
    command_stderr_bytes: 8 * 1024 => 32 * 1024,
    secret_command_seconds: 15 => 60,
    journal_records: 100000 => 1000000,
    accounts: 32 => 256,
    listeners: 8 => 32,
    clients: 32 => 128,
    handshakes: 8 => 32,
    handshake_seconds: 5 => 10,
    active_requests: 16 => 64,
    queued_requests: 64 => 256,
    buffered_bytes: 64 * 1024 * 1024 => 256 * 1024 * 1024,
    credential_workers: 2 => 8,
    queued_credentials: 8 => 32,
    connection_lifetime_seconds: 300 => 900,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    #[default]
    Cooperative,
    Isolated,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    Native,
    LinuxNativeWsl,
    WindowsHostedWsl,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Implicit,
    Starttls,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialSource {
    Native {},
    Systemd {
        path: PathBuf,
    },
    Command {
        executable: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        working_dir: PathBuf,
    },
    Session {},
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    pub key: String,
    pub alias: String,
    pub server: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: TlsMode,
    pub username: String,
    pub mailboxes: Vec<String>,
    pub from_identities: Vec<String>,
    pub drafts_mailbox: Option<String>,
    pub credential: CredentialSource,
    #[serde(default)]
    pub retain_history: bool,
}
fn default_port() -> u16 {
    993
}
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub name: String,
    pub endpoint: PathBuf,
    pub peer_uids: Vec<u32>,
    pub profile: Profile,
    pub accounts: Vec<String>,
    pub mailboxes: Vec<String>,
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    name: String,
    endpoint: PathBuf,
    peer_uids: Vec<u32>,
    #[serde(default)]
    profile: Profile,
    accounts: Vec<String>,
    mailboxes: Vec<String>,
    #[serde(default)]
    limits: LimitOverrides,
}
#[derive(Clone, Debug)]
pub struct Config {
    pub version: u32,
    pub deployment: Deployment,
    pub topology: Topology,
    pub state_dir: PathBuf,
    pub limits: Limits,
    pub accounts: Vec<AccountConfig>,
    pub listeners: Vec<ListenerConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u32,
    #[serde(default)]
    deployment: Deployment,
    topology: Topology,
    state_dir: PathBuf,
    #[serde(default)]
    limits: Limits,
    accounts: Vec<AccountConfig>,
    listeners: Vec<RawListener>,
}
impl Config {
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        let raw: RawConfig = toml::from_str(input).map_err(|_| invalid())?;
        raw.limits.validate()?;
        let listeners = raw
            .listeners
            .into_iter()
            .map(|listener| {
                Ok(ListenerConfig {
                    name: listener.name,
                    endpoint: listener.endpoint,
                    peer_uids: listener.peer_uids,
                    profile: listener.profile,
                    accounts: listener.accounts,
                    mailboxes: listener.mailboxes,
                    limits: listener.limits.resolve(&raw.limits)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        let config = Self {
            version: raw.version,
            deployment: raw.deployment,
            topology: raw.topology,
            state_dir: raw.state_dir,
            limits: raw.limits,
            accounts: raw.accounts,
            listeners,
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.version != 1
            || !safe_path(&self.state_dir)
            || self.accounts.len() > self.limits.accounts
            || self.listeners.is_empty()
            || self.listeners.len() > self.limits.listeners
        {
            return Err(invalid());
        }
        let mut keys = HashSet::new();
        let mut aliases = HashSet::new();
        for account in &self.accounts {
            if !identifier(&account.key)
                || !label(&account.alias)
                || !keys.insert(&account.key)
                || !aliases.insert(&account.alias)
                || !server_name(&account.server)
                || account.port == 0
                || !label(&account.username)
                || !unique_labels(&account.mailboxes, self.limits.mailbox_inventory)
                || !unique_labels(&account.from_identities, 100)
                || account
                    .drafts_mailbox
                    .as_ref()
                    .is_some_and(|mailbox| !account.mailboxes.contains(mailbox))
            {
                return Err(invalid());
            }
            match &account.credential {
                CredentialSource::Systemd { path } if !safe_path(path) => return Err(invalid()),
                CredentialSource::Command {
                    executable,
                    args,
                    working_dir,
                } if !safe_path(executable)
                    || !safe_path(working_dir)
                    || args.len() > 64
                    || args
                        .iter()
                        .any(|arg| arg.len() > 4096 || arg.contains('\0')) =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        let mut names = HashSet::new();
        let mut endpoints = HashSet::new();
        for listener in &self.listeners {
            listener.limits.validate()?;
            // Programmatically assembled configurations receive the same ceiling check.
            let limits = serde_json::to_value(&listener.limits).map_err(|_| invalid())?;
            let ceilings = serde_json::to_value(&self.limits).map_err(|_| invalid())?;
            if limits
                .as_object()
                .ok_or_else(invalid)?
                .iter()
                .any(|(key, value)| value.as_u64() > ceilings[key].as_u64())
            {
                return Err(invalid());
            }
            if !identifier(&listener.name)
                || !names.insert(&listener.name)
                || !safe_path(&listener.endpoint)
                || !endpoints.insert(&listener.endpoint)
                || listener.peer_uids.is_empty()
                || listener.peer_uids.len() > 128
                || listener.accounts.len() > self.limits.accounts
                || !unique_labels(&listener.mailboxes, self.limits.mailbox_inventory)
                || listener.accounts.iter().any(|key| !keys.contains(key))
            {
                return Err(invalid());
            }
            if listener.profile != Profile::ReadOnly
                && listener.accounts.iter().any(|key| {
                    self.accounts
                        .iter()
                        .find(|account| &account.key == key)
                        .is_none_or(|account| {
                            account
                                .drafts_mailbox
                                .as_ref()
                                .is_none_or(|mailbox| !listener.mailboxes.contains(mailbox))
                        })
                })
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn safe_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        && path.to_str().is_some_and(|value| !value.contains('\0'))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn unique_labels(values: &[String], max: usize) -> bool {
    let unique: HashSet<_> = values.iter().collect();
    !values.is_empty()
        && values.len() <= max
        && unique.len() == values.len()
        && values.iter().all(|value| label(value))
}
fn server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
}
