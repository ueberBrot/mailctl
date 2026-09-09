//! Versioned operator configuration. Parsing validates authority and resource ceilings.
use crate::{domain::Error, policy::Profile};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
};

pub(crate) const MAX_BYTES: usize = 4 * 1024 * 1024;

fn invalid() -> Error {
    Error::setup_required()
}

fn obsolete_runtime_capacity(input: &str) -> bool {
    fn contains(value: &toml::Value) -> bool {
        match value {
            toml::Value::Table(values) => values.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "runtimes"
                        | "runtime_slots"
                        | "runtime_slot"
                        | "shared_permit"
                        | "shared_permits"
                ) || contains(value)
            }),
            toml::Value::Array(values) => values.iter().any(contains),
            _ => false,
        }
    }
    toml::from_str::<toml::Value>(input).is_ok_and(|value| contains(&value))
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
                if !resolved.fits_within(ceiling) { return Err(invalid()); }
                resolved.validate()?;
                Ok(resolved)
            }
        }
        impl Limits {
            fn fits_within(&self, ceiling: &Self) -> bool { $(self.$name <= ceiling.$name)&&+ }
            pub fn validate(&self) -> Result<(), Error> {
                if $(self.$name == 0 || self.$name > $max)||+ { return Err(invalid()); }
                if self.buffered_bytes < crate::encoding::request_buffer_bytes(self.envelope_bytes) + self.envelope_bytes + 192 || self.envelope_bytes < 1024
                    || self.connection_seconds > self.operation_seconds
                    || self.initialization_seconds > self.operation_seconds
                    || self.mailbox_page > self.mailbox_inventory { return Err(invalid()); }
                Ok(())
            }
        }
    }
}
limits! {
    envelope_bytes: 16 * 1024 * 1024 => 64 * 1024 * 1024,
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
    grants: 8 => 32,
    initialization_seconds: 5 => 10,
    active_requests: 16 => 64,
    queued_requests: 64 => 256,
    buffered_bytes: 64 * 1024 * 1024 => 256 * 1024 * 1024,
    credential_workers: 2 => 8,
    queued_credentials: 8 => 32,
    doctor_checks_per_minute: 2 => 12,
    connection_lifetime_seconds: 300 => 900,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    #[default]
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
#[derive(Clone, Debug, Serialize)]
pub struct AccessGrant {
    pub name: String,
    pub profile: Profile,
    pub accounts: Vec<String>,
    pub mailboxes: Vec<String>,
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    name: String,
    #[serde(default)]
    profile: Profile,
    accounts: Vec<String>,
    mailboxes: Vec<String>,
    #[serde(default)]
    limits: LimitOverrides,
}
#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub version: u32,
    pub default_grant: String,
    pub topology: Topology,
    pub state_dir: PathBuf,
    pub limits: Limits,
    pub accounts: Vec<AccountConfig>,
    pub grants: Vec<AccessGrant>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u32,
    #[serde(default = "default_grant")]
    default_grant: String,
    #[serde(default)]
    topology: Topology,
    state_dir: PathBuf,
    #[serde(default)]
    limits: Limits,
    accounts: Vec<AccountConfig>,
    grants: Vec<RawGrant>,
}
fn default_grant() -> String {
    "default".into()
}
impl Config {
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > MAX_BYTES {
            return Err(invalid());
        }
        let raw: RawConfig = toml::from_str(input).map_err(|_| {
            if obsolete_runtime_capacity(input) {
                Error::obsolete_runtime_capacity()
            } else {
                invalid()
            }
        })?;
        raw.limits.validate()?;
        let grants = raw
            .grants
            .into_iter()
            .map(|grant| {
                Ok(AccessGrant {
                    name: grant.name,
                    profile: grant.profile,
                    accounts: grant.accounts,
                    mailboxes: grant.mailboxes,
                    limits: grant.limits.resolve(&raw.limits)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        let config = Self {
            version: raw.version,
            default_grant: raw.default_grant,
            topology: raw.topology,
            state_dir: raw.state_dir,
            limits: raw.limits,
            accounts: raw.accounts,
            grants,
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.version != 1
            || !safe_path(&self.state_dir)
            || self.accounts.len() > self.limits.accounts
            || self.grants.is_empty()
            || self.grants.len() > self.limits.grants
            || !identifier(&self.default_grant)
            || !self
                .grants
                .iter()
                .any(|grant| grant.name == self.default_grant && grant.profile == Profile::ReadOnly)
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
        for grant in &self.grants {
            grant.limits.validate()?;
            if !grant.limits.fits_within(&self.limits) {
                return Err(invalid());
            }
            if !identifier(&grant.name)
                || !names.insert(&grant.name)
                || grant.accounts.len() > self.limits.accounts
                || !unique_labels(&grant.mailboxes, self.limits.mailbox_inventory)
                || grant.accounts.iter().any(|key| !keys.contains(key))
            {
                return Err(invalid());
            }
            if grant.profile != Profile::ReadOnly
                && grant.accounts.iter().any(|key| {
                    self.accounts
                        .iter()
                        .find(|account| &account.key == key)
                        .is_none_or(|account| {
                            account
                                .drafts_mailbox
                                .as_ref()
                                .is_none_or(|mailbox| !grant.mailboxes.contains(mailbox))
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
    let mut unique = HashSet::new();
    !values.is_empty()
        && values.len() <= max
        && values
            .iter()
            .all(|value| label(value) && unique.insert(value))
}
fn server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
}
