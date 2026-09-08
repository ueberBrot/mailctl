//! Configuration lookup and explicit operator initialization.
use crate::{
    config::{AccessGrant, AccountConfig, Config, CredentialSource, Limits, TlsMode, Topology},
    domain::{Error, ErrorCode, Setup},
    policy::Profile,
    service::Service,
};
use etcetera::{AppStrategy, AppStrategyArgs, app_strategy::choose_native_strategy};
use std::{
    io::{BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

pub(super) fn default_path() -> PathBuf {
    directories()
        .map(|directories| directories.in_config_dir("config.toml"))
        .unwrap_or_else(|_| PathBuf::from("mailctl.toml"))
}

fn directories() -> Result<impl AppStrategy, Error> {
    choose_native_strategy(AppStrategyArgs {
        top_level_domain: "org".into(),
        author: "ueberBrot".into(),
        app_name: "mailctl".into(),
    })
    .map_err(|_| Error::setup_required())
}

pub(super) fn load(path: &Path) -> Result<Config, Error> {
    Config::parse(&existing(path)?.ok_or_else(Error::setup_required)?)
}

pub(super) fn open(path: &Path, config: Config) -> Result<Service, Error> {
    let expected = serde_json::to_vec(&config).map_err(|_| Error::setup_required())?;
    Service::open_checked(config, || {
        let current = load(path)?;
        if serde_json::to_vec(&current).map_err(|_| Error::setup_required())? != expected {
            return Err(Error::new(ErrorCode::OperationConflict));
        }
        Ok(())
    })
}

fn existing(path: &Path) -> Result<Option<String>, Error> {
    crate::file_storage::read(path, 4 * 1024 * 1024)
        .map_err(|_| Error::setup_required())?
        .map(|bytes| String::from_utf8(bytes).map_err(|_| Error::setup_required()))
        .transpose()
}

pub(super) fn setup(
    path: &Path,
    mut args: super::arguments::Setup,
    selected: &[String],
    json: bool,
) -> Result<Setup, Error> {
    let previous = existing(path)?;
    if previous.is_none() && args.alias.is_none() {
        if json || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(Error::setup_required());
        }
        args.alias = Some(prompt("Account alias: ")?);
        args.server = Some(prompt("IMAP server: ")?);
        args.username = Some(prompt("Account username: ")?);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|_| Error::setup_required())?;
    let parent = std::fs::canonicalize(parent).map_err(|_| Error::setup_required())?;
    let destination = parent.join(path.file_name().ok_or_else(Error::setup_required)?);
    let mut config = match &previous {
        Some(text) => Config::parse(text)?,
        None => Config {
            version: 1,
            topology: Topology::Native,
            state_dir: if path == default_path() {
                directories()?.in_data_dir("state")
            } else {
                parent.join("state")
            },
            default_grant: "default".into(),
            limits: Limits::default(),
            accounts: Vec::new(),
            grants: vec![AccessGrant {
                name: "default".into(),
                profile: Profile::ReadOnly,
                accounts: Vec::new(),
                mailboxes: vec!["INBOX".into()],
                limits: Limits::default(),
            }],
        },
    };
    if selected.len() > 1 {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    let edited = args.alias.is_some();
    if let Some(alias) = args.alias {
        let target = selected.first().unwrap_or(&alias);
        if let Some(account) = config
            .accounts
            .iter_mut()
            .find(|account| &account.alias == target)
        {
            account.alias = alias;
            if let Some(server) = args.server {
                account.server = server;
            }
            if let Some(username) = args.username {
                account.username = username;
            }
        } else {
            if !selected.is_empty() {
                return Err(Error::new(ErrorCode::AccountNotAllowed));
            }
            let key = uuid::Uuid::new_v4().to_string();
            config.accounts.push(AccountConfig {
                key: key.clone(),
                alias: alias.clone(),
                server: args.server.ok_or_else(Error::setup_required)?,
                username: args.username.ok_or_else(Error::setup_required)?,
                port: 993,
                tls: TlsMode::Implicit,
                mailboxes: vec!["INBOX".into()],
                from_identities: vec![alias],
                drafts_mailbox: None,
                credential: CredentialSource::Native {},
                retain_history: false,
            });
            config
                .grants
                .iter_mut()
                .find(|grant| grant.name == config.default_grant)
                .ok_or_else(Error::setup_required)?
                .accounts
                .push(key);
        }
    }
    if !edited && !selected.is_empty() {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    let replacement = if edited || previous.is_none() {
        Some(toml::to_string_pretty(&config).map_err(|_| Error::setup_required())?)
    } else {
        None
    };
    let (setup, ()) = Service::maintain(config, || {
        if existing(&destination)? != previous {
            return Err(Error::new(ErrorCode::OperationConflict));
        }
        if let Some(text) = replacement {
            crate::file_storage::replace(&destination, text.as_bytes())
                .map_err(|_| Error::setup_required())?;
        }
        Ok(())
    })?;
    Ok(setup)
}

fn prompt(label: &str) -> Result<String, Error> {
    write!(std::io::stderr().lock(), "{label}")
        .and_then(|()| std::io::stderr().flush())
        .map_err(|_| Error::setup_required())?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(1025)
        .read_line(&mut line)
        .map_err(|_| Error::setup_required())?;
    if line.len() > 1024 || line.trim().is_empty() {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    Ok(line.trim().to_owned())
}
