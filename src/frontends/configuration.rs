//! Configuration lookup and explicit operator initialization.
use crate::{
    config::{AccessGrant, AccountConfig, Config, CredentialSource, Limits, TlsMode, Topology},
    domain::{Error, ErrorCode, Setup},
    policy::Profile,
    service::Service,
};
use directories::ProjectDirs;
use std::{
    fs::OpenOptions,
    io::{BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

pub(super) fn default_path() -> PathBuf {
    ProjectDirs::from("org", "ueberBrot", "mailctl")
        .map(|directories| directories.config_local_dir().join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("mailctl.toml"))
}

fn read(path: &Path) -> Result<String, Error> {
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    let invalid = Error::setup_required;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
        for ancestor in path.ancestors().filter(|part| !part.as_os_str().is_empty()) {
            use std::os::windows::fs::MetadataExt;
            if std::fs::symlink_metadata(ancestor)
                .map_err(|_| invalid())?
                .file_attributes()
                & 0x400
                != 0
            {
                return Err(invalid());
            }
        }
    }
    let file = options.open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(invalid());
        }
    }
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| invalid())?;
    if text.len() as u64 > MAX_BYTES {
        return Err(invalid());
    }
    Ok(text)
}

pub(super) fn load(path: &Path) -> Result<Config, Error> {
    Config::parse(&read(path)?)
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
    match std::fs::symlink_metadata(path) {
        Ok(_) => read(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::setup_required()),
    }
}

pub(super) fn setup(
    path: &Path,
    mut args: super::cli::Setup,
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
                ProjectDirs::from("org", "ueberBrot", "mailctl")
                    .ok_or_else(Error::setup_required)?
                    .data_local_dir()
                    .join("state")
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
            persist(&destination, &text)?;
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

fn persist(path: &Path, text: &str) -> Result<(), Error> {
    let temporary = path.with_file_name(format!(".config-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        std::fs::File::open(path.parent().unwrap())?.sync_all()?;
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result.map_err(|_| Error::setup_required())
}
