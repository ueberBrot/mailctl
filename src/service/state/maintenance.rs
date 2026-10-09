//! Offline installation snapshots protected by the same leases as live runtimes.
use super::drafts::{DraftHistory, Recovery};
use super::*;
use crate::{
    domain::{Setup, StateMaintenance},
    draft_journal::DraftJournal,
    file_storage,
};
use sha2::{Digest, Sha256};
use std::{fs, fs::OpenOptions, io::Read};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    files: BTreeMap<String, String>,
}

struct Maintenance<'a> {
    config: Cow<'a, Config>,
    marker: Vec<u8>,
    directory: PathBuf,
    _initialization: File,
    _maintenance: File,
}
impl<'a> Maintenance<'a> {
    fn acquire(config: &'a Config) -> Result<Self, Error> {
        config.validate()?;
        let directory = storage::directory(&config.state_dir, false)?;
        let deadline =
            Instant::now() + Duration::from_secs(config.limits.initialization_seconds as u64);
        let mut initialization = storage::open_lock(&directory, "initialization.lock")?;
        storage::lock(&initialization, LockMode::Exclusive, deadline)?;
        let marker = storage::initialization_marker(&mut initialization)?;
        let maintenance = storage::open_lock(&directory, "maintenance.lock")?;
        storage::lock(&maintenance, LockMode::Exclusive, deadline)?;
        let mut canonical = Cow::Borrowed(config);
        if config.state_dir.as_os_str() != directory.as_os_str() {
            canonical.to_mut().state_dir = directory.clone();
        }
        Ok(Self {
            config: canonical,
            marker,
            directory,
            _initialization: initialization,
            _maintenance: maintenance,
        })
    }
    fn registry(&self) -> Result<Registry, Error> {
        let registry = load(&self.directory)?.ok_or_else(invalid)?;
        if registry.configuration_revision != fingerprint(&self.config)?
            || self.marker != registry.installation.as_bytes()
        {
            return Err(Error::new(ErrorCode::OperationConflict));
        }
        Ok(registry)
    }

    fn receipt(&self, registry: Registry, action: &str) -> Result<StateMaintenance, Error> {
        Ok(StateMaintenance {
            action: action.into(),
            draft_creation_suspended: Recovery::read(&self.directory)?.is_some(),
            installation: Setup {
                installation_id: registry.installation,
                configuration_revision: registry.configuration_revision,
                accounts: self.config.accounts.len(),
                grants: self.config.grants.len(),
            },
        })
    }
}

pub(in crate::service) fn backup(
    config: &Config,
    destination: &Path,
) -> Result<StateMaintenance, Error> {
    let maintenance = Maintenance::acquire(config)?;
    let config = maintenance.config.as_ref();
    let registry = maintenance.registry()?;
    if !destination.is_absolute() || destination.starts_with(&maintenance.directory) {
        return Err(invalid());
    }
    file_storage::create_new_directory(destination).map_err(|_| invalid())?;
    let result = (|| {
        if storage::directory(destination, false)?.starts_with(&maintenance.directory) {
            return Err(invalid());
        }
        let mut names = vec!["accounts.json", "config.toml"];
        file_storage::replace(
            &destination.join("accounts.json"),
            &storage::read(&maintenance.directory)?.ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let config_bytes = toml::to_string_pretty(config).map_err(|_| invalid())?;
        if config_bytes.len() > crate::config::MAX_BYTES {
            return Err(invalid());
        }
        file_storage::replace(&destination.join("config.toml"), config_bytes.as_bytes())
            .map_err(|_| invalid())?;
        if registry.draft_history_initialized {
            let mut history = DraftHistory::open(&maintenance.directory)?;
            let path = destination.join("drafts.sqlite");
            // VACUUM INTO accepts an empty destination. Create it privately first.
            let file = file_storage::open(&path, OpenOptions::new().write(true).create_new(true))
                .map_err(|_| invalid())?;
            history
                .access(|journal| journal.snapshot(&path))
                .map_err(|_| Error::new(ErrorCode::JournalUnavailable))?;
            file.sync_all().map_err(|_| invalid())?;
            names.push("drafts.sqlite");
        }
        if let Some(recovery) = Recovery::read(&maintenance.directory)? {
            if recovery == Recovery::Restoring {
                return Err(Error::new(ErrorCode::JournalUnavailable));
            }
            recovery.persist(destination)?;
            names.push("drafts.suspended");
        }
        let mut files = BTreeMap::new();
        for name in names {
            files.insert(name.into(), digest(&destination.join(name))?);
        }
        let manifest = crate::encoding::serialize_bounded(&Manifest { version: 1, files }, 4096)
            .map_err(|_| invalid())?;
        // A missing manifest identifies an incomplete snapshot after a crash.
        file_storage::replace(&destination.join("manifest.json"), &manifest)
            .map_err(|_| invalid())?;
        sync_directory(destination)?;
        sync_directory(destination.parent().ok_or_else(invalid)?)?;
        maintenance.receipt(registry, "backup")
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}
fn digest(path: &Path) -> Result<String, Error> {
    let mut file =
        file_storage::open(path, OpenOptions::new().read(true)).map_err(|_| invalid())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| invalid())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(crate::encoding::hex(&hash.finalize()))
}
#[cfg_attr(
    not(unix),
    allow(
        clippy::unnecessary_wraps,
        reason = "Unix directory synchronization can fail through this shared interface"
    )
)]
fn sync_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| invalid())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(in crate::service) fn restore(
    config: &Config,
    source: &Path,
) -> Result<StateMaintenance, Error> {
    let maintenance = Maintenance::acquire(config)?;
    let config = maintenance.config.as_ref();
    let source = storage::directory(source, false)?;
    if source.starts_with(&maintenance.directory) {
        return Err(invalid());
    }
    let manifest: Manifest = serde_json::from_slice(
        &file_storage::read(&source.join("manifest.json"), 4096)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    if manifest.version != 1 {
        return Err(Error::incompatible_schema());
    }
    for (name, expected) in &manifest.files {
        if ![
            "accounts.json",
            "config.toml",
            "drafts.sqlite",
            "drafts.suspended",
        ]
        .contains(&name.as_str())
            || digest(&source.join(name))? != *expected
        {
            return Err(invalid());
        }
    }
    if !manifest.files.contains_key("accounts.json") || !manifest.files.contains_key("config.toml")
    {
        return Err(invalid());
    }
    let registry_bytes = storage::read(&source)?.ok_or_else(invalid)?;
    let registry = decode_registry(&registry_bytes)?;
    let saved_config = Config::parse(
        &String::from_utf8(
            file_storage::read(&source.join("config.toml"), crate::config::MAX_BYTES)
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?,
    )?;
    let revision = fingerprint(config)?;
    if registry.configuration_revision != revision
        || fingerprint(&saved_config)? != revision
        || maintenance.marker != registry.installation.as_bytes()
        || registry.draft_history_initialized != manifest.files.contains_key("drafts.sqlite")
    {
        return Err(Error::new(ErrorCode::OperationConflict));
    }
    Recovery::read(&source)?;
    drafts::private_files(&maintenance.directory)?;
    // Durable fence precedes every replacement. Interrupted restore cannot expose
    // a mixed registry/journal or silently make absent operations dispatchable.
    Recovery::Restoring.persist(&maintenance.directory)?;
    if registry.draft_history_initialized {
        let temporary = maintenance
            .directory
            .join(format!(".restore-{}.sqlite", Uuid::new_v4()));
        let result = (|| {
            copy_private(&source.join("drafts.sqlite"), &temporary)?;
            let journal = DraftJournal::open_existing_nowait(&temporary)
                .map_err(|_| Error::new(ErrorCode::JournalUnavailable))?;
            journal.verify().map_err(journal_error)?;
            drop(journal);
            for name in ["drafts.sqlite-wal", "drafts.sqlite-shm"] {
                match fs::remove_file(maintenance.directory.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(invalid()),
                }
            }
            fs::rename(&temporary, maintenance.directory.join("drafts.sqlite"))
                .map_err(|_| invalid())?;
            sync_directory(&maintenance.directory)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        file_storage::replace(&maintenance.directory.join("drafts.initialized"), b"2")
            .map_err(|_| invalid())?;
    }
    storage::persist(&maintenance.directory, &registry_bytes)?;
    Recovery::Suspended.persist(&maintenance.directory)?;
    maintenance.receipt(registry, "restore")
}

fn copy_private(source: &Path, destination: &Path) -> Result<(), Error> {
    let mut source =
        file_storage::open(source, OpenOptions::new().read(true)).map_err(|_| invalid())?;
    let mut destination =
        file_storage::open(destination, OpenOptions::new().write(true).create_new(true))
            .map_err(|_| invalid())?;
    std::io::copy(&mut source, &mut destination).map_err(|_| invalid())?;
    destination.sync_all().map_err(|_| invalid())
}

pub(in crate::service) fn verify(config: &Config) -> Result<StateMaintenance, Error> {
    let maintenance = Maintenance::acquire(config)?;
    let registry = maintenance.registry()?;
    if Recovery::read(&maintenance.directory)? == Some(Recovery::Restoring) {
        return Err(Error::new(ErrorCode::JournalUnavailable));
    }
    if registry.draft_history_initialized {
        DraftHistory::open(&maintenance.directory)?
            .access(|journal| journal.verify())
            .map_err(journal_error)?;
    }
    maintenance.receipt(registry, "verify")
}
fn journal_error(error: crate::draft_journal::DraftJournalError) -> Error {
    Error::new(match error {
        crate::draft_journal::DraftJournalError::InvalidOperation => {
            ErrorCode::UnsupportedCapability
        }
        _ => ErrorCode::JournalUnavailable,
    })
}
