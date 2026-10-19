use super::{Availability, MutableSecretStore, SERVICE_NAME, Secret, SecretSource, SourceError};
use secret_service::{
    EncryptionType,
    blocking::{Item, SecretService},
};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};
use uuid::Uuid;
use zbus::{
    blocking::{Connection, Proxy, connection::Builder},
    zvariant::{Dict, OwnedObjectPath, OwnedValue, Value},
};

const DESTINATION: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";

pub struct NativeSource;

impl NativeSource {
    pub fn shared() -> Arc<dyn SecretSource> {
        static SOURCE: OnceLock<Arc<NativeSource>> = OnceLock::new();
        SOURCE.get_or_init(|| Arc::new(Self)).clone()
    }
}

impl SecretSource for NativeSource {
    fn prerequisite(&self) -> Option<&'static str> {
        Some(
            "Native Linux credentials require an unlocked default Secret Service collection on the execution identity's session D-Bus",
        )
    }

    fn availability(&self, account: Uuid) -> Availability {
        let inspect = || -> Result<Availability, SourceError> {
            let service = Service::connect()?;
            match service.find(account)? {
                Some(_) => Ok(Availability::Available),
                None => {
                    service.default_collection()?;
                    Ok(Availability::Missing)
                }
            }
        };
        inspect().unwrap_or_else(Availability::from)
    }

    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
        let service = Service::connect()?;
        let path = service.find(account)?.ok_or(SourceError::Missing)?;
        let encrypted = service.encrypted()?;
        let item = encrypted.get_item_by_path(path).map_err(source_error)?;
        service.check_item(&item, &attributes(&account.to_string()))?;
        let secret = Secret::new(item.get_secret().map_err(source_error)?)?;
        service.check_owner()?;
        Ok(secret)
    }

    fn mutable_store(&self) -> Option<&dyn MutableSecretStore> {
        Some(self)
    }
}

impl MutableSecretStore for NativeSource {
    fn set(&self, account: Uuid, secret: &Secret) -> Result<(), SourceError> {
        let service = Service::connect()?;
        service.lock_mutation(account)?;
        let existing = service.find(account)?;
        let created = existing.is_none();
        let encrypted = service.encrypted()?;
        let identity = if created { Uuid::new_v4() } else { account }.to_string();
        let expected = if created {
            staging_attributes(&identity)
        } else {
            attributes(&identity)
        };
        let path = match existing {
            Some(path) => path,
            None => service.create_staging_item(&identity)?,
        };
        let initialized = encrypted
            .get_item_by_path(path.clone())
            .map_err(source_error)
            .and_then(|item| {
                service.check_item(&item, &expected)?;
                item.set_secret(secret.expose().as_bytes(), "text/plain")
                    .map_err(source_error)?;
                service.check_owner()?;
                Ok(item)
            });
        let item = match initialized {
            Ok(item) => item,
            Err(error) => {
                if created {
                    let _ = service.delete(&path);
                }
                return Err(error);
            }
        };
        if created {
            let vacant = service.find(account).and_then(|entry| match entry {
                Some(_) => Err(SourceError::Internal),
                None => Ok(()),
            });
            if let Err(error) = vacant {
                let _ = service.delete(&path);
                return Err(error);
            }
            let username = account.to_string();
            item.set_attributes(attributes(&username))
                .map_err(source_error)?;
            service.check_owner()?;
            // A concurrent creator must never make an arbitrary credential win.
            if service.find(account)? != Some(path) {
                return Err(SourceError::Internal);
            }
        }
        Ok(())
    }

    fn delete(&self, account: Uuid) -> Result<(), SourceError> {
        let service = Service::connect()?;
        service.lock_mutation(account)?;
        let path = service.find(account)?.ok_or(SourceError::Missing)?;
        service.delete(&path)
    }
}

struct Service {
    connection: Connection,
    owner: String,
}

impl Service {
    fn connect() -> Result<Self, SourceError> {
        let connection = Builder::session()
            .map_err(bus_error)?
            .method_timeout(Duration::from_secs(5))
            .build()
            .map_err(bus_error)?;
        // Do not start a desktop keyring daemon as a side effect of inspection.
        let owner = bus(&connection)?
            .call("GetNameOwner", &(DESTINATION,))
            .map_err(bus_error)?;
        Ok(Self { connection, owner })
    }

    fn proxy<'a>(&'a self, path: &'a str, interface: &'a str) -> Result<Proxy<'a>, SourceError> {
        Proxy::new(&self.connection, self.owner.as_str(), path, interface).map_err(bus_error)
    }

    fn lock_mutation(&self, account: Uuid) -> Result<(), SourceError> {
        let name = format!("org.mailctl.Credential.a{}", account.simple());
        // The connection holds this nonqueued name until the operation ends.
        let result: u32 = bus(&self.connection)?
            .call("RequestName", &(name, 4u32))
            .map_err(bus_error)?;
        match result {
            1 | 4 => Ok(()),
            _ => Err(SourceError::Unavailable),
        }
    }

    fn check_owner(&self) -> Result<(), SourceError> {
        let owner: String = bus(&self.connection)?
            .call("GetNameOwner", &(DESTINATION,))
            .map_err(bus_error)?;
        if owner != self.owner {
            return Err(SourceError::Unavailable);
        }
        Ok(())
    }

    fn check_item(
        &self,
        item: &Item<'_>,
        expected: &HashMap<&str, &str>,
    ) -> Result<(), SourceError> {
        self.check_owner()?;
        let actual = item.get_attributes().map_err(source_error)?;
        if expected
            .iter()
            .any(|(key, value)| actual.get(*key).map(String::as_str) != Some(*value))
        {
            return Err(SourceError::Internal);
        }
        self.check_owner()
    }

    fn find(&self, account: Uuid) -> Result<Option<OwnedObjectPath>, SourceError> {
        let account = account.to_string();
        let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
            .proxy(ROOT, SERVICE)?
            .call("SearchItems", &(attributes(&account),))
            .map_err(bus_error)?;
        if unlocked.len().saturating_add(locked.len()) > 1 {
            return Err(SourceError::Internal);
        }
        if !locked.is_empty() {
            return Err(SourceError::Locked);
        }
        Ok(unlocked.pop())
    }

    fn default_collection(&self) -> Result<OwnedObjectPath, SourceError> {
        let path: OwnedObjectPath = self
            .proxy(ROOT, SERVICE)?
            .call("ReadAlias", &("default",))
            .map_err(bus_error)?;
        if path.as_str() == "/" {
            return Err(SourceError::Unavailable);
        }
        let locked: bool = self
            .proxy(path.as_str(), COLLECTION)?
            .get_property("Locked")
            .map_err(bus_error)?;
        if locked {
            return Err(SourceError::Locked);
        }
        Ok(path)
    }

    fn encrypted(&self) -> Result<SecretService<'_>, SourceError> {
        self.check_owner()?;
        let service =
            SecretService::connect_with_existing(EncryptionType::Dh, self.connection.clone())
                .map_err(source_error)?;
        self.check_owner()?;
        Ok(service)
    }

    fn create_staging_item(&self, pending: &str) -> Result<OwnedObjectPath, SourceError> {
        let collection = self.default_collection()?;
        let (_, session): (OwnedValue, OwnedObjectPath) = self
            .proxy(ROOT, SERVICE)?
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(bus_error)?;
        let attributes: Dict = staging_attributes(pending).into();
        let properties = HashMap::from([
            (
                "org.freedesktop.Secret.Item.Label",
                Value::from("mailctl credential"),
            ),
            (
                "org.freedesktop.Secret.Item.Attributes",
                Value::from(attributes),
            ),
        ]);
        // Only an empty unpublished item uses the plain session. Secret bytes
        // use the maintained library's encrypted SetSecret before publication.
        let secret = (&session, Vec::<u8>::new(), Vec::<u8>::new(), "text/plain");
        let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .proxy(collection.as_str(), COLLECTION)?
            .call("CreateItem", &(properties, secret, false))
            .map_err(bus_error)?;
        self.reject_prompt(&prompt)?;
        if item.as_str() == "/" {
            return Err(SourceError::Unavailable);
        }
        Ok(item)
    }

    fn delete(&self, path: &OwnedObjectPath) -> Result<(), SourceError> {
        let prompt = self
            .proxy(path.as_str(), ITEM)?
            .call("Delete", &())
            .map_err(bus_error)?;
        self.reject_prompt(&prompt)
    }

    fn reject_prompt(&self, path: &OwnedObjectPath) -> Result<(), SourceError> {
        if path.as_str() == "/" {
            return Ok(());
        }
        if let Ok(prompt) = self.proxy(path.as_str(), "org.freedesktop.Secret.Prompt") {
            let _: Result<(), _> = prompt.call("Dismiss", &());
        }
        Err(SourceError::InteractionRequired)
    }
}

fn bus(connection: &Connection) -> Result<Proxy<'static>, SourceError> {
    Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(bus_error)
}

fn attributes(account: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE_NAME), ("username", account)])
}

fn staging_attributes(pending: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE_NAME), ("mailctl-pending", pending)])
}

fn source_error(error: secret_service::Error) -> SourceError {
    match error {
        secret_service::Error::Locked => SourceError::Locked,
        secret_service::Error::NoResult => SourceError::Missing,
        secret_service::Error::Prompt => SourceError::InteractionRequired,
        secret_service::Error::Zbus(error) => bus_error(error),
        secret_service::Error::ZbusFdo(error) => bus_error(error.into()),
        secret_service::Error::Unavailable | secret_service::Error::PromptDisconnected => {
            SourceError::Unavailable
        }
        _ => SourceError::Internal,
    }
}

fn bus_error(error: zbus::Error) -> SourceError {
    match error {
        zbus::Error::MethodError(name, _, _) => match name.as_str() {
            "org.freedesktop.Secret.Error.IsLocked" => SourceError::Locked,
            "org.freedesktop.Secret.Error.NoSuchObject" => SourceError::Missing,
            "org.freedesktop.DBus.Error.AccessDenied" | "org.freedesktop.DBus.Error.AuthFailed" => {
                SourceError::AccessDenied
            }
            "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => {
                SourceError::InteractionRequired
            }
            _ => SourceError::Unavailable,
        },
        zbus::Error::FDO(error) => match *error {
            zbus::fdo::Error::AccessDenied(_) | zbus::fdo::Error::AuthFailed(_) => {
                SourceError::AccessDenied
            }
            zbus::fdo::Error::InteractiveAuthorizationRequired(_) => {
                SourceError::InteractionRequired
            }
            zbus::fdo::Error::ZBus(error) => bus_error(error),
            _ => SourceError::Unavailable,
        },
        _ => SourceError::Unavailable,
    }
}
