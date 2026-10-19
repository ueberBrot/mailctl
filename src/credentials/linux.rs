use super::{Availability, MutableSecretStore, SERVICE_NAME, Secret, SecretSource, SourceError};
use futures_util::FutureExt;
use oo7::dbus::{Item, Service as EncryptedService};
use std::{
    collections::HashMap,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::runtime::Runtime;
use uuid::Uuid;
use zbus::{
    Connection, Proxy,
    connection::Builder,
    zvariant::{Dict, OwnedObjectPath, OwnedValue, Value},
};

const DESTINATION: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const TIMEOUT: Duration = Duration::from_secs(5);

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
        run(async {
            let service = Service::connect().await?;
            match service.find(account).await? {
                Some(_) => Ok(Availability::Available),
                None => {
                    service.default_collection().await?;
                    Ok(Availability::Missing)
                }
            }
        })
        .unwrap_or_else(Availability::from)
    }

    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
        run(async {
            let service = Service::connect().await?;
            let path = service.find(account).await?.ok_or(SourceError::Missing)?;
            let encrypted = service.encrypted().await?;
            let item = service
                .item(&encrypted, &path, &attributes(&account.to_string()))
                .await?;
            let mut value = item.secret().await.map_err(source_error)?;
            let bytes = match &mut value {
                oo7::Secret::Text(text) => std::mem::take(text).into_bytes(),
                oo7::Secret::Blob(bytes) => std::mem::take(bytes),
            };
            let secret = Secret::new(bytes)?;
            service.check_owner().await?;
            Ok(secret)
        })
    }

    fn mutable_store(&self) -> Option<&dyn MutableSecretStore> {
        Some(self)
    }
}

impl MutableSecretStore for NativeSource {
    fn set(&self, account: Uuid, secret: &Secret) -> Result<(), SourceError> {
        run(async {
            let service = Service::connect().await?;
            service.lock_mutation(account).await?;
            let existing = service.find(account).await?;
            let created = existing.is_none();
            let encrypted = service.encrypted().await?;
            let identity = if created { Uuid::new_v4() } else { account }.to_string();
            let expected = if created {
                staging_attributes(&identity)
            } else {
                attributes(&identity)
            };
            let path = match existing {
                Some(path) => path,
                None => service.create_staging_item(&identity).await?,
            };
            let initialized = async {
                let item = service.item(&encrypted, &path, &expected).await?;
                item.set_secret(oo7::Secret::text(secret.expose()))
                    .await
                    .map_err(source_error)?;
                service.check_owner().await?;
                Ok(item)
            }
            .await;
            let item = match initialized {
                Ok(item) => item,
                Err(error) => {
                    if created {
                        let _ = service.delete(&path).await;
                    }
                    return Err(error);
                }
            };
            if created {
                let vacant = service.find(account).await.and_then(|entry| match entry {
                    Some(_) => Err(SourceError::Internal),
                    None => Ok(()),
                });
                if let Err(error) = vacant {
                    let _ = service.delete(&path).await;
                    return Err(error);
                }
                let username = account.to_string();
                item.set_attributes(&attributes(&username))
                    .await
                    .map_err(source_error)?;
                service.check_owner().await?;
                if service.find(account).await? != Some(path) {
                    return Err(SourceError::Internal);
                }
            }
            Ok(())
        })
    }

    fn delete(&self, account: Uuid) -> Result<(), SourceError> {
        run(async {
            let service = Service::connect().await?;
            service.lock_mutation(account).await?;
            let path = service.find(account).await?.ok_or(SourceError::Missing)?;
            service.delete(&path).await
        })
    }
}

fn run<T: Send>(
    operation: impl Future<Output = Result<T, SourceError>> + Send,
) -> Result<T, SourceError> {
    static RUNTIME: OnceLock<Result<Runtime, SourceError>> = OnceLock::new();
    let runtime = RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(|_| SourceError::Unavailable)
        })
        .as_ref()
        .map_err(|error| *error)?;
    let execute = || {
        runtime.block_on(async {
            match AssertUnwindSafe(tokio::time::timeout(TIMEOUT, operation))
                .catch_unwind()
                .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(SourceError::Unavailable),
                Err(_) => Err(SourceError::Internal),
            }
        })
    };
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("mailctl-native-credential".into())
                .spawn_scoped(scope, execute)
                .map_err(|_| SourceError::Unavailable)?
                .join()
                .unwrap_or(Err(SourceError::Internal))
        })
    } else {
        execute()
    }
}

struct Service {
    connection: Connection,
    owner: String,
}

impl Service {
    async fn connect() -> Result<Self, SourceError> {
        let connection = Builder::session()
            .map_err(bus_error)?
            .method_timeout(TIMEOUT)
            .build()
            .await
            .map_err(bus_error)?;
        // Inspection must not activate a desktop keyring daemon.
        let owner = bus(&connection)
            .await?
            .call("GetNameOwner", &(DESTINATION,))
            .await
            .map_err(bus_error)?;
        Ok(Self { connection, owner })
    }

    async fn proxy<'a>(
        &'a self,
        path: &'a str,
        interface: &'a str,
    ) -> Result<Proxy<'a>, SourceError> {
        Proxy::new(&self.connection, self.owner.as_str(), path, interface)
            .await
            .map_err(bus_error)
    }

    async fn lock_mutation(&self, account: Uuid) -> Result<(), SourceError> {
        let name = format!("org.mailctl.Credential.a{}", account.simple());
        // The connection holds this nonqueued name until the operation ends.
        let result: u32 = bus(&self.connection)
            .await?
            .call("RequestName", &(name, 4u32))
            .await
            .map_err(bus_error)?;
        match result {
            1 | 4 => Ok(()),
            _ => Err(SourceError::Unavailable),
        }
    }

    async fn check_owner(&self) -> Result<(), SourceError> {
        let owner: String = bus(&self.connection)
            .await?
            .call("GetNameOwner", &(DESTINATION,))
            .await
            .map_err(bus_error)?;
        if owner != self.owner {
            return Err(SourceError::Unavailable);
        }
        Ok(())
    }

    async fn item(
        &self,
        encrypted: &EncryptedService,
        path: &OwnedObjectPath,
        expected: &HashMap<&str, &str>,
    ) -> Result<Item, SourceError> {
        self.check_owner().await?;
        for collection in encrypted.collections().await.map_err(source_error)? {
            for item in collection
                .search_items(expected)
                .await
                .map_err(source_error)?
            {
                if item.path().as_str() != path.as_str() {
                    continue;
                }
                let actual = item.attributes().await.map_err(source_error)?;
                if expected
                    .iter()
                    .any(|(key, value)| actual.get(*key).map(String::as_str) != Some(*value))
                {
                    return Err(SourceError::Internal);
                }
                self.check_owner().await?;
                return Ok(item);
            }
        }
        Err(SourceError::Missing)
    }

    async fn find(&self, account: Uuid) -> Result<Option<OwnedObjectPath>, SourceError> {
        let account = account.to_string();
        let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
            .proxy(ROOT, SERVICE)
            .await?
            .call("SearchItems", &(attributes(&account),))
            .await
            .map_err(bus_error)?;
        if unlocked.len().saturating_add(locked.len()) > 1 {
            return Err(SourceError::Internal);
        }
        if !locked.is_empty() {
            return Err(SourceError::Locked);
        }
        Ok(unlocked.pop())
    }

    async fn default_collection(&self) -> Result<OwnedObjectPath, SourceError> {
        let path: OwnedObjectPath = self
            .proxy(ROOT, SERVICE)
            .await?
            .call("ReadAlias", &("default",))
            .await
            .map_err(bus_error)?;
        if path.as_str() == "/" {
            return Err(SourceError::Unavailable);
        }
        let locked: bool = self
            .proxy(path.as_str(), COLLECTION)
            .await?
            .get_property("Locked")
            .await
            .map_err(bus_error)?;
        if locked {
            return Err(SourceError::Locked);
        }
        Ok(path)
    }

    async fn encrypted(&self) -> Result<EncryptedService, SourceError> {
        self.check_owner().await?;
        let service = EncryptedService::encrypted().await.map_err(source_error)?;
        self.check_owner().await?;
        Ok(service)
    }

    async fn create_staging_item(&self, pending: &str) -> Result<OwnedObjectPath, SourceError> {
        let collection = self.default_collection().await?;
        let (_, session): (OwnedValue, OwnedObjectPath) = self
            .proxy(ROOT, SERVICE)
            .await?
            .call("OpenSession", &("plain", Value::from("")))
            .await
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
        // Only an empty unpublished item uses the plain session. oo7 encrypts
        // the actual secret before the account's attributes are published.
        let secret = (&session, Vec::<u8>::new(), Vec::<u8>::new(), "text/plain");
        let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = self
            .proxy(collection.as_str(), COLLECTION)
            .await?
            .call("CreateItem", &(properties, secret, false))
            .await
            .map_err(bus_error)?;
        self.reject_prompt(&prompt).await?;
        if item.as_str() == "/" {
            return Err(SourceError::Unavailable);
        }
        Ok(item)
    }

    async fn delete(&self, path: &OwnedObjectPath) -> Result<(), SourceError> {
        let prompt = self
            .proxy(path.as_str(), ITEM)
            .await?
            .call("Delete", &())
            .await
            .map_err(bus_error)?;
        self.reject_prompt(&prompt).await
    }

    async fn reject_prompt(&self, path: &OwnedObjectPath) -> Result<(), SourceError> {
        if path.as_str() == "/" {
            return Ok(());
        }
        if let Ok(prompt) = self
            .proxy(path.as_str(), "org.freedesktop.Secret.Prompt")
            .await
        {
            let _: Result<(), _> = prompt.call("Dismiss", &()).await;
        }
        Err(SourceError::InteractionRequired)
    }
}

async fn bus(connection: &Connection) -> Result<Proxy<'static>, SourceError> {
    Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .map_err(bus_error)
}

fn attributes(account: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE_NAME), ("username", account)])
}

fn staging_attributes(pending: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE_NAME), ("mailctl-pending", pending)])
}

fn source_error(error: oo7::dbus::Error) -> SourceError {
    use oo7::dbus::{Error, ServiceError};
    match error {
        Error::Service(ServiceError::IsLocked(_)) => SourceError::Locked,
        Error::Service(ServiceError::NoSuchObject(_)) | Error::Deleted | Error::NotFound(_) => {
            SourceError::Missing
        }
        Error::Service(ServiceError::NoSession(_)) | Error::IO(_) => SourceError::Unavailable,
        Error::Dismissed => SourceError::InteractionRequired,
        Error::ZBus(error) | Error::Service(ServiceError::ZBus(error)) => bus_error(error),
        Error::Crypto(_) => SourceError::Internal,
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

#[cfg(test)]
mod tests {
    use super::{SourceError, run};

    #[test]
    fn provider_panics_return_a_safe_failure() {
        assert_eq!(
            run::<()>(std::future::poll_fn(|_| {
                panic!("fixture-private-provider-data")
            })),
            Err(SourceError::Internal)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_source_bridge_can_run_inside_an_active_runtime() {
        assert_eq!(run(async { Ok(()) }), Ok(()));
    }
}
