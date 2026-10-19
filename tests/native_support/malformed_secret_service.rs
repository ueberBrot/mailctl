use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;
use zbus::{
    Proxy,
    connection::Builder,
    interface,
    zvariant::{OwnedObjectPath, OwnedValue, Type, Value},
};

const DESTINATION: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
const COLLECTION: &str = "/org/freedesktop/secrets/collection/fixture";
const ITEM: &str = "/org/freedesktop/secrets/collection/fixture/item";
const SESSION: &str = "/org/freedesktop/secrets/session/fixture";

struct State {
    account: String,
    collection: OwnedObjectPath,
    item: OwnedObjectPath,
    session: OwnedObjectPath,
    reads: AtomicUsize,
    closes: AtomicUsize,
    locked: bool,
    timestamp: u64,
}

impl State {
    fn matches(&self, attributes: &HashMap<String, String>) -> bool {
        attributes.get("service").map(String::as_str) == Some("mailctl")
            && attributes.get("username") == Some(&self.account)
    }

    fn attributes(&self) -> HashMap<String, String> {
        HashMap::from([
            ("service".into(), "mailctl".into()),
            ("username".into(), self.account.clone()),
        ])
    }
}

struct Service(Arc<State>);

#[interface(interface = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("unlocked", "locked"))]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let items = if self.0.matches(&attributes) {
            vec![self.0.item.clone()]
        } else {
            Vec::new()
        };
        (items, Vec::new())
    }

    #[zbus(out_args("output", "result"))]
    fn open_session(
        &self,
        algorithm: &str,
        _input: OwnedValue,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        if algorithm != "dh-ietf1024-sha256-aes128-cbc-pkcs7" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "encrypted session required".into(),
            ));
        }
        Ok((
            Value::from(vec![2u8]).try_to_owned().unwrap(),
            self.0.session.clone(),
        ))
    }

    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![self.0.collection.clone()]
    }
}

struct Collection(Arc<State>);

#[interface(interface = "org.freedesktop.Secret.Collection")]
impl Collection {
    fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        if self.0.matches(&attributes) {
            vec![self.0.item.clone()]
        } else {
            Vec::new()
        }
    }

    #[zbus(property)]
    fn label(&self) -> &str {
        &self.0.account
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.0.timestamp
    }

    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        vec![self.0.item.clone()]
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.locked
    }
}

#[derive(serde::Serialize, Type)]
struct MalformedSecret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

struct Item(Arc<State>);

#[interface(interface = "org.freedesktop.Secret.Item")]
impl Item {
    fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<MalformedSecret> {
        if session != self.0.session {
            return Err(zbus::fdo::Error::InvalidArgs(
                "unknown fixture session".into(),
            ));
        }
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        Ok(MalformedSecret {
            session,
            parameters: Vec::new(),
            value: Vec::new(),
            content_type: "text/plain".into(),
        })
    }

    #[zbus(property)]
    fn label(&self) -> &str {
        &self.0.account
    }

    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        self.0.attributes()
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        self.0.timestamp
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.0.timestamp
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.locked
    }
}

struct Session(Arc<State>);

#[interface(interface = "org.freedesktop.Secret.Session")]
impl Session {
    fn close(&self) {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) async fn reject_malformed_secret() {
    use mailctl::{
        config::CredentialSource,
        credentials::{self, SourceError},
    };

    let account = Uuid::new_v4();
    let state = Arc::new(State {
        account: account.to_string(),
        collection: COLLECTION.try_into().unwrap(),
        item: ITEM.try_into().unwrap(),
        session: SESSION.try_into().unwrap(),
        reads: AtomicUsize::new(0),
        closes: AtomicUsize::new(0),
        locked: false,
        timestamp: 0,
    });
    let connection = Builder::session()
        .unwrap()
        .method_timeout(Duration::from_secs(5))
        .serve_at(ROOT, Service(state.clone()))
        .unwrap()
        .serve_at(COLLECTION, Collection(state.clone()))
        .unwrap()
        .serve_at(ITEM, Item(state.clone()))
        .unwrap()
        .serve_at(SESSION, Session(state.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let bus = Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .unwrap();
    let owned: bool = bus.call("NameHasOwner", &(DESTINATION,)).await.unwrap();
    assert!(
        !owned,
        "the real native fixture daemon must be stopped before installing its replacement"
    );
    let acquired: u32 = bus.call("RequestName", &(DESTINATION, 4u32)).await.unwrap();
    assert_eq!(
        acquired, 1,
        "claim only the unowned private fixture service"
    );

    let result = tokio::task::spawn_blocking(move || {
        credentials::source_for(&CredentialSource::Native {}).resolve(account)
    })
    .await
    .expect("native resolution must contain the dependency panic");
    assert_eq!(result.unwrap_err(), SourceError::Internal);
    assert_eq!(
        state.reads.load(Ordering::SeqCst),
        1,
        "the malformed GetSecret response must reach the native adapter"
    );
    drop(bus);
    connection.close().await.unwrap();
}
