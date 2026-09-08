#![cfg(unix)]

use mailctl::ipc::serialize_bounded;
use serde_json::json;

#[test]
fn response_serialization_stops_at_the_frame_ceiling() {
    assert_eq!(
        serialize_bounded(&json!({"ok": true}), 11).unwrap(),
        br#"{"ok":true}"#
    );
    assert_eq!(
        serialize_bounded(&json!({"ok": true}), 10)
            .unwrap_err()
            .code,
        mailctl::domain::ErrorCode::ResponseTooLarge
    );
}

use mailctl::{
    config::Config,
    domain::{ErrorCode, ListAccountsInput, Operation},
    ipc::{Broker, Client},
    policy::Narrowing,
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::oneshot,
    time::timeout,
};

struct Fixture {
    directory: PathBuf,
    config: Config,
}
impl Fixture {
    fn new() -> Self {
        let directory = fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("mailctl-ipc-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let config = Config::parse(&format!(
            r#"
version = 1
deployment = "cooperative"
topology = "native"
state_dir = "{}"
[limits]
ipc_frame_bytes = 4096
buffered_bytes = 65536
handshake_seconds = 1
operation_seconds = 2
connection_seconds = 1
[[accounts]]
key = "first"
alias = "First"
server = "localhost"
username = "fixture-first"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["first"]
drafts_mailbox = "Drafts"
credential = {{source = "native"}}
[[accounts]]
key = "second"
alias = "Second"
server = "localhost"
username = "fixture-second"
mailboxes = ["INBOX", "Drafts"]
from_identities = ["second"]
drafts_mailbox = "Drafts"
credential = {{source = "native"}}
[[listeners]]
name = "first"
endpoint = "{}/first.sock"
peer_uids = [{}]
accounts = ["first"]
mailboxes = ["INBOX"]
[[listeners]]
name = "second"
endpoint = "{}/second.sock"
peer_uids = [{}]
profile = "drafts_only"
accounts = ["second"]
mailboxes = ["Drafts"]
"#,
            directory.display(),
            directory.display(),
            uid,
            directory.display(),
            uid
        ))
        .unwrap();
        Self { directory, config }
    }
    fn endpoint(&self, name: &str) -> PathBuf {
        self.directory.join(format!("{name}.sock"))
    }
    fn start(&self) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let broker = Broker::bind(self.config.clone()).unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            broker
                .run(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        (stop, task)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
async fn send(stream: &mut UnixStream, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).unwrap();
    stream.write_u32(bytes.len() as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}
async fn receive(stream: &mut UnixStream) -> serde_json::Value {
    let length = timeout(Duration::from_secs(3), stream.read_u32())
        .await
        .unwrap()
        .unwrap();
    assert!(length <= 4096);
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
async fn raw(fixture: &Fixture, listener: &str) -> UnixStream {
    let mut stream = UnixStream::connect(fixture.endpoint(listener))
        .await
        .unwrap();
    send(
        &mut stream,
        json!({"type":"hello","version":1,"client_name":"forged-admin","narrowing":{}}),
    )
    .await;
    assert_eq!(receive(&mut stream).await["version"], 1);
    stream
}
async fn closed(stream: &mut UnixStream) {
    let mut byte = [0];
    let read = timeout(Duration::from_secs(3), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "connection remained usable: {read:?}"
    );
}
async fn stop(stop: oneshot::Sender<()>, task: tokio::task::JoinHandle<()>) {
    stop.send(()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn real_listeners_authenticate_and_filter_discovery_independently() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    for (listener, expected) in [("first", "First"), ("second", "Second")] {
        let mut client = Client::connect(
            &fixture.endpoint(listener),
            rustix::process::geteuid().as_raw(),
            Narrowing::default(),
        )
        .await
        .unwrap();
        let response = client
            .request(
                "one",
                Operation::ListAccounts(ListAccountsInput { limit: None }),
            )
            .await
            .unwrap();
        assert_eq!(
            response.result.as_ref().unwrap()["accounts"][0]["alias"],
            expected
        );
        assert_eq!(
            response.result.unwrap()["accounts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    stop(shutdown, task).await;
    assert!(!fixture.endpoint("first").exists());
}

#[tokio::test]
async fn raw_requests_cannot_widen_session_narrowing_or_forge_authority() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    let mut stream = UnixStream::connect(fixture.endpoint("second"))
        .await
        .unwrap();
    send(&mut stream, json!({"type":"hello","version":1,"client_name":"administrator","narrowing":{"read_only":true,"accounts":[]}})).await;
    let welcome = receive(&mut stream).await;
    assert_eq!(
        welcome["effective"]["permissions"],
        json!(["list_accounts"])
    );
    send(&mut stream, json!({"type":"request","request_id":"one","request":{"operation":"list_accounts","input":{}},"narrowing":{"read_only":false,"accounts":["first","second"]}})).await;
    assert_eq!(receive(&mut stream).await["result"]["accounts"], json!([]));
    stop(shutdown, task).await;
}

#[tokio::test]
async fn invalid_version_and_unknown_handshake_fields_have_safe_errors() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    for (hello, expected) in [
        (json!({"type":"hello","version":2}), "protocol_mismatch"),
        (
            json!({"type":"hello","version":1,"profile":"read_and_drafts"}),
            "invalid_request",
        ),
    ] {
        let mut stream = UnixStream::connect(fixture.endpoint("first"))
            .await
            .unwrap();
        send(&mut stream, hello).await;
        assert_eq!(receive(&mut stream).await["error"]["code"], expected);
        closed(&mut stream).await;
    }
    stop(shutdown, task).await;
}

#[tokio::test]
async fn zero_and_oversized_prefixes_close_without_waiting_for_payload() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    for length in [0, 4097, u32::MAX] {
        let mut stream = raw(&fixture, "first").await;
        stream.write_u32(length).await.unwrap();
        closed(&mut stream).await;
    }
    stop(shutdown, task).await;
}

#[tokio::test]
async fn malformed_utf8_unknown_fields_deep_json_and_duplicate_ids_close() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    for bytes in [vec![0xff], deep.into_bytes(), br#"{"type":"request","request_id":"one","request":{"operation":"capabilities"},"profile":"read_and_drafts"}"#.to_vec()] {
        let mut stream = raw(&fixture, "first").await;
        stream.write_u32(bytes.len() as u32).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        closed(&mut stream).await;
    }
    let mut stream = raw(&fixture, "first").await;
    let request =
        json!({"type":"request","request_id":"same","request":{"operation":"capabilities"}});
    send(&mut stream, request.clone()).await;
    receive(&mut stream).await;
    send(&mut stream, request).await;
    closed(&mut stream).await;
    stop(shutdown, task).await;
}

#[tokio::test]
async fn endpoint_peer_and_private_state_checks_fail_closed() {
    let mut fixture = Fixture::new();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(Broker::bind(fixture.config.clone()), Err(error) if error.code == ErrorCode::PermissionDenied)
    );
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(fixture.endpoint("first"), "not a socket").unwrap();
    assert!(
        matches!(Broker::bind(fixture.config.clone()), Err(error) if error.code == ErrorCode::PermissionDenied)
    );
    fs::remove_file(fixture.endpoint("first")).unwrap();
    symlink(fixture.directory.join("target"), fixture.endpoint("first")).unwrap();
    assert!(
        matches!(Broker::bind(fixture.config.clone()), Err(error) if error.code == ErrorCode::PermissionDenied)
    );
    fs::remove_file(fixture.endpoint("first")).unwrap();
    fixture.config.listeners[0].peer_uids =
        vec![rustix::process::geteuid().as_raw().wrapping_add(1)];
    let (shutdown, task) = fixture.start();
    let mut stream = UnixStream::connect(fixture.endpoint("first"))
        .await
        .unwrap();
    closed(&mut stream).await;
    assert!(
        matches!(Client::connect(&fixture.endpoint("second"), rustix::process::geteuid().as_raw().wrapping_add(1), Narrowing::default()).await,
        Err(error) if error.code == ErrorCode::PermissionDenied)
    );
    stop(shutdown, task).await;
}

#[tokio::test]
async fn state_lock_excludes_a_second_broker_and_releases_on_shutdown() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    assert!(
        matches!(Broker::bind(fixture.config.clone()), Err(error) if error.code == ErrorCode::BrokerUnavailable)
    );
    stop(shutdown, task).await;
    let (shutdown, task) = fixture.start();
    stop(shutdown, task).await;
}

#[tokio::test]
async fn operational_listener_failure_preserves_other_authorized_reads() {
    let mut fixture = Fixture::new();
    fixture.config.listeners[1].endpoint = fixture.directory.join("missing/second.sock");
    let (shutdown, task) = fixture.start();
    let mut client = Client::connect(
        &fixture.endpoint("first"),
        rustix::process::geteuid().as_raw(),
        Narrowing::default(),
    )
    .await
    .unwrap();
    assert!(
        client
            .request("health", Operation::Health)
            .await
            .unwrap()
            .success
    );
    stop(shutdown, task).await;
}

#[tokio::test]
async fn slow_handshakes_release_capacity_and_other_listener_keeps_serving() {
    let mut fixture = Fixture::new();
    fixture.config.listeners[0].limits.handshakes = 1;
    let (shutdown, task) = fixture.start();
    let mut slow = UnixStream::connect(fixture.endpoint("first"))
        .await
        .unwrap();
    slow.write_u32(40).await.unwrap();
    let mut healthy = raw(&fixture, "second").await;
    send(
        &mut healthy,
        json!({"type":"request","request_id":"one","request":{"operation":"capabilities"}}),
    )
    .await;
    assert!(receive(&mut healthy).await["result"].is_object());
    closed(&mut slow).await;
    let mut replacement = raw(&fixture, "first").await;
    send(
        &mut replacement,
        json!({"type":"request","request_id":"one","request":{"operation":"capabilities"}}),
    )
    .await;
    assert!(receive(&mut replacement).await["result"].is_object());
    stop(shutdown, task).await;
}

#[tokio::test]
async fn exact_frame_ceiling_is_accepted_and_listener_byte_exhaustion_is_local() {
    let mut fixture = Fixture::new();
    fixture.config.listeners[0].limits.buffered_bytes = 3 * 4096 + 192;
    let (shutdown, task) = fixture.start();
    let mut exact = raw(&fixture, "second").await;
    let mut bytes =
        br#"{"type":"request","request_id":"exact","request":{"operation":"capabilities"}}"#
            .to_vec();
    bytes.resize(4096, b' ');
    exact.write_u32(4096).await.unwrap();
    exact.write_all(&bytes).await.unwrap();
    assert!(receive(&mut exact).await["result"].is_object());

    let mut slow = raw(&fixture, "first").await;
    let mut excess = raw(&fixture, "first").await;
    slow.write_u32(4096).await.unwrap();
    // Both payloads reserve capacity from the same listener before allocating.
    excess.write_u32(4096).await.unwrap();
    closed(&mut excess).await;
    send(
        &mut exact,
        json!({"type":"request","request_id":"healthy","request":{"operation":"capabilities"}}),
    )
    .await;
    assert!(receive(&mut exact).await["result"].is_object());
    closed(&mut slow).await;
    stop(shutdown, task).await;
}

#[tokio::test]
async fn connected_clients_are_bounded_before_handshake() {
    let mut fixture = Fixture::new();
    fixture.config.listeners[0].limits.clients = 1;
    fixture.config.listeners[0].limits.handshakes = 1;
    fixture.config.listeners[0].limits.active_requests = 1;
    let (shutdown, task) = fixture.start();
    let mut existing = raw(&fixture, "first").await;
    let mut rejected = UnixStream::connect(fixture.endpoint("first"))
        .await
        .unwrap();
    closed(&mut rejected).await;
    send(
        &mut existing,
        json!({"type":"request","request_id":"healthy","request":{"operation":"capabilities"}}),
    )
    .await;
    assert!(receive(&mut existing).await["result"].is_object());
    stop(shutdown, task).await;
}

#[tokio::test]
async fn cancellation_is_confined_to_the_request_connection() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    let mut first = raw(&fixture, "first").await;
    let mut second = raw(&fixture, "first").await;
    send(
        &mut first,
        json!({"type":"request","request_id":"foreign","request":{"operation":"capabilities"}}),
    )
    .await;
    send(
        &mut second,
        json!({"type":"cancel","request_id":"cancel","target_request_id":"foreign"}),
    )
    .await;
    assert_eq!(
        receive(&mut second).await["error"]["code"],
        "invalid_request"
    );
    assert!(receive(&mut first).await["result"].is_object());
    send(
        &mut second,
        json!({"type":"request","request_id":"own","request":{"operation":"capabilities"}}),
    )
    .await;
    assert!(receive(&mut second).await["result"].is_object());
    stop(shutdown, task).await;
}

#[tokio::test]
async fn a_replaced_endpoint_is_never_unlinked_by_shutdown() {
    let fixture = Fixture::new();
    let (shutdown, task) = fixture.start();
    fs::remove_file(fixture.endpoint("first")).unwrap();
    fs::write(fixture.endpoint("first"), "replacement").unwrap();
    stop(shutdown, task).await;
    assert_eq!(
        fs::read_to_string(fixture.endpoint("first")).unwrap(),
        "replacement"
    );
}

#[tokio::test]
async fn stale_sockets_are_recovered_but_live_brokers_keep_their_endpoints() {
    let fixture = Fixture::new();
    let stale = std::os::unix::net::UnixListener::bind(fixture.endpoint("first")).unwrap();
    fs::set_permissions(fixture.endpoint("first"), fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let (shutdown, task) = fixture.start();
    let second_state = fixture.directory.join("other-state");
    fs::create_dir(&second_state).unwrap();
    fs::set_permissions(&second_state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut competing = fixture.config.clone();
    competing.state_dir = second_state;
    assert!(
        matches!(Broker::bind(competing), Err(error) if error.code == ErrorCode::BrokerUnavailable)
    );
    let mut client = Client::connect(
        &fixture.endpoint("first"),
        rustix::process::geteuid().as_raw(),
        Narrowing::default(),
    )
    .await
    .unwrap();
    assert!(
        client
            .request("still-live", Operation::Capabilities)
            .await
            .unwrap()
            .success
    );
    stop(shutdown, task).await;
}

#[tokio::test]
async fn requested_isolation_fails_until_an_os_boundary_is_qualified() {
    let mut fixture = Fixture::new();
    fixture.config.deployment = mailctl::config::Deployment::Isolated;
    assert!(
        matches!(Broker::bind(fixture.config.clone()), Err(error) if error.code == ErrorCode::UnsupportedCapability)
    );
    assert!(!fixture.directory.join("broker.lock").exists());
}
