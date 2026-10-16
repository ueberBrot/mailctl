#![allow(
    dead_code,
    reason = "integration-test crates use different subsets of these shared fixture helpers"
)]

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

mod command;
use command::DecodeError;
pub use command::{Command, parse as parse_command};
use mailctl::imap::{Limits, TlsMode};
mod client;
pub use client::Client;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer},
};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type Wire = Box<dyn Stream>;
pub type Script = Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct Fixture {
    pub port: u16,
    pub roots: RootCertStore,
    pub probe: Client,
    pub task: JoinHandle<()>,
}

pub async fn fixture(
    mode: TlsMode,
    limits: Limits,
    script: impl FnOnce(Wire) -> Script + Send + 'static,
) -> Fixture {
    fixture_with_name(mode, limits, "127.0.0.1", script).await
}

pub async fn fixture_with_name(
    mode: TlsMode,
    limits: Limits,
    certificate_name: &str,
    script: impl FnOnce(Wire) -> Script + Send + 'static,
) -> Fixture {
    let mut script = Some(script);
    fixture_sessions(mode, limits, certificate_name, 1, move |wire| {
        script.take().unwrap()(wire)
    })
    .await
}

/// Keep the same verified endpoint across operations and continuation requests.
pub async fn repeating_fixture(
    limits: Limits,
    sessions: usize,
    script: impl FnMut(Wire) -> Script + Send + 'static,
) -> Fixture {
    fixture_sessions(TlsMode::Implicit, limits, "127.0.0.1", sessions, script).await
}

async fn fixture_sessions(
    mode: TlsMode,
    limits: Limits,
    certificate_name: &str,
    sessions: usize,
    mut script: impl FnMut(Wire) -> Script + Send + 'static,
) -> Fixture {
    let wrong_hostname = certificate_name != "127.0.0.1";
    let cert = rcgen::generate_simple_self_signed(vec![certificate_name.into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Match the IPv4 listener directly so the operation deadline cannot expire
    // while localhost first attempts an unavailable IPv6 address on Windows.
    let probe = Client::new("127.0.0.1".into(), port, mode, roots.clone(), limits).unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..sessions {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("fixture connection deadline")
                .unwrap();
            if matches!(mode, TlsMode::StartTls) {
                write(&mut socket, "* OK synthetic server ready\r\n").await;
                capability(&mut socket, "IMAP4rev1 STARTTLS LOGINDISABLED").await;
                let tag = expect(&mut socket, "STARTTLS").await;
                write(&mut socket, &format!("{tag} OK begin TLS\r\n")).await;
            }
            match acceptor.accept(socket).await {
                Ok(mut socket) => {
                    if matches!(mode, TlsMode::Implicit) {
                        write(&mut socket, "* OK synthetic server ready\r\n").await;
                    }
                    script(Box::new(socket)).await;
                }
                Err(_) if wrong_hostname => {}
                Err(error) => panic!("fixture TLS handshake failed: {error}"),
            }
        }
    });
    Fixture {
        probe,
        task,
        port,
        roots,
    }
}

pub async fn write<S: AsyncWrite + Unpin + ?Sized>(wire: &mut S, response: &str) {
    wire.write_all(response.as_bytes()).await.unwrap();
    wire.flush().await.unwrap();
}

pub async fn literal_bytes(
    wire: &mut Wire,
    section: &str,
    offset: usize,
    count: usize,
    value: &[u8],
) {
    let tag = expect(
        wire,
        &format!("UID FETCH 4 (UID BODY.PEEK[{section}]<{offset}.{count}>)"),
    )
    .await;
    write(
        wire,
        &format!(
            "* 1 FETCH (UID 4 BODY[{section}]<{offset}> {{{}}}\r\n",
            value.len()
        ),
    )
    .await;
    wire.write_all(value).await.unwrap();
    write(wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
}

/// Observe a bounded command independently of the production wire guard.
/// EOF, reset, or abort before a command is allowed; partial commands and stalls fail the fixture.
pub async fn observe_command(wire: &mut Wire, deadline: Duration) -> Option<Command> {
    tokio::time::timeout(deadline, async {
        let mut input = Vec::new();
        loop {
            match wire.read_u8().await {
                Ok(byte) => input.push(byte),
                Err(error)
                    if input.is_empty()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                {
                    return None;
                }
                Err(error) => panic!(
                    "incomplete independently observed command: kind={:?} bytes={}",
                    error.kind(),
                    input.len()
                ),
            }
            assert!(
                input.len() <= 1024,
                "independently observed command ceiling"
            );
            if input.ends_with(b"\r\n") {
                return Some(parse_command(&input).expect("independently observed command syntax"));
            }
        }
    })
    .await
    .expect("independent command observation deadline")
}

/// Compare lexical argument values, leaving tags and string framing unconstrained.
pub async fn expect<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    wire: &mut S,
    body: &str,
) -> String {
    let expected = parse_command(format!("expected {body}\r\n").as_bytes())
        .expect("valid independent command");
    let mut input = Vec::new();
    let mut last_continuation = 0;
    loop {
        let byte = tokio::time::timeout(Duration::from_secs(5), wire.read_u8())
            .await
            .expect("command deadline")
            .expect("command EOF");
        input.push(byte);
        assert!(input.len() <= 16 * 1024, "fixture command bound");
        match parse_command(&input) {
            Ok(actual) => {
                assert_eq!(actual.body, expected.body, "unexpected IMAP command");
                return actual.tag;
            }
            Err(DecodeError::Incomplete) => {}
            Err(DecodeError::Literal { boundary }) => {
                if input.len() == boundary && boundary != last_continuation {
                    last_continuation = boundary;
                    write(wire, "+ literal accepted\r\n").await;
                }
            }
            Err(error) => panic!("malformed command: {error:?}"),
        }
    }
}

pub async fn capability<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    wire: &mut S,
    capabilities: &str,
) {
    let tag = expect(wire, "CAPABILITY").await;
    write(
        wire,
        &format!("* CAPABILITY {capabilities}\r\n{tag} OK capabilities\r\n"),
    )
    .await;
}

pub async fn authenticate(wire: &mut Wire) {
    capability(wire, "IMAP4rev1").await;
    let tag = expect(wire, "LOGIN \"fixture\" \"disposable-password\"").await;
    write(wire, &format!("{tag} OK authenticated\r\n")).await;
    capability(wire, "IMAP4rev1 UIDPLUS").await;
}

pub async fn examine(wire: &mut Wire) {
    let tag = expect(wire, "EXAMINE INBOX").await;
    write(wire, &format!("* FLAGS (\\Seen \\Answered)\r\n* 2 EXISTS\r\n* OK [UIDVALIDITY 77] identity\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
}

pub async fn logout(wire: &mut Wire) {
    let tag = expect(wire, "LOGOUT").await;
    write(wire, &format!("* BYE closing\r\n{tag} OK logout\r\n")).await;
}

pub async fn dropped(wire: &mut Wire) {
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(3), wire.read(&mut byte))
        .await
        .expect("connection must be disposed");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "unexpected command after terminal failure"
    );
}

/// Poll deliberately deep published-parser fixtures on the executable's worker stack.
/// Process-driver tests separately retain their constrained 1 MiB lifecycle caller.
pub fn protocol_stack(operation: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(operation)
        .unwrap()
        .join()
        .unwrap();
}

pub fn protocol_runtime(operation: impl Future<Output = ()> + Send + 'static) {
    protocol_stack(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(operation);
    });
}

/// Keep fixture allocations on a separate thread from the measured client runtime.
pub fn dedicated_fixture(
    mode: TlsMode,
    limits: Limits,
    script: impl FnOnce(Wire) -> Script + Send + 'static,
) -> (Client, std::thread::JoinHandle<()>) {
    let mut script = Some(script);
    dedicated_sessions(mode, limits, 1, move |wire| script.take().unwrap()(wire))
}

/// Measure successive reads against the same endpoint without counting server allocations.
pub fn dedicated_sessions(
    mode: TlsMode,
    limits: Limits,
    sessions: usize,
    script: impl FnMut(Wire) -> Script + Send + 'static,
) -> (Client, std::thread::JoinHandle<()>) {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let Fixture { probe, task, .. } =
                fixture_sessions(mode, limits, "127.0.0.1", sessions, script).await;
            send.send(probe).unwrap();
            task.await.unwrap();
        });
    });
    (receive.recv().unwrap(), server)
}

pub async fn plaintext_fixture(
    limits: Limits,
    script: impl FnOnce(Wire) -> Script + Send + 'static,
) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let probe = Client::new(
        "127.0.0.1".into(),
        port,
        TlsMode::StartTls,
        RootCertStore::empty(),
        limits,
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("fixture connection deadline")
            .unwrap();
        script(Box::new(socket)).await;
    });
    Fixture {
        probe,
        task,
        port,
        roots: RootCertStore::empty(),
    }
}

/// Counts bytes independently at the synthetic server's decrypted write boundary.
pub struct CountedWire {
    pub wire: Wire,
    pub written: Arc<AtomicUsize>,
}

impl AsyncRead for CountedWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(context, buffer)
    }
}

impl AsyncWrite for CountedWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.wire).poll_write(context, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.written.fetch_add(*count, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.wire).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.wire).poll_shutdown(context)
    }
}
