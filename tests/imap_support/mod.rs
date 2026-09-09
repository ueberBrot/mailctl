use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use io_imap::codec::{
    CommandCodec,
    decode::{CommandDecodeError, Decoder},
};
use io_imap::types::command::CommandBody;
use mailctl::imap::{ImapProbe, Limits, TlsMode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
    pub probe: ImapProbe,
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
    let probe = ImapProbe::new("127.0.0.1".into(), port, mode, roots, limits).unwrap();
    let task = tokio::spawn(async move {
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
    });
    Fixture { probe, task }
}

pub async fn write<S: AsyncWrite + Unpin + ?Sized>(wire: &mut S, response: &str) {
    wire.write_all(response.as_bytes()).await.unwrap();
    wire.flush().await.unwrap();
}

/// Compare decoded command bodies, leaving tags and literal framing unconstrained.
pub async fn expect<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    wire: &mut S,
    body: &str,
) -> String {
    let expected = format!("expected {body}\r\n");
    let codec = CommandCodec::new();
    let (_, expected) = codec
        .decode(expected.as_bytes())
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
        match codec.decode(&input) {
            Ok((remaining, actual)) => {
                assert!(remaining.is_empty());
                assert_eq!(
                    normalized(actual.body),
                    normalized(expected.body.clone()),
                    "unexpected IMAP command"
                );
                return actual.tag.as_ref().to_owned();
            }
            Err(CommandDecodeError::Incomplete) => {}
            Err(CommandDecodeError::LiteralFound { .. }) => {
                if input.ends_with(b"\r\n") && input.len() != last_continuation {
                    last_continuation = input.len();
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

/// Keep fixture allocations on a separate thread from the measured client runtime.
pub fn dedicated_fixture(
    mode: TlsMode,
    limits: Limits,
    script: impl FnOnce(Wire) -> Script + Send + 'static,
) -> (ImapProbe, std::thread::JoinHandle<()>) {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let Fixture { probe, task } = fixture(mode, limits, script).await;
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
    let probe = ImapProbe::new(
        "127.0.0.1".into(),
        listener.local_addr().unwrap().port(),
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
    Fixture { probe, task }
}

fn normalized(mut body: CommandBody<'_>) -> CommandBody<'_> {
    use io_imap::types::{
        mailbox::{ListMailbox, Mailbox},
        secret::Secret,
    };
    fn mailbox(value: &mut Mailbox<'_>) {
        if let Mailbox::Other(name) = value {
            *value = name.as_ref().to_vec().try_into().unwrap();
        }
    }
    match &mut body {
        CommandBody::Login { username, password } => {
            *username = username.as_ref().to_vec().try_into().unwrap();
            *password = Secret::new(password.declassify().as_ref().to_vec().try_into().unwrap());
        }
        CommandBody::List {
            reference,
            mailbox_wildcard,
        } => {
            mailbox(reference);
            let value = match mailbox_wildcard {
                ListMailbox::Token(value) => value.as_ref().to_vec(),
                ListMailbox::String(value) => value.as_ref().to_vec(),
            };
            *mailbox_wildcard = String::from_utf8(value).unwrap().try_into().unwrap();
        }
        CommandBody::Examine { mailbox: name, .. } => mailbox(name),
        _ => {}
    }
    body
}
