#![allow(
    dead_code,
    reason = "integration-test crates use different subsets of these shared fixture helpers"
)]

use super::imap_support;
use std::{
    collections::VecDeque,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::watch;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer},
};

struct Expected {
    username: &'static str,
    password: &'static str,
    operation: ExpectedOperation,
}

enum ExpectedOperation {
    Authenticate,
    Append(DraftReply),
    RejectAuthentication(bool),
    Mailboxes(Vec<&'static str>),
    Search(&'static str, Option<u32>),
    Body(&'static str, Vec<u8>),
    Attachment(&'static str, AttachmentPhase),
}

#[derive(Clone)]
pub enum DraftReply {
    Created(bool),
    Rejected,
    Disconnect,
    Hold(Arc<AtomicUsize>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AttachmentPhase {
    List,
    Start,
    Continue,
    Interrupted,
}

pub struct ImapServer {
    pub port: u16,
    pub certificate: PathBuf,
    expected: Arc<Mutex<VecDeque<Expected>>>,
    accepted: Arc<AtomicUsize>,
    interrupted: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
    task: Option<thread::JoinHandle<()>>,
}

impl ImapServer {
    pub fn new(directory: &Path) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate = directory.join("fixture-ca.pem");
        fs::write(&certificate, cert.cert.pem()).unwrap();
        let tls = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected = Arc::new(Mutex::new(VecDeque::<Expected>::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let (stop, mut stopping) = watch::channel(false);
        let queue = expected.clone();
        let count = accepted.clone();
        let interrupted = Arc::new(AtomicUsize::new(0));
        let stalled = interrupted.clone();
        let task = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let acceptor = TlsAcceptor::from(Arc::new(tls));
                loop {
                    let socket = tokio::select! {
                        _ = stopping.changed() => return,
                        connection = listener.accept() => connection.unwrap().0,
                    };
                    count.fetch_add(1, Ordering::SeqCst);
                    let Expected { username, password, operation } = queue.lock().unwrap().pop_front().expect("unexpected provider connection");
                    tokio::select! {
                        _ = stopping.changed() => return,
                        result = tokio::time::timeout(Duration::from_secs(10), async {
                            let mut wire: imap_support::Wire = Box::new(acceptor.accept(socket).await.unwrap());
                            imap_support::write(&mut wire, "* OK synthetic server ready\r\n").await;
                            imap_support::capability(&mut wire, "IMAP4rev1").await;
                            let tag = imap_support::expect(&mut wire, &format!("LOGIN \"{username}\" \"{password}\"")).await;
                            if let ExpectedOperation::RejectAuthentication(malformed) = operation {
                                let payload = if malformed { "fixture-private-provider-secret \u{1b}]52;c;payload\u{7}\u{202e}" } else { "fixture-private-provider-secret" };
                                imap_support::write(&mut wire, &format!("{tag} NO {payload}\r\n")).await;
                                use tokio::io::AsyncReadExt;
                                let end = wire.read(&mut [0]).await;
                                assert!(matches!(end, Ok(0)) || end.is_err());
                                return;
                            }
                            imap_support::write(&mut wire, &format!("{tag} OK authenticated\r\n")).await;
                            imap_support::capability(&mut wire, "IMAP4rev1").await;
                            match operation {
                                ExpectedOperation::Authenticate => {},
                                ExpectedOperation::Append(reply) => {
                                    let tag = imap_support::expect(&mut wire, "EXAMINE Drafts").await;
                                    imap_support::write(&mut wire, &format!("* 0 EXISTS\r\n* OK [UIDVALIDITY 77] incarnation\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                                    append_draft(&mut wire, reply, &stalled).await;
                                    return;
                                },
                                ExpectedOperation::RejectAuthentication(_) => unreachable!(),
                                ExpectedOperation::Mailboxes(mailboxes) => {
                                    for name in mailboxes {
                                        let tag = imap_support::expect(&mut wire, &format!("LIST \"\" {name}")).await;
                                        let attributes = if name == "Archive" { "\\Archive" } else { "" };
                                        imap_support::write(&mut wire, &format!("* LIST ({attributes}) \"/\" {name}\r\n{tag} OK listed\r\n")).await;
                                    }
                                }
                                ExpectedOperation::Search(mailbox, position) => search_page(&mut wire, mailbox, position).await,
                                ExpectedOperation::Body(mailbox, text) => body_page(&mut wire, mailbox, &text).await,
                                ExpectedOperation::Attachment(mailbox, phase) => {
                                    attachment_page(&mut wire, mailbox, phase, &stalled).await;
                                    if phase == AttachmentPhase::Interrupted { return; }
                                },
                            }
                            imap_support::logout(&mut wire).await;
                        }) => result.expect("IMAP authentication transcript deadline"),
                    }
                }
            });
        });
        Self {
            port,
            certificate,
            expected,
            accepted,
            interrupted,
            stop,
            task: Some(task),
        }
    }

    pub fn expect_append(&self, reply: DraftReply) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Append(reply),
        });
    }

    pub fn interrupted(&self) -> usize {
        self.interrupted.load(Ordering::SeqCst)
    }

    pub fn expect(&self, username: &'static str, password: &'static str) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::Authenticate,
        });
    }

    pub fn reject_authentication(&self, malformed: bool) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::RejectAuthentication(malformed),
        });
    }

    pub fn expect_mailboxes(
        &self,
        username: &'static str,
        password: &'static str,
        mailboxes: &[&'static str],
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::Mailboxes(mailboxes.to_vec()),
        });
    }

    pub fn expect_search(
        &self,
        username: &'static str,
        password: &'static str,
        mailbox: &'static str,
        position: Option<u32>,
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::Search(mailbox, position),
        });
    }

    pub fn expect_body(
        &self,
        username: &'static str,
        password: &'static str,
        mailbox: &'static str,
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::Body(mailbox, b"Short body.\r\n".to_vec()),
        });
    }

    pub fn expect_body_bytes(&self, mailbox: &'static str, text: &[u8]) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Body(mailbox, text.to_vec()),
        });
    }

    pub fn expect_attachment(
        &self,
        username: &'static str,
        password: &'static str,
        mailbox: &'static str,
        payload: AttachmentPhase,
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::Attachment(mailbox, payload),
        });
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub fn finish(&mut self) {
        let _ = self.stop.send(true);
        self.task
            .take()
            .unwrap()
            .join()
            .expect("IMAP authentication transcript");
        assert!(
            self.expected.lock().unwrap().is_empty(),
            "every expected authentication occurred"
        );
    }
}

async fn search_page(wire: &mut imap_support::Wire, mailbox: &str, position: Option<u32>) {
    use imap_support::{expect, write};
    let tag = expect(wire, &format!("EXAMINE {mailbox}")).await;
    write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    if position.is_none() {
        let tag = expect(wire, "UID SEARCH UID *").await;
        write(wire, &format!("* SEARCH 3\r\n{tag} OK boundary\r\n")).await;
    }
    let uid = position.unwrap_or(3);
    let range = if uid == 1 {
        "1".to_owned()
    } else {
        format!("1:{uid}")
    };
    let tag = expect(wire, &format!("UID SEARCH UID {range}")).await;
    let matches = (1..=uid)
        .map(|uid| uid.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    write(
        wire,
        &format!("* SEARCH {matches}\r\n{tag} OK searched\r\n"),
    )
    .await;
    let tag = expect(
        wire,
        &format!("UID FETCH {uid} (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)"),
    )
    .await;
    let flags = if uid == 1 { "" } else { "\\Seen" };
    let subject = format!("Search fixture {uid} {}", "x".repeat(12000));
    write(wire, &format!("* {uid} FETCH (UID {uid} ENVELOPE (NIL \"{subject}\" NIL NIL NIL NIL NIL NIL NIL \"<search-{uid}@example.test>\") FLAGS ({flags}) INTERNALDATE \"01-Sep-2026 12:00:00 +0000\" RFC822.SIZE 13000)\r\n{tag} OK fetched\r\n")).await;
}

async fn body_page(wire: &mut imap_support::Wire, mailbox: &str, text: &[u8]) {
    use imap_support::{expect, write};
    let encoded;
    let (encoding, text) = if text == b"Short body.\r\n" {
        ("7BIT", text)
    } else {
        use base64::{Engine, engine::general_purpose::STANDARD};
        encoded = STANDARD.encode(text);
        ("BASE64", encoded.as_bytes())
    };
    let tag = expect(wire, &format!("EXAMINE {mailbox}")).await;
    write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    let tag = expect(wire, "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(wire, &format!("* 3 FETCH (UID 3 RFC822.SIZE 3000300 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"{encoding}\" {} 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" NIL) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n", text.len())).await;
    for (section, count, value) in [
        (
            "HEADER",
            16384,
            b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n"
                .as_slice(),
        ),
        ("1", text.len() + 1, text),
    ] {
        let tag = expect(
            wire,
            &format!("UID FETCH 3 (UID BODY.PEEK[{section}]<0.{count}>)"),
        )
        .await;
        write(
            wire,
            &format!(
                "* 3 FETCH (UID 3 BODY[{section}]<0> {{{}}}\r\n",
                value.len()
            ),
        )
        .await;
        use tokio::io::AsyncWriteExt;
        wire.write_all(value).await.unwrap();
        write(wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
    }
}

impl Drop for ImapServer {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

async fn attachment_page(
    wire: &mut imap_support::Wire,
    mailbox: &str,
    payload: AttachmentPhase,
    interrupted: &AtomicUsize,
) {
    use imap_support::{expect, write};
    let tag = expect(wire, &format!("EXAMINE {mailbox}")).await;
    write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    if payload != AttachmentPhase::Continue {
        let tag = expect(wire, "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)").await;
        write(wire, &format!("* 3 FETCH (UID 3 RFC822.SIZE 3000300 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 8 NIL (\"ATTACHMENT\" (\"FILENAME\" \"fixture.bin\")) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
    }
    if payload == AttachmentPhase::Interrupted {
        use tokio::io::AsyncReadExt;
        expect(wire, "UID FETCH 3 (UID BODY.PEEK[2]<0.16384>)").await;
        interrupted.fetch_add(1, Ordering::SeqCst);
        let closed = wire.read(&mut [0]).await;
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof),
            "cancelled export disposes the connection"
        );
    }
    if payload == AttachmentPhase::Start {
        let tag = expect(wire, "UID FETCH 3 (UID BODY.PEEK[2]<0.16384>)").await;
        write(
            wire,
            &format!("* 3 FETCH (UID 3 BODY[2]<0> {{8}}\r\nYWJjZGVm)\r\n{tag} OK fetched\r\n"),
        )
        .await;
    }
}

async fn append_draft(wire: &mut imap_support::Wire, reply: DraftReply, observed: &AtomicUsize) {
    use io_imap::codec::{CommandCodec, decode::Decoder};
    use tokio::io::AsyncReadExt;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n") {
        header.push(wire.read_u8().await.unwrap());
        assert!(header.len() < 4096);
    }
    let text = std::str::from_utf8(&header).unwrap();
    let (prefix, length) = text.rsplit_once('{').unwrap();
    let length: usize = length.strip_suffix("}\r\n").unwrap().parse().unwrap();
    assert!(length < 1024 * 1024);
    let command = format!("{prefix}{{0}}\r\n\r\n");
    let codec = CommandCodec::new();
    let (_, actual) = codec.decode(command.as_bytes()).unwrap();
    let (_, expected) = codec
        .decode(b"expected APPEND Drafts (\\Draft) {0}\r\n\r\n")
        .unwrap();
    assert_eq!(actual.body, expected.body);
    let tag = actual.tag.as_ref().to_owned();
    imap_support::write(wire, "+ continue\r\n").await;
    let mut literal = vec![0; length];
    wire.read_exact(&mut literal).await.unwrap();
    let mut ending = [0; 2];
    wire.read_exact(&mut ending).await.unwrap();
    assert_eq!(&ending, b"\r\n");
    let text = std::str::from_utf8(&literal).unwrap();
    assert!(text.contains("Message-ID: <"));
    assert!(text.contains("@mailctl.invalid>"));
    assert!(text.contains("Content-Type: text/plain"));
    observed.fetch_add(1, Ordering::SeqCst);
    match reply {
        DraftReply::Created(uid) => {
            imap_support::write(
                wire,
                &format!(
                    "{tag} OK{} accepted\r\n",
                    if uid { " [APPENDUID 77 4]" } else { "" }
                ),
            )
            .await
        }
        DraftReply::Rejected => {
            imap_support::write(wire, &format!("{tag} NO synthetic rejection\r\n")).await
        }
        DraftReply::Disconnect => return,
        DraftReply::Hold(release) => {
            let mut byte = [0];
            loop {
                tokio::select! {
                    result = wire.read(&mut byte) => { assert!(matches!(result, Ok(0)) || result.is_err()); return; },
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        if release.load(Ordering::SeqCst) > 0 { break; }
                    }
                }
            }
            imap_support::write(wire, &format!("{tag} OK accepted\r\n")).await;
        }
    }
    let end = wire.read(&mut [0]).await;
    assert!(
        matches!(end, Ok(0)) || end.is_err(),
        "APPEND connection must close without optional work"
    );
}
