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
    mailboxes: Vec<&'static str>,
    search: Option<(&'static str, Option<u32>)>,
}

pub struct NativeServer {
    pub port: u16,
    pub certificate: PathBuf,
    expected: Arc<Mutex<VecDeque<Expected>>>,
    accepted: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
    task: Option<thread::JoinHandle<()>>,
}

impl NativeServer {
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
                    let Expected { username, password, mailboxes, search } = queue.lock().unwrap().pop_front().expect("unexpected provider connection");
                    tokio::select! {
                        _ = stopping.changed() => return,
                        result = tokio::time::timeout(Duration::from_secs(10), async {
                            let mut wire: imap_support::Wire = Box::new(acceptor.accept(socket).await.unwrap());
                            imap_support::write(&mut wire, "* OK synthetic server ready\r\n").await;
                            imap_support::capability(&mut wire, "IMAP4rev1").await;
                            let tag = imap_support::expect(&mut wire, &format!("LOGIN \"{username}\" \"{password}\"")).await;
                            imap_support::write(&mut wire, &format!("{tag} OK authenticated\r\n")).await;
                            imap_support::capability(&mut wire, "IMAP4rev1").await;
                            for name in mailboxes {
                                let tag = imap_support::expect(&mut wire, &format!("LIST \"\" {name}")).await;
                                let attributes = if name == "Archive" { "\\Archive" } else { "" };
                                imap_support::write(&mut wire, &format!("* LIST ({attributes}) \"/\" {name}\r\n{tag} OK listed\r\n")).await;
                            }
                            if let Some((mailbox, position)) = search {
                                search_page(&mut wire, mailbox, position).await;
                            }
                            imap_support::logout(&mut wire).await;
                        }) => result.expect("native authentication transcript deadline"),
                    }
                }
            });
        });
        Self {
            port,
            certificate,
            expected,
            accepted,
            stop,
            task: Some(task),
        }
    }

    pub fn expect(&self, username: &'static str, password: &'static str) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            mailboxes: Vec::new(),
            search: None,
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
            mailboxes: mailboxes.to_vec(),
            search: None,
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
            mailboxes: vec![],
            search: Some((mailbox, position)),
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
            .expect("native authentication transcript");
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
    let tag = expect(wire, &format!("UID SEARCH UID 1:{uid}")).await;
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

impl Drop for NativeServer {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
