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
                    let Expected { username, password, mailboxes } = queue.lock().unwrap().pop_front().expect("unexpected provider connection");
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

impl Drop for NativeServer {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
