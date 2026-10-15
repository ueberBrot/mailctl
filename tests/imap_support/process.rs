#![allow(
    dead_code,
    reason = "integration-test crates use different subsets of these shared fixture helpers"
)]

use super::imap_support;

#[path = "body_routes.rs"]
pub mod body_routes;
#[path = "export_faults.rs"]
pub mod export_faults;
#[path = "transfer_lifecycle.rs"]
pub mod transfer_lifecycle;
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

#[path = "process/drafts.rs"]
mod draft_cases;
pub use draft_cases::ReconciliationCase;

struct Expected {
    username: &'static str,
    password: &'static str,
    operation: ExpectedOperation,
}

enum ExpectedOperation {
    Authenticate,
    Append(DraftReply, Duration),
    NamedAppend(String, DraftReply),
    DraftTarget(u32),
    NamedDraftTarget(String, u32),
    Reconcile(ReconciliationReply),
    ReconcileBytes(Vec<u8>),
    DraftReconciliation(ReconciliationCase),
    RejectAuthentication(bool),
    Mailboxes(Vec<&'static str>),
    AllMailboxes(Vec<&'static str>),
    Search(&'static str, Option<u32>),
    Body(&'static str, Vec<u8>, BodyKind),
    BodyBound(&'static str, BodyBound),
    BodyCase(&'static str, BodyCase),
    Attachment(&'static str, AttachmentPhase, String),
    AttachmentCase(&'static str, AttachmentCase, bool),
    BodyRoute(&'static str, body_routes::BodyRoute),
    MimeDepth {
        depth: usize,
        kind: usize,
        admitted: bool,
    },
    TransferStall(transfer_lifecycle::TransferStall),
    ExportPause(export_faults::ExportPause),
}

pub enum DraftReply {
    Created(bool),
    ObservedCreated(tokio::sync::oneshot::Sender<()>),
    Rejected,
    Disconnect,
    Hold(Arc<AtomicUsize>),
}

enum ReconciliationReply {
    Verified,
    Stalled,
    Hold {
        reached: tokio::sync::oneshot::Sender<()>,
        resume: tokio::sync::oneshot::Receiver<()>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AttachmentPhase {
    List,
    Start,
    Continue,
    StaleContinuation,
    Truncated,
    TruncatedContinuation,
    Interrupted,
    InterruptedContinuation,
}

#[derive(Clone, Copy, Debug)]
pub enum AttachmentCase {
    Base64Truncated,
    Base64BadPadding,
    QuotedPrintableTruncated,
    WrongUid,
    WrongSection,
    WrongOrigin,
    NilPayload,
    OversizedLiteral,
    WireAtLimit,
    WireOverLimit,
    DecodedAtLimit,
    DecodedOverLimit,
    BinaryEncoding,
    UnknownEncoding,
}

#[derive(Clone, Copy, Debug)]
pub enum BodyKind {
    Plain,
    Html,
    Alternative,
}

#[derive(Clone, Copy, Debug)]
pub enum BodyBound {
    Exact,
    DeclaredExcess,
    ReceivedExcess,
}

#[derive(Clone, Copy, Debug)]
pub enum BodyCase {
    HeadersAtLimit,
    HeadersOverLimit,
    PartsAtLimit,
    PartsOverLimit,
    MalformedStructure,
    ExcessiveNesting,
    Base64Tail,
    QuotedPrintableTail,
}

pub struct ImapServer {
    pub port: u16,
    pub certificate: PathBuf,
    expected: Arc<Mutex<VecDeque<Expected>>>,
    accepted: Arc<AtomicUsize>,
    interrupted: Arc<AtomicUsize>,
    stalled_reconciliations: Arc<AtomicUsize>,
    drafts: Arc<Mutex<Vec<Vec<u8>>>>,
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
        let stalled_reconciliations = Arc::new(AtomicUsize::new(0));
        let reconciling = stalled_reconciliations.clone();
        let drafts = Arc::new(Mutex::new(Vec::new()));
        let captured = drafts.clone();
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
                            if matches!(&operation, ExpectedOperation::TransferStall(transfer_lifecycle::TransferStall::Authentication)) {
                                transfer_lifecycle::stall_authentication(&mut wire, &stalled).await;
                                return;
                            }
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
                                ExpectedOperation::Append(reply, preparation_delay) => {
                                    let tag = imap_support::expect(&mut wire, "EXAMINE Drafts").await;
                                    if !preparation_delay.is_zero() {
                                        tokio::time::sleep(preparation_delay).await;
                                    }
                                    imap_support::write(&mut wire, &format!("* 0 EXISTS\r\n* OK [UIDVALIDITY 77] incarnation\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                                    append_draft(&mut wire, "Drafts", reply, &stalled, &captured).await;
                                    return;
                                },
                                ExpectedOperation::NamedAppend(mailbox, reply) => {
                                    draft_cases::target(&mut wire, &mailbox, 77).await;
                                    append_draft(&mut wire, &mailbox, reply, &stalled, &captured).await;
                                    return;
                                },
                                ExpectedOperation::NamedDraftTarget(mailbox, validity) => {
                                    draft_cases::target(&mut wire, &mailbox, validity).await;
                                    imap_support::dropped(&mut wire).await;
                                    return;
                                },
                                ExpectedOperation::Reconcile(reply) => {
                                    let bytes = captured.lock().unwrap().last().unwrap().clone();
                                    reconcile_draft(&mut wire, &bytes, reply, &reconciling).await;
                                    return;
                                },
                                ExpectedOperation::ReconcileBytes(bytes) => {
                                    reconcile_draft(&mut wire, &bytes, ReconciliationReply::Verified, &reconciling).await;
                                    return;
                                },
                                ExpectedOperation::DraftReconciliation(case) => {
                                    let bytes = captured.lock().unwrap().last().unwrap().clone();
                                    draft_cases::reconcile(&mut wire, &bytes, case).await;
                                    return;
                                },
                                ExpectedOperation::DraftTarget(validity) => {
                                    let tag = imap_support::expect(&mut wire, "EXAMINE Drafts").await;
                                    imap_support::write(&mut wire, &format!("* 0 EXISTS\r\n* OK [UIDVALIDITY {validity}] incarnation\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
                                    imap_support::dropped(&mut wire).await;
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
                                ExpectedOperation::AllMailboxes(mailboxes) => {
                                    let tag = imap_support::expect(&mut wire, "LIST \"\" *").await;
                                    for name in mailboxes {
                                        let attributes = match name {
                                            "Archive" => "\\Archive",
                                            "Projects" => "\\Noselect",
                                            _ => "",
                                        };
                                        imap_support::write(&mut wire, &format!("* LIST ({attributes}) \"/\" \"{name}\"\r\n")).await;
                                    }
                                    imap_support::write(&mut wire, &format!("{tag} OK listed\r\n")).await;
                                }
                                ExpectedOperation::Search(mailbox, position) => search_page(&mut wire, mailbox, position).await,
                                ExpectedOperation::Body(mailbox, text, kind) => body_page(&mut wire, mailbox, &text, kind).await,
                                ExpectedOperation::BodyBound(mailbox, bound) => {
                                    bounded_body(&mut wire, mailbox, bound).await;
                                    if !matches!(bound, BodyBound::Exact) { return; }
                                },
                                ExpectedOperation::BodyCase(mailbox, case) => {
                                    if !body_case(&mut wire, mailbox, case).await { return; }
                                },
                                ExpectedOperation::Attachment(mailbox, phase, filename) => {
                                    attachment_page(&mut wire, mailbox, phase, &filename, &stalled).await;
                                    if matches!(phase, AttachmentPhase::StaleContinuation | AttachmentPhase::Truncated | AttachmentPhase::TruncatedContinuation | AttachmentPhase::Interrupted | AttachmentPhase::InterruptedContinuation) { return; }
                                },
                                ExpectedOperation::AttachmentCase(mailbox, case, listing) => {
                                    attachment_case(&mut wire, mailbox, case, listing).await;
                                    return;
                                },
                                ExpectedOperation::BodyRoute(mailbox, case) => {
                                    body_routes::serve(&mut wire, mailbox, case).await;
                                    return;
                                },
                                ExpectedOperation::MimeDepth { depth, kind, admitted } => {
                                    mime_depth(&mut wire, depth, kind, admitted).await;
                                    return;
                                },
                                ExpectedOperation::TransferStall(_) => {
                                    transfer_lifecycle::stall_payload(&mut wire, &stalled).await;
                                    return;
                                },
                                ExpectedOperation::ExportPause(pause) => {
                                    export_faults::resume_attachment(&mut wire, pause).await;
                                    return;
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
            stalled_reconciliations,
            drafts,
            stop,
            task: Some(task),
        }
    }

    pub fn expect_reconciliation(&self) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Reconcile(ReconciliationReply::Verified),
        });
    }

    pub fn expect_held_reconciliation(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached, search) = tokio::sync::oneshot::channel();
        let (release, resume) = tokio::sync::oneshot::channel();
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Reconcile(ReconciliationReply::Hold { reached, resume }),
        });
        (search, release)
    }

    pub fn expect_reconciliation_case(&self, case: ReconciliationCase) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::DraftReconciliation(case),
        });
    }

    pub fn expect_reconciliation_bytes(&self, bytes: Vec<u8>) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::ReconcileBytes(bytes),
        });
    }

    pub fn expect_stalled_reconciliation(&self) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Reconcile(ReconciliationReply::Stalled),
        });
    }

    pub fn stalled_reconciliations(&self) -> usize {
        self.stalled_reconciliations.load(Ordering::SeqCst)
    }

    pub fn expect_append(&self, reply: DraftReply) {
        self.expect_append_after(reply, Duration::ZERO);
    }

    pub fn expect_observed_creation(&self) -> tokio::sync::oneshot::Receiver<()> {
        let (acknowledged, observation) = tokio::sync::oneshot::channel();
        self.expect_append(DraftReply::ObservedCreated(acknowledged));
        observation
    }

    pub fn expect_append_after(&self, reply: DraftReply, preparation_delay: Duration) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Append(reply, preparation_delay),
        });
    }

    pub fn expect_draft_target(&self, validity: u32) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::DraftTarget(validity),
        });
    }

    pub fn expect_named_append(&self, mailbox: &str, reply: DraftReply) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::NamedAppend(mailbox.into(), reply),
        });
    }

    pub fn expect_named_draft_target(&self, mailbox: &str, validity: u32) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::NamedDraftTarget(mailbox.into(), validity),
        });
    }
    pub fn drafts(&self) -> Vec<Vec<u8>> {
        self.drafts.lock().unwrap().clone()
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

    pub fn expect_all_mailboxes(
        &self,
        username: &'static str,
        password: &'static str,
        mailboxes: &[&'static str],
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::AllMailboxes(mailboxes.to_vec()),
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
            operation: ExpectedOperation::Body(
                mailbox,
                b"Short body.\r\n".to_vec(),
                BodyKind::Plain,
            ),
        });
    }

    pub fn expect_body_bytes(&self, mailbox: &'static str, text: &[u8]) {
        self.expect_body_kind(mailbox, BodyKind::Plain, text);
    }

    pub fn expect_body_kind(&self, mailbox: &'static str, kind: BodyKind, text: &[u8]) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::Body(mailbox, text.to_vec(), kind),
        });
    }

    pub fn expect_body_bound(&self, mailbox: &'static str, bound: BodyBound) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::BodyBound(mailbox, bound),
        });
    }

    pub fn expect_body_case(&self, mailbox: &'static str, case: BodyCase) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::BodyCase(mailbox, case),
        });
    }

    pub fn expect_attachment(
        &self,
        username: &'static str,
        password: &'static str,
        mailbox: &'static str,
        payload: AttachmentPhase,
    ) {
        self.expect_attachment_named(username, password, mailbox, payload, "fixture.bin");
    }

    pub fn expect_attachment_named(
        &self,
        username: &'static str,
        password: &'static str,
        mailbox: &'static str,
        payload: AttachmentPhase,
        filename: &str,
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username,
            password,
            operation: ExpectedOperation::Attachment(mailbox, payload, filename.to_owned()),
        });
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub fn expect_attachment_case(
        &self,
        mailbox: &'static str,
        case: AttachmentCase,
        listing: bool,
    ) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::AttachmentCase(mailbox, case, listing),
        });
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

    pub fn expect_mime_depth(&self, depth: usize, kind: usize, admitted: bool) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::MimeDepth {
                depth,
                kind,
                admitted,
            },
        });
    }
}

async fn mime_depth(wire: &mut imap_support::Wire, depth: usize, kind: usize, admitted: bool) {
    let mut body = "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 2 1)".to_owned();
    for level in 1..depth {
        body = if kind == 1 || (kind == 2 && level % 2 == 0) {
            format!(
                "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 2 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {body} 1)"
            )
        } else {
            format!("({body} \"MIXED\")")
        };
    }
    let tag = imap_support::expect(wire, "EXAMINE INBOX").await;
    imap_support::write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    let tag = imap_support::expect(wire, "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    imap_support::write(
        wire,
        &format!(
            "* 3 FETCH (UID 3 RFC822.SIZE 3000300 BODYSTRUCTURE {body})\r\n{tag} OK fetched\r\n"
        ),
    )
    .await;
    if admitted {
        imap_support::logout(wire).await;
    } else {
        // Neither headers nor payloads may be requested after rejection.
        imap_support::dropped(wire).await;
    }
}

fn mailbox_argument(mailbox: &str) -> String {
    format!("\"{}\"", mailbox.replace('\\', "\\\\").replace('"', "\\\""))
}

async fn search_page(wire: &mut imap_support::Wire, mailbox: &str, position: Option<u32>) {
    use imap_support::{expect, write};
    let tag = expect(wire, &format!("EXAMINE {}", mailbox_argument(mailbox))).await;
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

async fn body_page(wire: &mut imap_support::Wire, mailbox: &str, text: &[u8], kind: BodyKind) {
    let encoded;
    let (encoding, text) = if text == b"Short body.\r\n" {
        ("7BIT", text)
    } else {
        use base64::{Engine, engine::general_purpose::STANDARD};
        encoded = STANDARD.encode(text);
        ("BASE64", encoded.as_bytes())
    };
    let (subtype, section) = match kind {
        BodyKind::Plain => ("PLAIN", "1"),
        BodyKind::Html => ("HTML", "1"),
        BodyKind::Alternative => ("PLAIN", "1.2"),
    };
    let selected = format!(
        "(\"TEXT\" \"{subtype}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"{encoding}\" {} 1 NIL NIL NIL NIL)",
        text.len()
    );
    let body = if matches!(kind, BodyKind::Alternative) {
        format!(
            "((\"TEXT\" \"HTML\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 19 1 NIL NIL NIL NIL){selected} \"ALTERNATIVE\" NIL NIL NIL NIL)"
        )
    } else {
        selected
    };
    body_headers(wire, mailbox, &body, text.len()).await;
    body_literal(wire, section, 0, text.len() + 1, text).await;
}

async fn body_headers(wire: &mut imap_support::Wire, mailbox: &str, body: &str, size: usize) {
    body_metadata(wire, mailbox, body, size).await;
    body_literal(
        wire,
        "HEADER",
        0,
        16384,
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n",
    )
    .await;
}

async fn body_metadata(wire: &mut imap_support::Wire, mailbox: &str, body: &str, size: usize) {
    use imap_support::{expect, write};
    let tag = expect(wire, &format!("EXAMINE {}", mailbox_argument(mailbox))).await;
    write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    let tag = expect(wire, "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    // Only the selected part is fetchable; the 3 MB attachment and all mailbox
    // mutations are independently rejected by exact command matching.
    let total = size + 3_000_000 + 300;
    write(wire, &format!("* 3 FETCH (UID 3 RFC822.SIZE {total} BODYSTRUCTURE ({body}(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"BASE64\" 3000000 NIL (\"ATTACHMENT\" NIL) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
}

async fn body_literal(
    wire: &mut imap_support::Wire,
    section: &str,
    offset: usize,
    count: usize,
    value: &[u8],
) {
    use tokio::io::AsyncWriteExt;
    let tag = imap_support::expect(
        wire,
        &format!("UID FETCH 3 (UID BODY.PEEK[{section}]<{offset}.{count}>)"),
    )
    .await;
    let mut response = format!(
        "* 3 FETCH (UID 3 BODY[{section}]<{offset}> {{{}}}\r\n",
        value.len()
    )
    .into_bytes();
    response.extend_from_slice(value);
    response.extend_from_slice(format!(")\r\n{tag} OK fetched\r\n").as_bytes());
    wire.write_all(&response).await.unwrap();
    wire.flush().await.unwrap();
}

async fn bounded_body(wire: &mut imap_support::Wire, mailbox: &str, bound: BodyBound) {
    const SIZE: usize = 2 * 1024 * 1024;
    let declared = SIZE + usize::from(matches!(bound, BodyBound::DeclaredExcess));
    let body = format!(
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" {declared} 1 NIL NIL NIL NIL)"
    );
    body_headers(wire, mailbox, &body, declared).await;
    if !matches!(bound, BodyBound::DeclaredExcess) {
        // Eight distinguishable 256 KiB regions make repeated or skipped pages
        // observable without retaining a complete source or reconstructed body.
        for (region, byte) in b"abcdefgh".iter().enumerate() {
            let chunk = [*byte; 16 * 1024];
            for offset in (region * 256 * 1024..(region + 1) * 256 * 1024).step_by(chunk.len()) {
                body_literal(wire, "1", offset, chunk.len(), &chunk).await;
            }
        }
        let excess = if matches!(bound, BodyBound::ReceivedExcess) {
            b"x".as_slice()
        } else {
            b""
        };
        body_literal(wire, "1", SIZE, 1, excess).await;
    }
    if !matches!(bound, BodyBound::Exact) {
        imap_support::dropped(wire).await;
    }
}

async fn body_case(wire: &mut imap_support::Wire, mailbox: &str, case: BodyCase) -> bool {
    use BodyCase::*;

    let (encoding, payload) = match case {
        Base64Tail => ("BASE64", b"SGVsbG8".as_slice()),
        QuotedPrintableTail => ("QUOTED-PRINTABLE", b"hello=".as_slice()),
        _ => ("7BIT", b"ok".as_slice()),
    };
    let mut body = format!(
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"{encoding}\" {} 1 NIL NIL NIL NIL)",
        payload.len()
    );
    match case {
        PartsAtLimit | PartsOverLimit => {
            // Count the outer MIXED node, selected leaf, and 3 MB attachment too.
            let extra = if matches!(case, PartsAtLimit) {
                197
            } else {
                198
            };
            body.push_str(&"(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"7BIT\" 0 NIL (\"ATTACHMENT\" NIL) NIL NIL)".repeat(extra));
        }
        MalformedStructure => {
            // Body types must be strings, so this unquoted atom cannot decode.
            body = "(INVALID)".into();
        }
        ExcessiveNesting => {
            // Exceed the independent protocol nesting guard even when the codec
            // admits structures within the configured MIME depth range.
            for _ in 0..128 {
                body = format!("({body} \"MIXED\" NIL NIL NIL NIL)");
            }
        }
        _ => {}
    }
    let header_case = matches!(case, HeadersAtLimit | HeadersOverLimit);
    let metadata_rejected = matches!(case, PartsOverLimit | MalformedStructure | ExcessiveNesting);
    if header_case || metadata_rejected {
        body_metadata(wire, mailbox, &body, payload.len()).await;
    } else {
        body_headers(wire, mailbox, &body, payload.len()).await;
    }
    if metadata_rejected {
        imap_support::dropped(wire).await;
        return false;
    }
    if header_case {
        const LIMIT: usize = 64 * 1024;
        let size = LIMIT + usize::from(matches!(case, HeadersOverLimit));
        let mut headers =
            b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n".to_vec();
        // Ordinary ignored fields exercise the byte ceiling without relying on
        // overlong lines or another parser-work limit to reject the headers.
        while size - headers.len() > 256 {
            headers.extend_from_slice(b"X-Pad: ");
            headers.resize(headers.len() + 119, b'x');
            headers.extend_from_slice(b"\r\n");
        }
        headers.extend_from_slice(b"X-Pad: ");
        headers.resize(size - 4, b'x');
        headers.extend_from_slice(b"\r\n\r\n");
        for offset in (0..LIMIT).step_by(16 * 1024) {
            body_literal(
                wire,
                "HEADER",
                offset,
                16 * 1024,
                &headers[offset..offset + 16 * 1024],
            )
            .await;
        }
        body_literal(wire, "HEADER", LIMIT, 1, &headers[LIMIT..]).await;
        if matches!(case, HeadersOverLimit) {
            imap_support::dropped(wire).await;
            return false;
        }
    }
    body_literal(wire, "1", 0, payload.len() + 1, payload).await;
    true
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
    filename: &str,
    interrupted: &AtomicUsize,
) {
    use imap_support::{expect, write};
    let tag = expect(wire, &format!("EXAMINE {}", mailbox_argument(mailbox))).await;
    if payload == AttachmentPhase::TruncatedContinuation {
        // The previous operation yielded a chunk. Drop this continuation before
        // selection succeeds, without supplying another chunk or LOGOUT reply.
        return;
    }
    if payload == AttachmentPhase::InterruptedContinuation {
        interrupt_attachment(wire, interrupted).await;
        return;
    }
    if payload == AttachmentPhase::StaleContinuation {
        write(
            wire,
            &format!(
                "* 3 EXISTS\r\n* OK [UIDVALIDITY 78] replaced\r\n{tag} OK [READ-ONLY] selected\r\n"
            ),
        )
        .await;
        // Buffered decoded bytes must not bypass the mailbox identity check.
        imap_support::dropped(wire).await;
        return;
    }
    write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    if payload != AttachmentPhase::Continue {
        attachment_metadata(wire, "BASE64", 8, filename).await;
    }
    if payload == AttachmentPhase::Interrupted {
        expect(wire, "UID FETCH 3 (UID BODY.PEEK[2]<0.16384>)").await;
        interrupt_attachment(wire, interrupted).await;
    }
    if payload == AttachmentPhase::Truncated {
        expect(wire, "UID FETCH 3 (UID BODY.PEEK[2]<0.16384>)").await;
        // Close after half the promised literal; no success or LOGOUT reply.
        write(wire, "* 3 FETCH (UID 3 BODY[2]<0> {8}\r\nYWJj").await;
        return;
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

async fn attachment_metadata(
    wire: &mut imap_support::Wire,
    encoding: &str,
    size: usize,
    filename: &str,
) {
    let tag = imap_support::expect(wire, "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    imap_support::write(wire, &format!("* 3 FETCH (UID 3 RFC822.SIZE 3000300 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 13 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"{encoding}\" {size} NIL (\"ATTACHMENT\" (\"FILENAME\" \"{filename}\")) NIL NIL) \"MIXED\" NIL NIL NIL NIL))\r\n{tag} OK fetched\r\n")).await;
}

async fn attachment_case(
    wire: &mut imap_support::Wire,
    mailbox: &str,
    case: AttachmentCase,
    listing: bool,
) {
    use AttachmentCase::*;

    let (encoding, payload) = match case {
        Base64Truncated => ("BASE64", b"SGVsbG8".as_slice()),
        Base64BadPadding => ("BASE64", b"Zg=A".as_slice()),
        QuotedPrintableTruncated => ("QUOTED-PRINTABLE", b"unfinished=".as_slice()),
        BinaryEncoding => ("BINARY", b"".as_slice()),
        UnknownEncoding => ("X-UNKNOWN", b"".as_slice()),
        _ => ("7BIT", b"".as_slice()),
    };
    let size = match case {
        WireAtLimit | DecodedAtLimit => 16384,
        WireOverLimit | DecodedOverLimit => 16385,
        Base64Truncated | Base64BadPadding | QuotedPrintableTruncated => payload.len(),
        _ => 40000,
    };
    let tag = imap_support::expect(wire, &format!("EXAMINE {}", mailbox_argument(mailbox))).await;
    imap_support::write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    attachment_metadata(wire, encoding, size, "fixture.bin").await;
    if listing {
        imap_support::logout(wire).await;
        return;
    }
    match case {
        BinaryEncoding | UnknownEncoding => {
            // Refuse the unavailable encoding before any payload request.
        }
        WrongUid | WrongSection | WrongOrigin | NilPayload | OversizedLiteral => {
            imap_support::expect(wire, "UID FETCH 3 (UID BODY.PEEK[2]<0.16384>)").await;
            let frame = match case {
                WrongUid => "* 3 FETCH (UID 4 BODY[2]<0> {1}\r\nx)\r\n",
                WrongSection => "* 3 FETCH (UID 3 BODY[1]<0> {1}\r\nx)\r\n",
                WrongOrigin => "* 3 FETCH (UID 3 BODY[2]<1> {1}\r\nx)\r\n",
                NilPayload => "* 3 FETCH (UID 3 BODY[2]<0> NIL)\r\n",
                // The declaration alone must close the connection, without
                // allocating or waiting for this payload, or attempting LOGOUT.
                OversizedLiteral => "* 3 FETCH (UID 3 BODY[2]<0> {4294967295}\r\n",
                _ => unreachable!(),
            };
            imap_support::write(wire, frame).await;
        }
        WireAtLimit | WireOverLimit | DecodedAtLimit | DecodedOverLimit => {
            body_literal(wire, "2", 0, 16384, &[b'x'; 16384]).await;
            let count = if matches!(case, WireAtLimit | WireOverLimit) {
                1
            } else {
                16384
            };
            let tail = if matches!(case, WireOverLimit | DecodedOverLimit) {
                b"x".as_slice()
            } else {
                b"".as_slice()
            };
            // A full first literal cannot prove EOF. The wire ceiling narrows
            // the next request to one byte; decoded limits are tested separately.
            body_literal(wire, "2", 16384, count, tail).await;
            if matches!(case, WireAtLimit | DecodedAtLimit) {
                imap_support::logout(wire).await;
                return;
            }
        }
        Base64Truncated | Base64BadPadding | QuotedPrintableTruncated => {
            body_literal(wire, "2", 0, 16384, payload).await;
        }
    }
    imap_support::dropped(wire).await;
}

async fn interrupt_attachment(wire: &mut imap_support::Wire, interrupted: &AtomicUsize) {
    use tokio::io::AsyncReadExt;
    interrupted.fetch_add(1, Ordering::SeqCst);
    let closed = wire.read(&mut [0]).await;
    assert!(
        matches!(closed, Ok(0))
            || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof),
        "cancelled export disposes the connection"
    );
}

async fn append_draft(
    wire: &mut imap_support::Wire,
    mailbox: &str,
    reply: DraftReply,
    observed: &AtomicUsize,
    captured: &Mutex<Vec<Vec<u8>>>,
) {
    use io_imap::codec::{CommandCodec, decode::Decoder};
    use io_imap::types::{command::CommandBody, mailbox::Mailbox};
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
    let (_, mut actual) = codec.decode(command.as_bytes()).unwrap();
    let expected = format!(
        "expected APPEND {} (\\Draft) {{0}}\r\n\r\n",
        mailbox_argument(mailbox)
    );
    let (_, mut expected) = codec.decode(expected.as_bytes()).unwrap();
    // Atom/quoted/literal spelling does not change the exact mailbox identity.
    let normalize = |body: &mut CommandBody<'_>| {
        if let CommandBody::Append { mailbox, .. } = body
            && let Mailbox::Other(name) = mailbox
        {
            *mailbox = name.as_ref().to_vec().try_into().unwrap();
        }
    };
    normalize(&mut actual.body);
    normalize(&mut expected.body);
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
    captured.lock().unwrap().push(literal);
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
        DraftReply::ObservedCreated(acknowledged) => {
            imap_support::write(wire, &format!("{tag} OK [APPENDUID 77 4] accepted\r\n")).await;
            acknowledged.send(()).unwrap();
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

async fn reconcile_draft(
    wire: &mut imap_support::Wire,
    bytes: &[u8],
    reply: ReconciliationReply,
    stalled: &AtomicUsize,
) {
    use tokio::io::AsyncWriteExt;
    {
        let tag = imap_support::expect(wire, "EXAMINE Drafts").await;
        imap_support::write(wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 77] incarnation\r\n* OK [UIDNEXT 5] next\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
    }
    let text = std::str::from_utf8(bytes).unwrap();
    let id = text
        .split("Message-ID: <")
        .nth(1)
        .unwrap()
        .split('>')
        .next()
        .unwrap();
    let tag =
        imap_support::expect(wire, &format!("UID SEARCH UID 1:4 HEADER Message-ID {id}")).await;
    match reply {
        ReconciliationReply::Verified => {}
        ReconciliationReply::Stalled => {
            stalled.fetch_add(1, Ordering::SeqCst);
            imap_support::dropped(wire).await;
            return;
        }
        ReconciliationReply::Hold { reached, resume } => {
            reached
                .send(())
                .expect("reconciliation observer is waiting");
            resume.await.expect("reconciliation fixture released");
        }
    }
    imap_support::write(wire, &format!("* SEARCH 4\r\n{tag} OK found\r\n")).await;
    let tag = imap_support::expect(wire, "UID FETCH 4 (UID BODY.PEEK[]<0.16384>)").await;
    imap_support::write(
        wire,
        &format!("* 1 FETCH (UID 4 BODY[]<0> {{{}}}\r\n", bytes.len()),
    )
    .await;
    wire.write_all(bytes).await.unwrap();
    imap_support::write(wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
    imap_support::dropped(wire).await;
}
