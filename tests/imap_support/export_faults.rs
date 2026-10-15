use super::{Expected, ExpectedOperation, ImapServer, imap_support};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::oneshot;

pub struct ExportPause {
    waiting: Arc<AtomicBool>,
    resume: oneshot::Receiver<()>,
}

pub struct ExportControl {
    waiting: Arc<AtomicBool>,
    resume: oneshot::Sender<()>,
}

impl ExportControl {
    pub fn waiting(&self) -> bool {
        self.waiting.load(Ordering::SeqCst)
    }

    pub fn resume(self) {
        self.resume
            .send(())
            .expect("export continuation is waiting");
    }
}

impl ImapServer {
    pub fn expect_export_pause(&self) -> ExportControl {
        let waiting = Arc::new(AtomicBool::new(false));
        let (resume, receiver) = oneshot::channel();
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::ExportPause(ExportPause {
                waiting: waiting.clone(),
                resume: receiver,
            }),
        });
        ExportControl { waiting, resume }
    }
}

/// The CLI has written its first authorized chunk before it requests selection
/// for the continuation. Keep that request pending while a test observes and
/// changes the actual filesystem, then finish the normal buffered transfer.
pub async fn resume_attachment(wire: &mut imap_support::Wire, pause: ExportPause) {
    let tag = imap_support::expect(wire, "EXAMINE INBOX").await;
    pause.waiting.store(true, Ordering::SeqCst);
    pause.resume.await.expect("export fixture released");
    imap_support::write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    imap_support::logout(wire).await;
}
