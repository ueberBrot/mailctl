use super::{Expected, ExpectedOperation, ImapServer, imap_support};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug)]
pub enum TransferStall {
    Authentication,
    Payload,
}

impl ImapServer {
    pub fn expect_transfer_stall(&self, stage: TransferStall) {
        self.expected.lock().unwrap().push_back(Expected {
            username: "work@example.test",
            password: "disposable-password",
            operation: ExpectedOperation::TransferStall(stage),
        });
    }
}

pub async fn stall_authentication(wire: &mut imap_support::Wire, observed: &AtomicUsize) {
    imap_support::expect(wire, "CAPABILITY").await;
    observed.fetch_add(1, Ordering::SeqCst);
    // An unfinished capability exchange cannot be returned to a clean pool or
    // followed by LOGOUT when its attachment request stops.
    imap_support::dropped(wire).await;
}

pub async fn stall_payload(wire: &mut imap_support::Wire, observed: &AtomicUsize) {
    let tag = imap_support::expect(wire, "EXAMINE INBOX").await;
    imap_support::write(
        wire,
        &format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n"),
    )
    .await;
    super::attachment_metadata(wire, "7BIT", 40_000, "fixture.bin").await;
    imap_support::expect(wire, "UID FETCH 3 (UID BODY.PEEK[2]<0.16384>)").await;
    imap_support::write(wire, "* 3 FETCH (UID 3 BODY[2]<0> {16384}\r\npartial").await;
    observed.fetch_add(1, Ordering::SeqCst);
    // The declared literal remains incomplete. Any attempted command, including
    // LOGOUT, is rejected; cancellation and either deadline must close instead.
    imap_support::dropped(wire).await;
}
