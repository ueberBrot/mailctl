//! Adversarial reconciliation transcripts for real production processes.
use crate::imap_support::{Wire, dropped, expect, write};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Copy, Debug)]
pub enum ReconciliationCase {
    Absent,
    Multiple,
    WrongMessageId,
    WrongContent,
    Recreated,
    Denied,
    SearchBudget,
    OversizedLiteral,
    WrongUid,
}

pub(super) async fn target(wire: &mut Wire, mailbox: &str, validity: u32) {
    let tag = expect(
        wire,
        &format!("EXAMINE {}", super::mailbox_argument(mailbox)),
    )
    .await;
    write(wire, &format!("* 0 EXISTS\r\n* OK [UIDVALIDITY {validity}] incarnation\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
}

pub(super) async fn reconcile(wire: &mut Wire, bytes: &[u8], case: ReconciliationCase) {
    let tag = expect(wire, "EXAMINE Drafts").await;
    if matches!(case, ReconciliationCase::Denied) {
        write(wire, &format!("{tag} NO [NOPERM] synthetic denial\r\n")).await;
        dropped(wire).await;
        return;
    }
    let validity = if matches!(case, ReconciliationCase::Recreated) {
        88
    } else {
        77
    };
    write(wire, &format!("* 1 EXISTS\r\n* OK [UIDVALIDITY {validity}] incarnation\r\n* OK [UIDNEXT 5] next\r\n{tag} OK [READ-ONLY] selected\r\n")).await;
    if matches!(case, ReconciliationCase::Recreated) {
        dropped(wire).await;
        return;
    }
    let text = std::str::from_utf8(bytes).unwrap();
    let id = text
        .split("Message-ID: <")
        .nth(1)
        .unwrap()
        .split('>')
        .next()
        .unwrap();
    let range = if matches!(case, ReconciliationCase::SearchBudget) {
        "1:2"
    } else {
        "1:4"
    };
    let tag = expect(
        wire,
        &format!("UID SEARCH UID {range} HEADER Message-ID {id}"),
    )
    .await;
    let matches = match case {
        ReconciliationCase::Absent | ReconciliationCase::SearchBudget => "",
        ReconciliationCase::Multiple => " 3 4",
        _ => " 4",
    };
    write(wire, &format!("* SEARCH{matches}\r\n{tag} OK found\r\n")).await;
    if matches!(
        case,
        ReconciliationCase::Absent
            | ReconciliationCase::Multiple
            | ReconciliationCase::SearchBudget
    ) {
        dropped(wire).await;
        return;
    }
    let tag = expect(wire, "UID FETCH 4 (UID BODY.PEEK[]<0.16384>)").await;
    if matches!(case, ReconciliationCase::OversizedLiteral) {
        write(wire, "* 1 FETCH (UID 4 BODY[]<0> {16385}\r\n").await;
        dropped(wire).await;
        return;
    }
    let mut body = bytes.to_vec();
    if matches!(case, ReconciliationCase::WrongMessageId) {
        body = text
            .replace(&format!("<{id}>"), &format!("<prefix{id}>"))
            .into_bytes();
    }
    if matches!(case, ReconciliationCase::WrongContent) {
        body.push(b'x');
    }
    let uid = if matches!(case, ReconciliationCase::WrongUid) {
        3
    } else {
        4
    };
    write(
        wire,
        &format!("* 1 FETCH (UID {uid} BODY[]<0> {{{}}}\r\n", body.len()),
    )
    .await;
    wire.write_all(&body).await.unwrap();
    write(wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
    dropped(wire).await;
}
