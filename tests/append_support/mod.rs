#![allow(
    dead_code,
    reason = "integration-test crates use different subsets of these shared fixture helpers"
)]

use crate::imap_support::{Wire, parse_command, write};
use mailctl::draft::{DraftInput, PreparedDraft};
use tokio::io::AsyncReadExt;

pub fn input() -> DraftInput {
    DraftInput {
        from: "author@example.test".into(),
        to: vec!["reader@example.test".into()],
        cc: vec!["copy@example.test".into()],
        bcc: vec!["hidden@example.test".into()],
        subject: "Unsent fixture".into(),
        body: "First line\nSecond line\n".into(),
        message_id: "operation@example.test".into(),
        date_unix: 1_700_000_000,
        ..Default::default()
    }
}
pub fn draft() -> PreparedDraft {
    PreparedDraft::compose(input(), 1024 * 1024).unwrap()
}

/// Independently decode the command while leaving the literal unsent for fault injection.
pub async fn header(wire: &mut Wire, target: &str, len: usize) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n") {
        bytes.push(wire.read_u8().await.unwrap());
        assert!(bytes.len() < 16 * 1024);
    }
    let suffix = format!("{{{len}}}\r\n");
    let prefix = bytes
        .strip_suffix(suffix.as_bytes())
        .expect("synchronizing literal with exact byte count");
    let mut command = prefix.to_vec();
    command.extend_from_slice(b"{0}\r\n\r\n");
    let actual = parse_command(&command).unwrap();
    let escaped = target.replace('\\', "\\\\").replace('"', "\\\"");
    let expected = format!("expected APPEND \"{escaped}\" (\\Draft) {{0}}\r\n\r\n");
    let expected = parse_command(expected.as_bytes()).unwrap();
    assert_eq!(
        actual.body, expected.body,
        "only exact-target APPEND with initial Draft is allowed"
    );
    actual.tag
}
pub async fn receive(wire: &mut Wire, target: &str, expected: &[u8]) -> String {
    let tag = header(wire, target, expected.len()).await;
    write(wire, "+ continue\r\n").await;
    let mut actual = vec![0; expected.len()];
    wire.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, expected);
    let mut ending = [0; 2];
    wire.read_exact(&mut ending).await.unwrap();
    assert_eq!(&ending, b"\r\n");
    tag
}
