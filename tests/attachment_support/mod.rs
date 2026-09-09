use crate::imap_support::*;
use io_imap::codec::{CommandCodec, decode::Decoder};
use io_imap::types::command::CommandBody;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn structure(encoding: &str, size: usize) -> String {
    format!(
        "((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 5 1 NIL NIL NIL NIL)(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"{encoding}\" {size} NIL (\"ATTACHMENT\" (\"FILENAME\" \"fixture.bin\")) NIL NIL) \"MIXED\" NIL NIL NIL NIL)"
    )
}

pub async fn metadata(wire: &mut Wire, structure: &str) {
    let tag = expect(wire, "UID FETCH 4 (UID RFC822.SIZE BODYSTRUCTURE)").await;
    write(wire, &format!("* 1 FETCH (UID 4 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n")).await;
}

/// Serve only the next bounded PEEK or LOGOUT. The expected offset is maintained
/// by the server, independently of the client's transfer state.
pub async fn payload_session(
    wire: &mut Wire,
    payload: &[u8],
    position: &Arc<AtomicUsize>,
    count: usize,
) {
    loop {
        let mut raw = Vec::new();
        while !raw.ends_with(b"\r\n") {
            raw.push(
                tokio::time::timeout(std::time::Duration::from_secs(5), wire.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert!(raw.len() < 1024);
        }
        let codec = CommandCodec::new();
        let (remaining, command) = codec.decode(&raw).unwrap();
        assert!(remaining.is_empty());
        let tag = command.tag.as_ref();
        if matches!(command.body, CommandBody::Logout) {
            write(wire, &format!("* BYE closing\r\n{tag} OK logout\r\n")).await;
            return;
        }
        let offset = position.load(Ordering::Relaxed);
        let expected = format!("expected UID FETCH 4 (UID BODY.PEEK[2]<{offset}.{count}>)\r\n");
        let (_, expected) = codec.decode(expected.as_bytes()).unwrap();
        assert_eq!(
            command.body, expected.body,
            "only sequential bounded PEEK is allowed"
        );
        let end = (offset + count).min(payload.len());
        let bytes = &payload[offset..end];
        write(
            wire,
            &format!("* 1 FETCH (UID 4 BODY[2]<{offset}> {{{}}}\r\n", bytes.len()),
        )
        .await;
        wire.write_all(bytes).await.unwrap();
        write(wire, &format!(")\r\n{tag} OK fetched\r\n")).await;
        position.store(end, Ordering::Relaxed);
    }
}
