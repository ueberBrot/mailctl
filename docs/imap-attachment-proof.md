# Bounded IMAP attachment streaming

This reference records the backend proof for [issue #5](https://github.com/ueberBrot/mailctl/issues/5)
under [the parent contract](https://github.com/ueberBrot/mailctl/issues/1).
`ImapProbe::list_attachments` and `ImapProbe::read_attachment` exercise the routes
directly. Application authorization, authenticated resource references, base64
result serialization, and CLI/MCP attachment commands belong to #12. Filesystem
export belongs to the platform export tickets.

## Operation matrix

| Operation | Pinned route | Executable evidence |
| --- | --- | --- |
| List attachment metadata | Verified TLS, typed authentication, EXAMINE, `UID FETCH <uid> (UID RFC822.SIZE BODYSTRUCTURE)`, LOGOUT; no payload request | `imap_attachment`, `imap_attachment_bounds`, `greenmail` |
| Start a transfer | Same metadata route; select an attachment part and its transfer encoding; bounded `UID FETCH <uid> (UID BODY.PEEK[<part>]<offset.count>)` | `imap_attachment`, `imap_attachment_bounds` |
| Continue a transfer | Consume the probe's opaque continuation; reconnect, authenticate, and EXAMINE before returning bytes or advancing the partial fetch | `imap_attachment`, `imap_attachment_bounds` |
| Finish | Observe a short partial response, finish the decoder, deliver remaining bytes, and return total decoded bytes plus SHA-256 | `imap_attachment`, `imap_attachment_allocations`, `greenmail` |
| Cancel, expire, or fail | Remove decoder state; dispose of any active connection on cancellation, timeout, or framing failure | `imap_attachment_bounds` |

The backend remains `io-imap =0.6.0` with default features disabled, driven by the
existing pinned Tokio/rustls transport. Attachment requests use its typed
`ImapMessageFetch` coroutine. The shared FETCH contract checks UID, section,
offset, literal size, duplicate rows, and unexpected fields before the coroutine
can accumulate responses. The existing [body proof](imap-body-proof.md) records
the narrowly scoped GreenMail separator repair used by both routes.

Listing inspects bounded BODYSTRUCTURE data and reports numeric parts, media types,
transfer-encoded size hints, safe optional filenames, and encoding availability.
It does not download a payload to learn its name. Unsafe or oversized filenames
are omitted. Declared sizes are hints; actual bytes remain subject to transfer
and framing limits.

## Transfer contract

Each result contains raw decoded bytes, their decoded offset, completion status,
and an optional continuation. Only a final result contains the total byte count
and SHA-256 of the complete decoded payload. A result may contain fewer bytes
than the configured chunk size, including zero bytes while an encoding spans
wire chunks or while a final request establishes EOF. Continue until `complete`
is true.

Supported transfer encodings are base64, quoted-printable, 7bit, and 8bit.
Base64 and quoted-printable preserve arbitrary decoded bytes, including NUL.
Binary transfer encoding is reported unavailable: its NUL-containing payloads
need a separately proved IMAP BINARY/literal8 route. Unknown encodings also fail
before payload retrieval.

The incremental decoder preserves base64 quartets and quoted-printable escapes
and soft line breaks across fetches. Malformed encodings fail explicitly instead
of substituting attachment bytes. Payloads are never opened, interpreted as text,
unpacked, or executed.

Continuations are opaque, non-cloneable values tied to one probe and authentication
identity, mailbox, UIDVALIDITY, UID, part, and its fixed limits. They hold no secret.
A continuation is consumed by resume or cancellation. Every resume establishes
the expected UIDVALIDITY on its exclusive connection, including when enough
decoded bytes are already buffered. A mismatch fails before returning those bytes.
Public session/grant-bound tokens are separate application work.

Completed, cancelled, and failed transfers release their decoder state. Idle
transfers hold no connection. Expired entries are removed on the next attachment
operation; an expired continuation returns `TransferExpired`. Dropping a probe
releases all its entries. Dropping an in-flight read disposes of the connection
and its removed or newly created transfer state.

## Bounds

| Resource | Default | Maximum |
| --- | --- | --- |
| Decoded attachment bytes | 10 MiB | 32 MiB |
| Encoded payload bytes | 16 MiB | 64 MiB |
| Decoded result chunk | 64 KiB | 256 KiB |
| Transfer lifetime | 5 minutes | 10 minutes |
| Retained transfers per probe | 2 | 4 |

Each call fetches at most one 16 KiB slice, narrowed by the literal, frame, and
remaining transfer budgets. At the exact wire limit, a one-byte request must
prove EOF; receiving another byte fails. A short response proves EOF independently
of the declared size. Both encoded and decoded limits apply throughout a transfer.

The existing operation byte, response-count, nesting, parser-work, MIME-part, and
deadline limits also apply. Decoding work accumulates across continuations under
`max_decode_steps`. Metrics expose operation wire/parser counters and cumulative
transfer payload, decoded bytes, decoding work, and retained decoder state.
The allocation suite measures the client separately from the fixture server and
compares reported wire bytes with independently counted server writes.

## Reproduce the evidence

```sh
cargo test --locked --test imap_attachment --test imap_attachment_bounds --test imap_attachment_allocations -- --nocapture
cargo test --locked --test greenmail --features docker-tests
```

Transcript tests use synthetic email and disposable credentials over loopback TLS.
GreenMail additionally needs Docker and OpenSSL. Its independent observers compare
message contents, UIDVALIDITY, UIDs, and seen/unseen flags before and after reads.
The existing component CI matrix includes all transcript and allocation tests;
the required Docker job includes the GreenMail proof.
