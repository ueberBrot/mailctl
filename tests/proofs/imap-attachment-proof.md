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

The proof lists single parts with an explicit attachment disposition, including
an attached message as one whole part. Embedded message structures still consume
the MIME limits; their nested attachments are not listed separately. Inferred
attachments, inline resources, and multipart attachment envelopes are outside
this metadata qualification.

## Transfer contract

Each result contains raw decoded bytes, their decoded offset, and an
`AttachmentProgress` outcome: `Continue` carries the next continuation; `Complete`
carries the total byte count and SHA-256 of the complete decoded payload. A result may contain fewer bytes
than the configured chunk size, including zero bytes while an encoding spans
wire chunks or while a final request establishes EOF. Continue until the outcome
is `Complete`.

Supported transfer encodings are base64, quoted-printable, 7bit, and 8bit.
Base64 and quoted-printable preserve arbitrary decoded bytes, including NUL.
Binary transfer encoding is reported unavailable: its NUL-containing payloads
need a separately proved IMAP BINARY/literal8 route. Unknown encodings also fail
before payload retrieval.

The incremental decoder preserves base64 quartets and quoted-printable escapes
and soft line breaks across fetches. It removes quoted-printable transport padding
while retaining explicitly encoded whitespace. Malformed encodings fail explicitly instead
of substituting attachment bytes. Payloads are never opened, interpreted as text,
unpacked, or executed.

Continuations are opaque, non-cloneable values tied to one probe and authentication
identity, mailbox, UIDVALIDITY, UID, part, and its fixed limits. They hold no secret.
A continuation is consumed by resume or cancellation. Every resume establishes
the expected UIDVALIDITY on its exclusive connection, including when enough
decoded bytes are already buffered. A mismatch fails before returning those bytes.
Public session/grant-bound tokens are separate application work.

Completed, cancelled, and failed transfers release their decoder state, including
resumes rejected during local input validation. Dropping a continuation also
releases its issuing slot, including after rejection by another probe. The absolute transfer deadline
also bounds authentication, fetches, and cleanup. Idle
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

Each call fills a decoded chunk through PEEK slices of at most 16 KiB, narrowed
by the literal, frame, and remaining transfer budgets. It returns an available
prefix at a clean command boundary when another maximum response pair would
approach the operation budget. At the exact wire limit, a one-byte request must
prove EOF; receiving another byte fails. A short response proves EOF independently
of the declared size. Both encoded and decoded limits apply throughout a transfer.

The existing operation byte, response-count, nesting, parser-work, MIME-part, and
deadline limits also apply. Decoding work accumulates across continuations under
`max_decode_steps`. Metrics expose operation wire/parser counters and cumulative
transfer payload, decoded bytes, decoding work, and retained decoder state.
The allocation suite measures the client separately from the fixture server and
compares reported wire bytes with independently counted server writes. For each
supported decoder, it transfers 64 KiB and 1 MiB fixtures while requiring peak
client allocation below 512 KiB. The client retains only the current chunk.

## Reproduce the evidence

```sh
cargo test --locked --test imap_attachment --test imap_attachment_bounds --test imap_attachment_allocations --test imap_attachment_decoding --test imap_attachment_types -- --nocapture
cargo test --locked --doc
cargo test --locked --test greenmail --features docker-tests
```

Transcript tests use synthetic email and disposable credentials over loopback TLS.
GreenMail additionally needs Docker and OpenSSL. Its independent observers compare
message contents, UIDVALIDITY, UIDs, and seen/unseen flags before and after reads.
The existing component CI matrix includes all transcript and allocation tests;
the required Docker job includes the GreenMail proof.

Local acceptance passed on macOS 26.6.2, arm64, with Rust 1.98.1 and the pinned
GreenMail image in [the fixture reference](../specs/README.md).
`cargo test --locked --workspace --all-features` passed, including GreenMail and
the ownership compile-fail fixtures. Formatting, all-feature Clippy, repository
dependency policy, cargo-deny, and separate CLI-only/MCP-only typechecks passed.

For the 1 MiB+13-byte decoded fixtures, measured peak client allocations were
125,226 bytes for 8bit, 176,681 bytes for base64, and 155,730 bytes for
quoted-printable. Listing a declared 4,294,967,295-byte attachment used 547 wire
bytes and 26,579 bytes of peak client allocation. These are local measurements;
the executable ceilings above remain the regression gates.
