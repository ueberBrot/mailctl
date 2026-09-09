# Bounded IMAP body retrieval

This reference records the backend proof for [issue #4](https://github.com/ueberBrot/mailctl/issues/4),
under [the parent contract](https://github.com/ueberBrot/mailctl/issues/1) and
[ADR-0004](adr/0004-read-bodies-independently-of-attachments.md).
`ImapProbe::read_body` exercises the route directly. CLI/MCP reading and authenticated
public continuation tokens remain separate delivery work in #11 and #13.

## Route and representation

Every read authenticates over verified TLS, obtains one exclusive connection, and
checks the requested UIDVALIDITY with EXAMINE. It then requests
`UID FETCH <uid> (UID RFC822.SIZE BODYSTRUCTURE)` and bounded `BODY.PEEK[HEADER]`.
The read fetches only the selected numeric section with PEEK. MIME headers are
fetched when a multipart child needs a Content-ID to resolve a declared related root.
The coroutine driver permits only these typed requests and the existing read-only
setup/cleanup requests.

Partial fetches contain at most 16 KiB, narrowed by the literal and frame limits.
A short response proves EOF; an exact-size response requires another bounded
request. BODYSTRUCTURE size is an admission hint, never permission to allocate
without checking the literal announcement. A larger actual body fails explicitly.
A supported single-part text message may use whole-message PEEK when its reported
size fits the wire budget. That route checks the fetched header prefix and feeds
the body into the same decoder. Multipart messages always use selected parts.

Selection excludes attachment-disposition subtrees and attached messages. Alternatives
prefer eligible plain text, then HTML. Related content uses its declared eligible
root, with a fallback to the first eligible body. Mixed content uses its first
eligible subtree. These rules apply recursively. No supported body produces an
empty result with absent part/media metadata.

The renderer preserves plain-text quotes and whitespace, decodes transfer encodings
and character sets, and marks replacement/fallback behavior. HTML becomes inert plain
text with link text and targets; scripts, styles, and remote resources are not executed
or retrieved. The representation identifies `mail-parser 0.11.8` and
`html2text 0.17.1`, with direct `encoding_rs 0.8.40`. CSS/XML converter features remain
disabled. The selected IMAP route still uses `io-imap 0.6.0` without default features
and the existing pinned Tokio/rustls transport.

Each page ends at a UTF-8 boundary. The in-memory continuation binds the endpoint,
username, mailbox, UIDVALIDITY, UID, part, source/representation content, renderer
version, and limits. Continuing refetches and renders within the same bounds; changed
content or context returns `StaleCursor`. This proof does not expose a serializable
or cross-process cursor.

## Bounds and evidence

The default body wire budget is 2 MiB, with an 8 MiB maximum. The independent
aggregate operation ceiling is 4 MiB by default, with a 16 MiB maximum, leaving room
for headers and framing. Header bytes across requested sections are capped at
64 KiB by default, with a 256 KiB maximum. MIME parts are capped at 200/1,000.
Decoded representation bytes are capped at 8/32 MiB; page text at 256 KiB/2 MiB.
`Limits` also bounds response/literal bytes, response count, nesting, parser work,
decoding work, and deadlines. Narrowed limits may reject a body before a larger
ceiling is reached.

Decoding reserves capacity/work before dependency calls. HTML admission is at most
64 KiB and one sixteenth of the decoded representation budget. A conservative
markup-work reservation precedes parsing. The DOM check caps nodes at 4,096,
attributes at four times the node ceiling, and cells at 128; it also checks depth.
Table spans are clamped to 1–8 before conversion. Rendering reserves a conservative
output/work bound before allocation. These extra limits can reject complex HTML.
`Metrics` reports wire bytes, frame/literal peaks, responses, parser steps, decoded
bytes, and decoding work, including conservative HTML reservations.

| Evidence | Test target |
| --- | --- |
| Exact PEEK route, deterministic MIME selection, decoding, inert HTML, UTF-8 continuation, whole-message admission | `imap_body` |
| Independent server byte count and client-only allocation measurement; wrong identities/fields; oversized announcements; cancellation disposal | `imap_body_bounds` |
| MIME and rendering bounds, hostile spans, and a full default-sized selected body | `imap_body_representation_bounds` |
| Actual large-attachment retrieval; independent before/after content, UID, and seen/unseen flag observations | `greenmail` |

The allocation test varies the advertised attachment size from megabytes to the
32-bit size ceiling while keeping the selected body fixed. It requires under 2 MiB
of peak client allocation, under 16 MiB total allocation, and under 4 KiB of actual
plaintext server output. The server runs on a separate thread; its allocations
are excluded. The byte count is checked against actual server writes, independently
of the production metrics. The transcript accepts no attachment payload request.

Run the proof with the pinned toolchain:

```sh
cargo test --locked --test imap_body --test imap_body_bounds --test imap_body_representation_bounds
cargo test --locked --test greenmail --features docker-tests
```

GreenMail needs Docker and OpenSSL. Tests use isolated local accounts and synthetic
mail; they do not use operator credentials. Shared transcript tests run in the
existing CLI/MCP component CI matrix. The existing required Docker job includes
the GreenMail proof. Local acceptance was run on macOS 26.6.2, arm64, Rust 1.98.1,
with the pinned native-arm64 GreenMail image recorded in
[the fixture reference](../tests/specs/README.md).

## Pinned server constraints

GreenMail 2.1.13 has several relevant differences from compliant transcripts:

- [Partial body responses omit a separator before the literal](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-core/src/main/java/com/icegreen/greenmail/imap/commands/FetchCommand.java#L306).
  The driver repairs only that separator on the first literal announcement, for the
  exact requested section and offset. It reserves the extra byte and sends the same
  repaired frame through both typed decoders. Literal payloads stay unchanged.
- [Complete HEADER responses omit the blank separator](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-core/src/main/java/com/icegreen/greenmail/imap/commands/FetchCommand.java#L353).
  After bounded EOF, the reader adds it within the header budget.
- [BODYSTRUCTURE sizes include MIME headers](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-core/src/main/java/com/icegreen/greenmail/store/SimpleMessageAttributes.java#L127).
  Earlier EOF is accepted; the literal, aggregate byte, and declared-size ceilings
  still apply.
- [Nested `.MIME` requests return the parent headers](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-core/src/main/java/com/icegreen/greenmail/imap/commands/FetchCommand.java#L229),
  and [selected-body extraction trims whitespace](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-core/src/main/java/com/icegreen/greenmail/util/GreenMailUtil.java#L126).
  Independent compliant transcripts establish nested related-root headers and exact
  whitespace preservation. GreenMail establishes actual mailbox effects and bounded
  retrieval; its response cannot establish bytes that its own extraction discards.

Malformed or unsupported structures fail explicitly. The pinned IMAP decoder also
has a recursion ceiling below the configurable MIME maximum; the nesting regression
records its effective boundary. The configurable maximum is a resource ceiling,
not a claim that the backend accepts every MIME tree at that depth.
