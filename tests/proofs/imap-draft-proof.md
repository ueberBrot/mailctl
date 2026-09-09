# Draft APPEND acknowledgement proof

This reference records the backend proof for [issue #6](https://github.com/ueberBrot/mailctl/issues/6)
under [the parent contract](https://github.com/ueberBrot/mailctl/issues/1).
It covers bounded draft composition, direct IMAP APPEND, and SQLite persistence of
the observed outcome. The authorized CLI/MCP draft workflow, account writer locks,
historical reconstruction, and reconciliation belong to issues #19–#23.

## Acknowledgement contract

APPEND targets an existing mailbox and supplies `\\Draft` in the initial flag list.
The route has no sending, mailbox-creation, or post-append flag-update operation.
The caller supplies the approved target and identity; this backend proof does not
replace application grant checks.

## Pinned routes

| Module | Version and features | Role |
| --- | --- | --- |
| `io-imap` | `=0.6.0`, defaults disabled | Typed `ImapMessageAppendStream` coroutine |
| `tokio` / `tokio-rustls` | `=1.53.1` / `=0.26.5`; rustls features `ring`, `tls12` | Application-owned verified TLS and deadlines |
| `mail-builder` | `=0.5.0`, defaults disabled | Bounded text/plain MIME construction with explicit Message-ID |
| `rusqlite` | `=0.40.2`, defaults disabled; `bundled`, which enables `modern_sqlite` | Transactional local journal |
| `libsqlite3-sys` | `0.38.2` in `Cargo.lock`; bundled SQLite `3.53.2` | Fixed SQLite implementation |

`cargo run --locked --example check-policy` verifies the direct pins and selected
production features. `cargo tree --locked -e features -i <crate>` shows the
resolved feature graph.

## Outcome observations

| Observation | Outcome | Dispatch again? |
| --- | --- | --- |
| Matching tagged OK | Created, with optional UID information | No |
| Matching tagged NO or BAD | Rejected | No |
| Connection loss, timeout, malformed response, or cancellation after dispatch begins | Acceptance unknown | No |
| Local validation or authentication fails before dispatch | No APPEND dispatched | Only through the later application workflow |

The [IMAP APPEND specification](https://www.rfc-editor.org/rfc/rfc9051.html#section-6.3.12)
defines tagged completion separately from optional UID information. The proof
preserves that distinction: missing APPENDUID does not turn creation into failure.
Reference lookup is optional work after the acknowledgement has been committed.
Its failure cannot change a stored creation into rejection or authorize redispatch.

## Journal durability

The journal uses local SQLite storage with WAL and `synchronous=FULL`, checked on
open. In WAL mode, FULL synchronizes the log at transaction commit; this is the
durability setting required by the parent contract. See
[SQLite synchronous](https://www.sqlite.org/pragma.html#pragma_synchronous) and
[WAL](https://www.sqlite.org/wal.html).

Record preparation before dispatch eligibility, then commit `in_flight` before
writing APPEND bytes. Persist the observed outcome before optional reference work.
Only a prepared operation can enter dispatch. An interrupted in-flight operation
remains non-dispatchable when the database is reopened. A failed outcome commit
also leaves recovery work; it does not establish rejection.

This adapter proves storage transitions. SQLite transactions do not coordinate
the network effect across independent processes. The application workflow must
hold the account writer lock through inspection, dispatch, and outcome recording,
as required by [ADR-0002](../../docs/adr/0002-coordinate-draft-creation.md).

The journal retains identity, original target, hashes, and outcome metadata.
Composition input remains with the caller; credentials and message content are
not journal fields.

## Bounds and transcript evidence

The APPEND coroutine uses synchronizing literals (`non_sync=false`) and a single
initial `Draft` flag. The transport validates the typed target and literal length
before writing the command. It waits for one continuation, writes the frozen MIME
directly, and checks each response under the shared framing and parser limits.
The owned connection closes after APPEND; cleanup introduces no further command.

Composition accepts ASCII addr-spec addresses, explicit creation time and
Message-ID, ordered To/Cc/Bcc recipients, text, and bounded reply identifiers.
The proof permits empty recipient lists, subject, and body. Display names and
international address input remain part of the later application composition
contract. Header injection is rejected, body line endings are normalized, and
Bcc remains in the unsent MIME.

| Resource | Proof ceiling |
| --- | --- |
| Composed MIME | Caller limit, at most 8 MiB |
| Input body | At most the caller's MIME limit |
| Recipients across To/Cc/Bcc | 100 |
| Subject | 8 KiB |
| Message/reply identifier | 998 bytes each |
| References | 50 |
| Outgoing headers | `Limits.max_header_bytes` (64 KiB by default) |
| Incoming responses plus attempted APPEND bytes | `Limits.max_operation_bytes` (4 MiB by default) |
| Operation deadline | 30 seconds by default; at most 120 seconds |

`append_wire_bytes` counts attempted outgoing APPEND bytes, including a write
interrupted by cancellation. `wire_bytes` counts incoming bytes. Composition
reserves at most the MIME limit, and the backend streams that existing buffer.
The allocation tests isolate the fixture on another thread and require peak
transport allocation below 512 KiB, with at most 64 KiB growth between the small
and large payloads. Parser work remains subject to the shared operation ceiling.

## Reproduce the evidence

```sh
cargo test --locked --test imap_append --test imap_append_allocations --test imap_append_journal --test draft_journal -- --nocapture
cargo test --locked --test greenmail --features docker-tests imap_append_creates -- --nocapture
cargo run --locked --example check-policy
cargo deny --locked --all-features check
```

The transcript suite verifies exact target/MIME/initial flags, tagged success
with and without APPENDUID, early and late rejection, malformed responses, lost
acknowledgement, deadlines, and cancellation with observed transport disposal.
The combined journal/transport suite checks that acknowledgement is durable
before a failing optional lookup and that interrupted operations cannot re-enter
dispatch. Real SQLite fault tests cover failed writes and retained outcomes.

The GreenMail proof uses an existing nested mailbox and checks exact stored MIME
through the administrative interface. A separate non-mutating IMAP observer checks
the Draft flag, UID identity, unchanged existing messages, and unchanged INBOX.
Only disposable accounts and synthetic email are used. Docker and OpenSSL are
required; the pinned image and fixture provenance are in the
[fixture reference](../specs/README.md).

The existing shared component CI matrix includes the new transcript, journal,
and allocation suites. The required GreenMail job includes the new independent
draft observation.

## Local acceptance record

Verified on 2026-09-09 at code commit `2c48b83`, against starting commit
`a5a5499`, on macOS 26.6.2, arm64, with Rust 1.98.1 and Docker 29.7.2.
`cargo test --locked --workspace --all-features` passed 157 tests, with no failures
or ignored tests. This includes 13 APPEND/composition tests, two allocation tests,
three combined journal/transport tests, nine SQLite tests, and all five GreenMail
tests. The journal suite includes abrupt process death after in-flight and created
commits, failed outcome writes, and bounded writer contention.

Formatting, all-feature Clippy with warnings denied, the repository dependency
policy, and cargo-deny passed. Separate CLI-only and MCP-only workspace typechecks
also passed. These checks qualify the backend proof; they do not advertise a
CLI/MCP draft command or a released platform artifact.

The isolated transport measurements used 24,884-byte and 1,573,172-byte MIME
payloads. Peak client allocation was 44,172 and 84,222 bytes respectively; each
exchange received 178 response bytes and used 553 parser steps. The executable
ceilings above remain the regression gates.
