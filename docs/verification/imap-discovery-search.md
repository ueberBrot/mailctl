# IMAP discovery and search evidence

This proof covers [issue #3](https://github.com/ueberBrot/mailctl/issues/3)
under the [application contract](https://github.com/ueberBrot/mailctl/issues/1).
It exercises the direct protocol adapter with disposable local accounts. It does
not enable mailbox discovery or search commands in either executable; those
application workflows belong to #9 and #10.

## Reproduce the checks

Use the pinned Rust toolchain. The transcript suite creates temporary TLS
identities in memory. The GreenMail suite additionally needs Docker and OpenSSL
on PATH; it owns its server, accounts, certificates, and cleanup. The pinned
GreenMail image is pulled by digest and may appear with tag `<none>` in Docker.
Use `docker image ls --all --digests` to find it. Tests remove their containers
afterward; the cached image remains.

```sh
cargo test --locked --test imap_transcript -- --nocapture
cargo test --locked --test greenmail --features docker-tests -- --nocapture
cargo run --locked --example check-policy
cargo deny --locked --all-features check
```

Shared CI runs the transcript suite on Ubuntu, macOS, and Windows. The existing
Ubuntu Docker job runs the GreenMail suite. Local success qualifies the recorded
local run; CI results establish the other operating-system checks.

## Dependency selection

[io-imap 0.6.0](https://docs.rs/io-imap/0.6.0/io_imap/) provides I/O-free
coroutines. The adapter owns the socket and verified TLS configuration rather
than using the crate's blocking client or transport features. Pimalaya lists
[io-email as frozen](https://pimalaya.org/ecosystem/); it is forbidden in the
production dependency graph. Himalaya is upstream implementation evidence and
is not an executable or library dependency.

| Package | Locked version | Declared MSRV | License |
| --- | --- | --- | --- |
| io-imap | 0.6.0 | 1.88 | MIT OR Apache-2.0 |
| imap-codec | 2.0.0-alpha.9 | 1.85 | MIT OR Apache-2.0 |
| imap-types | 2.0.0-alpha.7 | 1.85 | MIT OR Apache-2.0 |
| io-sasl | 0.1.0 | 1.87 | MIT OR Apache-2.0 |
| Tokio | 1.53.1 | 1.71 | MIT |
| tokio-rustls | 0.26.5 | 1.71 | MIT OR Apache-2.0 |
| rustls | 0.23.44 | 1.71 | Apache-2.0 OR ISC OR MIT |
| ring | 0.17.14 | 1.66.0 | Apache-2.0 AND ISC |

The workspace declares and tests Rust **1.98.1**. Lower dependency MSRVs do not
establish support for a lower workspace toolchain. The manifest pins io-imap,
Tokio, and tokio-rustls exactly; Cargo.lock pins their transitive dependencies.
`check-policy` rejects changed direct pins, io-imap features, foreign transport
clients, SMTP/unrelated backends, and test infrastructure in production.

io-imap has no enabled features. tokio-rustls enables only `ring` and `tls12`;
rustls resolves `ring`, `std`, and `tls12`. Tokio enables the existing runtime,
I/O, network, synchronization, timer, and signal support. Test process support
also enables `process` in the shared test graph.

io-imap enables imap-codec's default features, `ext_condstore_qresync`, `ext_id`,
`ext_login_referrals`, `ext_mailbox_referrals`, `ext_metadata`, `ext_namespace`,
`ext_utf8`, `starttls`, `tag_generator`, and its compatibility quirks. These are
parser capabilities, not permission to issue those operations. The locked graph
can be inspected with `cargo tree --locked -e features -i imap-codec`.

## Operation routes

Each `ImapProbe` operation opens its own connection, authenticates, performs one
bounded discovery or UID-window search, and logs out. It returns owned results;
no connection returns to a pool. Dropping the operation future drops its socket,
including on timeout, EOF, malformed responses, or failed selection.

| Step | Direct io-imap route | Application check |
| --- | --- | --- |
| Implicit TLS | Tokio TCP and tokio-rustls before `ImapGreetingGet` | Trusted certificate chain and hostname; no plaintext authentication |
| STARTTLS | `ImapCapabilityGet`, typed `ImapSend<CommandCodec>` STARTTLS, tokio-rustls | Require advertised STARTTLS and tagged success; discard pre-upgrade capabilities and refresh after TLS |
| Authentication | `ImapLogin`, then `ImapCapabilityGet` | Require IMAP4rev1, refuse LOGINDISABLED, refresh capabilities after authentication |
| Exact discovery | `ImapMailboxList` for each deduplicated approved name | Reject wildcard requests and unexpected returned names; bounded deterministic inventory |
| Selection | `ImapMailboxExamine` | Require UIDVALIDITY and tagged READ-ONLY before search |
| Search | `ImapMessageSearch` with `uid: true` and one explicit UID range | Exactly one SEARCH result; validate UID range, uniqueness, and result ceiling |
| Envelopes | `ImapMessageFetch` with `uid: true` | Request only UID, ENVELOPE, FLAGS, INTERNALDATE, and RFC822.SIZE; no message payload or flag-writing command |
| Cleanup | `ImapLogout` | Consume typed BYE and tagged completion; never send CLOSE or EXPUNGE |

Before forwarding a response to a coroutine, the adapter bounds its framing and
literal announcement, limits nesting, decodes it, and verifies its command tag
and permitted response shape. This guard is necessary because io-imap 0.6.0
otherwise skips some malformed untagged responses, accepts unrelated completion
tags, and can expand unsolicited VANISHED ranges. The probe rejects those ranges
before the backend can allocate their UID list. Referrals fail locally; they
never cause a connection to another server.

## Bounds and measured allocations

| Probe limit | Default | Maximum |
| --- | --- | --- |
| One IMAP response frame | 64 KiB | 256 KiB |
| Decrypted IMAP bytes per operation | 2 MiB | 8 MiB |
| One literal | 64 KiB | Response-frame limit |
| Response count | 4,096 | 16,384 |
| Parser-work budget | 8,388,608 | 33,554,432 |
| Parenthesis nesting outside quoted strings/literals | 20 | 40 |
| Approved mailbox names | 1,000 | 1,000 |
| UID-window width | 1,000 | 10,000 |
| Returned envelopes | 50 | 200 |
| Whole operation / connection establishment | 30 / 10 seconds | 120 / 30 seconds |

A response must fit the frame and remaining operation budgets, including its
literal. Exceeding a result ceiling returns an explicit error. This probe does
not return partial results or claim that an unfinished search is complete.
Parser work charges incoming bytes, two typed passes per frame, and coroutine
resumes. The nesting guard runs before recursive decoding. Response counters
also bound unsolicited progress that might otherwise retain an operation.

The allocation test measures the client on a current-thread runtime; the
transcript server runs on another OS thread. Measurements include client TLS,
framing, parsing, and result allocation during the operation, but exclude
endpoint/certificate construction and server allocations. Assertions cap the
small reference routes at 2 MiB live heap, 16 MiB cumulative allocation, and
100,000 allocations. These thresholds are regression gates for the fixtures,
not claims about every permitted mailbox or input. Protocol counters separately
enforce the configured byte and work ceilings.

The 32 MiB oversized-literal case sends only the declaration. It must fail while
the admitted-literal counter remains zero, and the server must observe the
connection close. The test therefore detects draining or allocation based on
the declared payload length.

## Recorded local run

On 2026-09-09, the transcript suite passed 16 tests and the GreenMail suite passed
2 tests on macOS 26.6.2 (25G83), Apple Silicon, Rust 1.98.1, and Docker Engine
29.7.2 through Docker Desktop's `desktop-linux` context. Both suites used debug
builds, local synthetic fixtures, and fixture-only credentials. No provider
account or native credential store was used.

The client-only allocation run observed the following byte counts; minor
variation between runs is expected from generated command tags and TLS state.

| Reference route | Peak live allocated bytes | Cumulative allocated bytes |
| --- | ---: | ---: |
| Exact discovery | 20,601 | 39,324 |
| UID search and envelope | 24,289 | 57,779 |
| Envelope with a 60 KiB subject literal | 330,171 | 741,459 |
| STARTTLS search and envelope | 24,407 | 64,755 |
| Refused 32 MiB literal declaration | 19,699 | 40,938 |

The 60 KiB subject case consumed 61,923 IMAP bytes and 185,799 parser-work units.
Its subject was returned intact. The oversized case admitted zero literal bytes.
Dependency policy, license/advisory checks, typechecking, and scoped Clippy also
passed. Reproduce allocation output with the transcript command above.

## Evidence gates

Authentication currently accepts printable ASCII credentials. Mailbox names
accept printable ASCII, including spaces and ampersands, but reject wildcards
and international names. Literal authentication and wider mailbox-name support
need their own route evidence.

The probe proves only the routes exercised by its tests. Bounded selected-body
retrieval remains gated by #4, attachment streaming by #5, and APPEND
acknowledgement semantics by #6. Search predicates, durable cursors, access-grant
integration, and normalized application envelopes remain #9–#10 work. Native
credential provisioning remains #7 work. No local fixture result establishes
live IONOS compatibility or platform release qualification.
