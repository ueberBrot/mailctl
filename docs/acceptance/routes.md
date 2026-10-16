# Acceptance routes and evidence limits

This record supports [#18](https://github.com/ueberBrot/mailctl/issues/18) and
[#24](https://github.com/ueberBrot/mailctl/issues/24). It describes the routes and
test oracles in main `6732bd066fa067656e0ed88a9a240d257a54d1c8`, source tree
`f62048a4804455b44cb40201d7e84d0a64ad20e8`. It does not qualify a release by itself.
See [Operations](../operations.md) for the operator procedures and profile matrix.

## Platform and components

The first distribution scope is cooperative macOS on Apple Silicon, with
CLI-only, MCP-only, and combined installations. The retained packaged checks ran
on macOS 26.6.2 (25G83), arm64. No minimum macOS version is established by that
run. [Development CI](../../.github/workflows/ci.yml) builds and tests on Ubuntu,
macOS, and Windows; those jobs do not establish distribution qualification for
Linux, WSL, Windows, or Intel Macs. Homebrew and optional native isolation require
their own acceptance.

## Dependencies and operation routes

[Cargo.toml](../../Cargo.toml) and [Cargo.lock](../../Cargo.lock) pin io-imap
0.7.1 without default features, Tokio 1.53.2, tokio-rustls 0.26.6 with `ring` and
`tls12`, mail-builder 1.0.0 without default features, and rusqlite 0.40.2 with
bundled SQLite. The immutable imap-codec patch revision is
`d69e4bd1b26b812518a0e47a2cf636ed7671ba66`.

The executable [policy check](../../examples/check-policy.rs), run with
`cargo run --locked --example check-policy`, checks those five direct version
pins, the relevant production features, CLI-only exclusion of MCP dependencies,
toolchain consistency, and fixture checksums. The codec revision is recorded in
the manifests; the policy executable does not check that revision.

| Operation | Current production route | Evidence |
| --- | --- | --- |
| Authentication and TLS | Tokio networking, tokio-rustls, io-imap greeting/capabilities/LOGIN; implicit TLS or explicitly configured STARTTLS | [authentication](../../src/authentication.rs), [transcripts](../../tests/imap_transcript.rs) |
| Mailbox discovery | Bounded LIST inventory or exact LIST for approved names | [IMAP service](../../src/service/imap.rs), [transcripts](../../tests/imap_transcript.rs) |
| Search and metadata | EXAMINE, bounded UID SEARCH, UID FETCH of UID/ENVELOPE/FLAGS/INTERNALDATE/RFC822.SIZE | [search route](../../src/imap/search.rs), [search bounds](../../tests/search_bounds.rs) |
| Selected text | EXAMINE, UID/RFC822.SIZE/BODYSTRUCTURE, bounded header and whole-message or selected-part BODY.PEEK; mail-parser/encoding_rs decoding and html2text conversion | [body route](../../src/imap/body.rs), [body bounds](../../tests/imap_body_bounds.rs), [representation bounds](../../tests/imap_body_representation_bounds.rs) |
| Attachments | Bounded structure/metadata retrieval and selected-part BODY.PEEK chunks; incremental decoding and SHA-256 | [attachment route](../../src/imap/attachment.rs), [allocation oracle](../../tests/imap_attachment_allocations.rs) |
| Draft creation | mail-builder composition; rusqlite journal and account writer ownership; streamed APPEND with `\Draft` | [draft service](../../src/service/drafts.rs), [APPEND oracle](../../tests/imap_append_allocations.rs), [packaged drafts](../../tests/packaged_drafts.rs) |
| Draft status and reconciliation | Status reads the journal. Explicit reconciliation uses the stored original target, EXAMINE, bounded UID SEARCH by Message-ID, BODY.PEEK chunks, and full MIME hash comparison; no APPEND | [draft service](../../src/service/drafts.rs), [reconciliation oracle](../../tests/imap_reconciliation.rs) |

## Fixture bounds

These are asserted ceilings for the named fixtures, not universal memory maxima
for arbitrary messages or configured limits. Allocation-counter measures client
heap allocations within each measured call: peak live bytes and cumulative
allocated bytes. Fixture servers run separately. These figures exclude thread
stacks, RSS, and allocations outside the measured calls. Wire below means admitted
inbound response bytes unless explicitly marked outbound; parser steps are the
instrumented parser counter, not CPU instructions. KiB/MiB use powers of 1024.

| Oracle and fixture | Asserted evidence |
| --- | --- |
| [imap_transcript](../../tests/imap_transcript.rs), `client_allocations_remain_bounded_for_discovery_envelopes_and_oversized_literals`: single/1,000-mailbox discovery, simple/60 KiB-subject/STARTTLS envelope, oversized declaration | Each peak <2 MiB, cumulative <16 MiB, wire <64 KiB, parser steps <256 × 1024. The declared 32 MiB literal is refused before payload admission (`max_literal_bytes == 0`). |
| [search_bounds](../../tests/search_bounds.rs), `maximum_fragmented_search_and_page_have_bounded_client_resources`: 32 × 4,096-byte predicate literals and 200 result rows | Peak <8 MiB, cumulative <32 MiB, inbound wire <64 KiB, parser steps <512 × 1024. The wire measure excludes the 128 KiB of outbound predicate literals. |
| [imap_body_bounds](../../tests/imap_body_bounds.rs), `body_representations_have_measured_initial_and_continuation_bounds`: transfer encodings, charsets, malformed tails and HTML, whole/selected routes, initial page and one continuation | Each measured call peak <2 MiB, cumulative <16 MiB, with 1,024-byte text pages and the test's 8,192/32,768-repeat inputs (HTML uses one eighth). The separate near-default-2-MiB ASCII fixture, `whole_and_partial_continuation_have_measured_finite_costs`, asserts peak <32 MiB and cumulative <128 MiB. |
| [imap_body_representation_bounds](../../tests/imap_body_representation_bounds.rs), `hostile_html_admission_and_refusal_have_bounded_allocations` | 128 table cells accepted/129 refused; independently counted 4,096 DOM nodes accepted/4,097 refused; huge spans accepted safely; source-size and early work refusals. Peak <2 MiB, cumulative <16 MiB. Failed HTML renders expose wire/parser/allocation evidence, with no exposed decoder-work or node-visit counter. |
| [imap_attachment_allocations](../../tests/imap_attachment_allocations.rs), `full_attachment_transfers_have_payload_independent_memory_and_bounded_counters`: raw/base64/quoted-printable, decoded sizes 64 KiB + 13 and 1 MiB + 13 | Peak <512 KiB, cumulative <128 MiB, retained transfer state ≤32,896 bytes using 16 KiB wire slices/chunks. Independent decoded length and SHA-256 checks; per-call parser steps ≤4 × wire + 64. |
| [imap_append_allocations](../../tests/imap_append_allocations.rs), `streamed_append_keeps_backend_allocations_independent_of_mime_size`: 16 KiB/1 MiB input bodies | Backend peak <512 KiB; peak growth ≤64 KiB; outbound APPEND bytes ≤MIME length + 128; parser steps ≤4 × inbound wire + 128. MIME composition precedes this measurement. |
| [imap_reconciliation](../../tests/imap_reconciliation.rs), `multi_chunk_reconciliation_has_bounded_memory_wire_and_parser_work`: 16 KiB/512 KiB input bodies | Peak <512 KiB; literal ≤16 KiB; response frame ≤20 KiB; wire ≤configured `wire_fetch_bytes`; parser steps ≤4 × wire + 1,024; zero outbound APPEND bytes. |
| [imap_mime_depth](../../tests/imap_mime_depth.rs), [imap_allocations](../../tests/imap_allocations.rs), and [process caller checks](../../tests/process-driver/tests/mime_depth.rs) | Semantic depth exact/one-over checks include default 20 and maximum 40. Codec checks include 63 accepted/64 refused, malformed/truncated forms and extensions. Codec heap peak <512 KiB, cumulative <2 MiB. Separate stack checks use 2 MiB debug/1 MiB optimized library polling stacks and one-MiB CLI/MCP lifecycle callers. |

## Retained packaged evidence

The [PR #72 candidate audit](https://github.com/ueberBrot/mailctl/pull/72) records build
commit `703bf93eb6384e7c1c6d4170f3a329c0d19908bf`, with the same source tree as
the main commit above. Its `mailctl-candidate-aarch64-apple-darwin` artifact retains
the build/acceptance records, installer manifest, binaries and checksummed logs.
Later candidate bytes still need their own matching evidence.

| Installed selection | Packaged reading checks passed | Packaged draft checks passed |
| --- | --- | --- |
| CLI-only | 13 | 18 |
| MCP-only | 12 | 19 |
| Combined | 25 | 39 |

These checks use disposable loopback TLS providers and externally provisioned
synthetic command credentials. The separate native credential check uses a
disposable Apple Keychain entry. They do not establish live-provider behavior.
Retained SHA-256 values identify the exact candidate and suite logs:

```text
44b2362e41e35129fb55c15bf1f5b44a9785d0583066654bc5ecf7a5f3b3108f  mailctl-aarch64-apple-darwin.tar.gz
e6dd52553692ee67a252ffa251ce2f1d172cf756bf42876cb97a04fd03538b1f  mailctl
87cfdb6af2cd8b92208c825ffe4835e7f1b371d78b778184efcc69660c258c52  mailctl-mcp
e6a7118ed55e07d1be2c6e745e9062d23bfbbf8e9ab2f5d32be3755f79757558  installed-reading-cli-acceptance.log
f46fa493d191212b27045edc6f35d73ff453a1545540f3b43fe3bed95d2af5cd  installed-reading-mcp-acceptance.log
c1b286c593c64283c742effa05b36e16c955a173931fbf7adde2ddb91926bd96  installed-reading-cli-mcp-acceptance.log
c3dfb9a5fd1c2563bba582e492504aa285d5c244136feee5d3e7fbabaf57ab49  installed-drafts-cli-acceptance.log
cfb238db4288fc89fa2b0389df6a85327acb8ef80739cecc1fd03da3f568524b  installed-drafts-mcp-acceptance.log
3639ab9b9385ae1c5bc4f65ab374a0c157c8f3d0c2db619f3e9c3c28af6b641b  installed-drafts-cli-mcp-acceptance.log
```

The accepted IONOS baseline in [#43](https://github.com/ueberBrot/mailctl/issues/43)
and [#50](https://github.com/ueberBrot/mailctl/issues/50) remains completed. The
final affected packaged IONOS refresh remains pending within the existing approved
scope. Genuine uncertain-draft fault cases require an approved disposable account;
ordinary-account authorization does not cover induced faults. Final packaged
actual-client and fresh-agent acceptance also remains pending under the
[Codex procedure](codex-mcp.md), after the candidate
README is final. None of this evidence authorizes publication or completes those
remaining gates.

## Release-note review

The first release remains unreleased. Review the regenerated release-plz candidate
for compatibility and migration text, including the required
`body.representation_version` field and strict response-schema regeneration.
[release-plz.toml](../../release-plz.toml) retains that migration in its curated
initial-release template. Keep the preparation PR open while the candidate changes;
version changes, merging the release PR, tags, and publication are separate work.
