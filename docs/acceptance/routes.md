# Acceptance routes and evidence limits

This record supports [#18](https://github.com/ueberBrot/mailctl/issues/18) and
[#24](https://github.com/ueberBrot/mailctl/issues/24). It describes the routes and
test oracles audited in main `744ad89386610465b487686533d1d1c5b32c061d`, source tree
`c9a09e015a4beca1ff5b2c368a2af5a4c0913017`. It does not qualify a release by itself.
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

The [PR #73 candidate audit](https://github.com/ueberBrot/mailctl/issues/24#issuecomment-6209304368)
records build commit `52189ca06c1a5085a9d6ad1d41d85fc154c1b096`, with the same source tree as
the main commit above. Its `mailctl-candidate-aarch64-apple-darwin` artifact retains
the build/acceptance records, installer manifest, binaries and checksummed logs:
[artifact 11991697237](https://github.com/ueberBrot/mailctl/actions/runs/38770249651/artifacts/11991697237).
Later candidate bytes still need their own matching evidence.

The later [candidate audit](https://github.com/ueberBrot/mailctl/issues/18#issuecomment-6210340300)
identifies build `bdce9b795b6034afafabb2a00c978e96463e213e`, artifact `12030484034`,
associated with main `7d16a87a30fcb3aa6bf78ae9dbcc86992b28b7ec`. Its CLI/MCP and
README bytes match the earlier candidate. The prospective Codex evaluation below
selects those exact packaged bytes; its runner commit `5c449dd` changes only the
evaluation task/procedure. This does not establish full-tree equality with the
newer main or qualify newly built artifacts automatically.

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
8d8ae93b6f15a28ded68225e8e2c5e9958ec7a04cf1f41c70071b1291f1ba736  mailctl-aarch64-apple-darwin.tar.gz
e6dd52553692ee67a252ffa251ce2f1d172cf756bf42876cb97a04fd03538b1f  mailctl
87cfdb6af2cd8b92208c825ffe4835e7f1b371d78b778184efcc69660c258c52  mailctl-mcp
54eafe2c76bed0189f9de215add54c67faaaa97771b3bd6649a807727e10d71a  installed-reading-cli-acceptance.log
dae4943b98f40c5e9607e8f5bfa97159145d63f1c5e9e14c380b539a98621318  installed-reading-mcp-acceptance.log
62a01958c50e30af4df92c4e77ef6da3f0cb3a8bf3bc60e2823fd43dd0438f3d  installed-reading-cli-mcp-acceptance.log
508654654cfe2f36be8a448f80f94fd4876d6874984d1798ec978f892de99353  installed-drafts-cli-acceptance.log
8e67cad0dd7fea037841b2e493e9a233c99547108ab37fe167c68244b2cd7bbf  installed-drafts-mcp-acceptance.log
32d494edff12522bc7b77c261fe419c1cdba06fa1e600113fc21c8adbd34e9b4  installed-drafts-cli-mcp-acceptance.log
```

The accepted IONOS baseline in [#43](https://github.com/ueberBrot/mailctl/issues/43)
and [#50](https://github.com/ueberBrot/mailctl/issues/50) remains completed. The
affected ordinary packaged IONOS refresh passed on October 16 within the approved
scope. The current audit records matching CLI/MCP body continuation/version and
attachment/export bytes, two new acknowledged unsent drafts, retries/status/
conflict/permission checks, and independent content/flag/exactly-one observations.
The entire two-message INBOX remained unchanged. The operator subsequently
reported deleting the test drafts; their historical receipts and observations
remain valid, and cleanup does not authorize recreating them.

The operator explicitly approved a [single existing-account recovery check](https://github.com/ueberBrot/mailctl/issues/24#issuecomment-6212252957)
using one new labelled unsent draft and a local outcome-persistence failure in a
fresh private installation. [The preregistered check passed](https://github.com/ueberBrot/mailctl/issues/24#issuecomment-6212484189)
on these exact packaged bytes. Actual journal history progressed from
`in_flight` to `outcome_unknown`, then to `duplicate` through explicit MCP
reconciliation. The independent observer verified the original draft before
retry, its exact MIME hash/content/initial Draft flag, and the same sole UID
after CLI/MCP retries and reconciliation. Both preexisting INBOX messages kept
their content and flags; Entwürfe changed from empty to that one draft. Original
configuration/history fingerprints remained unchanged, and the owned trigger
was removed. Two independent audits verified the retained evidence.

This qualifies genuine uncertain local history and real IONOS reconciliation
after local outcome persistence failed. No tagged provider acknowledgement,
live acknowledgement loss or wire-level command count was independently
observed; broader fault coverage remains in synthetic packaged fixtures. The
single test draft remains for operator cleanup. No additional draft or live
check is needed for this unchanged scoped result. Publication remains excluded.

The October 16 Codex CLI 0.163.0 archive-recovery run
passed both mechanical profiles against these MCP and README bytes. Its complete
private archive is retained. Both fresh answers still omit part of the required
capacity explanation; those historical grades remain incomplete.

The subsequent single [preregistered scheduling evaluation](https://github.com/ueberBrot/mailctl/issues/18#issuecomment-6211505047)
passed both mechanical profiles and all five original comprehension items under
the [Codex procedure](codex-mcp.md). This completes actual-client/fresh-agent
criterion 7 for the named candidate. Initialization overlapped and tools/list
discovery remained sequential. Qualification establishes prompted application
of public guidance. The result retains unexplained nonfatal pre-turn client
diagnostics and the limits of payload-free evidence; it does not erase earlier
grades or establish spontaneous mention of every capacity layer. The single
attempt is consumed. None of these checks authorizes publication; #24 retains
the explicit operator publication gate and final commit/artifact checks.

## Release-note review

The first release remains unreleased. [Preparation PR #54](https://github.com/ueberBrot/mailctl/pull/54),
head `47dc66b42919efe4ff06bc99a05859673de3c613`, was reviewed for version 0.1.0,
the qualified platform scope and compatibility/migration text, including the
required `body.representation_version` field and strict response-schema regeneration.
[release-plz.toml](../../release-plz.toml) retains that migration in its curated
initial-release template. Keep the preparation PR open while the candidate changes;
version changes, merging the release PR, tags, and publication are separate work.
