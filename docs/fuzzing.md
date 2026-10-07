# Bounded parser campaigns

Run the retained regressions with the ordinary workspace tests. The required
CLI-only, MCP-only, and combined CI jobs discover them automatically. They use
synthetic corpus inputs and disposable loopback TLS fixtures.

Dispatch a local mutation campaign explicitly:

```sh
bash scripts/fuzz-campaign.sh
```

`MAILCTL_FUZZ_CASES` selects 1–4096 mutations per surface (default 64).
`MAILCTL_FUZZ_SEED` selects the decimal seed (default 35001). For example:

```sh
MAILCTL_FUZZ_CASES=256 MAILCTL_FUZZ_SEED=35002 bash scripts/fuzz-campaign.sh
```

The runner records the commit, working-tree patch and checksum, corpus checksums,
platform, toolchain, command results, executable checksums, and campaign status in
`target/fuzz-campaigns/`. Each surface reports its seed, case count, input ceiling,
and elapsed time. Reports identify synthetic cases without printing mutated
inputs, resource references, credentials, or email content.

The campaigns mutate real IMAP MIME/body and attachment decoding routes,
authenticated resource references and cursors, application operations, MCP STDIO
frames, IMAP framing, and uncertain draft retries. The mutation generator uses
specified integer arithmetic and caps inputs at 16 KiB. Each harness checks
allocation ceilings and bounded completion; IMAP harnesses also check production
wire/parser/decode metrics and independently reject mutating commands. Draft
retries keep their original identity and verify that uncertainty never causes
another APPEND. MCP process capture drains both streams with byte ceilings and a
termination deadline.

These are reproducible mutation campaigns. They do not use coverage feedback or
establish exhaustive parser coverage. Runtime-generated authentic references have
fresh installation identities; the seed reproduces their mutation positions and
operations rather than their opaque bytes.

When a campaign finds a failure, reduce its synthetic input while keeping the
same public operation and failing assertion. Retain the smallest useful fixture
under `tests/fuzz_corpus/`, add a normal test with an independently expected
result, fix the production path, and rerun the affected campaign. Keep private
provider inputs and secrets out of the corpus and evidence.

Release preparation and new CI dispatch jobs remain gated on the real-provider
reading acceptance in issue #43. A future gated preparation job can invoke this
same runner and retain its evidence. Ordinary pushes run the deterministic
regressions; campaigns have no scheduled workflow.
