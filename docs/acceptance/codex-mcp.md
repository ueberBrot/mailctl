# Actual Codex MCP acceptance

This opt-in check covers the actual Codex CLI interoperability and fresh-agent
criterion in [#18](https://github.com/ueberBrot/mailctl/issues/18). It uses the
current native Codex login and makes authenticated model calls. Run it only with
operator authorization. Ordinary PR CI must not run it.

## Prerequisites and invocation

Use Python 3.9 or newer, OpenSSL, and an authenticated Codex CLI. The runner was
checked with Codex CLI 0.162.1 and 0.163.0. Its installed `exec --help` must support
`--strict-config`, `--ignore-user-config`, `--ignore-rules`, `--ephemeral`,
`--json`, `--sandbox`, `--skip-git-repo-check`, and inline TOML `-c` settings.
It also uses the installed
`shell_tool`, `apps`, `plugins`, `multi_agent`, `skill_search`, and
`skip_host_skill_discovery` feature settings. Unsupported clients fail acceptance;
do not silently remove the isolation settings.

For provisional source evidence:

```sh
cargo build --locked --bins
python3 scripts/acceptance/codex_mcp.py --run \
  --bin-dir "$PWD/target/debug" --codex /opt/homebrew/bin/codex \
  --model gpt-6.1-sol --provenance source-provisional \
  --candidate-commit "$(git rev-parse HEAD)" --profile both --timeout 600
```

For a final packaged rerun, select the independently verified, installed
candidate directory and its matching README. Create a private persistent parent
directory, then select a new evidence directory for this run:

```sh
mkdir -m 700 -p "$HOME/.mailctl-qualification"
python3 scripts/acceptance/codex_mcp.py --run \
  --bin-dir /absolute/verified/candidate/bin --codex /opt/homebrew/bin/codex \
  --model gpt-6.1-sol --provenance packaged \
  --candidate-commit '<full qualified candidate commit>' \
  --readme /absolute/candidate/source/README.md --profile both --timeout 600 \
  --output "$HOME/.mailctl-qualification/codex-candidate-001"
```

`--provenance packaged` records the operator's selection; it does not verify an
archive, installer manifest, signature, or asserted commit. Attach the existing
candidate audit proving those associations. The runner records the actual MCP,
Codex and README hashes and pins a private copy of the MCP executable for both
profiles, so a concurrent source build cannot replace the tested bytes. It uses
only `mailctl-mcp`; a sibling CLI or broker is
unnecessary and absent from the MCP child PATH. This check does not establish
CLI-only or installer qualification.

Each profile owns a disposable installation and loopback TLS provider. Operator
setup runs before MCP starts, using production command credentials backed by a
private synthetic file and `/bin/cat`, with `SSL_CERT_FILE` for local trust. A
separate incorrect-password probe must fail. No Keychain, live provider,
operator mailctl configuration, or ordinary email is used. HOME and CODEX_HOME
retain their original meanings for native Codex authentication; the runner never
opens authentication files or prints credentials.

The two MCP definitions are passed together to a fresh actual `codex exec`.
Codex controls their startup and requests. One server sees both synthetic
accounts; the other is narrowed to synthetic-blue. User configuration and rules
are ignored; project instruction loading, shell, apps, plugins, skill discovery
and sub-agents are disabled. The model receives only the workflow task, public
README/help and draft input schemas, plus live MCP tool schemas and public guide
resources. It receives no implementation or evaluator rubric.

`small` configures a 65536-byte envelope and 4 active/4 queued process ceilings;
`default` retains the default envelope and process ceilings. Both use two
per-account connections and two waiting requests to make account admission
observable. A six-call probe requests limits 1 through 6 concurrently on each
server. Provider LIST replies have a fixed 0.8-second delay; the STDIO proxy adds
no artificial delay, startup barrier, request generation, or serialization.

`--timeout` bounds the combined authenticated execution, including fixture
preparation for both profiles after public-material collection. Certificate
generation, production setup, the entire wrong-password exchange and each client
run share that deadline; their individual limits can only shorten it. Expiry is
followed by bounded cleanup, including the client's three-second process-group
grace, up to three seconds to reap it and bounded pipe-worker joins. Each fixture
allows up to three seconds to join its provider threads. Owned process groups,
local sockets and temporary credential/state files are cleaned up on completion,
timeout or interruption.

## Evidence and evaluation

The runner prints its private evidence directory. `--output` can select a new
directory instead. Final qualification must use a persistent directory outside
the operating system's temporary directories. Keep its executable snapshot,
provenance, workflow, invocation, answers, summaries and traces together, and
record a checksum index after the run. Fixture cleanup is separate from evidence
retention. It retains hashes/platform/client identity, the public task,
invocation, payload-free client event metadata, per-server STDIO traces, synthetic
agent answers and a mechanical summary. Raw Codex diagnostics and raw MCP
payloads are not retained. STDIO trace records contain only monotonic timestamps,
production PIDs, methods, request IDs and result codes. Offline regression checks
verify exact byte forwarding and exclusion of payloads:

```sh
PYTHONPYCACHEPREFIX=/private/tmp/mailctl-codex-pycache \
  python3 -m unittest discover -s scripts/acceptance -p 'test_codex_mcp.py' -v
```

Inspect the results as separate evidence:

- Initialization request intervals prove or disprove concurrent startup. Record
  tools/list interval overlap separately: live process overlap alone does not
  prove concurrent discovery.
- Six distinct mailbox probe calls per server and overlapping actual STDIO tool
  request intervals prove client concurrency. Immediate refusals may finish
  before all six calls arrive, so peak outstanding requests can be below six.
- Record numeric JSON-RPC `-32000` transport refusals separately from structured
  application `rate_limited` outcomes and successful response durations. Default
  transport memory reservations can admit one request, retain one waiting
  request, and refuse excess. The smaller envelope permits several admissions;
  per-account connection/waiting limits can still refuse work. Advertised process
  ceilings are upper bounds. Neither profile establishes an installation-wide
  account quota.
- Mechanical checks verify discovered capabilities/accounts and all five guide
  reads on both servers, exact four-page Unicode text, unchanged 32-byte budget
  and continuation chain, the new opaque representation version, cross-process
  message-reference reuse, denial of mail_b searching the exact amber INBOX
  reference previously discovered through mail_a, foreign transfer-token
  refusal, and a restarted attachment's exact bytes/offsets/count/SHA-256. The
  independent provider rejects unknown or mutating commands and reports safe
  counters. No draft tool may be called.

A zero exit status establishes only the mechanical checks. Review the fresh
agent's answer against this comprehension rubric before claiming the #18
criterion complete:

1. It checks `ok` and discovery completion, chooses returned aliases/references,
   and explains that references do not expand the receiving access grant.
2. It retains the same message and max_bytes choice across continuation, follows
   `continuation_available` to completion, and records
   `body.representation_version` as opaque rendering metadata.
3. It explains attachment reference portability and token session ownership,
   replaces partial assembly after restarting, and distinguishes proposed
   application hash checks from checks actually performed by the runner.
4. For the hypothetical uncertain draft, it retains original account UUID and
   generation, operation UUID, exact mailbox and entire unchanged composition;
   proposes status and explicit reconciliation without another APPEND; and
   preserves uncertainty for operator review if verification is inconclusive.
5. It distinguishes configured process ceilings, transport admission and account
   connection/waiting limits, and separates observed outcomes from explanations
   or unperformed actions.

Document any failure using the public task, actual call/result metadata and
answer excerpt. Fix a concrete public guidance/schema defect before repeating
the same fresh task. Do not teach the expected answer through a revised task.

Archive loss requires a separately recorded evidence-recovery run. Before that
run, record the missing files, surviving results, selected executable/README and
client/model identities, and a stop after one complete small/default run. Keep
the task and rubric unchanged. Retain and assess the earlier incomplete results
alongside the new evidence; a recovery run does not erase them or establish a
guidance fix. Review every rubric item independently. If the new run is
incomplete, keep the gate open rather than repeating until it passes. Label this
as archive recovery, not as following the guidance-fix repeat procedure above.

Source results are provisional. Repeat against the final candidate after byte
changes; earlier 7113046 binaries cannot qualify representation-version metadata
added later. This procedure does not qualify live-provider refresh, draft fault
behavior, publication, or the remaining release gates.

Retained source-provisional runs with Codex CLI 0.162.1 recorded overlapping
initialization in both profiles. `tools/list` discovery overlapped only in
`small`; `default` discovery was sequential. The default agent answer claimed
it computed an attachment hash, but no observable hashing action substantiates
that claim. Only the runner's independent digest calculation is verified.
Final packaged qualification remains pending.

The [October 15 packaged run](https://github.com/ueberBrot/mailctl/issues/24#issuecomment-6209304368)
used the executable and README bytes associated with the PR73 candidate. Both
mechanical profiles passed. Independent review passed all five comprehension
items for small; default omitted per-account connection/waiting limits in item 5.
Its answer made no contrary claim, and the overview already explains those
limits. The original temporary archive is unavailable; recovered chat excerpts
include the default answer and selected summaries, but not the complete traces
or small answer. These retained observations do not complete the gate.

One preregistered archive-recovery run on October 16 used Codex CLI 0.163.0,
`gpt-6.1-sol`, the same packaged MCP/README bytes, and the unchanged task/rubric.
Both mechanical profiles passed; both initialized concurrently, while tools/list
discovery remained sequential. Full workflows, invocations, answers, summaries
and payload-free traces are retained in private persistent storage with checksums.
Independent review passed items 1–4 for each profile. Both answers omitted
per-account connection/waiting limits and did not explain transport memory
admission, leaving item 5 incomplete. Default also disclosed losing its own
capture of four probe responses; the runner traces retain their numeric transport
refusals. No unsafe action, unsupported hash claim or public guidance defect was
found. Criterion 7 remains open, and this recovery plan permits no further attempt.

## Prospective scheduling explanation

`scheduling-explanation-v1` asks how a consuming application would schedule a
larger read task using its probe results and public material, including what it
can and cannot determine. The original task asked for probe outcomes without
explicitly requesting this reasoning, while rubric item 5 assessed it. Two
independent reviews accepted the added question as neutral: it supplies no
expected capacity layers, mechanisms, numbers or answer. All existing task
requirements and all five rubric items remain unchanged; the rubric stays out
of the fresh client's materials. The runner records the protocol name and task
hash in provenance.

This amendment permits one prospective small/default evaluation pair under the
new protocol, separately from the exhausted archive-recovery plan and the
unchanged-task guidance-fix route. Publish this amendment and an immutable
preregistration before execution. Record the task, runner, fixture, executable
and README hashes, candidate audit, client/model identities, timeout, and stop
after one attempt of each profile, including failure or incomplete evidence.
Retain all earlier results and grade every rubric item independently. Item 5
requires its stated distinctions, without a detailed memory derivation or
unexposed numeric account limits. If either profile is incomplete, criterion 7
stays open and this protocol permits no further attempt.

This prospective design change follows observed omissions and therefore limits
comparison with earlier runs. It establishes no product guidance defect and
does not change earlier grades. Any passing result would establish prompted
application of the public guidance for the recorded candidate/client, rather
than spontaneous mention of every capacity layer.

The single [preregistered evaluation](https://github.com/ueberBrot/mailctl/issues/18#issuecomment-6211339872)
completed on October 16 with Codex CLI 0.163.0 and `gpt-6.1-sol` against the
same audited MCP/README bytes. [Retained results](https://github.com/ueberBrot/mailctl/issues/18#issuecomment-6211505047)
passed both mechanical profiles and all five original rubric items in two
independent semantic reviews. Initialization overlapped; tools/list discovery
remained sequential. Both answers distinguished process ceilings, transport
admission and per-account connection and waiting limits, with application
hash checks and hypothetical draft recovery correctly labelled as proposed.

Each profile emitted one pre-turn client error item whose text was intentionally
not retained; its cause remains unknown. No failed required operation was
associated with those events. Payload-free traces establish metadata facts;
detailed body/attachment checks rely on the reviewed runner's recorded results.
The complete private archive and checksum index are retained. This completes
criterion 7 for the named candidate under this protocol, preserving earlier
incomplete grades and all stated interpretation limits. The single attempt is
consumed; no further run is permitted. Publication remains separately gated;
[#24 records the subsequent scoped IONOS recovery result](https://github.com/ueberBrot/mailctl/issues/24#issuecomment-6212484189).
