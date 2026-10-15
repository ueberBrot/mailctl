# Operations

This guide covers the first distribution target: cooperative operation on macOS
on Apple Silicon, using CLI-only, MCP-only, or combined installations. Packaged
acceptance ran on macOS 26.6.2; this does not establish a minimum macOS version.
Ubuntu and Windows development CI do not qualify distribution on those systems.
Optional isolation, Homebrew, Linux, WSL, Windows, and Intel Mac distribution
remain separate acceptance work. See the [acceptance routes](acceptance/routes.md)
for the evidence and remaining gates.

## Choose an access grant

The operator configures access grants. Account and grant mailbox restrictions
intersect; omitted `mailboxes` allows current and future folders, while an explicit
list must be nonempty. A resource reference identifies a resource without granting
access to it.

| Configured profile | Account discovery | Mailbox discovery, search, body and attachment reads | Draft creation | Draft operation status |
| --- | --- | --- | --- | --- |
| `read_only` | Yes | Yes | No | No |
| `drafts_only` | Yes | No | Yes | Yes |
| `read_and_drafts` | Yes | Yes | Yes | Yes |

CLI uses the selected configured grant; the configured default must be
`read_only`. `--read-only` removes draft creation and draft history access; it
never adds reading permissions. Applied to `drafts_only`,
it leaves account discovery alone. MCP serving applies the same narrowing by
default. `--use-configured-grant` enables the selected grant's configured draft
permissions and conflicts with `--read-only`. `--grant` selects an approved grant;
`--account` narrows its accounts. Check the resulting permissions with
`mailctl capability show --json` or MCP `email_capabilities`.

Draft status requires current authority for the original account UUID, generation,
and exact target mailbox. For the current generation, current account and grant
mailbox restrictions and the configured Drafts mailbox apply. For an older
generation, the account must still be visible and the current grant must contain
an exact `historical_drafts` approval. An all-folders grant alone does not approve
historical generations.

Ordinary `draft status` / `email_draft_status` reads the journal without contacting
the provider. Explicit `--reconcile` / `reconcile: true` also requires draft
creation permission and writer ownership. Only an uncertain operation triggers
provider checks, against its stored original route. Reconfiguration never redirects
it to the current Drafts mailbox. An unavailable original route, missing target,
or changed UIDVALIDITY can leave the outcome uncertain. Reconciliation never
issues another APPEND. See `mailctl guide drafts` for the save/status recipe.

Setup, configuration changes, credential management, doctor checks, and state
maintenance are operator work. Both executables provide explicit administration
commands; MCP serving exposes none of them as tools and never prompts. Access
grants constrain mailctl calls, while separate shell or filesystem access remains
under the execution identity's OS permissions. See the
[access boundary](adr/0001-agent-email-access-boundary.md) and
[isolation decision](adr/0006-make-native-isolation-an-explicit-operator-choice.md).

## Rotate an account credential

Use the same configuration and execution identity as the affected installation.
For an MCP-only installation, substitute `mailctl-mcp` in the commands below.

1. Pause new CLI commands and MCP work for the account. Let active operations
   finish and retain their receipts and original draft inputs. Stop every relevant
   CLI process and long-running MCP runtime cleanly to close its authenticated
   sessions. Include an isolated runtime if that separately provisioned mode is
   in use. If a draft was interrupted after possible dispatch, preserve its
   `outcome_unknown` state and resolve the original operation after restart.
2. Obtain the replacement through the provider's approved procedure. For the
   native macOS Keychain source, provision it in an operator terminal:

   ```sh
   mailctl --account work credential set
   ```

   For a trusted command source, have its owner rotate the external secret and
   preserve its protected paths and execution permissions. `credential set` and
   `delete` cannot mutate an external command source. Do not put the replacement
   in command arguments or configuration.
3. Check provisioning, then explicitly test fresh authentication:

   ```sh
   mailctl --account work credential status --json
   mailctl --account work doctor --check-account --json
   ```

   Credential status reports source availability, not successful authentication.
   Require `ok: true` and
   `result.accounts[].authentication.outcome.status: "authenticated"` from the
   doctor check. Plain `doctor` performs no authentication.
4. Restart the runtimes with their approved grants, then resume work. Inspect any
   interrupted draft using its retained identity; request explicit reconciliation
   if needed. Keep uncertainty for operator review if verification is inconclusive.

Updating or deleting a local credential does not close an already authenticated
provider session. Without stopping processes, an existing pooled connection can
remain usable until its configured lifetime from connection establishment
(`connection_lifetime_seconds`: default 300 seconds, maximum 900 seconds), plus an
active operation's deadline. Rotation does not reset that age, and expiry does
not interrupt an active operation. Local deletion or replacement does not revoke
provider sessions or the old provider credential; provider-side revocation is a
separate operator action.

## Handle degraded operation

Readiness describes the selected grant and visible accounts, using locally
observed availability. It is not an authentication or provider-health guarantee.
Draft journal and creation readiness appear only when the caller has the
corresponding draft permissions. A read-only caller's readiness cannot establish
draft readiness.

`journal_full` refuses new draft operations while preserving existing status,
reconciliation, and healthy reads. The operator can raise `journal_records`
through the normal exclusive configuration update; never delete history or
tombstones to make space. A journal storage failure or unavailable account writer
is a different condition: creation can be suspended even when capacity remains.
Known status may still be readable. Preserve the installation and its history;
unavailable history does not mean an empty journal or prove no prior APPEND.

Use `mailctl guide errors` or `mailctl-mcp guide errors` for bounded retries,
capacity refusals, credential failures, and export failures. For backup, restore,
upgrades, and recovery fencing, read both components' shared state help:

```sh
mailctl state --help
mailctl-mcp state --help
```

Follow the instructions for the installed component. They require all runtimes
stopped and exclusive access, retain recovery copies, and keep creation suspended
until history completeness has independent support. Do not remove live lock files
or replace an uncertain operation with a new UUID.

## Consuming application responsibilities

The consuming application owns its workflow checkpoints, deduplication, and
downstream actions. mailctl does not checkpoint an ingestion job or coordinate
effects outside draft creation. Check `ok`, completion fields, and continuation
before marking work complete; retrying or restarting a search may revisit data.
Search predicates are evaluated against live provider state on each page. The
cursor's upper UID excludes later arrivals; it does not freeze flags, message
contents, or predicate matches into a snapshot.

Retain the original draft account UUID and generation, operation UUID, exact
mailbox, entire unchanged composition, and receipts in durable caller-owned
state. Retain uncertainty and escalate when status or reconciliation cannot
establish the outcome. The draft journal does not replace these caller records.

For body continuation, keep the same message reference and `max_bytes` choice.
Record `body.representation_version` as opaque metadata. For attachments, assemble
decoded chunks at their reported offsets and verify the final byte count and
SHA-256. After a transfer expires or its session ends, restart from the resource
reference and replace the partial assembly. See the installed `reading`,
`attachments`, and `drafts` guides for the complete contracts.
