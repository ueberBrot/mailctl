# Operations

Version 0.1.0 targets macOS on Apple Silicon, with CLI-only, MCP-only, or combined
installations. Standard operation uses the operator's OS identity. Access grants
limit calls through mailctl. Packaged acceptance ran on macOS 26.6.2, without
establishing a minimum macOS version.

The accepted IONOS and Codex baselines cover the candidate bytes recorded in the
[acceptance routes](acceptance/routes.md). They do not qualify arbitrary later
builds or other providers and clients. Ubuntu and Windows development CI do not
qualify distribution on those systems. Optional isolation, Homebrew, Linux, WSL,
Windows, and Intel Mac distribution require separate acceptance.

## Update or remove components

Use the installation channel that owns each executable. The standalone installer
owns its binaries and `.mailctl-components` manifest. It preserves account
configuration, credentials, installation history, and Cargo/rustup metadata.
It refuses foreign or modified binaries. Keep the manifest with its binaries.

Before an update, stop every CLI command and MCP runtime that uses the installation.
Use `mailctl state --help` for backup and compatibility instructions. For an
MCP-only installation, use `mailctl-mcp state --help`. Keep the original draft
inputs and receipts. Binary removal does not close a running provider session.

Use the [version-pinned installer](../README.md#install-010-on-macos) for the target
release. For an existing installation with a custom configuration, pass its
absolute path:

```sh
sh install-v0.1.0.sh --version 0.1.0 --config /absolute/path/to/config.toml
```

For a later release, use that version in both the filename and `--version`.
The installer inspects the default configuration path when it exists. It runs
`state verify` with staged binaries before replacement. If both components are
installed, update both together when the version or source commit changes.
A single-component selection preserves an unselected component when they remain
compatible.

If you used `--install-dir` or a custom `CARGO_HOME`, select the same destination
for updates and removal. To remove both installer-owned components, run:

```sh
sh install-v0.1.0.sh --uninstall
```

To remove only one component, add `--components cli` or `--components mcp`.
The unselected component remains installed. Configuration, credentials, reference
keys, account identities, and draft history remain available for reinstallation.
If the installer reports an interrupted update, wait for its owner process to exit.
Then use its `--recover` action with the same destination. Keep its lock and
backups until recovery completes.

## Choose an access grant

An access grant defines permitted accounts, mailboxes, and operations. The operator
configures these grants. Account and grant mailbox restrictions intersect.
Omitted `mailboxes` allows current and future folders. An explicit list must be
nonempty. A resource reference identifies a resource without granting access.

| Configured profile | Account discovery | Mailbox discovery, search, body and attachment reads | Draft creation | Draft operation status |
| --- | --- | --- | --- | --- |
| `read_only` | Yes | Yes | No | No |
| `drafts_only` | Yes | No | Yes | Yes |
| `read_and_drafts` | Yes | Yes | Yes | Yes |

CLI uses the selected configured grant. The configured default must be
`read_only`. `--read-only` removes draft creation and draft history access.
It never adds reading permissions. Applied to `drafts_only`, it leaves only
account discovery. MCP serving applies the same narrowing by default.

`--use-configured-grant` enables the selected grant's configured draft permissions
and conflicts with `--read-only`. `--grant` selects an approved grant.
`--account` narrows its accounts. Make sure that the resulting permissions match
the intended scope with `mailctl capability show --json` or MCP `email_capabilities`.

A UUID is a unique identifier. Draft status requires current authority for the
original account UUID, generation, and exact target mailbox. For the current
generation, current account and grant mailbox restrictions and the configured
Drafts mailbox apply. For an older
generation, the account must still be visible and the current grant must contain
an exact `historical_drafts` approval. An all-folders grant alone does not approve
historical generations.

The journal stores draft operations and their outcomes. Ordinary `draft status`
or `email_draft_status` reads it without contacting the provider.
Explicit `--reconcile` or `reconcile: true` also requires draft creation permission
and writer ownership. Only an uncertain operation triggers provider checks against
its stored original route. Reconfiguration never redirects
it to the current Drafts mailbox.

An unavailable original route, missing target, or changed UIDVALIDITY can leave
the outcome uncertain. Reconciliation never issues another IMAP APPEND command.
See `mailctl guide drafts` for the save/status
recipe.

Setup, configuration changes, credential management, doctor checks, and state
maintenance are operator work. Both executables provide explicit administration
commands. MCP serving exposes none of them as tools and never prompts. Separate
shell or filesystem access remains under the execution identity's OS permissions.
See the [access boundary](adr/0001-agent-email-access-boundary.md) and
[isolation decision](adr/0006-make-native-isolation-an-explicit-operator-choice.md).

## Rotate an account credential

Use the same configuration and execution identity as the affected installation.
For an MCP-only installation, substitute `mailctl-mcp` in the commands below.

1. Pause new CLI commands and MCP work for the account.
2. Let active operations finish.
3. Retain their receipts and original draft inputs.
4. Stop every relevant CLI process and MCP runtime cleanly to close its authenticated
   sessions. If you use an isolated runtime, include it. If a draft was interrupted
   after possible dispatch, preserve its `outcome_unknown` state. Resolve the
   original operation after restart.
5. Obtain the replacement through the provider's approved procedure.
6. For the native macOS Keychain source, provision it in an operator terminal:

   ```sh
   mailctl --account work credential set
   ```

   For a trusted command source, have its owner rotate the external secret.
   Preserve its protected paths and execution permissions. `credential set` and
   `credential delete` cannot change an external command source. Keep the
   replacement outside command arguments and configuration.
7. Make sure that provisioning succeeds:

   ```sh
   mailctl --account work credential status --json
   ```

   Credential status reports source availability. It does not prove successful
   authentication.
8. Test fresh authentication:

   ```sh
   mailctl --account work doctor --check-account --json
   ```

   Require `ok: true` and
   `result.accounts[].authentication.outcome.status: "authenticated"` from the
   doctor check. Plain `doctor` performs no authentication.
9. Restart the runtimes with their approved grants.
10. Inspect interrupted drafts with their retained identities. If an outcome remains
    uncertain, request explicit reconciliation. If reconciliation is inconclusive,
    keep uncertainty for operator review.
11. Resume work.

Updating or deleting a local credential does not close an already authenticated
provider session. A connection's age starts when it opens. Its
`connection_lifetime_seconds` defaults to 300 seconds, with a maximum of 900
seconds. Without stopped processes, a connection can remain usable for that
lifetime plus an active operation's deadline. Rotation does not reset that age.
Expiry does not interrupt an active operation.

Local deletion or replacement does not revoke provider sessions or the old
provider credential. Provider-side revocation is a separate operator action.

## Handle degraded operation

Readiness describes the selected grant and visible accounts, using locally
observed availability. It is not an authentication or provider-health guarantee.
Draft journal and creation readiness appear only when the caller has the
corresponding draft permissions. A read-only caller's readiness cannot establish
draft readiness.

`journal_full` refuses new draft operations while preserving existing status,
reconciliation, and healthy reads. The operator can raise `journal_records`
through the normal exclusive configuration update. Never delete history or
tombstones to make space. A journal storage failure or unavailable account writer
can suspend creation even when capacity remains. Known status can remain readable.

Preserve the installation and its history. Unavailable history does not mean an
empty journal or prove that no APPEND occurred. Use `mailctl guide errors` or
`mailctl-mcp guide errors` for bounded retries, capacity refusals, credential
failures, and export failures.

For backup, restore, upgrades, and recovery, read your component's state help:

```sh
mailctl state --help
mailctl-mcp state --help
```

Follow the instructions for the installed component. They require stopped
runtimes and exclusive access. Retain recovery copies. Keep creation suspended
until independent evidence supports complete history. Keep live lock files.
Keep an uncertain operation's original UUID.

## Consuming application responsibilities

The consuming application owns its workflow checkpoints, deduplication, and
downstream actions. mailctl does not checkpoint an ingestion job or coordinate
effects outside draft creation. Before marking work complete, make sure that
`ok`, completion fields, and continuation establish completion.

A repeated search can revisit data. Search evaluates predicates against live
provider state on each page. The cursor's upper UID excludes later arrivals.
It does not freeze flags, message contents, or predicate matches into a snapshot.

Retain the original draft account UUID, generation, operation UUID, exact mailbox,
and entire unchanged composition in durable caller-owned state. Retain each
receipt. Retain uncertainty and escalate when status or reconciliation cannot
establish the outcome. The draft journal does not replace these caller records.

For body continuation, keep the same message reference and `max_bytes` choice.
Record `body.representation_version` as opaque metadata.

For attachments, assemble decoded chunks at their reported offsets. Make sure that
the final byte count and SHA-256 match the assembled bytes. If a transfer expires or its session
ends, restart from the resource reference. Replace the partial assembly. See the
installed `reading`, `attachments`, and `drafts` guides for the complete contracts.
