# mailctl

Email tools for the command line and MCP. It supports account and mailbox
discovery, bounded message search and body reads, attachment retrieval, reusable
resource references, capability reporting, macOS credential provisioning, and
authentication diagnostics. It also creates unsent drafts and inspects their
durable outcomes through either interface. Retain the account UUID, generation,
operation UUID, and original input before saving. Identical retries share the
recorded outcome. Explicit reconciliation can verify an uncertain draft against
its original target; uncertainty never permits another APPEND.

Build both executables:

```sh
cargo build --locked
```

Configure an account and list it:

```sh
./target/debug/mailctl setup --alias work --server imap.example.com --username user@example.com
./target/debug/mailctl account list --json
```

For a new installation, setup grants read-only access to every current and future
folder. Newly created account and grant scopes omit `mailboxes`, which means all
folders. A folder created on the provider appears in a later discovery request
without editing configuration or restarting the process.

To restrict folders, set an explicit, nonempty list such as
`mailboxes = ["INBOX", "Archive"]` on the account, access grant, or both. The
effective scope is their intersection. Names containing `*` or `%` identify
literal folders; they are not patterns. An empty list is invalid. Re-running
setup preserves existing explicit restrictions and credential references.
After editing configuration, run `setup` to apply its revision and restart
long-running MCP processes. Draft creation requires a `drafts_only` or
`read_and_drafts` grant, approved From identities, and a configured existing
Drafts folder. MCP also requires `--use-configured-grant` to enable those draft
permissions.

Run `./target/debug/mailctl-mcp` to serve MCP over STDIO using the same configuration.
Use `--grant` to select an access grant, `--account` to narrow accounts, or `--help`
for available commands.

## Draft history after account changes

Keep the original account UUID, generation, operation UUID, mailbox, and input
when retrying a draft. Alias changes preserve the account identity. Changes to
the server, TLS settings, username, credential source reference, or Drafts mailbox
advance its generation. Restart MCP after changing configuration.

To inspect or resume an operation from an older generation, add its exact target
to the selected draft-capable grant. Replace the example UUID with the original
account UUID returned by discovery:

```toml
[[grants.historical_drafts]]
account_id = "11111111-1111-4111-8111-111111111111"
account_generation = 1
mailbox = "Drafts"
```

Place this table under the relevant `[[grants]]` entry. The grant must still
include that account's stable configuration key; account narrowing and read-only
narrowing also apply. Historical scope authorizes only draft history and retries
of existing prepared operations. It grants no message reads or new draft creation
in an old generation. Removing the scope revokes historical access.

Set `retain_history = true` on the account **before** repointing it to retain its
original server, TLS, username, and credential source reference for prepared
retries and reconciliation. Retention stores no secret values and grants no
authority by itself.
Disabling retention or removing the account removes historical credential routing;
re-enabling retention cannot reconstruct removed routes. Completed status and
same-input replay use the journal without provider access, even after routing or
From identities are removed. The account must remain configured and authorized.

A prepared retry uses its original Drafts mailbox and UIDVALIDITY, frozen date,
From identity, and encoder parameters. Its From identity must still be approved.
Missing routing, a renamed or recreated mailbox, revoked From permission, or
unsupported reconstruction fails before APPEND. Retrying an uncertain operation
returns its uncertainty and never creates another draft.

## Reconcile an uncertain draft

Ordinary `draft status` and `email_draft_status` calls read only the journal. To
check an uncertain operation against the provider, add `--reconcile` to the CLI
status command or set `reconcile: true` in the MCP input. Retain the original
account UUID, generation, operation UUID, and mailbox:

```sh
mailctl --grant writer draft status --account-id "$account_id" \
  --account-generation "$generation" --operation-id "$operation_id" \
  --mailbox Drafts --reconcile --json
```

The grant must permit both journal inspection and draft creation at that original
target. Read-only narrowing removes both permissions. Reconciliation uses the
shared account writer lock and bounded, read-only IMAP requests. A single candidate
with the exact generated Message-ID and frozen MIME hash produces a durable
`duplicate` receipt, including its message reference when representable. Later
status calls and identical saves replay that receipt without provider work.

No match, multiple candidates, changed content, a recreated mailbox, missing
historical routing, unavailable credentials, or exhausted work limits leave the
operation uncertain. The error retains the original identity, a safe reason, and
`retryable: false`. Neither reconciliation nor an uncertain save issues APPEND.
Reconciliation of a prepared operation returns its recorded status without
creating it. Drafts-only grants receive the receipt or error, never message content.

For parser mutation campaigns, retained fixtures, and failure records, see
[Bounded parser campaigns](docs/fuzzing.md).

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for PR
titles and commits made directly to `main`. PRs are squash-merged using the PR
title, so intermediate branch commits need not follow the convention. Describe
the resulting behavior and mark breaking changes with `!`, including changes to
flags, configuration, or machine-readable output.

```text
feat(cli): add message listing
fix(config): preserve account identities during setup
feat(config)!: replace account names with account IDs
ci: validate pull request titles
```

Use `feat` for features, `fix` for bug fixes, and `build`, `chore`, `ci`, `docs`,
`perf`, `refactor`, `revert`, `style`, or `test` for other changes. The scope in
parentheses is optional. PR titles are checked before merging; contributors
committing directly to `main` must apply the convention themselves.

Changelog generation and release automation remain inactive while the first
release is being prepared.

[ISC License](LICENSE).
