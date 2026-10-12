# mailctl

mailctl gives agents and scripts controlled access to email over IMAP. It can
discover accounts and mailboxes, search messages, read text and attachments, and
create unsent drafts. It does not send email or edit existing drafts.

The command-line interface is `mailctl`. The MCP server is `mailctl-mcp`, which
lets an agent harness call email tools over standard input and output. Both use
the same account configuration, access grants, and durable draft history. You
can use either interface on its own.

The project is unreleased. The first release targets macOS on Apple Silicon with
all current functionality. Build from source until release packages are available.

## Build from source

Use rustup-managed Cargo from the repository root. The repository pins its Rust
toolchain in [rust-toolchain.toml](rust-toolchain.toml). A default build produces
both executables:

```sh
cargo build --locked --release
export PATH="$PWD/target/release:$PATH"
mailctl --help
mailctl-mcp --help
```

For a single interface, add `--no-default-features --features cli` or
`--no-default-features --features mcp` to the build command. The executables share
application state regardless of which components you build.

For an MCP-only build, use `mailctl-mcp` for the setup, credential, and doctor
commands below.

## Set up an account on macOS

Use an email provider that supports IMAP login over TLS. Replace the hostname and
username below with the provider's values. `work` is your account alias, a name
that you choose for this account:

```sh
mailctl setup --alias work --server imap.example.com --username user@example.com
mailctl --account work credential set
mailctl --account work doctor --check-account --json
```

New accounts use TLS on port 993. `credential set` prompts in your terminal and
stores the credential in macOS Keychain. Enter the password or app password that
your provider requires for IMAP. Provision credentials before an agent starts
the MCP server.

In the doctor's JSON result, look for `ok: true` and
`result.accounts[].authentication.outcome.status: "authenticated"`. Plain
`doctor` inspects local readiness without authenticating.

An access grant defines the permitted accounts, mailboxes, and operations. New
installations grant read-only access to all current and future folders in the
configured accounts. To restrict folders, set an explicit, nonempty `mailboxes`
list in the account or grant configuration. Their intersection is the effective
scope. See `mailctl guide overview` for configuration rules.

Use `--config /absolute/path/to/config.toml` to select a different configuration
file. After editing configuration, stop the runtimes that use it, run `setup`,
and restart long-running MCP processes. Keep the installation state: it holds
account identities, the keys that validate references, and draft history.

## Find and read a message

Start with the effective permissions and available accounts. Then discover
mailboxes for the account you want to read:

```sh
mailctl capability show --json
mailctl account list --json
mailctl --account work mailbox list --json
```

Choose a selectable mailbox from `result.mailboxes`. Copy its `reference` into
the next command. A folder name such as `INBOX` is not a search reference:

```sh
mailbox_reference='<returned mailbox reference>'
mailctl message search --mailbox "$mailbox_reference" \
  --criteria '[{"field":"subject","value":"invoice"}]' --limit 10 --json
```

Copy a message reference from `result.messages` and read its selected text:

```sh
message_reference='<returned message reference>'
mailctl message get --message "$message_reference" --max-bytes 8192 --json
```

The text is in `result.body.text`. A body read retrieves text independently of
attachment payloads. Discovery, search, and body reads can return partial
results. Use `mailctl guide reading` for their completion fields and continuation
rules before treating a page as the whole result.

For scripts, use `--json` and inspect `ok` before reading `result`. Failures carry
`error` and return a nonzero exit code. Diagnostics go to standard error.

## Connect an MCP client

Configure a STDIO MCP server in your agent harness. Use these command and argument
values in the host's configuration, replacing the executable path:

```json
{
  "command": "/absolute/path/to/mailctl-mcp",
  "args": ["--account", "work"]
}
```

The host starts the process and communicates over its standard input and output.
Serving never prompts for credentials. Operator setup and credential commands
remain outside the MCP tools.

Start with `email_capabilities` and `email_list_accounts`, both with `{}`.
Available tools include mailbox discovery, message search, body reads, and
attachment retrieval. The host can read `mailctl://guide/overview` and the
`reading`, `attachments`, `drafts`, and `errors` guide resources. Tool results use
the same `ok` envelope in `structuredContent` as the CLI.

MCP serving is read-only by default. Draft tools require an approved grant and
the explicit `--use-configured-grant` flag. For example, a host can use
`["--grant", "writer", "--use-configured-grant", "--account", "work"]` after the
operator configures a `writer` grant.

## Attachments and unsent drafts

Use `attachment list` to choose an attachment before retrieving its bytes.
`attachment get` returns one bounded base64 result. `attachment export` writes
under an operator-approved export root. MCP retrieves attachments in chunks
within the issuing session. Read `mailctl guide attachments` for these workflows.

Draft creation needs an approved existing Drafts mailbox, approved From
identities, and a grant with `drafts_only` or `read_and_drafts` permissions.
Use `mailctl guide drafts` for the configuration and complete save/status recipe.
Use `mailctl schema draft_content` for the CLI composition file.

Before saving, retain the original composition and operation UUID in durable
caller-owned state. Retain the account UUID, generation, and exact Drafts mailbox
name with them. Reuse them unchanged for retries. If the outcome is uncertain,
inspect that operation with `draft status` and optionally `--reconcile`.
Reconciliation checks the original target without creating another draft.
A new operation UUID after an uncertain save risks a duplicate.

## Help and access boundaries

`mailctl guide` opens the workflow overview without account setup. Use
`mailctl guide errors` for failures and recovery, and
`mailctl schema <operation>` for exact JSON inputs. `mailctl-mcp` exposes the same
guides and schemas as offline commands. Each command also has `--help`.

Access grants constrain operations through mailctl. They do not restrict an
agent's separate shell or filesystem access under the same OS identity.
Optional macOS isolation uses a separate service identity and requires explicit
provisioning. See the [isolation decision](docs/adr/0006-make-native-isolation-an-explicit-operator-choice.md)
and [provisioning script](deployment/macos-isolated/install.sh).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for PR and commit requirements, local
checks, Rust conventions, and release preparation. Agent-specific workflows
live in [AGENTS.md](AGENTS.md).

mailctl uses the [ISC license](LICENSE).
