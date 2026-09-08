# Discover authorized email accounts

This guide runs a cooperative broker on macOS or Linux and connects CLI and MCP
clients to it. Discovery uses an in-memory backend: it reports configured email
accounts without contacting a mail server or resolving credentials. Availability
is `unknown`; it does not mean authentication succeeded.

## Run a local example

Use a POSIX shell from the repository root after installing the
[development prerequisites](development.md#prerequisites). The example creates
only synthetic configuration and private temporary state.

```sh
cargo build --locked --bins
umask 077
demo_root=$(mktemp -d /tmp/mailctl.XXXXXX)
demo_root=$(cd "$demo_root" && pwd -P)
mkdir "$demo_root/state"
cat > "$demo_root/config.toml" <<EOF_CONFIG
version = 1
deployment = "cooperative"
topology = "native"
state_dir = "$demo_root/state"

[[accounts]]
key = "primary"
alias = "work"
server = "imap.example.test"
username = "synthetic@example.test"
mailboxes = ["INBOX"]
from_identities = ["primary"]

[accounts.credential]
source = "native"

[[listeners]]
name = "reader"
endpoint = "$demo_root/reader.sock"
peer_uids = [$(id -u)]
accounts = ["primary"]
mailboxes = ["INBOX"]
EOF_CONFIG

target/debug/maild --config "$demo_root/config.toml" &
demo_pid=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$demo_root/reader.sock" ] && break
    kill -0 "$demo_pid" 2>/dev/null || break
    sleep 1
done

target/debug/mailctl --endpoint "$demo_root/reader.sock" --json account list
target/debug/mailctl --endpoint "$demo_root/reader.sock" --json capability show
target/debug/mailctl --endpoint "$demo_root/reader.sock" --json doctor
```

Account discovery returns the alias `work`, an assigned `account_id` UUID,
`generation: 1`, the approved From-identity identifier `primary`, capabilities,
and `availability: "unknown"`. `complete: true` means the authorized inventory
fits the result. `doctor` reports safe endpoint health; this slice has no
`--check-account` authentication check.

The client expects the broker to have the caller's UID by default. `--broker-uid`
sets the expected server UID explicitly. The broker checks the connecting peer
against the listener's `peer_uids`; a client name cannot replace that check.

Keep the broker running while trying the remaining examples.

## Configure accounts and listeners

Configuration is limited to 4 MiB. Version 1 rejects unknown keys, invalid versions, unknown profiles,
unsafe paths, unsupported TLS/source options, and limits outside the allowed
range. `deployment` defaults to `cooperative`; a listener's `profile` defaults
to `read_only`. Configuration and grants take effect at broker startup.

Use canonical absolute paths. On macOS, resolving `/tmp` with `pwd -P` produces
`/private/tmp`, which avoids a symlink in the configured endpoint path. The
state directory and each socket's parent directory must already exist, belong
to the broker UID, and have mode `0700`. Configuration and private state files
use mode `0600`; the broker creates sockets with mode `0600`. Keep Unix socket
paths short enough for the operating system's socket address limit.

An account's `key` is its durable configuration identity. Keep that key when
renaming `alias`. The broker stores its assigned UUID and generation history in
`state_dir/accounts.json`. Changing the server, port, TLS mode, or authentication
identity increments the generation. Changing the alias preserves both UUID and
generation. A new key creates a new account identity.

Stop the broker before backing up or restoring its configuration and state
directory together. Preserve their ownership and permissions. Deleting the
registry creates new identities at the next startup; corrupted history aborts
startup. Historical credential routing is removed by default when an account is
repointed. `retain_history = true` retains that routing metadata; secret values
are never stored there. Historical draft access remains future work.

Listener `accounts` entries refer to account keys. Listener `mailboxes` entries
scope exact configured mailbox names. Each listener shares the broker's global
budgets and may narrow them with `[listeners.limits]`. Global `[limits]` values
must stay within the maxima in [the configuration definitions](../src/config.rs).
For example, this global table belongs before the first `[[accounts]]` table:

```toml
[limits]
ipc_frame_bytes = 1048576
buffered_bytes = 8388608
accounts = 8
```

The default IPC frame ceiling is 16 MiB, with a 64 MiB maximum. Default JSON
nesting is 32, with a maximum of 64. The default configured account ceiling is
32, with a maximum of 256. Byte, connection, handshake, request, queue, and
lifetime limits apply across listeners; adding a listener does not multiply
broker capacity. Configuration rejects combinations that cannot admit a legal
maximum-size frame.

Credential definitions select `native`, `systemd`, `command`, or `session`
routing. This slice validates these definitions but does not access their
stores, execute helpers, or prompt. TLS defaults to verified implicit TLS;
`starttls` is the other accepted configuration mode. Provider connections arrive
in later work.

## Narrow a client's authority

An endpoint's profile sets its permission ceiling. `read_only` includes account
and email-read permissions. `drafts_only` includes account discovery, draft
append, and draft-operation inspection permissions. `read_and_drafts` includes
both sets. Configuring a draft-capable listener requires an account
`drafts_mailbox` inside both its account allowlist and listener mailbox scope.
Draft operations are not implemented in this slice; capability `operations`
lists what the running implementation supports.

CLI `--read-only` removes draft append and journal inspection authority. On a
`drafts_only` listener, it leaves account discovery without granting email reads.
Repeat `--account` to narrow discovery by alias:

```sh
target/debug/mailctl --endpoint "$demo_root/reader.sock" \
    --read-only --account work --json account list --limit 1
```

An alias outside the listener grant yields no matching account. A positive
`--limit` may only narrow the listener ceiling. When `complete` is false, request
a larger permitted limit or narrow the account set. Account discovery has no
continuation cursor in this slice.

## Connect an MCP client

Configure the consuming application's STDIO server command as the built
`target/debug/mail-mcp` executable, with these arguments while the broker runs:

```text
--endpoint /absolute/path/to/reader.sock
```

Use the absolute executable and socket paths in the consuming application's own
configuration. MCP starts with read-only narrowing. `--use-endpoint-grant`
explicitly retains the listener's configured permission ceiling and conflicts
with `--read-only`. Tool arguments cannot choose a profile or widen that ceiling.

The adapter uses `rmcp` 3.2.0 and negotiates MCP protocol `2025-11-25`. It exposes
`email_list_accounts` and `email_capabilities`, with input/output schemas in
`tools/list`. The first accepts an optional positive `limit`; capabilities
accepts an empty object and includes grant-filtered safe `health`. Calls to absent
tools fail before application access.

Results contain the same versioned envelope as CLI JSON in `structuredContent`
and as serialized JSON text. Domain failures set `isError: true`; unknown tools
and protocol failures use JSON-RPC errors. Compare results after removing
transport-generated request IDs. Generate the contract's JSON Schemas with:

```sh
cargo run --locked --example discovery-schema
```

MCP uses newline-delimited SDK JSON-RPC framing. Input lines are limited to
64 KiB and 32 nesting levels, with 4,096 input frames per session and eight
outstanding requests. Output is bounded to 1 MiB including structured/text
duplication. Initialization has a five-second deadline, frame reads and writes
have a 30-second deadline, and sessions last at most five minutes. Reconnect and
initialize again after expiry or a broker restart.

## Consume CLI JSON or raw IPC

CLI `--json` writes one envelope to stdout. Successful results have
`schema_version: 1`, `request_id`, `ok: true`, and `result`. Failures have
`ok: false` and a safe `error` with `code`, `message`, and `retryable`:

```json
{"schema_version":1,"request_id":"example","ok":false,"error":{"code":"permission_denied","message":"Access denied","retryable":false}}
```

Use stable error codes for program logic. CLI exit statuses group failures:

| Exit | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Usage, configuration, schema, or protocol |
| 3 | Authorization |
| 4 | Credential, authentication, or TLS |
| 5 | Availability, capacity, or deadline |
| 6 | Missing, stale, expired, or conflicting resource |
| 7 | Pending or uncertain mutation |
| 8 | Bounds, unsupported operation, journal, export, or internal failure |
| 130 | Local cancellation |

Some codes reserve behavior for later email operations. Machine commands never
prompt. Broker stdout is unused; MCP stdout contains only MCP traffic. Diagnostics
use safe JSON categories on stderr. `--log-format compact` is rejected with
`--json`; `off` and `json` are accepted. Human CLI output currently uses escaped,
uncolored pretty JSON.

Raw IPC uses a four-byte unsigned big-endian payload length followed by UTF-8
JSON. Authenticate the endpoint owner and peer before sending a version-1 hello:

```json
{"type":"hello","version":1,"narrowing":{"read_only":true},"client_name":"example"}
```

A successful welcome contains `version: 1` and `effective` capabilities. Send
requests with unique connection-local IDs of 1–64 ASCII letters, digits,
hyphens, or underscores:

```json
{"type":"request","request_id":"accounts-1","request":{"operation":"list_accounts","input":{"limit":1}}}
```

`capabilities` and `health` operations omit `input`. An optional request
`narrowing` intersects the hello's narrowing; it cannot undo it. Cancellation
uses `{"type":"cancel","request_id":"cancel-1","target_request_id":"accounts-1"}`
and affects only an outstanding request on the same connection. Responses use
the request ID in the versioned envelope. A connection accepts at most 4,096
unique request IDs. Invalid framing, nesting, fields, or IDs may close it.

## Stop the example

Stop the example before deleting its state:

```sh
kill -INT "$demo_pid"
wait "$demo_pid"
rm -r "$demo_root"
```

## Platform and feature scope

This slice exercises cooperative Unix transport on macOS and Linux. It enforces
permissions through the broker, but an unrestricted process under the same OS
user can access that user's resources outside it. Cross-user endpoint ACLs,
isolated deployments, Windows named pipes, WSL topologies, and native credential
stores remain unqualified. The broker rejects `deployment = "isolated"` until an
isolation mechanism is implemented and qualified. Windows runs the portable application contract tests;
its transport returns `unsupported_capability`.

Mailbox discovery, message reading, attachments, and draft operations remain
[planned work](https://github.com/ueberBrot/mailctl/issues/1). Credential resolution
and administration belong to [#7](https://github.com/ueberBrot/mailctl/issues/7),
deployment qualification to [#8](https://github.com/ueberBrot/mailctl/issues/8),
and full rendering verification to [#16](https://github.com/ueberBrot/mailctl/issues/16).
`mail-admin` currently reports `unsupported_capability`. The package has not been
released, and shared CI coverage does not qualify a deployment.
