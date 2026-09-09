# Configure macOS credentials

Both executables use the current macOS login identity's Apple Keychain. Set up
each email account, then provision its credential through either executable:

```sh
mailctl setup --alias work --server imap.example.com --username user@example.com
mailctl-mcp setup --alias personal --server imap.example.net --username user@example.net
mailctl --account work credential set
mailctl-mcp --account personal credential set
```

`credential set` reads from the operator terminal with echo disabled. It accepts
no password argument or JSON input. JSON requests and requests without a usable
operator terminal return `credential_unavailable` with
`credential_failure: interaction_required`.

Setup defaults to verified implicit TLS on port 993. For an account that requires
STARTTLS, set `tls = "starttls"` and the provider's port in that account's TOML
configuration, then run `setup` to validate the change. Plaintext authentication
is unavailable.

Use `--config /absolute/path/config.toml` with either component to select an
installation. Its configuration contains account metadata and a credential source;
credential bytes remain in Keychain. Its state gives each account a stable UUID.
Both components use the service name `mailctl` and that UUID to find the
credential. Keep the configuration and state together.

New entries allow applications running under the same macOS login to retrieve
the credential from an unlocked Keychain. This permits both executables to work
after relocation or rebuild. During explicit provisioning, mailctl uses
`/usr/bin/security` to create an empty entry with those permissions, then writes
the password through the native library. Password bytes never enter that
command's arguments or output. Existing entries keep their access permissions.
Unlock the selected Keychain before provisioning a new entry.

Credential commands are operator administration. `--account` selects from all
configured accounts. `--grant` scopes email operations and `doctor`; it does not
authorize or restrict credential commands.

## Inspect availability and check authentication

```sh
mailctl-mcp --account work credential status --json
mailctl doctor --json
mailctl --account work doctor --check-account --json
```

`credential status` inspects entry metadata. `doctor` reports installation
readiness, configured topology, and source availability within the selected access
grant. Neither command retrieves a password or contacts the email provider unless
you supply `doctor --check-account`. `doctor` also lists static `prerequisites`
when the selected topology or credential source cannot resolve credentials.

An explicit check selects one authorized account, resolves its credential,
authenticates over verified TLS, and disconnects. It does not open or change a
mailbox. The result includes `authentication.checked_at` in Unix seconds and an
`outcome` of `authenticated` or `failed`; a failed outcome includes a categorized
error. A completed diagnostic reports `status: degraded` when a source needs
attention or an explicit authentication check fails. Use the authentication
outcome to determine whether an account works. A failed check still
returns this diagnostic and exits with the failed outcome's categorized error code.

Source availability and authentication answer different questions:

| Source status | Meaning |
| --- | --- |
| `available` | Keychain entry metadata exists; authentication has not been verified. |
| `missing` | No entry was found for this account UUID. |
| `locked`, `access_denied`, `interaction_required` | The source requires operator action. |
| `configured`, `unknown` | The source's configuration or availability does not establish authentication. |
| `unavailable` | This build or execution environment cannot use the source. |

A locked Keychain can still expose entry metadata. With prompts disabled, macOS
can report `access_denied` or `interaction_required` for a locked Keychain or an
entry whose access policy needs confirmation. These errors do not reliably
distinguish the cause. Applications never open Keychain prompts during
authentication.

`mailctl-mcp doctor` provides the same explicit diagnostic in MCP-only installs.
Bare `mailctl-mcp` continues to serve STDIO. Credential commands and doctor are
absent from MCP tools.

## Rename, rotate, or delete

```sh
mailctl --account work setup --alias office
mailctl-mcp --account office credential set
mailctl --account office credential delete
```

Renaming preserves the account UUID and credential reference. Rotation and
deletion through either component affect the same entry. With multiple accounts,
credential commands require `--account`; they never guess which entry to change.

After rotation or deletion, finish active CLI work, stop MCP sessions, and restart
MCP. Already authenticated provider connections can remain valid after the stored
credential changes. New authentication resolves the source again. Existing local
connections expire after the configured lifetime at a clean operation boundary,
plus any operation already running. To revoke provider sessions immediately, use
the provider's session-revocation controls too.

## Limits and remaining sources

Each process applies its own limits. By default, an account allows two connections
and 16 pending requests. Credential resolution allows two workers and eight queued
requests. Each account allows one explicit doctor check every 30 seconds, and an
authenticated connection lives for five minutes. Access grants can narrow these
limits.

If an operation times out or is cancelled while macOS is resolving a credential,
its worker retains its admission slot until the OS call returns. Cancellation
does not create room for additional OS calls beyond the configured limit.

Owned secrets are zeroized and their debug output is redacted. Passwords are
borrowed during authentication and are not kept in a reusable application cache.
OS and dependency code can make temporary copies outside the application's
zeroization control.

This implementation supports native macOS credentials. Windows and Linux native
stores, systemd credentials, trusted credential commands, and foreground session
credentials remain separate implementation tasks. Those source configurations
can report safe availability or external provisioning ownership; they do not
claim successful authentication. Linux-native WSL requires a provisioned Linux
source; Windows-hosted WSL requires the Windows execution identity's store and
Windows executables.

Access grants govern mailctl requests. They are not an ACL for the login's
Keychain: other applications running as the same macOS login can read entries
provisioned by mailctl while that Keychain is unlocked. A deployment that isolates
credentials
from callers requires separate qualification; this embedded setup makes no such
isolation guarantee.
