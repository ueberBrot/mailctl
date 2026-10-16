# mailctl

Search and read email, retrieve attachments, and save unsent drafts from your
terminal or AI agent. mailctl connects to IMAP accounts over TLS. It does not
send email or edit existing drafts.

Use `mailctl` for the command-line interface (CLI) or `mailctl-mcp` for the
Model Context Protocol (MCP). Install both or use either on its own.

## Install

The standalone installer supports macOS on Apple Silicon. It does not require Rust.
Version 0.1.0 is not published yet. Until it is available, [build from source](#build-from-source).

Download the installer:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output install-v0.1.0.sh \
  https://github.com/ueberBrot/mailctl/releases/download/v0.1.0/install-v0.1.0.sh
```

Choose one installation. For both CLI and MCP:

```sh
sh install-v0.1.0.sh --version 0.1.0
```

For CLI only:

```sh
sh install-v0.1.0.sh --version 0.1.0 --components cli
```

For MCP only:

```sh
sh install-v0.1.0.sh --version 0.1.0 --components mcp
```

Executables go into `~/.cargo/bin`, or `CARGO_HOME/bin` when `CARGO_HOME` is nonempty.
Add that directory to your `PATH`. Use `--install-dir /absolute/path/to/bin` for a different destination.

## Connect your account

Run these commands in your own terminal. Replace the server and username with
your provider's values. `work` is the name that you give the account:

```sh
mailctl setup --alias work --server imap.example.com --username user@example.com
mailctl --account work credential set
mailctl --account work doctor --check-account --json
```

Enter your password or app password at the credential prompt. macOS Keychain
stores it. Account configuration contains a credential reference, not the password.
The doctor command tests authentication. New accounts use TLS on port 993.

For MCP-only installations, use `mailctl-mcp` for account, credential, and guide commands.
Use `--config /absolute/path/to/config.toml` to select a custom configuration.

## Read email with the CLI

List the account's mailboxes:

```sh
mailctl --account work mailbox list --json
```

Copy a mailbox's `reference` from the result and search it:

```sh
mailctl message search --mailbox '<mailbox reference>' \
  --criteria '[{"field":"subject","value":"invoice"}]' --limit 10 --json
```

Copy a message's `reference` from the search result and read its text:

```sh
mailctl message get --message '<message reference>' --max-bytes 8192 --json
```

Message text is in `result.body.text`. Results can span several pages.
Use `mailctl guide reading` for continuation and completion rules.
Scripts must inspect `ok` before using `result`. Failures return an `error` and a nonzero exit code.

The built-in guides cover attachment downloads, exports, and draft creation:

```sh
mailctl guide attachments
mailctl guide drafts
```

## Use MCP with your agent

Add a STDIO server to your agent's MCP configuration.
Use the installed executable's absolute path:

```json
{
  "command": "/absolute/path/to/mailctl-mcp",
  "args": ["--account", "work"]
}
```

Set up credentials before starting the server. MCP never prompts for passwords.
Start with `email_capabilities` and `email_list_accounts`. The server provides
tools for mailbox discovery, search, message text, attachments, and unsent drafts.
Guides are available at `mailctl://guide/overview`, with separate `reading`,
`attachments`, `drafts`, and `errors` resources.

MCP is read-only by default. For drafts, configure a grant with draft permissions
and add `--grant writer --use-configured-grant` to the server arguments.
Replace `writer` with your grant's name. Use `mailctl-mcp guide drafts` for the configuration.

## Install the agent skill

The [mailctl skill](skills/mailctl/SKILL.md) helps your agent install and update
mailctl, set up accounts, read messages and attachments, and create approved unsent drafts.
One skill covers CLI and MCP:

```sh
npx skills add ueberBrot/mailctl --skill mailctl
```

Choose your agent when prompted, or add `--agent codex` or `--agent claude-code`.
Add `--global` to make the skill available across projects.
Other compatible skill loaders can use the complete `skills/mailctl` directory.

For example, ask your agent to find invoices, summarize a thread, download an
attachment, or prepare an unsent reply. Enter account credentials in your terminal.

## Credentials and permissions

Keep passwords outside prompts, command arguments, and account configuration.
The standard setup stores them in macOS Keychain.
For external command credential sources, their owner controls the storage and protection.

An access grant defines the permitted accounts, mailboxes, and operations.
New installations allow read-only access to all folders in configured accounts.
Use `guide overview` for access grant configuration.
Inspect permissions with `mailctl capability show --json` or MCP `email_capabilities`.
Agents with separate shell or filesystem access retain their OS permissions.
Optional [macOS isolation](deployment/macos-isolated/install.sh) uses a separate service identity.

Draft history persists across restarts to prevent duplicate creation on retries.
Keep each draft's original input and operation UUID, a unique operation identifier.
After an interrupted save, inspect the same operation with `draft status` before retrying.
Use `mailctl guide drafts` for status and reconciliation.

## Update or remove

Before updating, stop the CLI commands and MCP servers that use the installation.
Download the new version's installer and repeat the matching installation command.
Update both components together when both are installed. For a custom configuration,
pass `--config /absolute/path/to/config.toml`.
Use the same destination as the original installation.

To remove both installer-owned executables:

```sh
sh install-v0.1.0.sh --uninstall
```

Add `--components cli` or `--components mcp` to remove only one.
Uninstalling preserves account configuration, credentials, and draft history.
Use `mailctl state --help` for backups and recovery, or `mailctl-mcp state --help` for MCP-only installations.

## Build from source

From the repository root, build with the toolchain in [rust-toolchain.toml](rust-toolchain.toml):

```sh
cargo build --locked --release
export PATH="$PWD/target/release:$PATH"
```

For CLI only, add `--no-default-features --features cli` to the build command.
For MCP only, use `--no-default-features --features mcp`.

Use `mailctl --help`, `mailctl guide`, or `mailctl guide errors` for more help.
See [CONTRIBUTING.md](CONTRIBUTING.md) for development and [LICENSE](LICENSE) for the ISC license.
