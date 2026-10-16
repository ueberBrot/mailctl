# mailctl

Search and read email, retrieve attachments, and save unsent drafts from your
terminal or AI agent. mailctl connects to IMAP accounts over TLS. It does not
send email or edit existing drafts.

Use `mailctl` for the command-line interface (CLI) or `mailctl-mcp` for the
Model Context Protocol (MCP). Install both or use either on its own.

## Install

The standalone installer supports macOS on Apple Silicon. It does not require Rust.
Install the latest stable release:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh
```

On first installation, both components install by default. For CLI only:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --components cli
```

For MCP only:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --components mcp
```

Executables go into `~/.cargo/bin`, or `$CARGO_HOME/bin` when `CARGO_HOME` is nonempty.
Add that directory to your `PATH`. Use `--install-dir /absolute/path/to/bin` for a different destination.

To install an exact release, set `VERSION` and use its installer:

```sh
VERSION=0.1.0
curl --fail --location --proto '=https' --proto-redir '=https' "https://github.com/ueberBrot/mailctl/releases/download/v${VERSION}/install.sh" | sh -s -- --version "$VERSION"
```

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

Merge the example into your agent's global or project MCP configuration.
Replace `/absolute/path/to/mailctl-mcp` with the path from `command -v mailctl-mcp`.
Project paths are relative to your project folder.

<details>
<summary>Claude Code</summary>

Global: `~/.claude.json`. Project: `.mcp.json`. [Docs](https://code.claude.com/docs/en/mcp#mcp-installation-scopes).

```json
{
  "mcpServers": {
    "mailctl": {
      "type": "stdio",
      "command": "/absolute/path/to/mailctl-mcp",
      "args": ["--account", "work"]
    }
  }
}
```

</details>

<details>
<summary>Codex</summary>

Global: `~/.codex/config.toml`. Project: `.codex/config.toml`. [Docs](https://developers.openai.com/codex/mcp#configure-with-configtoml).

```toml
[mcp_servers.mailctl]
command = "/absolute/path/to/mailctl-mcp"
args = ["--account", "work"]
```

</details>

<details>
<summary>Pi 1.0+</summary>

Global: `~/.pi/agent/mcp.json`. Project: `.pi/mcp.json`. [Docs](https://pi.dev/docs/latest/mcp#configure-servers).

```json
{
  "mcpServers": {
    "mailctl": {
      "command": "/absolute/path/to/mailctl-mcp",
      "args": ["--account", "work"]
    }
  }
}
```

</details>

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

Draft access creates `drafts.sqlite` in the configured state directory (`state_dir`).
SQLite is bundled with the executables and needs no database server.
The database records draft operations to prevent duplicate creation on retries.
Updates and removal preserve it.
Keep each draft's original input and operation UUID, a unique operation identifier.
After an interrupted save, inspect the same operation with `draft status` before retrying.
Use `mailctl guide drafts` for status and reconciliation.

## Update or remove

Before updating, stop the CLI commands and MCP servers that use the installation.
Repeat the install command to update to the latest stable release.
Without `--components`, the installer keeps your installed component selection.
If both components are installed, it updates both together.
Use `--components cli,mcp` to add a missing component.
Use the original `--install-dir` for a custom destination.
For a custom configuration, pass `--config /absolute/path/to/config.toml` so the installer can inspect its state.
When a configuration is available, the installer checks state compatibility before replacing binaries.
If that check fails, the installed binaries stay in place.

To remove the installed components:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --uninstall
```

Add `--components cli` or `--components mcp` to remove only one.
For a custom destination, add the original `--install-dir /absolute/path/to/bin`.
Updates and removal preserve account configuration, credentials, and draft history.
If the installer requires recovery, wait for its previous process to exit and rerun it with `--recover`.
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
