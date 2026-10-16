# mailctl

Search and read email, retrieve attachments, and save unsent drafts from your
terminal or AI agent. mailctl connects to IMAP accounts over TLS. It does not
send email or edit existing drafts.
Choose which accounts, mailboxes, and operations your agent can use.

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

Enter your password or app password at the credential prompt.
The doctor command tests authentication. New accounts use TLS on port 993.

For MCP-only installations, use `mailctl-mcp` for account, credential, and guide commands.
Use `--config /absolute/path/to/config.toml` to select a custom configuration.

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

Restart your agent after saving its configuration.
Ask it to find invoices, summarize a thread, download an attachment, or prepare an unsent reply.
The server includes tools and guides for reading email, attachments, and drafts.

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

The skill uses mailctl's CLI commands or MCP tools for the requested task.
Enter account credentials in your own terminal.

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

## Credentials and permissions

The standard setup stores account passwords in macOS Keychain.
Account configuration contains a reference to the saved credential.
Keep passwords out of agent chat, command arguments, and account configuration.
The MCP server never prompts for passwords or returns saved account passwords.
For external command credential sources, their owner controls the storage and protection.

An access grant defines the permitted accounts, mailboxes, and operations.
New installations allow read-only access to all folders in configured accounts.
Use `guide overview` for access grant configuration.
Inspect permissions with `mailctl capability show --json` or MCP `email_capabilities`.
Agents with separate shell or filesystem access retain their OS permissions.
Optional [macOS isolation](deployment/macos-isolated/install.sh) uses a separate service identity.

## Update or remove

Before updating, stop the CLI commands and MCP servers that use the installation.
Repeat the install command to update to the latest stable release.
Without `--components`, the installer keeps your installed component selection.
If both components are installed, it updates both together.
Use `--components cli,mcp` to add a missing component.
Use the original `--install-dir` for a custom destination.
For a custom configuration, also pass `--config /absolute/path/to/config.toml`.

To remove the installed components:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --uninstall
```

Add `--components cli` or `--components mcp` to remove only one.
For a custom destination, add the original `--install-dir /absolute/path/to/bin`.
Updates and removal preserve account configuration, credentials, and draft history.

## Build from source

From the repository root, build with the toolchain in [rust-toolchain.toml](rust-toolchain.toml):

```sh
cargo build --locked --release
export PATH="$PWD/target/release:$PATH"
```

For CLI only, add `--no-default-features --features cli` to the build command.
For MCP only, use `--no-default-features --features mcp`.

Use `mailctl --help`, `mailctl guide`, or `mailctl guide errors` for more help.
Released under the [ISC license](LICENSE).
