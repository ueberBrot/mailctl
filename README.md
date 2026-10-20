# mailctl

Search and read email, retrieve attachments, and save unsent drafts from your
terminal or AI agent. mailctl connects to IMAP accounts over TLS. It does not
send email or edit existing drafts.
Choose which accounts, mailboxes, and operations your agent can use.

Use `mailctl` for the command-line interface (CLI) or `mailctl-mcp` for the
Model Context Protocol (MCP). Install both or use either on its own.

## Install

Standalone installers use prebuilt binaries. Rust is not required.

| Platform | Installer | Default executable directory |
| --- | --- | --- |
| macOS on Apple Silicon | Shell | `~/.local/bin` |
| GNU/Linux x86_64 with glibc | Shell | `~/.local/bin` |
| Windows x86_64 | PowerShell | `%USERPROFILE%\.local\bin` |

### macOS and Linux

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

Use `--install-dir /absolute/path/to/bin` for a different destination.
Add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile so future terminals can find them.
For agents launched from a GUI, use the executable's full path if needed.

To install an exact release, set `VERSION` and use its installer:

```sh
VERSION=0.1.0
curl --fail --location --proto '=https' --proto-redir '=https' "https://github.com/ueberBrot/mailctl/releases/download/v${VERSION}/install.sh" | sh -s -- --version "$VERSION"
```

### Windows

Run this command in Windows PowerShell 5.1 or PowerShell 7:

```powershell
$installer = (Invoke-WebRequest -UseBasicParsing 'https://github.com/ueberBrot/mailctl/releases/latest/download/install.ps1').Content
& ([scriptblock]::Create($installer))
```

Both components install by default. Add `-Components cli` to the last line for CLI only, or `-Components mcp` for MCP only.
Use `-InstallDir 'C:\absolute\path\to\bin'` for a different destination.
Add the executable directory to your user `PATH`, then restart your terminal and agent.

<details>
<summary>Install an exact Windows version</summary>

```powershell
$Version = '0.1.0'
$installer = (Invoke-WebRequest -UseBasicParsing "https://github.com/ueberBrot/mailctl/releases/download/v$Version/install.ps1").Content
& ([scriptblock]::Create($installer)) -Version $Version
```

</details>

Inside WSL2, choose the Linux installer or run the Windows installer in Windows PowerShell.
Linux and Windows installations can coexist. They use separate configuration, credential stores, and draft history.

## Connect your account

For MCP-only installations, use `mailctl-mcp` for the commands below.
On Linux, native credentials need an unlocked Secret Service collection on your session D-Bus.
For headless Linux without that service, configure a command or systemd credential source as described in `mailctl guide overview`.
For Windows executables, enter credentials in a native Windows terminal under the same Windows account.
Use that terminal for credentials when you launch Windows executables from WSL2 too.

For native credentials, run these commands in your own terminal. Replace the server and username with
your provider's values. `work` is the name that you give the account:

```sh
mailctl setup --alias work --server imap.example.com --username user@example.com
mailctl --account work credential set
mailctl --account work doctor --check-account --json
```

Enter your password or app password at the credential prompt.
The doctor command tests authentication. New accounts use TLS on port 993.

Use `--config /absolute/path/to/config.toml` to select a custom configuration.

## Use MCP with your agent

Merge the example into your agent's global or project MCP configuration.
Replace `/absolute/path/to/mailctl-mcp` with the installed path as seen by your agent.
Find it with `command -v mailctl-mcp` on Unix or `(Get-Command mailctl-mcp).Source` in PowerShell.
In Windows JSON and TOML strings, use forward slashes, such as `C:/Users/you/.local/bin/mailctl-mcp.exe`.
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
One skill covers CLI and MCP for Codex, Claude Code, and other compatible agents:

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

The standard setup stores account passwords in macOS Keychain, Windows Credential Manager, or Linux Secret Service.
Account configuration contains a reference to the saved credential.
Keep passwords out of agent chat, command arguments, and account configuration.
The MCP server never prompts for passwords or returns saved account passwords.
For command credential sources, their owner controls storage and protection.
For systemd sources on Linux, systemd supplies the credentials to the configured service.

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
Use `--components cli,mcp` on Unix or `-Components 'cli,mcp'` in PowerShell to add a missing component.
Use the original `--install-dir` or `-InstallDir` for a custom destination.
For a custom configuration, also pass `--config` or `-Config` with its absolute path.

To remove the installed components on macOS or Linux:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --uninstall
```

Add `--components cli` or `--components mcp` to remove only one.
For a custom destination, add the original `--install-dir /absolute/path/to/bin`.

On Windows:

```powershell
$installer = (Invoke-WebRequest -UseBasicParsing 'https://github.com/ueberBrot/mailctl/releases/latest/download/install.ps1').Content
& ([scriptblock]::Create($installer)) -Uninstall
```

Add `-Components cli` or `-Components mcp` for partial removal, or the original `-InstallDir` for a custom destination.
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
