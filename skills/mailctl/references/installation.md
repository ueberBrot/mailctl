# Installation and setup

Use the standalone installer from the official `ueberBrot/mailctl` GitHub release.
Keep installation, account setup, and credential provisioning within the user's requested scope.
An installation request alone does not authorize account changes or email access.

## Select the installation

1. Select the operating system that will run the executables:

   - macOS on Apple Silicon uses `install.sh`.
   - GNU/Linux on x86_64 with glibc uses `install.sh`.
   - Windows on x86_64 uses `install.ps1` in native Windows PowerShell 5.1 or PowerShell 7.

   On Unix, inspect `uname -s` and `uname -m`. On Linux, also inspect `getconf GNU_LIBC_VERSION`.
   For WSL2, choose the Linux or Windows route described below before installation or account setup.
2. For an existing installation, determine its installation channel and destination.
   Keep package-manager installations under their owning package manager.
   The standalone destination is `~/.local/bin` on Unix or `%USERPROFILE%\.local\bin` on Windows.
   Preserve a custom destination with `--install-dir` on Unix or `-InstallDir` on Windows.
   Both require an absolute path. The standalone installer does not use `CARGO_HOME`.
3. For a first installation, install both components unless the user selects CLI only or MCP only.
   Unix uses `--components cli`, `--components mcp`, or `--components cli,mcp`.
   Windows uses `-Components cli`, `-Components mcp`, or `-Components 'cli,mcp'`.
   CLI installs `mailctl`. MCP installs `mailctl-mcp`. Windows executable names end in `.exe`.
   Neither component requires the other. For updates or removal, omit the selection to keep the installed components.

## Install or update

Before an update, stop the CLI commands and MCP runtimes that use the installation cleanly.
Retain installation history, original draft inputs, and operation receipts.
If your active MCP connection needs a restart, arrange that restart with the operator.
For an existing custom configuration, pass its absolute path with `--config` on Unix or `-Config` on Windows.
Use the original destination override for a custom destination.

On macOS or Linux, install the latest stable release:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh
```

On Windows, run this command in Windows PowerShell 5.1 or PowerShell 7:

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://github.com/ueberBrot/mailctl/releases/latest/download/install.ps1').Content))
```

To pass Unix arguments, replace `| sh` with `| sh -s --` and append the arguments.
For example, append `--components cli` for CLI only.
For Windows, append parameters after the final `)`, such as `-Components cli` for CLI only.

If the user requests an exact release, pin both the installer URL and the binary version.
On macOS or Linux:

```sh
VERSION=0.1.0
curl --fail --location --proto '=https' --proto-redir '=https' "https://github.com/ueberBrot/mailctl/releases/download/v${VERSION}/install.sh" | sh -s -- --version "$VERSION"
```

On Windows:

```powershell
$Version = '0.1.0'
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing "https://github.com/ueberBrot/mailctl/releases/download/v$Version/install.ps1").Content)) -Version $Version
```

Replace `0.1.0` with the requested version.
If the requested release or its assets are unavailable, report the failure.
Build from source only when the user requests that method.

The installer checks sizes, checksums, ownership, and compatibility before replacing components.
Without a component selection, it updates the installed components together.
Use `--components cli,mcp` on Unix or `-Components 'cli,mcp'` on Windows to add a missing component.
If an update requires both components, explain that requirement before expanding a single-component request.
If ownership, state compatibility, or recovery blocks installation, report the error and preserve the existing files.
Use `--recover` on Unix or `-Recover` on Windows only after the interrupted owner process exits.

Run each selected executable's `--version` and `--help` through its installed absolute path.
For a pinned release, make sure that the version matches the request.
Report the installed components, version, destination, and any required `PATH` change.
Keep shell configuration unchanged unless the user requests an edit.

## Remove components

On macOS or Linux, use the same installer with `--uninstall`:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --uninstall
```

On Windows, use `-Uninstall`:

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://github.com/ueberBrot/mailctl/releases/latest/download/install.ps1').Content)) -Uninstall
```

The default removes the installed components.
Pass a component selection for a requested partial removal.
Pass the original destination override for a custom destination.
Updates and removal preserve account configuration, credentials, and draft history.
Report the removed components and any remaining components.

## Choose a WSL2 route

For a Linux installation inside WSL2, use the Linux shell and `install.sh`.
That installation uses Linux configuration, paths, credential sources, and draft history.
Its native credentials need an unlocked Secret Service collection on the Linux session D-Bus.
Without that session, select an explicit external credential source as described below.

For a Windows installation called from WSL2, open Windows PowerShell with `powershell.exe -NoProfile`.
Run the Windows installation commands there.
Launch the installed Windows `.exe` files from WSL2 through Windows interoperability.
For an agent running inside WSL2, set its MCP command to a mounted path such as `/mnt/c/Users/Alice/.local/bin/mailctl-mcp.exe`.
Those executables use Windows configuration, paths, Credential Manager, and draft history under the Windows execution identity.
Use Windows paths for their configuration and exports.
Provision Windows credentials in a native Windows terminal under that same Windows user.

Both installations can coexist. Select one for each workflow and preserve its configuration and original draft operations.
They keep separate credentials and history. Copying account configuration does not join their draft history.
The Windows route is tested through WSL2. The Linux route is not separately qualified inside WSL2.

## Guide requested account setup

For CLI-only or combined installations, use `mailctl`. For MCP-only installations, use `mailctl-mcp`.
Read the selected executable's `setup --help` and `guide overview` for account and grant configuration.
Use the user's account alias, provider hostname, and username for an authorized setup.
Preserve existing account identities, grants, credential sources, and draft history during updates.

New accounts use the native credential store:

- macOS uses Keychain under the execution identity.
- Windows uses Credential Manager under the execution identity.
- Linux uses an unlocked default Secret Service collection on the execution identity's session D-Bus.

For native credentials, give the operator these commands for their own terminal:

```sh
mailctl setup --alias work --server imap.example.com --username user@example.com
mailctl --account work credential set
mailctl --account work credential status --json
mailctl --account work doctor --check-account --json
```

Replace `work`, the server, and the username with the approved account details.
Select `mailctl-mcp` for an MCP-only installation.
The operator enters the password or app password directly at the terminal prompt.
The native store saves it. The MCP tools neither prompt for nor return account passwords.
Keep passwords outside chat, command arguments, and account configuration.

Credential status reports local availability. It does not prove authentication.
Within authorized account setup, the doctor command tests fresh provider authentication.
Require `ok: true` and `result.accounts[].authentication.outcome.status: "authenticated"` before reporting successful authentication.

For headless Linux without Secret Service, have the operator select and provision an external source explicitly.
The account's `credential` configuration supports `source = "command"` for a trusted Unix executable.
Its owner provides the executable, arguments, working directory, and protected paths.
The helper runs with an empty environment and no input. Shell scripts are not supported as credential helpers.
Alternatively, Linux supports `source = "systemd"` with a credential `name`.
The operator provisions `LoadCredential=` or `LoadCredentialEncrypted=` and `User=` in the consuming systemd unit.
systemd supplies the private credential directory. Restart consuming units after credential rotation.
For both external sources, native `credential set` does not provision or replace their credentials.
After an approved configuration edit, run `setup` to apply its revision and restart long-running MCP processes.
If the selected source is unavailable, report its doctor prerequisite instead of changing sources automatically.

For MCP, configure the installed absolute server path in the user's selected agent's MCP configuration.
Use that agent's standard-input/output server configuration.
Serving is read-only by default. Add draft permissions only when the user requests and approves that access.
Finish when the requested components work and any requested account setup completes, or report the remaining operator step.
