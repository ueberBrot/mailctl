# Installation and setup

Use the standalone installer from the official `ueberBrot/mailctl` GitHub release.
Keep installation, account setup, and credential provisioning within the user's requested scope.
An installation request alone does not authorize account changes or email access.

## Select the installation

1. Make sure that the host is macOS on Apple Silicon with `uname -s` and `uname -m`.
   Other distribution targets require separate support.
2. For an existing installation, determine its installation channel and destination.
   Keep package-manager installations under their owning package manager.
   The standalone installer uses `CARGO_HOME/bin` when `CARGO_HOME` is nonempty, otherwise `~/.cargo/bin`.
   Use an absolute `CARGO_HOME` or `--install-dir` value. Preserve a custom destination.
3. For a first installation, install both components unless the user selects CLI only or MCP only.
   `--components cli` selects `mailctl`. `--components mcp` selects `mailctl-mcp`.
   `--components cli,mcp` selects both. Neither executable requires the other.
   For updates or removal, omit `--components` to keep the installed selection unless the user requests a change.

## Install or update

Before an update, stop the CLI commands and MCP runtimes that use the installation cleanly.
Retain installation history, original draft inputs, and operation receipts.
If your active MCP connection needs a restart, arrange that restart with the operator.
For an existing custom configuration, pass its absolute path with `--config`.
Use the original `--install-dir` for a custom destination.

The default command installs the latest stable release:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh
```

If the user requests an exact release, pin both the installer URL and the binary version:

```sh
VERSION=0.1.0
curl --fail --location --proto '=https' --proto-redir '=https' "https://github.com/ueberBrot/mailctl/releases/download/v${VERSION}/install.sh" | sh -s -- --version "$VERSION"
```

Replace `0.1.0` with the requested version.
To pass components or a custom destination, use `sh -s --` after the pipe and append the installer arguments.
If the requested release or its assets are unavailable, report the failure.
Build from source only when the user requests that method.

The installer checks sizes, checksums, ownership, and compatibility before replacing components.
Without `--components`, it updates the installed components together.
Use `--components cli,mcp` to add a missing component.
If an update requires both components, explain that requirement before expanding a single-component request.
If ownership, state compatibility, or recovery blocks installation, report the error and preserve the existing files.
Use the installer's `--recover` procedure only after the interrupted owner process exits.

Run each selected executable's `--version` and `--help` through its installed absolute path.
For a pinned release, make sure that the version matches the request.
Report the installed components, version, destination, and any required `PATH` change.
Keep shell configuration unchanged unless the user requests an edit.

## Remove components

Use the same installer with `--uninstall`:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/ueberBrot/mailctl/releases/latest/download/install.sh | sh -s -- --uninstall
```

The default removes the installed components.
Use `--components cli` or `--components mcp` for a requested partial removal.
Pass the original `--install-dir` for a custom destination.
Updates and removal preserve account configuration, credentials, and draft history.
Draft history uses `drafts.sqlite` in the configured state directory.
The installer preserves this SQLite database; no separate database server is installed.
Report the removed components and any remaining components.

## Guide requested account setup

For CLI-only or combined installations, use `mailctl`. For MCP-only installations, use `mailctl-mcp`.
Read the selected executable's `setup --help` and `guide overview` for account and grant configuration.
Use the user's account alias, provider hostname, and username for an authorized setup.
Preserve existing account identities, grants, credential sources, and draft history during updates.

For native macOS credentials, give the operator this command for their own terminal:

```sh
mailctl --account work credential set
```

Replace `work` with the approved alias and select `mailctl-mcp` for an MCP-only installation.
The operator enters the password directly at the terminal prompt. macOS Keychain stores it.
Keep passwords outside chat, command arguments, and account configuration.
If an existing account uses a trusted command credential source, its owner provisions that external source.
The native credential commands do not replace external command credentials.

After credential provisioning, use `credential status --json` for local availability.
That status does not prove authentication.
Within authorized account setup, use `doctor --check-account --json` to test fresh provider authentication.
Require `ok: true` and `result.accounts[].authentication.outcome.status: "authenticated"` before reporting successful authentication.

For MCP, configure the installed absolute server path in the user's selected harness.
Serving is read-only by default. Add draft permissions only when the user requests and approves that access.
Finish when the requested components work and any requested account setup completes, or report the remaining operator step.
