# Installation and setup

Use the standalone installer from the official `ueberBrot/mailctl` GitHub release.
Read the [README](https://github.com/ueberBrot/mailctl/blob/main/README.md) for supported versions and installation commands.
Keep installation, account setup, and credential provisioning within the user's requested scope.
An installation request alone does not authorize account changes or email access.

## Select the installation

1. Make sure that the host is macOS on Apple Silicon with `uname -s` and `uname -m`.
   Other distribution targets require separate support.
2. Use the requested released version.
   If the user omits a version, select the latest published stable release with matching Apple Silicon assets.
   If those assets are unavailable, stop and report that the release is unavailable.
   Build from source only when the user requests that method.
3. Select both components by default, or preserve the user's CLI-only or MCP-only choice.
   `--components cli` installs `mailctl`. `--components mcp` installs `mailctl-mcp`.
   `--components cli,mcp` installs both. Neither executable requires the other.
4. Determine the existing installation channel and destination before an update.
   Keep package-manager installations under their owning package manager.
   The standalone installer uses `CARGO_HOME/bin` when `CARGO_HOME` is nonempty, otherwise `~/.cargo/bin`.
   Use an absolute `CARGO_HOME` or `--install-dir` value. Preserve a custom destination.

## Install and inspect the selected components

Download `install-vVERSION.sh` from `https://github.com/ueberBrot/mailctl/releases/download/vVERSION/` into a temporary directory.
Replace both `VERSION` values with the selected release version.
Use HTTPS with failed HTTP responses treated as errors, as in the README's `curl` command.
Run the downloaded installer's `--help` before choosing its arguments.

Before an update, stop the CLI commands and MCP runtimes that use the installation cleanly.
Retain installation history, original draft inputs, and operation receipts.
If your active MCP connection needs a restart, arrange that restart with the operator.
For an existing custom configuration, pass its absolute path with `--config`.

Run the installer with `--version VERSION` and the selected components and destination.
The installer checks component sizes, checksums, ownership, and compatibility before replacement.
If an update requires both components, explain that requirement before expanding a single-component request.
If ownership, state compatibility, or recovery blocks installation, report the error and preserve the existing files.
Use the installer's `--recover` procedure only after the interrupted owner process exits.

Run each selected executable's `--version` and `--help` through its installed absolute path.
Make sure that the version matches the requested release.
Report the installed components, version, destination, and any required `PATH` change.
Keep shell configuration unchanged unless the user requests an edit.

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
