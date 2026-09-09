# Choose standard or isolated access on macOS

Standard mode is the default. Run `mailctl setup` or `mailctl-mcp setup`, provision
credentials, and use either executable directly. No service or administrator
setup is required. Access grants apply to mailctl requests; the user remains in
control of access granted through their shell, filesystem, and other programs.

Choose isolated mode when an operator wants a caller to use email tools without
giving that caller access to the email credentials or permission to edit its
access grant. It requires a separate, unprivileged macOS service identity and
explicit administrator provisioning. The CLI and MCP connect through a local
Unix socket; macOS authenticates both process identities. There are no SSH keys
or network listeners.

The operator and root remain trusted. This mode does not restrict an
administrator or protect against compromise of the service identity itself.
All processes running under an approved caller identity receive that identity's
assigned grant. It does not distinguish harness names or individual applications
running as that identity.

## Provision an isolated installation

Use an independently managed service account and an unprivileged caller account.
The service account must have home directory `/var/db/mailctl-isolated` and a
non-login shell, `/usr/bin/false` or `/sbin/nologin`. Neither account may be root
or an administrator. Creating or choosing these accounts is an explicit operator
decision; the installer does not alter existing accounts.

Build the selected executables and the optional broker:

```sh
cargo build --locked --release --features isolated
```

CLI-only and MCP-only builds remain available with
`--no-default-features --features cli,isolated` or
`--no-default-features --features mcp,isolated`. The broker uses the shared email
core directly and does not require the other frontend executable.

From the repository root, install the reviewed artifacts:

```sh
sudo deployment/macos-isolated/install.sh \
  --service-user mailctl_service \
  --caller-user mailctl_caller \
  --artifact-dir "$PWD/target/release"
```

Substitute your dedicated account names. The installer explains the isolated
deployment, refuses existing deployment paths, installs the selected binaries
and launchd definition, and creates protected directories, including the service
account's Keychain preferences directory. It does not start the
service, copy credentials, or change the standard installation.

Use the installed CLI for explicit administration under the service identity:

```sh
sudo -H -u mailctl_service \
  /Library/PrivilegedHelperTools/org.ueberbrot.mailctl/mailctl \
  --config /var/db/mailctl-isolated/config.toml \
  setup --alias work --server imap.example.com --username user@example.com
```

For an MCP-only installation, substitute `mailctl-mcp`. Repeat setup to add each
account. Configure the `isolated` access grant in the service's TOML file with
the approved account keys, mailbox names, and permission profile. For a new
installation with only the initial grant, you can rename that grant from
`default` to `isolated` and set `default_grant = "isolated"`; keep its
`read_only` profile. Run `setup` again to validate the edited configuration.

Provision a dedicated file-based Keychain for the service identity, select it as
that identity's default Keychain, and unlock it before credential provisioning.
macOS daemons require the file-based Keychain; the data-protection Keychain is
available only in a user login context.
[Apple's Keychain guidance](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains).

For the new dedicated service account:

```sh
sudo -H -u mailctl_service /usr/bin/security create-keychain \
  /var/db/mailctl-isolated/service.keychain-db
sudo -H -u mailctl_service /usr/bin/security list-keychains -d user -s \
  /var/db/mailctl-isolated/service.keychain-db
sudo -H -u mailctl_service /usr/bin/security default-keychain -d user -s \
  /var/db/mailctl-isolated/service.keychain-db
sudo -H -u mailctl_service /usr/bin/security unlock-keychain \
  /var/db/mailctl-isolated/service.keychain-db
```

Enter the Keychain password at its terminal prompt. These commands change only
the dedicated service account's Keychain selection. Keep the Keychain password
with the operator; it is not part of the route or application configuration.

Then provision each email credential through the operator terminal:

```sh
sudo -H -u mailctl_service \
  /Library/PrivilegedHelperTools/org.ueberbrot.mailctl/mailctl \
  --config /var/db/mailctl-isolated/config.toml \
  --account work credential set
```

Credential values stay in the service's Keychain. Provisioning does not accept
password arguments, machine JSON, or MCP tools. See
[credential administration](credentials.md) for rotation and source errors.

The public route file,
`/Library/Application Support/mailctl-isolated/route.json`, maps caller UIDs to
grant names and pins the service UID. Only the operator may edit this root-owned
file. Grant names and UIDs are routing metadata, not credentials. Stop the
service before changing its configuration or route, validate configuration as
the service identity, and restart it to apply changes.

## Start and use the selected mode

Unlock the dedicated Keychain in the service user's launchctl context, then start
the explicitly provisioned service:

```sh
service_uid=$(/usr/bin/id -u mailctl_service)
sudo /bin/launchctl asuser "$service_uid" /usr/bin/security unlock-keychain \
  /var/db/mailctl-isolated/service.keychain-db
sudo deployment/macos-isolated/service.sh start
```

Enter the Keychain password at the terminal prompt. Keychain unlock state belongs
to a security session: unlocking during credential provisioning alone does not
unlock it for launchd. The installed job uses `launchctl` as root to enter that
same service user's context, then `sudo` drops to the unprivileged service
identity before executing the broker. The launcher uses fixed arguments in the
root-owned plist; callers cannot select the executable or service identity.

The job starts at boot and restarts after process failure. Repeat the explicit
unlock after boot or when the Keychain locks. A broker process restart retains
the shared launchctl context and does not itself require another unlock.
Use `service.sh restart` after an administrative change and `service.sh stop`
to stop it. A locked or unavailable Keychain produces a credential error;
serving never prompts to unlock it.

Under the approved caller identity:

```sh
mailctl --isolated account list --json
mailctl --isolated --account work doctor --check-account --json
mailctl-mcp --isolated
```

Point the agent harness at `mailctl-mcp` with the argument `--isolated` for MCP
access. MCP remains read-only by default. `--account` and `--read-only` may narrow
the assigned grant. `--grant` and `--config` cannot override the protected route;
credential and setup commands are unavailable through isolated access.

An isolated invocation fails when its service or authenticated route is
unavailable. It never falls back to a caller-owned installation. Ordinary
invocations without `--isolated` continue to use standard mode and never discover
or start the service.

## Capacity and installation history

The broker admits at most four sessions, with one request at a time per session.
The configured active-request limit reduces the global session ceiling. Each
grant has a shared session ceiling that also honors its narrower active-request
limit, including when multiple caller identities use that grant. Excess sessions
are rejected without queueing.
Initialization is limited to five seconds, request frames to 64 KiB, and session
lifetime to five minutes. Configured access-grant limits can reduce these
ceilings. Capability results include the isolated session limits. The broker's
credential workers and provider connections use the shared core's per-process
limits; standard CLI/MCP processes retain independent budgets.

The service owns a separate installation. Its configuration, credential
references, and durable history are private to that identity. Operator-invoked
embedded processes under the service identity can use the same installation and
its existing maintenance and draft writer locks. Caller-owned standard
installations cannot share those files. Their independent journals cannot
coordinate retries of the same draft operation.

Changing modes requires explicitly choosing or provisioning the destination
installation. Keep existing configuration and history intact. Removing or
replacing binaries does not migrate credentials or combine installation history.

## Verify the deployment

Isolation is qualified only for the exact macOS version, architecture, artifacts,
and service setup recorded in [issue #8](https://github.com/ueberBrot/mailctl/issues/8).
The dedicated native acceptance suite uses disposable service and caller
identities. It verifies access through launchd, credential resolution, peer
identity, protected resources, bounded requests, and restart behavior. Missing
native evidence leaves isolated mode unqualified; standard mode is independent.

Run privileged acceptance only on a disposable macOS machine. The test creates
and removes its own OS accounts, Keychain, and fixed deployment paths and refuses
an existing deployment. The `native-isolation` CI job builds and invokes that
test with administrator privileges on a fresh hosted runner.
