# mailctl

Email tools for the command line and MCP. It supports account and mailbox
discovery, bounded message search and body reads, reusable resource references, capability reporting, macOS credential
provisioning, and authentication diagnostics.

Build both executables:

```sh
cargo build --locked
```

Configure an account and list it:

```sh
./target/debug/mailctl setup --alias work --server imap.example.com --username user@example.com
./target/debug/mailctl account list --json
```

Run `./target/debug/mailctl-mcp` to serve MCP over STDIO using the same configuration.
Use `--grant` to select an access grant, `--account` to narrow accounts, or `--help`
for available commands.

[Configure credentials, check authentication, and rotate passwords](docs/credentials.md).
[Discover approved mailboxes and reuse their references](docs/mailboxes.md).
[Search messages with resumable pages](docs/search.md) and
[read selected message text](docs/messages.md).

Standard operation needs no service. Operators who want a separate protected
credential identity can explicitly [set up native macOS isolation](docs/isolation.md).

Native Keychain acceptance runs in a dedicated macOS CI job. Its ignored local
test requires a disposable macOS user: it temporarily selects a test Keychain,
uses synthetic passwords, and restores the original preferences during cleanup.

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for PR
titles and commits made directly to `main`. PRs are squash-merged using the PR
title, so intermediate branch commits need not follow the convention. Describe
the resulting behavior and mark breaking changes with `!`, including changes to
flags, configuration, or machine-readable output.

```text
feat(cli): add message listing
fix(config): preserve account identities during setup
feat(config)!: replace account names with account IDs
ci: validate pull request titles
```

Use `feat` for features, `fix` for bug fixes, and `build`, `chore`, `ci`, `docs`,
`perf`, `refactor`, `revert`, `style`, or `test` for other changes. The scope in
parentheses is optional. PR titles are checked before merging; contributors
committing directly to `main` must apply the convention themselves.

Changelog generation and release automation remain inactive while the first
release is being prepared.

[ISC License](LICENSE).
