# mailctl

Email tools for the command line and MCP. It supports account and mailbox
discovery, bounded message search and body reads, attachment retrieval, reusable
resource references, capability reporting, macOS credential provisioning, and
authentication diagnostics. It also creates unsent drafts and inspects their
durable outcomes through either interface. Retain the account UUID, generation,
operation UUID, and original input before saving. Identical retries share the
recorded outcome. An uncertain outcome never permits another APPEND;
reconciliation is not yet available.

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
