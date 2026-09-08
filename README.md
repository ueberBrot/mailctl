# mailctl

`mailctl` CLI and `mailctl-mcp` are independent executables
around one shared Rust core. They share configured accounts and persistent state,
with independent connections and no required broker. See
[ADR-0001](docs/adr/0001-agent-email-access-boundary.md) and
[component installation](docs/adr/0005-install-cli-and-mcp-components.md).

Build either component with `cargo build --locked --no-default-features --features cli`
or `--features mcp`. The default `cargo build --locked` includes both executables.
Release installers remain [planned in issue #17](https://github.com/ueberBrot/mailctl/issues/17).

Run `mailctl setup --alias work --server imap.example.com --username user@example.com`
to create configuration and persistent account state, then `mailctl account list --json`
to discover authorized accounts. `mailctl-mcp setup` provides the same setup
commands; bare `mailctl-mcp` serves MCP over STDIO. Both use the same OS configuration
directory, or an explicit `--config` path. Adding another alias preserves existing
accounts; `--account old setup --alias new` renames one while preserving its identity.
Use `--grant` to select a configured grant and `--account` to narrow its accounts.
MCP defaults to read-only; `--use-configured-grant` opts into its configured profile.
Limits apply separately to each process.

Account discovery, capability reporting, and local health checks are implemented.
Credential commands report unsupported capability. Provider connections,
email reads, drafts, and platform qualification follow the
[parent specification](https://github.com/ueberBrot/mailctl/issues/1).

The [domain glossary](CONTEXT.md) and [architecture decisions](docs/adr/) define
the project's vocabulary and boundaries.

Licensed under the [ISC License](LICENSE).
