# mailctl

Email tools for the command line and MCP. Currently supports configured account
discovery, capability reporting, and local health checks.

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

For backend development, see the [body retrieval proof](docs/imap-body-proof.md),
[attachment streaming proof](docs/imap-attachment-proof.md), and
[draft acknowledgement proof](docs/imap-draft-proof.md).

[ISC License](LICENSE).
