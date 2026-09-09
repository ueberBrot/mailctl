# mailctl

Email tools for the command line and MCP. It supports configured account discovery,
capability reporting, macOS credential provisioning, and authentication diagnostics.

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

[ISC License](LICENSE).
