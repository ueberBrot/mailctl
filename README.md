# mailctl

Controlled email access through a broker (`maild`), command-line client (`mailctl`),
STDIO MCP adapter (`mail-mcp`), and operator administration tool (`mail-admin`).

The current implementation discovers authorized email accounts through CLI, MCP,
and authenticated Unix IPC. It provides stable account identities, permission
narrowing, capabilities, and safe health using an in-memory backend. Provider
connections, email reads, and drafts remain
[planned work](https://github.com/ueberBrot/mailctl/issues/1).

Run the [local discovery example](docs/discovery.md). This unreleased slice supports
cooperative Unix use; isolated deployments and Windows transport remain unqualified.

Start with the [development guide](docs/development.md). The [domain glossary](CONTEXT.md)
and [architecture decisions](docs/adr/) define the project's vocabulary and boundaries.
