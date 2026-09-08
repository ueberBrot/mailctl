# Share an email core between independent CLI and MCP executables

Ship `mailctl` as the email CLI and `mailctl-mcp` as an independently usable STDIO server. Both compile the same Rust core for authorization, credentials, bounded email operations, and draft coordination. The core is a build dependency, not another executable users install. CLI-only builds exclude MCP dependencies; MCP-only builds exclude the ordinary email command tree.

Each process owns its connections, queues, and request limits. CLI commands can run while MCP is absent, running, or exiting; MCP does not require the CLI. They share account configuration, credential references, and persistent installation identity/history. Normal use requires neither a broker nor discovery of another process. Persistent-state and draft safety follow [ADR-0002](0002-share-draft-writer-across-endpoints.md) and [ADR-0003](0003-preserve-email-and-draft-operation-identity.md).

`mailctl` owns the ordinary operator setup and credential commands. MCP-only installs expose equivalent explicit `mailctl-mcp setup` and `mailctl-mcp credential` commands through that same implementation; bare MCP serving never prompts or exposes administration as tools. Harness execution, model selection, and downstream use of email belong to the consuming application.

This revises the single-executable decision to support separately installed interfaces while retaining embedded operation. It also removes shared live-runtime admission: resource ceilings apply per process, and multiple processes multiply them. Cooperative application permissions do not isolate credentials from an unrestricted same-user process. Optional isolated deployments require separate OS/IPC qualification and do not gate ordinary releases.

[Issue #2](https://github.com/ueberBrot/mailctl/issues/2) adapts the in-progress embedded implementation. [ADR-0005](0005-install-cli-and-mcp-components.md) defines component distribution; these decisions do not claim completed implementation.
