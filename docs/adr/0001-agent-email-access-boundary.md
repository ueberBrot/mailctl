# Share an email core between independent CLI and MCP executables

Ship `mailctl` as the email CLI and `mailctl-mcp` as an independently usable STDIO server. Both compile the same Rust core for authorization, credentials, bounded email operations, and draft coordination. The core is a build dependency, not another executable users install. CLI-only builds exclude MCP dependencies; MCP-only builds exclude the ordinary email command tree.

Each process owns its connections, queues, and request limits. CLI commands can run while MCP is absent, running, or exiting; MCP does not require the CLI. They share account configuration, credential references, and persistent installation identity/history. Multiple processes multiply resource budgets. Normal use requires neither a broker nor discovery of another process.

`mailctl` owns the ordinary operator setup and credential commands. MCP-only installs expose equivalent explicit `mailctl-mcp setup` and `mailctl-mcp credential` commands through that same implementation; bare MCP serving never prompts or exposes administration as tools. Harness execution, model selection, and downstream use of email belong to the consuming application.

Independent executables let operators install either interface while keeping authorization and email behavior consistent. Cooperative application permissions do not isolate credentials from an unrestricted same-user process; credential isolation requires an OS security boundary.
