# Serve independent agent harnesses through CLI and MCP

Expose mailctl's agent-facing email operations through CLI and MCP, backed by one application contract and broker authorization. Credentials stay in the broker's security domain; the operator grants access there, and the broker checks every request independently of frontend validation.

Support independent agent harnesses through these interfaces. Harness execution, general shell access, model-provider selection and downstream use of returned data belong to the consuming application. This keeps mailctl usable across harnesses without owning their runtime or tool configuration.

Use established OS boundaries for deployments claiming isolation: protect broker credentials, executable, configuration and state from callers. Cooperative deployment enforces API permissions but cannot guarantee protection against bypass by an unrestricted process under the same OS user. The first isolated deployment mechanism remains to be selected and tested; adding a Rust sandbox library alone does not establish that guarantee.
