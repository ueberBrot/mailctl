# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.0](https://github.com/ueberBrot/mailctl/releases/tag/v0.1.0) - 2026-10-16

### Initial release

Email access from your terminal or AI agent.

- Independent CLI (`mailctl`) and MCP server (`mailctl-mcp`) with shared account configuration.
- Account and mailbox discovery, message search, and bounded text reads.
- Attachment retrieval and export to an approved directory.
- Unsent draft creation, status, and recovery after interrupted saves.
- Read-only defaults and access grants for selected accounts, mailboxes, and operations.
- Password storage in macOS Keychain and TLS connections to email providers.
- Standalone macOS Apple Silicon installer with CLI-only, MCP-only, and combined installations, updates, and removal.
- Installable agent skill for setup and email workflows through CLI or MCP.

mailctl does not send email or edit existing drafts.