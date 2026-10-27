# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.2](https://github.com/ueberBrot/mailctl/compare/v0.1.1...v0.1.2) - 2026-10-27


### Added

- add optional fuzzy search ([#110](https://github.com/ueberBrot/mailctl/pull/110))



### Security

- *(security)* update Tokio for RUSTSEC-2026-0386 ([#112](https://github.com/ueberBrot/mailctl/pull/112))
- *(security)* harden untrusted email text extraction ([#107](https://github.com/ueberBrot/mailctl/pull/107))

## [0.1.1](https://github.com/ueberBrot/mailctl/compare/v0.1.0...v0.1.1) - 2026-10-22

### Documentation

- *(readme)* add copyable AI agent setup prompt ([#103](https://github.com/ueberBrot/mailctl/pull/103))
- add mole branding and README header ([#100](https://github.com/ueberBrot/mailctl/pull/100))

### Security

- *(security)* update rustls-webpki for RUSTSEC-2026-0382 ([#101](https://github.com/ueberBrot/mailctl/pull/101))
## [0.1.0](https://github.com/ueberBrot/mailctl/releases/tag/v0.1.0) - 2026-10-20

### Initial release

Email access from your terminal or AI agent.

- Independent CLI (`mailctl`) and MCP server (`mailctl-mcp`) with shared account configuration.
- Account and mailbox discovery, message search, and bounded text reads.
- Attachment retrieval and export to an approved directory.
- Unsent draft creation, status, and recovery after interrupted saves.
- Read-only defaults and access grants for selected accounts, mailboxes, and operations.
- TLS connections and password storage in macOS Keychain, Windows Credential Manager, or Linux Secret Service.
- Prebuilt binaries and standalone installers for macOS Apple Silicon, GNU/Linux x86_64, and Windows x86_64.
- CLI-only, MCP-only, and combined installations, updates, and removal.
- Windows executables launched through WSL2 retain Windows credentials and paths.
- Installable agent skill for setup and email workflows through CLI or MCP.

mailctl does not send email or edit existing drafts.