# Contributing to mailctl

Keep each pull request focused on one change. Explain the problem, the resulting
behavior, and the checks that you ran. Preserve existing behavior unless the
change fixes a bug or deliberately changes the interface.

Use the terms in [GLOSSARY.md](GLOSSARY.md). Read the relevant
[architecture decisions](docs/adr/) before changing access boundaries, component
selection, or draft coordination. Agent-specific workflows live in
[AGENTS.md](AGENTS.md).

## PR titles and commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for PR
titles and commit messages:

```text
type(scope)!: summary
```

The scope is optional. Use `!` only for a breaking change. Write a short summary
that says what the change does.

The [PR title check](.github/workflows/pr-title.yml) accepts these types:

| Type | Use for |
| --- | --- |
| `feat` | New functionality |
| `fix` | Bug fixes |
| `perf` | Performance improvements |
| `refactor` | Code changes that preserve behavior |
| `docs` | Documentation |
| `test` | Tests and test fixtures |
| `build` | Build tooling and dependencies |
| `ci` | CI workflows |
| `chore` | Other maintenance |
| `style` | Formatting changes |
| `revert` | Reverting an earlier change |

For example:

```text
fix(drafts): preserve uncertainty after interrupted creation
perf(imap): avoid cloning attachment metadata
docs: explain contribution requirements
refactor(cli): simplify argument handling
```

For security fixes, use `fix(security): summary`. CI validates PR titles. It does
not validate individual commit messages.

For a breaking change, add `!` before the colon. In the commit body, include a
`BREAKING CHANGE:` footer that explains the effect and migration steps.
Mark breaking changes before the first release too.

This repository uses squash merges, which combine a PR into one commit. GitHub
uses the PR title as the final commit subject and leaves the body empty by
default. Keep the conventional title when merging. Copy any breaking-change
explanation into the final commit body as a `BREAKING CHANGE:` footer. The PR
description and branch commit bodies are not preserved automatically.

## Build and check changes

Run commands from the repository root. Use the Rust toolchain and components in
[rust-toolchain.toml](rust-toolchain.toml). The dependency policy check needs
`cargo-deny` at the version pinned in the [CI workflow](.github/workflows/ci.yml).

Before submitting Rust changes, run:

```sh
cargo fmt --all -- --check
cargo build --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo run --locked --example check-policy
cargo deny --locked --all-features check
```

The default build includes CLI and MCP. For changes to component boundaries or
dependencies, also check each feature selection:

```sh
cargo build --locked --workspace --all-targets --no-default-features --features cli
cargo clippy --locked --workspace --all-targets --no-default-features --features cli -- -D warnings
cargo test --locked --workspace --no-default-features --features cli
```

Repeat those commands with `mcp` and `cli,mcp` in place of `cli`.

For GreenMail integration changes, use a running Docker daemon compatible with
the pinned Docker client. Install OpenSSL and follow the Docker configuration in
the CI workflow. Then run:

```sh
cargo clippy --locked --workspace --all-targets --features docker-tests -- -D warnings
cargo test --locked --test greenmail --features docker-tests
```

Workspace tests use local servers and disposable installations. Allow localhost
connections when running them in a sandbox. Run native credential and isolation
acceptance checks in the disposable CI jobs.

For documentation changes, check the edited links and command examples. Run
checks that cover any executable examples that you change. Report failed or
unavailable checks in the PR description.

## Rust and testing conventions

- Prefer standard-library APIs and established Rust idioms. Borrow or move
  values when possible. Clone only when ownership or lifetime requirements need
  a copy.
- Use `?` to propagate errors. Retain useful, safe error context without exposing
  credentials or private email content.
- Keep abstractions focused on shared behavior or complexity that they hide.
  Remove redundant conversions and intermediate values when the code stays clear.
- Preserve access-grant checks, cancellation behavior, deadlines, and resource
  limits when changing service paths.
- Use compile-time fixtures to verify the published type contract. Reserve
  runtime tests for behavior that can fail at runtime. Avoid testing guarantees
  already enforced by the type system.
- For runtime bug fixes, add a regression test that fails without the fix.
  Use disposable data and the existing provider fixtures.

Keep dependency declarations, `Cargo.lock`, and repository policy checks
consistent when updating dependencies. The CI workflow defines the full platform
matrix and acceptance checks.

## Releases

The [main-only workflow](.github/workflows/release-plz.yml) uses
[release-plz](https://release-plz.dev/) and its embedded git-cliff to prepare a
release PR with version changes and `CHANGELOG.md`. The
[configuration](release-plz.toml) manages one product version for CLI and MCP.
Let this workflow prepare routine version and changelog updates.

Release-plz reads commit history on `main`. Review the proposed version and
release notes, including compatibility changes and migration instructions.

The workflow uses the built-in GitHub token. A maintainer with write access
must select "Approve workflows to run" on the generated PR. That approval
starts the CI checks.
Review the version, changelog, and candidate checks before a maintainer manually
merges the release PR. That merge approves publication. After the merged commit
passes all Development checks, the [publication workflow](.github/workflows/release.yml)
uses release-plz to create the version tag and draft release with its changelog.
The workflow verifies that run's qualified artifacts, attaches the installers,
binaries, and checksums, then publishes the release after verifying every asset.
Ordinary pushes to `main` do not publish releases.

If publication fails, inspect the retained release plan, publication journal,
and any existing tag or draft release before recovery. The manual commands in
`scripts/release.py` remain available for reviewed recovery.
