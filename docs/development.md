# Development

The workspace and isolated email fixture come from [issue #37](https://github.com/ueberBrot/mailctl/issues/37).
Tests use disposable accounts and synthetic mail; no provider credentials are needed.

## Prerequisites

- Install Rust through rustup and put Cargo on PATH. `rust-toolchain.toml` pins
  Rust **1.98.1**, Rustfmt and Clippy. The declared MSRV matches this compiler.
- Install a native C toolchain: Xcode Command Line Tools on macOS, a C compiler
  and linker on Linux, or Visual Studio Build Tools with C++ and Windows SDK.
- Docker tests require a running **local Linux-container Docker engine** and
  OpenSSL on PATH. Docker Desktop supports the Apple Silicon fixture. Shared
  tests do not need Docker, a credential store or OpenSSL.
- Initial setup downloads the Rust toolchain and locked crates. Dependency audits
  fetch RustSec advisories; Docker tests download the pinned GreenMail image.

## Commands

Run from the repository root. Cargo installs the toolchain in `rust-toolchain.toml`
on first use. Install the separate dependency checker once:

```sh
cargo fetch --locked
cargo install cargo-deny --version 0.20.2 --locked
```

Use these same commands locally and in CI:

```sh
cargo build --locked --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --no-default-features -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked --example check-policy
cargo deny --locked --all-features check
cargo test --locked --workspace --no-default-features
```

Clippy includes typechecking. During development, `cargo check --locked --workspace
--all-targets --all-features` runs typechecking alone. Use `cargo fmt --all` to
apply formatting and `cargo test --locked --test process` for the process tests.
All build/check/test commands honor `Cargo.lock`; update it explicitly when
changing dependencies.

The `check-policy` example is a development-only Rust check for MSRV/toolchain
agreement, vendored input checksums and production dependency features.
`cargo-deny` checks licenses, sources, advisories and yanked dependencies.

Docker tests have a separate entry point:

```sh
docker info
openssl version
cargo test --locked --test greenmail --features docker-tests -- --nocapture
```

The command runs two consecutive complete fixture lifecycles. Missing prerequisites
or failed readiness cause failure, never a silent skip. `docker-tests` enables only
development support; the shared suite works without a Docker engine even though
Clippy compiles that optional code.

## Application boundaries

The four executables currently support `--help` and `--version`. Otherwise they
exit 2 with a scaffold diagnostic on stderr. Email operations are not implemented.

The parent spec selects Clap for argument parsing; that choice can be revisited.
[Issue #2](https://github.com/ueberBrot/mailctl/issues/2) introduces CLI/MCP
operations, versioned JSON results and human output. Machine commands never prompt
and diagnostics stay on stderr. [Issue #16](https://github.com/ueberBrot/mailctl/issues/16)
completes rendering and color verification: interactive human streams may use
color, with explicit controls and `NO_COLOR`; JSON/MCP remain unstyled.

`domain` and `policy` remain independent of adapters. `secret` and `backend`
reserve credential-source and provider-neutral contracts; `service` owns the
application contract. `adapters/` holds IMAP and shared email integration; `ipc`
and `frontends` hold transport DTOs and frontend mapping. The modules are
placeholders until their feature slices define the contracts.

Only Clap is a production dependency. Backend adoption and route proofs remain
in #3 and its dependent tickets. `check-policy` rejects unintended protocol/provider
features, enabled io-email/io-imap defaults and test support in production
normal/build dependency paths. `deny.toml` lists accepted licenses and sources;
exceptions require a reviewed policy change. RustSec advisories stay current
independently of the lockfile.

## Docker fixture and cleanup

GreenMail **2.1.13** is pinned to an ARM64/x86-64 image digest with a matching
vendored API schema. See [provenance](../tests/specs/README.md). Each suite owns
one fresh server. Only SMTP (3025), IMAPS (3993) and API (8080) are published,
using random **127.0.0.1** host ports verified through Docker inspection.

Before startup, the fixture generates a temporary CA, localhost certificate and
PKCS#12 keystore. TLS verifies that CA and hostname. `GREENMAIL_OPTS` replaces the
image defaults. **Do not set `greenmail.auth.disabled`, even to `false`: the
presence of that property disables authentication.**

After API readiness, the fixture creates its disposable account, verifies TLS
login and wrong-password rejection independently, and seeds synthetic mail through
SMTP. Bounded API responses are checked against DTOs and the corrected release
schema. IMAP EXAMINE/flag observations verify mailbox count, UID identity and
unseen state. A distinct message in a nested folder with spaces checks API path
encoding independently from INBOX.

Connections close before purge/reset. Reset repeats readiness, account creation,
authentication and seeding. Explicit cleanup confirms container removal; removal
on drop is the failure fallback. `TESTCONTAINERS_COMMAND=keep` is rejected.
There are no persistent volumes or retained account state.

If the process is forcibly killed or Docker fails, inspect
`docker ps -a --filter ancestor=greenmail/standalone:2.1.13` and remove only the
interrupted suite's container with `docker rm -f <id>`. No global Docker cleanup
is needed.

## CI and evidence

CI runs on pull requests, pushes to `main`, and explicit dispatch. The shared
matrix uses `ubuntu-latest`, `macos-latest` and `windows-latest`; Ubuntu also owns
formatting/dependency checks and Docker integration. These labels follow GitHub's
current runner images. They are development coverage, not deployment qualification.

`actions-rust-lang/setup-rust-toolchain` reads our toolchain file and installs
Rust/Cargo and components. `taiki-e/install-action` installs pinned cargo-deny.
Steps then run the Cargo commands above directly. Action revisions, the compiler,
Cargo dependencies and the GreenMail image/schema remain pinned. There are no
scheduled jobs or ignored check failures.

Branch protection must select these jobs to enforce them before merging; this
scaffold does not change repository settings. Acceptance results and CI runs are
recorded on [issue #37](https://github.com/ueberBrot/mailctl/issues/37).
