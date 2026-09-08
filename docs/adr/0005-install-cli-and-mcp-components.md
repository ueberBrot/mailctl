# Install CLI and MCP as selectable components

Install both `mailctl` and `mailctl-mcp` by default so the standard installation provides both interfaces. Offer CLI-only and MCP-only installation as explicit selections; each component remains independently usable. Default source builds follow the same selection.

The standalone installer downloads verified binaries and installs selected components side by side in Cargo's binary directory, matching rustup: `CARGO_HOME/bin` when configured, otherwise `~/.cargo/bin` on Unix or `%USERPROFILE%\.cargo\bin` on Windows. An explicit destination override is supported. Rust and rustup are not runtime prerequisites.

The installer owns only its product files and component manifest. Keep configuration, installation history, and per-account credential references independent of binary location and installed components. Preserve unselected components and user state during upgrades/removal, reject foreign file collisions, and qualify supported component/schema combinations. Do not modify Cargo/rustup metadata or unrelated binaries in the shared directory.

Homebrew is a separate installation channel using its native prefix and package ownership. Separate CLI/MCP formulae and a combined dependency formula support the same component choices; they share application state rather than install ownership. Update and uninstall through the channel that owns each binary. This follows [rustup's destination convention](https://rust-lang.github.io/rustup/installation/index.html) without introducing a toolchain manager or forcing Homebrew into a user Cargo directory.

[Issue #17](https://github.com/ueberBrot/mailctl/issues/17) owns standalone install/upgrade/removal acceptance; [issue #38](https://github.com/ueberBrot/mailctl/issues/38) qualifies Homebrew. Both paths must demonstrate CLI-only, MCP-only, and combined use, including operator setup without the other executable.
