# Install CLI and MCP as selectable components

Install both `mailctl` and `mailctl-mcp` by default on first installation so the standard installation provides both interfaces. Offer CLI-only and MCP-only installation as explicit selections. Each component remains independently usable. On later installer runs, preserve the installed selection when no component selection is supplied, including during removal. Default source builds include both components.

The standalone installer downloads verified binaries and installs selected components side by side in `~/.local/bin` on Unix or `%USERPROFILE%\.local\bin` on Windows. An explicit destination override is supported. Rust and rustup are not runtime prerequisites. The operator configures `PATH` or uses full executable paths.

The installer owns only its product files and component manifest. Keep configuration, installation history, and per-account credential references independent of binary location and installed components. Preserve unselected components and user state during upgrades/removal, reject foreign file collisions, and reject incompatible component/schema combinations. Do not modify Cargo/rustup metadata or unrelated binaries in the shared directory.

Homebrew is a separate installation channel using its native prefix and package ownership. Separate CLI/MCP formulae and a combined dependency formula support the same component choices; they share application state rather than install ownership. Update and uninstall through the channel that owns each binary.
