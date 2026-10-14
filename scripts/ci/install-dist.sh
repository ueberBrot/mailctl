#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?}" "${DIST_BIN_DIR:?}" "${GITHUB_PATH:?}"
cd "$RUNNER_TEMP"

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
	https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-aarch64-apple-darwin.tar.xz \
	--output dist.tar.xz
printf '%s\n' '7b3cbe25511de01d74c0f5fcb7909edabd379bea9cfa284d93af5a3cdfa3247c  dist.tar.xz' | shasum -a 256 -c -
mkdir -p "$DIST_BIN_DIR"
tar -xJf dist.tar.xz --strip-components=1 -C "$DIST_BIN_DIR"
test "$("$DIST_BIN_DIR/dist" --version)" = 'cargo-dist 0.33.0'
printf '%s\n' "$DIST_BIN_DIR" >>"$GITHUB_PATH"
