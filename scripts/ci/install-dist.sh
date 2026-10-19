#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?}" "${DIST_BIN_DIR:?}" "${GITHUB_PATH:?}"
cd "$RUNNER_TEMP"

case "$(uname -s):$(uname -m)" in
Darwin:arm64)
	dist_target=aarch64-apple-darwin
	dist_checksum=7b3cbe25511de01d74c0f5fcb7909edabd379bea9cfa284d93af5a3cdfa3247c
	;;
Linux:x86_64)
	dist_target=x86_64-unknown-linux-gnu
	dist_checksum=4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293
	;;
*)
	printf 'Unsupported native dist build host.\n' >&2
	exit 1
	;;
esac

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
	"https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-$dist_target.tar.xz" \
	--output dist.tar.xz
if command -v sha256sum >/dev/null; then
	printf '%s  dist.tar.xz\n' "$dist_checksum" | sha256sum -c -
else
	printf '%s  dist.tar.xz\n' "$dist_checksum" | shasum -a 256 -c -
fi
mkdir -p "$DIST_BIN_DIR"
tar -xJf dist.tar.xz --strip-components=1 -C "$DIST_BIN_DIR"
test "$("$DIST_BIN_DIR/dist" --version)" = 'cargo-dist 0.33.0'
printf '%s\n' "$DIST_BIN_DIR" >>"$GITHUB_PATH"
