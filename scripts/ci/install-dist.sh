#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?}" "${DIST_BIN_DIR:?}" "${GITHUB_PATH:?}"
cd "$RUNNER_TEMP"

case "$(uname -s):$(uname -m)" in
Darwin:arm64)
	dist_target=aarch64-apple-darwin
	dist_checksum=d1eec30e63eed23e5a5bd48fe96eae314799811bffca254ec1d2264638ba1890
	;;
Linux:x86_64)
	dist_target=x86_64-unknown-linux-gnu
	dist_checksum=7fee44ff3ff71ed0064b32d4ec62fee6b58bd37c5887b12a86aedddc5af0c7b5
	;;
*)
	printf 'Unsupported native dist build host.\n' >&2
	exit 1
	;;
esac

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
	"https://github.com/axodotdev/cargo-dist/releases/download/v0.34.0/cargo-dist-$dist_target.tar.xz" \
	--output dist.tar.xz
if command -v sha256sum >/dev/null; then
	printf '%s  dist.tar.xz\n' "$dist_checksum" | sha256sum -c -
else
	printf '%s  dist.tar.xz\n' "$dist_checksum" | shasum -a 256 -c -
fi
mkdir -p "$DIST_BIN_DIR"
tar -xJf dist.tar.xz --strip-components=1 -C "$DIST_BIN_DIR"
test "$("$DIST_BIN_DIR/dist" --version)" = 'cargo-dist 0.34.0'
printf '%s\n' "$DIST_BIN_DIR" >>"$GITHUB_PATH"
