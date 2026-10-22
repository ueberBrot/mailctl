#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

case "${1:-}" in
systemd)
	: "${MAILCTL_FEATURES:?}"
	test_binaries=$(cargo test --locked --workspace --no-default-features \
		--features "$MAILCTL_FEATURES" \
		--test systemd_native --test systemd_credentials \
		--no-run --message-format=json |
		jq -s 'map(select(.reason == "compiler-artifact" and
              .executable != null)) |
              map({key: .target.name, value: .executable}) | from_entries')
	test_binary=$(jq -r '.systemd_native // empty' <<<"$test_binaries")
	acl_test_binary=$(jq -r '.systemd_credentials // empty' <<<"$test_binaries")
	test -n "$test_binary"
	test -n "$acl_test_binary"
	sudo env MAILCTL_DISPOSABLE_SYSTEMD=1 \
		"$acl_test_binary" \
		linux::systemd_source_accepts_only_the_service_user_acl \
		--exact --ignored --nocapture --test-threads=1
	sudo env MAILCTL_DISPOSABLE_SYSTEMD=1 \
		"$test_binary" --ignored --nocapture --test-threads=1
	systemctl --version
	uname -a
	for binary in target/debug/mailctl target/debug/mailctl-mcp; do
		if test -f "$binary"; then sha256sum "$binary"; fi
	done
	;;
isolation)
	test_binary=$(cargo test --locked --features isolated \
		--test isolated_native --no-run --message-format=json |
		jq -r 'select(.reason == "compiler-artifact" and
              .target.name == "isolated_native" and .executable != null) |
              .executable')
	test -n "$test_binary"
	sudo env MAILCTL_DISPOSABLE_MACOS=1 \
		"$test_binary" --ignored --nocapture --test-threads=1
	;;
*)
	printf 'Usage: %s {systemd|isolation}\n' "$0" >&2
	exit 2
	;;
esac
