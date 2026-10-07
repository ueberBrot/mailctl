#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export MAILCTL_FUZZ_CASES="${MAILCTL_FUZZ_CASES:-64}"
export MAILCTL_FUZZ_SEED="${MAILCTL_FUZZ_SEED:-35001}"

record_dir="target/fuzz-campaigns/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$record_dir"

checksum() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

{
	printf 'commit=%s\n' "$(git rev-parse HEAD)"
	printf 'cases=%s seed=%s input_max=16384\n' "$MAILCTL_FUZZ_CASES" "$MAILCTL_FUZZ_SEED"
	printf 'started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	uname -sm
	rustc --version
	git status --short
	find tests/fuzz_corpus -type f -exec shasum -a 256 {} + | sort
} >"$record_dir/metadata.txt"
git diff HEAD --binary >"$record_dir/working-tree.patch"
checksum "$record_dir/working-tree.patch" >>"$record_dir/metadata.txt"

if cargo test --locked \
	--test fuzz_mime --test fuzz_tokens --test fuzz_envelopes \
	--test fuzz_imap --test draft_dispatch fuzz_ \
	-- --ignored --nocapture --test-threads=1 2>&1 | tee "$record_dir/results.log"; then
	printf 'status=passed\n' >>"$record_dir/metadata.txt"
else
	printf 'status=failed\n' >>"$record_dir/metadata.txt"
	printf 'Campaign failed. Evidence: %s\n' "$record_dir" >&2
	exit 1
fi
printf 'finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$record_dir/metadata.txt"
checksum target/debug/mailctl target/debug/mailctl-mcp >>"$record_dir/metadata.txt"
printf 'Campaign evidence: %s\n' "$record_dir"
