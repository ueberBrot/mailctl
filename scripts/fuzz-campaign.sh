#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export MAILCTL_FUZZ_CASES="${MAILCTL_FUZZ_CASES:-64}"
export MAILCTL_FUZZ_SEED="${MAILCTL_FUZZ_SEED:-35001}"

record_dir="target/fuzz-campaigns/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$record_dir"

if command -v sha256sum >/dev/null 2>&1; then
	checksum_command=(sha256sum)
else
	checksum_command=(shasum -a 256)
fi
checksum() { "${checksum_command[@]}" "$@"; }

campaign_command=(cargo test --locked --lib
	--test fuzz_mime --test fuzz_tokens --test fuzz_envelopes
	--test fuzz_imap --test draft_dispatch fuzz_
	-- --ignored --nocapture --test-threads=1)

{
	printf 'commit=%s\n' "$(git rev-parse HEAD)"
	printf 'cases=%s seed=%s input_max=16384\n' "$MAILCTL_FUZZ_CASES" "$MAILCTL_FUZZ_SEED"
	printf 'started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	uname -sm
	rustc --version
	git status --short
	printf 'command='
	printf '%q ' "${campaign_command[@]}"
	printf '\n'
	while IFS= read -r corpus_file; do
		checksum "$corpus_file"
	done < <(find tests/fuzz_corpus -type f | sort)
} >"$record_dir/metadata.txt"
git diff HEAD --binary >"$record_dir/working-tree.patch"
checksum "$record_dir/working-tree.patch" >>"$record_dir/metadata.txt"

if ! "${campaign_command[@]}" 2>&1 | tee "$record_dir/results.log"; then
	printf 'status=failed\n' >>"$record_dir/metadata.txt"
	printf 'Campaign failed. Evidence: %s\n' "$record_dir" >&2
	exit 1
fi
for surface in mime tokens application-envelopes mcp-envelopes mcp-decoding imap uncertain_draft_retries; do
	records=$(awk -v surface="$surface" \
		'index($0, "fuzz surface=" surface " ") && index($0, "status=passed") { count++ } END { print count+0 }' \
		"$record_dir/results.log")
	if [ "$records" -ne 1 ]; then
		printf 'status=failed missing_or_duplicate_surface=%s\n' "$surface" >>"$record_dir/metadata.txt"
		printf 'Expected one passing record for %s. Evidence: %s\n' "$surface" "$record_dir" >&2
		exit 1
	fi
done
{
	checksum target/debug/mailctl target/debug/mailctl-mcp
	printf 'status=passed\n'
	printf 'finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >>"$record_dir/metadata.txt"
printf 'Campaign evidence: %s\n' "$record_dir"
