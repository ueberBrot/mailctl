#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Keep each qualification visible as a workflow step. Evidence below uses the
# same argument arrays as execution, so changes cannot leave stale commands.
case "${1:-}" in
build)
	mkdir -p target
	dist build --artifacts=local --target aarch64-apple-darwin \
		--output-format=json >target/dist-build.json
	exit
	;;
prepare)
	: "${MAILCTL_CANDIDATE_DIR:?}" "${MAILCTL_PACKAGED_BIN_DIR:?}" "${GITHUB_ENV:?}"
	python3 scripts/prepare-installer.py --output "$MAILCTL_CANDIDATE_DIR"
	printf 'MAILCTL_CANDIDATE_DIR=%s\nMAILCTL_PACKAGED_BIN_DIR=%s\n' \
		"$MAILCTL_CANDIDATE_DIR" "$MAILCTL_PACKAGED_BIN_DIR" >>"$GITHUB_ENV"
	exit
	;;
installer | state | process | native | reading | drafts | record | components) ;;
*)
	printf 'Usage: %s {build|prepare|installer|state|process|native|reading|drafts|record|components SELECTION DIRECTORY}\n' "$0" >&2
	exit 2
	;;
esac

: "${MAILCTL_CANDIDATE_DIR:?}" "${MAILCTL_PACKAGED_BIN_DIR:?}"
installer_command=(python3 tests/installer.py --suite packaged
	--artifacts "$MAILCTL_CANDIDATE_DIR" --install-to "$MAILCTL_PACKAGED_BIN_DIR")
state_command=(cargo test --locked --test administration_process --test state_maintenance)
process_command=(cargo test --locked
	--test mcp_process --test message_process --test attachment_process
	--test search_process --test discovery_process
	--test read_contention_process --test draft_process)
native_command=(cargo test --locked --test native_credentials -- --ignored --test-threads=1)
component_command=(bash scripts/ci/candidate.sh components)
component_installer_command=(python3 tests/installer.py --artifacts "$MAILCTL_CANDIDATE_DIR" --install-only)

select_reading_components() {
	components=$1
	reading_command=(cargo test --locked --test packaged_reading)
	case "$components" in
	cli,mcp)
		label=cli-mcp
		installed=$MAILCTL_PACKAGED_BIN_DIR
		;;
	cli | mcp)
		label=$components
		installed="$MAILCTL_PACKAGED_BIN_DIR-$components"
		reading_command+=("${components}_")
		;;
	esac
	reading_command+=(-- --test-threads=1)
}

select_draft_components() {
	components=$1
	drafts_command=(cargo test --locked --test packaged_drafts)
	case "$components" in
	cli,mcp)
		label=cli-mcp
		installed=$MAILCTL_PACKAGED_BIN_DIR
		;;
	cli | mcp)
		label=$components
		installed="$MAILCTL_PACKAGED_BIN_DIR-$components"
		drafts_command+=("${components}_")
		;;
	esac
	drafts_command+=(-- --test-threads=1)
}

record_command() {
	printf '%s=' "$1"
	shift
	printf '%q ' "$@"
	printf '\n'
}

run_acceptance() {
	local log=$1
	shift
	"$@" 2>&1 | tee "$MAILCTL_CANDIDATE_DIR/$log"
}

case "$1" in
components)
	[ "$#" -eq 3 ] || exit 2
	case "$2" in cli | mcp | cli,mcp) ;; *) exit 2 ;; esac
	# Reading and draft fixtures own separate application state. Share only the
	# installer-qualified bytes, and reject stale or changed component selections.
	if [ ! -e "$3" ] && [ ! -L "$3" ]; then
		"${component_installer_command[@]}" --components "$2" --install-to "$3"
	fi
	python3 - "$MAILCTL_CANDIDATE_DIR" "$2" "$3" <<'PY'
import hashlib
import os
from pathlib import Path
import sys

artifacts, selection, directory = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def fields(path):
    require(path.is_file() and not path.is_symlink(), f"Expected a regular manifest: {path}")
    entries = [line.split("=", 1) for line in path.read_text().splitlines()]
    require(all(len(entry) == 2 for entry in entries), f"Malformed manifest: {path}")
    result = dict(entries)
    require(len(result) == len(entries), f"Duplicate manifest fields: {path}")
    return result

manifests = list(artifacts.glob("manifest-v*-aarch64-apple-darwin.txt"))
require(len(manifests) == 1, "Expected one candidate manifest")
manifest = fields(manifests[0])
require(directory.is_dir() and not directory.is_symlink(), f"Expected an installed directory: {directory}")
lock = directory / ".mailctl-installer.lock"
require(not lock.exists() and not lock.is_symlink(), "Installer update is active or requires recovery")
receipt = fields(directory / ".mailctl-components")
expected_fields = {"format", "target", "compatibility"}
expected_entries = {".mailctl-components"}
for field in expected_fields:
    require(receipt.get(field) == manifest[field], f"Installed {field} differs from the candidate")
for component, name in (("cli", "mailctl"), ("mcp", "mailctl-mcp")):
    binary = directory / name
    if component not in selection.split(","):
        require(not binary.exists() and not binary.is_symlink(), f"Unselected component exists: {binary}")
        continue
    expected_entries.add(name)
    require(binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK),
            f"Expected an executable candidate component: {binary}")
    require(binary.stat().st_size == int(manifest[f"{component}_size"]) and
            hashlib.sha256(binary.read_bytes()).hexdigest() == manifest[f"{component}_sha256"],
            f"Installed component differs from the candidate: {binary}")
    for field in ("version", "commit", "sha256"):
        key = f"{component}_{field}"
        expected_fields.add(key)
        expected = manifest[key] if field == "sha256" else manifest[field]
        require(receipt.get(key) == expected, f"Installed receipt differs from the candidate: {key}")
    expected_fields.add(f"{component}_origin")
require(set(receipt) == expected_fields, "Installed receipt has a different component selection")
require({entry.name for entry in directory.iterdir()} == expected_entries,
        "Installed directory has unexpected entries")
print(f"Verified installed candidate components {selection} in {directory}")
PY
	;;
installer)
	run_acceptance installer-acceptance.log "${installer_command[@]}"
	;;
state)
	run_acceptance installed-state-acceptance.log "${state_command[@]}"
	;;
process)
	run_acceptance installed-process-acceptance.log "${process_command[@]}"
	;;
native)
	run_acceptance installed-native-acceptance.log "${native_command[@]}"
	;;
reading)
	for components in cli mcp cli,mcp; do
		select_reading_components "$components"
		log="$MAILCTL_CANDIDATE_DIR/installed-reading-$label-acceptance.log"
		{
			"${component_command[@]}" "$components" "$installed"
			MAILCTL_PACKAGED_BIN_DIR="$installed" "${reading_command[@]}"
		} 2>&1 | tee "$log"
		if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
			printf 'Packaged reading acceptance for %s must pass at least one test with none failed or ignored. Log: %s\n' \
				"$components" "$log" >&2
			exit 1
		fi
	done
	;;
drafts)
	for components in cli mcp cli,mcp; do
		select_draft_components "$components"
		log="$MAILCTL_CANDIDATE_DIR/installed-drafts-$label-acceptance.log"
		{
			"${component_command[@]}" "$components" "$installed"
			MAILCTL_PACKAGED_BIN_DIR="$installed" "${drafts_command[@]}"
		} 2>&1 | tee "$log"
		if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
			printf 'Packaged draft acceptance for %s must pass at least one test with none failed or ignored. Log: %s\n' \
				"$components" "$log" >&2
			exit 1
		fi
	done
	;;
record)
	# Verify the original artifact hashes before adding passing acceptance.
	(cd "$MAILCTL_CANDIDATE_DIR" && shasum -a 256 -c SHA256SUMS)
	{
		printf 'status=passed\ntopology=cooperative-embedded\ncredential_source=disposable-apple-keychain\n'
		sw_vers
		uname -sm
		printf 'packaged_bin_directory=%s\n' "$MAILCTL_PACKAGED_BIN_DIR"
		record_command installer_command "${installer_command[@]}"
		record_command state_command "${state_command[@]}"
		record_command process_command "${process_command[@]}"
		record_command native_command "${native_command[@]}"
		printf 'reading_credential_source=disposable-command-helper\nreading_tls_source=fixture-ca-via-SSL_CERT_FILE\n'
		for components in cli mcp cli,mcp; do
			select_reading_components "$components"
			record_command "reading_components_command_$components" \
				"${component_command[@]}" "$components" "$installed"
			record_command "reading_command_$components" env \
				"MAILCTL_PACKAGED_BIN_DIR=$installed" "${reading_command[@]}"
		done
		printf 'drafts_credential_source=disposable-command-helper\ndrafts_tls_source=fixture-ca-via-SSL_CERT_FILE\n'
		for components in cli mcp cli,mcp; do
			select_draft_components "$components"
			record_command "drafts_components_command_$components" \
				"${component_command[@]}" "$components" "$installed"
			record_command "drafts_command_$components" env \
				"MAILCTL_PACKAGED_BIN_DIR=$installed" "${drafts_command[@]}"
		done
		printf 'real_provider=not-qualified\nisolation=not-qualified\npublication=not-performed\n'
	} >"$MAILCTL_CANDIDATE_DIR/acceptance-evidence.txt"
	(cd "$MAILCTL_CANDIDATE_DIR" && shasum -a 256 acceptance-evidence.txt installer-acceptance.log \
		installed-state-acceptance.log installed-process-acceptance.log \
		installed-native-acceptance.log installed-reading-*-acceptance.log \
		installed-drafts-*-acceptance.log >>SHA256SUMS)
	;;
esac
