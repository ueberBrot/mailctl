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
installer | state | process | native | reading | record) ;;
*)
	printf 'Usage: %s {build|prepare|installer|state|process|native|reading|record}\n' "$0" >&2
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
reading_installer_command=(python3 tests/installer.py --artifacts "$MAILCTL_CANDIDATE_DIR" --install-only)

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
			if [ "$components" != cli,mcp ]; then
				"${reading_installer_command[@]}" --components "$components" --install-to "$installed"
			fi
			MAILCTL_PACKAGED_BIN_DIR="$installed" "${reading_command[@]}"
		} 2>&1 | tee "$log"
		if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
			printf 'Packaged reading acceptance for %s must pass at least one test with none failed or ignored. Log: %s\n' \
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
			if [ "$components" != cli,mcp ]; then
				record_command "reading_installer_command_$components" \
					"${reading_installer_command[@]}" --components "$components" --install-to "$installed"
			fi
			record_command "reading_command_$components" env \
				"MAILCTL_PACKAGED_BIN_DIR=$installed" "${reading_command[@]}"
		done
		printf 'real_provider=not-qualified\nisolation=not-qualified\npublication=not-performed\n'
	} >"$MAILCTL_CANDIDATE_DIR/acceptance-evidence.txt"
	(cd "$MAILCTL_CANDIDATE_DIR" && shasum -a 256 acceptance-evidence.txt installer-acceptance.log \
		installed-state-acceptance.log installed-process-acceptance.log \
		installed-native-acceptance.log installed-reading-*-acceptance.log >>SHA256SUMS)
	;;
esac
