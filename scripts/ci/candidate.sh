#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

case "${MAILCTL_TARGET:-}" in
"")
	case "$(uname -s):$(uname -m)" in
	Darwin:arm64) target=aarch64-apple-darwin ;;
	Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
	*)
		printf 'Unsupported native candidate host.\n' >&2
		exit 1
		;;
	esac
	;;
aarch64-apple-darwin | x86_64-unknown-linux-gnu) target=$MAILCTL_TARGET ;;
*)
	printf 'Unsupported candidate target.\n' >&2
	exit 1
	;;
esac

# Keep each qualification visible as a workflow step. Evidence below uses the
# same argument arrays as execution, so changes cannot leave stale commands.
case "${1:-}" in
build)
	mkdir -p target
	dist build --artifacts=local --target "$target" \
		--output-format=json >target/dist-build.json
	exit
	;;
prepare)
	: "${MAILCTL_CANDIDATE_DIR:?}" "${MAILCTL_PACKAGED_BIN_DIR:?}" "${GITHUB_ENV:?}"
	python3 scripts/prepare-installer.py --target "$target" --output "$MAILCTL_CANDIDATE_DIR"
	printf 'MAILCTL_CANDIDATE_DIR=%s\nMAILCTL_PACKAGED_BIN_DIR=%s\n' \
		"$MAILCTL_CANDIDATE_DIR" "$MAILCTL_PACKAGED_BIN_DIR" >>"$GITHUB_ENV"
	exit
	;;
installer | state | process | native | reading | drafts | record) ;;
*)
	printf 'Usage: %s {build|prepare|installer|state|process|native|reading|drafts|record}\n' "$0" >&2
	exit 2
	;;
esac

: "${MAILCTL_CANDIDATE_DIR:?}" "${MAILCTL_PACKAGED_BIN_DIR:?}"
hash_command=(shasum -a 256)
if command -v sha256sum >/dev/null; then hash_command=(sha256sum); fi
installer_command=(python3 tests/installer.py --suite packaged
	--artifacts "$MAILCTL_CANDIDATE_DIR" --install-to "$MAILCTL_PACKAGED_BIN_DIR")
state_command=(cargo test --locked --test administration_process --test state_maintenance)
process_command=(cargo test --locked
	--test mcp_process --test message_process --test attachment_process
	--test search_process --test discovery_process
	--test read_contention_process --test draft_process)
native_command=(cargo test --locked --test native_credentials -- --ignored --test-threads=1)
if [[ $target == x86_64-unknown-linux-gnu ]]; then
	native_command=(bash scripts/ci/linux-acceptance.sh credentials)
fi
component_command=(python3 tests/installer.py --artifacts "$MAILCTL_CANDIDATE_DIR" --install-only --reuse)

select_packaged_components() {
	local suite=$1 components=$2
	packaged_command=(cargo test --locked --test "packaged_$suite")
	case "$components" in
	cli,mcp)
		label=cli-mcp
		installed=$MAILCTL_PACKAGED_BIN_DIR
		;;
	cli | mcp)
		label=$components
		installed="$MAILCTL_PACKAGED_BIN_DIR-$components"
		packaged_command+=("${components}_")
		;;
	esac
	packaged_command+=(-- --test-threads=1)
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

run_packaged_acceptance() {
	local suite=$1 noun=$2 components log
	for components in cli mcp cli,mcp; do
		select_packaged_components "$suite" "$components"
		log="$MAILCTL_CANDIDATE_DIR/installed-$suite-$label-acceptance.log"
		{
			"${component_command[@]}" --components "$components" --install-to "$installed"
			MAILCTL_PACKAGED_BIN_DIR="$installed" "${packaged_command[@]}"
		} 2>&1 | tee "$log"
		if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
			printf 'Packaged %s acceptance for %s must pass at least one test with none failed or ignored. Log: %s\n' \
				"$noun" "$components" "$log" >&2
			exit 1
		fi
	done
}

record_packaged_acceptance() {
	local suite=$1 components
	printf '%s_credential_source=disposable-command-helper\n%s_tls_source=fixture-ca-via-SSL_CERT_FILE\n' \
		"$suite" "$suite"
	for components in cli mcp cli,mcp; do
		select_packaged_components "$suite" "$components"
		record_command "${suite}_components_command_$components" \
			"${component_command[@]}" --components "$components" --install-to "$installed"
		record_command "${suite}_command_$components" env \
			"MAILCTL_PACKAGED_BIN_DIR=$installed" "${packaged_command[@]}"
	done
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
	if [[ $target == x86_64-unknown-linux-gnu ]]; then
		bash scripts/ci/linux-acceptance.sh reading
	else
		run_packaged_acceptance reading reading
	fi
	;;
drafts)
	if [[ $target == x86_64-unknown-linux-gnu ]]; then
		bash scripts/ci/linux-acceptance.sh drafts
	else
		run_packaged_acceptance drafts draft
	fi
	;;
record)
	# Verify the original artifact hashes before adding passing acceptance.
	(cd "$MAILCTL_CANDIDATE_DIR" && "${hash_command[@]}" -c SHA256SUMS)
	{
		printf 'status=passed\ntopology=cooperative-embedded\n'
		if [[ $target == x86_64-unknown-linux-gnu ]]; then
			printf 'credential_source=command,systemd,interactive-session\n'
			cat /etc/os-release
			systemctl --version
			cat "$MAILCTL_CANDIDATE_DIR/linux-source-evidence.txt"
		else
			printf 'credential_source=disposable-apple-keychain\n'
			sw_vers
		fi
		uname -sm
		printf 'packaged_bin_directory=%s\n' "$MAILCTL_PACKAGED_BIN_DIR"
		record_command installer_command "${installer_command[@]}"
		record_command state_command "${state_command[@]}"
		record_command process_command "${process_command[@]}"
		record_command native_command "${native_command[@]}"
		if [[ $target == aarch64-apple-darwin ]]; then
			record_packaged_acceptance reading
			record_packaged_acceptance drafts
		fi
		printf 'real_provider=not-qualified\nisolation=not-qualified\npublication=not-performed\n'
	} >"$MAILCTL_CANDIDATE_DIR/acceptance-evidence.txt"
	if [[ $target == x86_64-unknown-linux-gnu ]]; then
		(cd "$MAILCTL_CANDIDATE_DIR" && "${hash_command[@]}" \
			acceptance-evidence.txt linux-source-evidence.txt ./*.log >>SHA256SUMS)
	else
		(cd "$MAILCTL_CANDIDATE_DIR" && "${hash_command[@]}" acceptance-evidence.txt installer-acceptance.log \
			installed-state-acceptance.log installed-process-acceptance.log \
			installed-native-acceptance.log installed-reading-*-acceptance.log \
			installed-drafts-*-acceptance.log >>SHA256SUMS)
	fi
	;;
esac
