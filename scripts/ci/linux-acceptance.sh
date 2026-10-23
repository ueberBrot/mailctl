#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

case "${1:-}" in
credentials)
	test_targets=(linux_credentials systemd_native systemd_credentials)
	;;
reading | drafts)
	test_targets=("packaged_$1")
	;;
*)
	printf 'Usage: %s {credentials|reading|drafts}\n' "$0" >&2
	exit 2
	;;
esac

: "${MAILCTL_CANDIDATE_DIR:?}" "${MAILCTL_PACKAGED_BIN_DIR:?}"
test "$(uname -sm)" = 'Linux x86_64'
test "$(cat /proc/1/comm)" = systemd
test "$(id -u)" -ne 0
test -x /usr/bin/python3

if [[ -n ${MAILCTL_HARNESS_DIR:-} ]]; then
	compile=(python3 scripts/ci/candidate-harness.py artifacts)
	for target in "${test_targets[@]}"; do compile+=(--test "$target"); done
	artifacts=$("${compile[@]}")
else
	compile=(cargo test --locked --workspace --no-default-features --features 'cli,mcp')
	for target in "${test_targets[@]}"; do compile+=(--test "$target"); done
	compile+=(--no-run --message-format=json)
	artifacts=$("${compile[@]}" | jq -s --arg root "$PWD/tests/" \
		'map(select(.reason == "compiler-artifact" and .executable != null and
      .target.src_path == ($root + .target.name + ".rs"))) |
      map({key: .target.name, value: .executable}) | from_entries')
fi

workspace=$(mktemp -d /tmp/mailctl-linux-acceptance.XXXXXXXX)
cleanup() { sudo rm -rf -- "$workspace"; }
trap cleanup EXIT
sudo chown root:root "$workspace"
sudo chmod 755 "$workspace"
sudo install -d -o 65534 -g 65534 -m 700 "$workspace/home"
sudo install -d -o root -g root -m 700 "$workspace/provision"
printf 'disposable-password' | sudo tee "$workspace/provision/password" >/dev/null
sudo chmod 600 "$workspace/provision/password"
for target in "${test_targets[@]}"; do
	binary=$(jq -er --arg target "$target" '.[$target]' <<<"$artifacts")
	sudo install -o root -g root -m 755 "$binary" "$workspace/$target"
	cmp "$binary" "$workspace/$target"
done

record_command() {
	printf '%s=' "$1"
	shift
	printf '%q ' "$@"
	printf '\n'
}

evidence="$MAILCTL_CANDIDATE_DIR/linux-source-evidence.txt"
{
	printf 'suite=%s\n' "$1"
	record_command harness_build "${compile[@]}"
	printf 'execution_identity=65534:65534\nprovisioning_identity=root\n'
	printf 'credential_sources=explicit-command,systemd-LoadCredential\n'
	printf 'desktop_session=absent\nhome=disposable-private-directory\n'
	uname -a
	cat /etc/os-release
	systemctl --version
} >>"$evidence"

unit=(sudo systemd-run --quiet --wait --pipe --collect --service-type=exec
	--property=User=65534 --property=Group=65534
	--property=NoNewPrivileges=yes --property=ProtectHome=yes
	--property=RuntimeMaxSec=1200s --property=WorkingDirectory=/tmp
	"--setenv=HOME=$workspace/home" --setenv=PATH=/usr/bin:/bin)

run_suite() {
	local credential_source=$1 label=$2 binary=$3 filter=$4 log=$5
	local -a command=("${unit[@]}" "--setenv=MAILCTL_PACKAGED_BIN_DIR=$workspace/$label/bin"
		--setenv=MAILCTL_LINUX_ACCEPTANCE=1
		"--setenv=MAILCTL_PACKAGED_CREDENTIAL_SOURCE=$credential_source")
	if test "$credential_source" = systemd; then
		command+=("--property=LoadCredential=password:$workspace/provision/password")
	fi
	command+=("$workspace/$binary")
	if test -n "$filter"; then command+=("$filter"); fi
	command+=(--nocapture --test-threads=1)
	record_command "${binary}_${credential_source}_${label}" "${command[@]}" >>"$evidence"
	"${command[@]}" 2>&1 | tee "$log"
	if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
		printf 'Linux acceptance must run passing tests with none failed or ignored: %s\n' "$log" >&2
		exit 1
	fi
}

for components in cli mcp cli,mcp; do
	case "$components" in
	cli,mcp)
		label=cli-mcp
		installed=$MAILCTL_PACKAGED_BIN_DIR
		filter=''
		;;
	*)
		label=$components
		installed="$MAILCTL_PACKAGED_BIN_DIR-$components"
		filter="${components}_"
		;;
	esac
	python3 tests/installer.py --artifacts "$MAILCTL_CANDIDATE_DIR" \
		--install-only --reuse --components "$components" --install-to "$installed"
	case "$components" in
	cli) test -f "$installed/mailctl" && test ! -e "$installed/mailctl-mcp" ;;
	mcp) test -f "$installed/mailctl-mcp" && test ! -e "$installed/mailctl" ;;
	cli,mcp) test -f "$installed/mailctl" && test -f "$installed/mailctl-mcp" ;;
	esac
	sudo install -d -o root -g root -m 755 "$workspace/$label" "$workspace/$label/bin"
	for binary in mailctl mailctl-mcp; do
		if test -f "$installed/$binary"; then
			sudo install -o 65534 -g 65534 -m 700 "$installed/$binary" "$workspace/$label/bin/$binary"
			sudo cmp "$installed/$binary" "$workspace/$label/bin/$binary"
			{
				sha256sum "$installed/$binary"
				sudo sha256sum "$workspace/$label/bin/$binary"
				stat -c 'installed=%n uid=%u gid=%g mode=%a' "$installed/$binary" "$workspace/$label/bin/$binary"
			} >>"$evidence"
		fi
	done
	for credential_source in command systemd; do
		if test "$1" = credentials; then
			log="$MAILCTL_CANDIDATE_DIR/installed-linux-credentials-$credential_source-$label-acceptance.log"
			run_suite "$credential_source" "$label" linux_credentials "$filter" "$log"
		else
			log="$MAILCTL_CANDIDATE_DIR/installed-$1-$credential_source-$label-acceptance.log"
			run_suite "$credential_source" "$label" "packaged_$1" "$filter" "$log"
		fi
	done
done

if test "$1" = credentials; then
	"${unit[@]}" /usr/bin/id 2>&1 | tee "$MAILCTL_CANDIDATE_DIR/installed-linux-credentials-identity.log"
	for target in systemd_credentials systemd_native; do
		command=(sudo env MAILCTL_DISPOSABLE_SYSTEMD=1
			"MAILCTL_PACKAGED_BIN_DIR=$workspace/cli-mcp/bin" "$workspace/$target")
		if test "$target" = systemd_credentials; then
			command+=(linux::systemd_source_accepts_only_the_service_user_acl --exact)
		fi
		command+=(--ignored --nocapture --test-threads=1)
		record_command "$target" "${command[@]}" >>"$evidence"
		log="$MAILCTL_CANDIDATE_DIR/installed-linux-credentials-$target-acceptance.log"
		"${command[@]}" 2>&1 | tee "$log"
		if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
			printf 'Linux native credential acceptance did not pass: %s\n' "$log" >&2
			exit 1
		fi
	done
fi
