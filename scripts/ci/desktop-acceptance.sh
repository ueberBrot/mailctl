#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

case "${1:-}" in
prerequisites)
	sudo apt-get update -qq
	sudo apt-get install -y --no-install-recommends gnome-keyring dbus libglib2.0-bin
	exit
	;;
credentials) target=secret_service_credentials ;;
reading | drafts) target="packaged_$1" ;;
*)
	printf 'Usage: %s {prerequisites|credentials|reading|drafts}\n' "$0" >&2
	exit 2
	;;
esac

: "${MAILCTL_CANDIDATE_DIR:?}" "${MAILCTL_PACKAGED_BIN_DIR:?}"
[[ $(uname -sm) == 'Linux x86_64' && $(id -u) != 0 ]]
for tool in dbus-daemon dbus-monitor gdbus gnome-keyring-daemon python3; do
	test -x "/usr/bin/$tool"
done
compile=(cargo test --locked --workspace --no-default-features --features 'cli,mcp'
	--test "$target" --no-run --message-format=json)
binary=$("${compile[@]}" | jq -ser --arg target "$target" \
	'map(select(.reason == "compiler-artifact" and .target.name == $target and .executable != null)) |
  if length == 1 then .[0].executable else error("Missing or ambiguous native acceptance harness") end')

workspace=$(mktemp -d /tmp/mailctl-desktop.XXXXXXXX)
cleanup() { sudo rm -rf -- "$workspace"; }
trap cleanup EXIT
sudo chown root:root "$workspace"
sudo chmod 755 "$workspace"
sudo install -o root -g root -m 755 "$binary" "$workspace/$target"
sudo install -o root -g root -m 755 scripts/ci/secret-service-session.sh "$workspace/session.sh"
cmp "$binary" "$workspace/$target"

record_command() {
	printf '%s=' "$1"
	shift
	printf '%q ' "$@"
	printf '\n'
}

evidence="$MAILCTL_CANDIDATE_DIR/desktop-source-evidence.txt"
{
	printf 'suite=%s\ncredential_source=native-secret-service\nexecution_identity=65534:65534\n' "$1"
	printf 'store=disposable-gnome-keyring\nbus=private-session\n'
	printf 'topology=cooperative-embedded\nisolation=not-qualified\n'
	record_command harness_build "${compile[@]}"
	dpkg-query -W -f='${Package}=${Version}\n' gnome-keyring dbus libglib2.0-bin
	/usr/bin/gnome-keyring-daemon --version
	uname -a
} >>"$evidence"

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
	root="$workspace/session-$label"
	sudo install -d -o 65534 -g 65534 -m 700 "$root" "$root/bin" "$root/home" \
		"$root/runtime" "$root/config" "$root/data" "$root/cache"
	for executable in mailctl mailctl-mcp; do
		if test -f "$installed/$executable"; then
			sudo install -o 65534 -g 65534 -m 700 "$installed/$executable" "$root/bin/$executable"
			sudo cmp "$installed/$executable" "$root/bin/$executable"
			{
				sha256sum "$installed/$executable"
				sudo sha256sum "$root/bin/$executable"
				sudo stat -c 'installed=%n uid=%u gid=%g mode=%a' "$installed/$executable" "$root/bin/$executable"
			} >>"$evidence"
		fi
	done
	command=(sudo systemd-run --quiet --wait --pipe --collect --service-type=exec
		--property=User=65534 --property=Group=65534 --property=NoNewPrivileges=yes
		--property=ProtectHome=yes --property=RuntimeMaxSec=1200s --property=WorkingDirectory=/tmp
		"--setenv=HOME=$root/home" "--setenv=XDG_RUNTIME_DIR=$root/runtime"
		"--setenv=XDG_CONFIG_HOME=$root/config" "--setenv=XDG_DATA_HOME=$root/data"
		"--setenv=XDG_CACHE_HOME=$root/cache" "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=$root/bus"
		--setenv=PATH=/usr/bin:/bin --setenv=MAILCTL_SECRET_SERVICE_ACCEPTANCE=1
		"--setenv=MAILCTL_SECRET_SERVICE_ROOT=$root" "--setenv=MAILCTL_PACKAGED_BIN_DIR=$root/bin"
		"--setenv=MAILCTL_PACKAGED_COMPONENTS=$components" --setenv=MAILCTL_PACKAGED_CREDENTIAL_SOURCE=native
		/bin/bash "$workspace/session.sh" "$1" "$workspace/$target" "$filter")
	record_command "${target}_native_$label" "${command[@]}" >>"$evidence"
	log="$MAILCTL_CANDIDATE_DIR/installed-$1-native-$label-acceptance.log"
	"${command[@]}" 2>&1 | tee "$log"
	if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$log"; then
		printf 'Native Secret Service acceptance must run passing tests: %s\n' "$log" >&2
		exit 1
	fi
done
