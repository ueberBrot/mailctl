#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${MAILCTL_SECRET_SERVICE_ACCEPTANCE:?}" "${MAILCTL_SECRET_SERVICE_ROOT:?}"
: "${HOME:?}" "${XDG_RUNTIME_DIR:?}" "${DBUS_SESSION_BUS_ADDRESS:?}"
[[ $MAILCTL_SECRET_SERVICE_ACCEPTANCE == 1 ]]
[[ $(id -u) == 65534 && $(id -g) == 65534 ]]
[[ $MAILCTL_SECRET_SERVICE_ROOT == /tmp/mailctl-desktop.*/session-* ]]
[[ $HOME == "$MAILCTL_SECRET_SERVICE_ROOT/home" ]]
[[ $XDG_RUNTIME_DIR == "$MAILCTL_SECRET_SERVICE_ROOT/runtime" ]]
[[ $DBUS_SESSION_BUS_ADDRESS == "unix:path=$MAILCTL_SECRET_SERVICE_ROOT/bus" ]]

mode=${1:?}
harness=${2:?}
filter=${3:-}
control="$MAILCTL_SECRET_SERVICE_ROOT/control"
mkdir -m 700 "$control"

bus_pid='' keyring_pid=''
stop_keyring() {
	if [[ -n $keyring_pid ]]; then
		kill "$keyring_pid" 2>/dev/null || true
		wait "$keyring_pid" 2>/dev/null || true
		keyring_pid=''
	fi
}
cleanup() {
	stop_keyring
	if [[ -n $bus_pid ]]; then
		kill "$bus_pid" 2>/dev/null || true
		wait "$bus_pid" 2>/dev/null || true
	fi
}
trap cleanup EXIT

/usr/bin/dbus-daemon --session --nofork --nopidfile \
	--address="$DBUS_SESSION_BUS_ADDRESS" >"$XDG_RUNTIME_DIR/bus.log" 2>&1 &
bus_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
	if timeout 2 /usr/bin/gdbus call --session --dest org.freedesktop.DBus \
		--object-path /org/freedesktop/DBus \
		--method org.freedesktop.DBus.ListNames >/dev/null 2>&1; then break; fi
	kill -0 "$bus_pid"
	sleep 0.1
done
timeout 2 /usr/bin/gdbus call --session --dest org.freedesktop.DBus \
	--object-path /org/freedesktop/DBus \
	--method org.freedesktop.DBus.ListNames >/dev/null

start_keyring() {
	printf '%s' 'mailctl-disposable-keyring-password' |
		/usr/bin/gnome-keyring-daemon --foreground --unlock --components=secrets \
			--control-directory "$control" >"$XDG_RUNTIME_DIR/keyring.log" 2>&1 &
	keyring_pid=$!
	local names
	for ((attempt = 0; attempt < 100; attempt++)); do
		names=$(timeout 2 /usr/bin/gdbus call --session --dest org.freedesktop.DBus \
			--object-path /org/freedesktop/DBus \
			--method org.freedesktop.DBus.ListNames)
		if [[ $names == *"'org.freedesktop.secrets'"* ]]; then return; fi
		kill -0 "$keyring_pid"
		sleep 0.1
	done
	printf 'Private Secret Service did not become ready.\n' >&2
	return 1
}

run_exact_test() {
	local name=$1 listing
	listing=$("$harness" "$name" --exact --ignored --list)
	if ! grep -Fxq "$name: test" <<<"$listing"; then
		printf 'Required native acceptance test is missing: %s\n' "$name" >&2
		return 1
	fi
	"$harness" "$name" --exact --ignored --nocapture --test-threads=1
}

start_keyring
case "$mode" in
credentials)
	run_exact_test native_secret_service_credentials_cross_components_rotate_and_clean_up
	stop_keyring
	start_keyring
	run_exact_test native_secret_service_recovers_after_service_restart
	stop_keyring
	run_exact_test native_secret_service_rejects_malformed_secret_response
	;;
reading | drafts)
	arguments=(--nocapture --test-threads=1)
	if [[ -n $filter ]]; then arguments=("$filter" "${arguments[@]}"); fi
	"$harness" "${arguments[@]}"
	;;
*)
	printf 'Unknown private Secret Service test suite.\n' >&2
	exit 2
	;;
esac
