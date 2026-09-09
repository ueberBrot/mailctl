#!/bin/bash
# Provision the optional macOS isolated gateway. Run this script manually as root.
set -euo pipefail

readonly INSTALL_ROOT='/Library/PrivilegedHelperTools/org.ueberbrot.mailctl'
readonly HELPER_DIRECTORY='/Library/PrivilegedHelperTools'
readonly PUBLIC_ROOT='/Library/Application Support/mailctl-isolated'
readonly ROUTE_PATH="$PUBLIC_ROOT/route.json"
readonly RUN_DIRECTORY="$PUBLIC_ROOT/run"
readonly SOCKET_PATH="$RUN_DIRECTORY/socket"
readonly SERVICE_HOME='/var/db/mailctl-isolated'
readonly CONFIG_PATH="$SERVICE_HOME/config.toml"
readonly STATE_DIRECTORY="$SERVICE_HOME/state"
readonly PLIST_PATH='/Library/LaunchDaemons/org.ueberbrot.mailctl-isolated.plist'
readonly LABEL='org.ueberbrot.mailctl-isolated'

usage() {
  cat <<'USAGE'
Usage: sudo install.sh --service-user USER --caller-user USER --artifact-dir ABSOLUTE_PATH

Installs the optional local isolated gateway. Both users must already exist, be
different, be unprivileged, and the service user must have a non-login shell.
The artifact directory must contain an executable mailctl-isolated binary. It
may also contain mailctl and mailctl-mcp for service-user administration.

Ordinary CLI and MCP installations keep their usual configuration and do not
use this gateway.

This installer refuses an existing deployment. Upgrade and removal are manual.
USAGE
}

die() {
  printf '%s\n' "install.sh: $*" >&2
  exit 1
}

require_root_macos() {
  [ "$(/usr/bin/id -u)" -eq 0 ] || die 'run as root'
  [ "$(/usr/bin/uname -s)" = 'Darwin' ] || die 'requires macOS'
}

validate_user_name() {
  case "$1" in
    '' | *[!A-Za-z0-9_-]* | [0-9-]* | -*) die "invalid user name: $1" ;;
  esac
}

user_id() {
  /usr/bin/id -u "$1" 2>/dev/null || die "user does not exist: $1"
}

user_group_id() {
  /usr/bin/id -g "$1" 2>/dev/null || die "cannot read primary group for: $1"
}

require_non_admin() {
  local status
  if /usr/sbin/dseditgroup -o checkmember -m "$1" admin >/dev/null 2>&1; then
    die "user must not be an administrator: $1"
  else
    status=$?
  fi
  [ "$status" -eq 67 ] || die "cannot determine administrator membership: $1"
}

require_service_shell() {
  local shell
  shell=$(/usr/bin/dscl . -read "/Users/$1" UserShell 2>/dev/null | /usr/bin/awk '$1 == "UserShell:" { print $2 }')
  case "$shell" in
    /usr/bin/false | /sbin/nologin) ;;
    *) die "service user must have /usr/bin/false or /sbin/nologin: $1" ;;
  esac
}

require_service_home() {
  local home
  home=$(/usr/bin/dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '$1 == "NFSHomeDirectory:" { print $2 }')
  [ "$home" = "$SERVICE_HOME" ] || die "service user home must be $SERVICE_HOME: $1"
}

canonical_directory() {
  (cd -P -- "$1" && /bin/pwd -P)
}

require_absolute_directory() {
  case "$1" in
    /*) ;;
    *) die "artifact directory must be absolute: $1" ;;
  esac
  [ -d "$1" ] || die "artifact directory does not exist: $1"
}

require_protected_ancestry() {
  local candidate owner mode permissions
  candidate=$1
  while [ ! -e "$candidate" ]; do
    candidate=$(/usr/bin/dirname "$candidate")
  done
  candidate=$(canonical_directory "$candidate") || die "cannot resolve protected ancestry: $1"

  while :; do
    owner=$(/usr/bin/stat -f '%u' "$candidate") || die "cannot inspect: $candidate"
    mode=$(/usr/bin/stat -f '%Lp' "$candidate") || die "cannot inspect: $candidate"
    permissions=$((8#$mode))
    [ "$owner" -eq 0 ] || die "protected ancestry is not root-owned: $candidate"
    [ $((permissions & 0022)) -eq 0 ] || die "protected ancestry is writable: $candidate"
    [ "$candidate" = '/' ] && return
    candidate=$(/usr/bin/dirname "$candidate")
  done
}

require_absent() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    die "refusing existing deployment path: $1"
  fi
}

make_directory() {
  /bin/mkdir "$1"
  /bin/chmod -N "$1"
  /usr/sbin/chown "$2:$3" "$1"
  /bin/chmod "$4" "$1"
}

install_artifact() {
  local name source
  name=$1
  source="$ARTIFACT_DIRECTORY/$name"
  [ -e "$source" ] || return
  [ -f "$source" ] && [ ! -L "$source" ] && [ -x "$source" ] || die "artifact must be an executable regular file: $source"
  /usr/bin/install -o root -g wheel -m 0755 "$source" "$INSTALL_ROOT/$name"
  /bin/chmod -N "$INSTALL_ROOT/$name"
}

SERVICE_USER=''
CALLER_USER=''
ARTIFACT_DIRECTORY=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --service-user)
      [ "$#" -ge 2 ] || die 'missing value for --service-user'
      SERVICE_USER=$2
      shift 2
      ;;
    --caller-user)
      [ "$#" -ge 2 ] || die 'missing value for --caller-user'
      CALLER_USER=$2
      shift 2
      ;;
    --artifact-dir)
      [ "$#" -ge 2 ] || die 'missing value for --artifact-dir'
      ARTIFACT_DIRECTORY=$2
      shift 2
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_root_macos
[ -n "$SERVICE_USER" ] && [ -n "$CALLER_USER" ] && [ -n "$ARTIFACT_DIRECTORY" ] || {
  usage >&2
  exit 1
}
validate_user_name "$SERVICE_USER"
validate_user_name "$CALLER_USER"
require_absolute_directory "$ARTIFACT_DIRECTORY"
ARTIFACT_DIRECTORY=$(canonical_directory "$ARTIFACT_DIRECTORY") || die 'cannot resolve artifact directory'

SERVICE_UID=$(user_id "$SERVICE_USER")
CALLER_UID=$(user_id "$CALLER_USER")
SERVICE_GROUP=$(user_group_id "$SERVICE_USER")
[ "$SERVICE_UID" -ne 0 ] || die 'service user must not be root'
[ "$CALLER_UID" -ne 0 ] || die 'caller user must not be root'
[ "$SERVICE_UID" -ne "$CALLER_UID" ] || die 'service user and caller user must differ'
require_non_admin "$SERVICE_USER"
require_non_admin "$CALLER_USER"
require_service_shell "$SERVICE_USER"
require_service_home "$SERVICE_USER"

[ -f "$ARTIFACT_DIRECTORY/mailctl-isolated" ] && [ ! -L "$ARTIFACT_DIRECTORY/mailctl-isolated" ] && [ -x "$ARTIFACT_DIRECTORY/mailctl-isolated" ] || die 'artifact directory must contain executable mailctl-isolated'

VAR_CANONICAL=$(canonical_directory /var) || die 'cannot resolve /var'
[ "$VAR_CANONICAL" = '/private/var' ] || die "/var must resolve to /private/var, found: $VAR_CANONICAL"
require_protected_ancestry "$INSTALL_ROOT"
require_protected_ancestry "$HELPER_DIRECTORY"
require_protected_ancestry "$PUBLIC_ROOT"
require_protected_ancestry "$SERVICE_HOME"
require_protected_ancestry "$PLIST_PATH"
require_absent "$INSTALL_ROOT"
require_absent "$PUBLIC_ROOT"
require_absent "$SERVICE_HOME"
require_absent "$PLIST_PATH"

SCRIPT_DIRECTORY=$(canonical_directory "$(/usr/bin/dirname "$0")") || die 'cannot resolve installer directory'
PLIST_TEMPLATE="$SCRIPT_DIRECTORY/$LABEL.plist.in"
[ -f "$PLIST_TEMPLATE" ] && [ ! -L "$PLIST_TEMPLATE" ] || die "missing plist template: $PLIST_TEMPLATE"

ROUTE_TEMP=$(/usr/bin/mktemp -t mailctl-isolated.route.XXXXXX) || die 'cannot create route temporary file'
PLIST_TEMP=$(/usr/bin/mktemp -t mailctl-isolated.plist.XXXXXX) || die 'cannot create plist temporary file'
trap '/bin/rm -f "$ROUTE_TEMP" "$PLIST_TEMP"' EXIT HUP INT TERM
/bin/chmod 0600 "$ROUTE_TEMP" "$PLIST_TEMP"

if [ ! -e "$HELPER_DIRECTORY" ]; then
  make_directory "$HELPER_DIRECTORY" root wheel 0755
fi
make_directory "$INSTALL_ROOT" root wheel 0755
make_directory "$PUBLIC_ROOT" root wheel 0755
make_directory "$RUN_DIRECTORY" "$SERVICE_USER" "$SERVICE_GROUP" 0711
make_directory "$SERVICE_HOME" "$SERVICE_USER" "$SERVICE_GROUP" 0700
make_directory "$SERVICE_HOME/Library" "$SERVICE_USER" "$SERVICE_GROUP" 0700
make_directory "$SERVICE_HOME/Library/Preferences" "$SERVICE_USER" "$SERVICE_GROUP" 0700
make_directory "$STATE_DIRECTORY" "$SERVICE_USER" "$SERVICE_GROUP" 0700

install_artifact mailctl-isolated
install_artifact mailctl
install_artifact mailctl-mcp

/usr/bin/printf '{\n  "version": 1,\n  "service_uid": %s,\n  "socket": "%s",\n  "callers": [\n    {"uid": %s, "grant": "isolated"}\n  ]\n}\n' \
  "$SERVICE_UID" "$SOCKET_PATH" "$CALLER_UID" >"$ROUTE_TEMP"
/usr/bin/install -o root -g wheel -m 0644 "$ROUTE_TEMP" "$ROUTE_PATH"
/bin/chmod -N "$ROUTE_PATH"

/usr/bin/sed "s|__SERVICE_USER__|$SERVICE_USER|g" "$PLIST_TEMPLATE" >"$PLIST_TEMP"
/usr/bin/plutil -lint "$PLIST_TEMP" >/dev/null || die 'generated launchd plist is invalid'
/usr/bin/install -o root -g wheel -m 0644 "$PLIST_TEMP" "$PLIST_PATH"
/bin/chmod -N "$PLIST_PATH"

if [ -x "$INSTALL_ROOT/mailctl" ]; then
  SETUP_EXECUTABLE="$INSTALL_ROOT/mailctl"
elif [ -x "$INSTALL_ROOT/mailctl-mcp" ]; then
  SETUP_EXECUTABLE="$INSTALL_ROOT/mailctl-mcp"
else
  SETUP_EXECUTABLE='/absolute/path/to/mailctl'
fi

printf '%s\n' "Installed $LABEL without starting it."
printf '%s\n' "Create and provision $CONFIG_PATH as $SERVICE_USER before starting the gateway:"
printf '  sudo -u %s -H -- %s --config %s setup --alias ACCOUNT --server HOST --username USERNAME\n' \
  "$SERVICE_USER" "$SETUP_EXECUTABLE" "$CONFIG_PATH"
printf '%s\n' "Add a named isolated grant to $CONFIG_PATH with only the account keys and mailboxes the caller may use."
printf '  sudo -u %s -H -- %s --config %s --account ACCOUNT credential set\n' \
  "$SERVICE_USER" "$SETUP_EXECUTABLE" "$CONFIG_PATH"
printf '%s\n' "After provisioning, bootstrap it with: sudo /bin/launchctl bootstrap system $PLIST_PATH"
printf '%s\n' "Restart it with: sudo /bin/launchctl kickstart -k system/$LABEL"
printf '%s\n' "Stop it with: sudo /bin/launchctl bootout system/$LABEL"
