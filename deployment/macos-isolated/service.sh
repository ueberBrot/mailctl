#!/bin/bash
# Start, restart, or stop the provisioned isolated gateway as root.
set -euo pipefail

readonly LABEL='org.ueberbrot.mailctl-isolated'
readonly PLIST_PATH='/Library/LaunchDaemons/org.ueberbrot.mailctl-isolated.plist'

die() {
  printf '%s\n' "service.sh: $*" >&2
  exit 1
}

[ "$(/usr/bin/id -u)" -eq 0 ] || die 'run as root'
[ "$(/usr/bin/uname -s)" = 'Darwin' ] || die 'requires macOS'
[ -f "$PLIST_PATH" ] || die "missing installed plist: $PLIST_PATH"
[ "$#" -eq 1 ] || die 'usage: sudo service.sh start|restart|stop'

loaded() {
  /bin/launchctl print "system/$LABEL" >/dev/null 2>&1
}

case "$1" in
  start | restart)
    if loaded; then
      /bin/launchctl kickstart -k "system/$LABEL"
    else
      /bin/launchctl bootstrap system "$PLIST_PATH"
    fi
    ;;
  stop)
    loaded || die 'gateway is not loaded'
    /bin/launchctl bootout "system/$LABEL"
    ;;
  *) die 'usage: sudo service.sh start|restart|stop' ;;
esac
