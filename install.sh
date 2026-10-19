#!/bin/sh
# Standalone installation owns only product binaries and .mailctl-components.
set -eu
umask 077

fail() {
	printf 'mailctl installer: %s\n' "$*" >&2
	exit 1
}
usage() {
	cat <<'EOF'
Usage: sh install.sh [options]
       sh install.sh --uninstall [options]
       sh install.sh --recover [options]

  --version VERSION       Select a release (default: latest stable).
  --components SELECTION  cli, mcp, or cli,mcp (default: installed selection,
                          or cli,mcp for a new installation).
  --install-dir DIRECTORY Override CARGO_HOME/bin or ~/.cargo/bin.
  --base-url URL          Candidate download directory; HTTPS or loopback HTTP.
  --config FILE           Verify this existing installation before replacement.
  --uninstall             Remove selected installer-owned components.
  --recover               Roll back an interrupted installer whose process ended.
  --help                  Show this help.

Rust is not required. Configuration, credentials, and draft history are preserved.
Stop mailctl/MCP runtimes before updating an existing configured installation.
EOF
}
requested_version='' components='' install_dir='' base_url='' config='' explicit_config=0 mode=install
while [ "$#" -gt 0 ]; do
	case "$1" in
	--version | --components | --install-dir | --base-url | --config)
		[ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1."
		case "$1" in
		--version) requested_version=$2 ;;
		--components)
			case "$2" in
			cli) components=cli ;; mcp) components=mcp ;;
			cli,mcp | mcp,cli) components='cli mcp' ;;
			*) fail 'Components must be cli, mcp, or cli,mcp.' ;;
			esac
			;;
		--install-dir) install_dir=$2 ;;
		--base-url) base_url=${2%/} ;;
		--config)
			config=$2
			explicit_config=1
			;;
		esac
		shift 2
		;;
	--uninstall | --recover)
		[ "$mode" = install ] || fail 'Choose one installer action.'
		mode=${1#--}
		shift
		;;
	--help | -h)
		usage
		exit 0
		;;
	*) fail "Unknown option: $1. Use --help." ;;
	esac
done
export LC_ALL=C
stable_version() {
	printf '%s\n' "$1" | awk '/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/ {ok=1} END {exit !(NR == 1 && ok)}'
}
case "$(uname -s):$(uname -m)" in
Darwin:arm64 | Darwin:aarch64) target=aarch64-apple-darwin ;;
Linux:x86_64)
	target=x86_64-unknown-linux-gnu
	getconf GNU_LIBC_VERSION >/dev/null 2>&1 || fail 'Linux installation requires GNU libc on x86_64.'
	;;
*) fail 'This installer supports macOS Apple Silicon and GNU/Linux x86_64.' ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
	checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
	checksum_tool=shasum
else
	fail 'Install sha256sum or shasum to verify downloaded and installed files.'
fi
if [ "$mode" = install ]; then
	version=${requested_version#v}
	if [ -n "$requested_version" ]; then
		stable_version "$version" || fail 'Specify --version with a stable release version.'
	fi
	github_release=0
	if [ -z "$base_url" ]; then
		github_release=1
		base_url=https://github.com/ueberBrot/mailctl/releases/latest/download
		if [ -n "$version" ]; then base_url="https://github.com/ueberBrot/mailctl/releases/download/v$version"; fi
	fi
	# HTTP is restricted to local fixture servers, including redirects.
	case "$base_url" in
	https://*) protocol='=https' ;;
	http://127.0.0.1:*/* | http://127.0.0.1:*)
		port=${base_url#http://127.0.0.1:}
		port=${port%%/*}
		case "$port" in '' | *[!0-9]*) fail 'Invalid loopback download URL.' ;; esac
		protocol='=http,https'
		;;
	*) fail 'Downloads require HTTPS (or HTTP on 127.0.0.1 for local tests).' ;;
	esac
	printf '%s\n' "$base_url" | awk '/^[[:graph:]]+$/ && !/@/ {ok=1} END {exit !(NR == 1 && ok)}' || fail 'Invalid download URL.'
fi
if [ -z "$install_dir" ]; then
	if [ -n "${CARGO_HOME:-}" ]; then
		install_dir=$CARGO_HOME/bin
	else
		[ -n "${HOME:-}" ] || fail 'Set HOME or --install-dir.'
		install_dir=$HOME/.cargo/bin
	fi
fi
case "$install_dir" in /*) ;; *) fail 'The installation directory must be absolute.' ;; esac
case "$install_dir" in *'
'*) fail 'The installation directory must not contain newlines.' ;; esac
[ -d "$install_dir" ] || {
	[ "$mode" = install ] || fail 'Installation directory does not exist.'
	mkdir -p "$install_dir"
}
cd -P "$install_dir" || fail 'Cannot access installation directory.'
install_dir=$(pwd -P)
receipt=.mailctl-components
lock=.mailctl-installer.lock

regular() { [ -f "$1" ] && [ ! -L "$1" ]; }
hash() {
	case "$checksum_tool" in
	sha256sum) sha256sum "$1" ;;
	shasum) shasum -a 256 "$1" ;;
	esac | awk '{print $1}'
}
value() { awk -F= -v key="$2" '$1 == key {print substr($0, length(key)+2)}' "$1"; }
selected() { case " $components " in *" $1 "*) return 0 ;; *) return 1 ;; esac }
name() { case "$1" in cli) printf mailctl ;; mcp) printf mailctl-mcp ;; esac }

validate_receipt() {
	regular "$1" || fail 'Component manifest must be a regular file.'
	[ "$(wc -c <"$1")" -le 4096 ] || fail 'Component manifest is too large.'
	awk -F= -v target="$target" '
        NF != 2 || seen[$1]++ {exit 1}
        $1 == "format" {if ($2 != "1") exit 1; next}
        $1 == "target" {if ($2 != target) exit 1; next}
        $1 == "compatibility" {if ($2 != "1") exit 1; next}
        $1 ~ /^(cli|mcp)_version$/ {if ($2 !~ /^[0-9]+\.[0-9]+\.[0-9]+$/) exit 1; next}
        $1 ~ /^(cli|mcp)_commit$/ {if (length($2) != 40 || $2 !~ /^[0-9a-f]+$/) exit 1; next}
        $1 ~ /^(cli|mcp)_sha256$/ {if (length($2) != 64 || $2 !~ /^[0-9a-f]+$/) exit 1; next}
        $1 ~ /^(cli|mcp)_origin$/ {if ($2 !~ /^https?:\/\/[[:graph:]]+$/) exit 1; next}
        {exit 1}
        END {
            if (!seen["format"] || !seen["target"] || !seen["compatibility"]) exit 1
            for (i=1;i<=2;i++) {c=(i==1 ? "cli" : "mcp"); count=seen[c "_version"]+seen[c "_commit"]+seen[c "_sha256"]+seen[c "_origin"]; if (count != 0 && count != 4) exit 1}
        }
    ' "$1" || fail 'Unsupported or malformed component manifest; preserve it for inspection.'
}

# Recovery never takes ownership of a live lock or an unknown directory.
rollback() {
	[ -e "$lock/ready" ] || return 0
	regular "$lock/before" && regular "$lock/after" || return 1
	for c in cli mcp; do
		binary=$(name "$c")
		before=$(value "$lock/before" "${c}_sha256")
		after=$(value "$lock/after" "${c}_sha256")
		if [ -e "$binary" ] || [ -L "$binary" ]; then
			regular "$binary" || return 1
			current=$(hash "$binary")
			[ "$current" = "$before" ] || [ "$current" = "$after" ] || return 1
		fi
		if [ -n "$before" ]; then
			regular "$lock/backup/$binary" || return 1
			[ "$(hash "$lock/backup/$binary")" = "$before" ] || return 1
		fi
	done
	for c in cli mcp; do
		binary=$(name "$c")
		if [ -n "$(value "$lock/before" "${c}_sha256")" ]; then
			cp "$lock/backup/$binary" "$lock/restore-$binary" || return 1
			chmod 755 "$lock/restore-$binary" || return 1
			mv -f "$lock/restore-$binary" "$binary" || return 1
		elif [ -e "$binary" ]; then rm -f "$binary" || return 1; fi
	done
	if [ -e "$lock/had-receipt" ]; then
		cp "$lock/before" "$lock/restore-receipt" || return 1
		mv -f "$lock/restore-receipt" "$receipt" || return 1
	else rm -f "$receipt" || return 1; fi
}
if [ "$mode" = recover ]; then
	if [ -L "$lock" ] || [ ! -d "$lock" ] || ! regular "$lock/pid"; then fail 'No recognized interrupted installer to recover.'; fi
	owner=$(cat "$lock/pid")
	case "$owner" in '' | *[!0-9]*) fail 'Invalid installer owner; preserve the lock for inspection.' ;; esac
	! kill -0 "$owner" 2>/dev/null || fail 'The installer owner is still running; do not remove its lock.'
	mkdir .mailctl-installer.recovery 2>/dev/null || fail 'Another recovery is active.'
	trap 'rmdir .mailctl-installer.recovery' 0
	trap 'exit 1' 1 2 15
	if [ -e "$lock/ready" ]; then
		validate_receipt "$lock/before"
		validate_receipt "$lock/after"
	fi
	if [ ! -e "$lock/committed" ]; then rollback || fail 'Recovery failed; preserve the installer lock and backups.'; fi
	rm -rf "$lock"
	printf 'Recovered interrupted installation in %s. Application state is preserved.\n' "$install_dir"
	exit 0
fi
[ ! -L "$lock" ] || fail 'Installer lock is a symlink.'
mkdir "$lock" 2>/dev/null || fail 'Installer update is active or interrupted. After its process exits, use --recover.'
printf '%s\n' "$$" >"$lock/pid"
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ ! -e "$lock/committed" ] && ! rollback; then
		printf 'mailctl installer: rollback failed; preserve %s/%s and use --recover.\n' "$install_dir" "$lock" >&2
		exit 1
	fi
	rm -rf "$lock"
	exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 15
mkdir "$lock/backup" "$lock/download"
if [ -e "$receipt" ] || [ -L "$receipt" ]; then
	validate_receipt "$receipt"
	cp "$receipt" "$lock/before"
	: >"$lock/had-receipt"
else
	printf 'format=1\ntarget=%s\ncompatibility=1\n' "$target" >"$lock/before"
fi
for c in cli mcp; do
	binary=$(name "$c")
	owned=$(value "$lock/before" "${c}_sha256")
	if [ -e "$binary" ] || [ -L "$binary" ]; then
		[ -n "$owned" ] && regular "$binary" && [ "$(hash "$binary")" = "$owned" ] || fail "Foreign or modified $binary; move it aside explicitly or use its owning installation channel."
		cp "$binary" "$lock/backup/$binary"
	elif [ -n "$owned" ]; then fail "Owned $binary is missing; preserve the component manifest for inspection."; fi
done
if [ -z "$components" ]; then
	for c in cli mcp; do
		if [ -n "$(value "$lock/before" "${c}_version")" ]; then components="${components:+$components }$c"; fi
	done
	if [ -z "$components" ] && [ "$mode" = install ]; then components='cli mcp'; fi
fi
printf 'format=1\ntarget=%s\ncompatibility=1\n' "$target" >"$lock/after"
if [ "$mode" = install ]; then
	if [ -z "$config" ] && [ -n "${HOME:-}" ]; then
		case "$target" in
		aarch64-apple-darwin) config="$HOME/Library/Preferences/org.ueberbrot.mailctl/config.toml" ;;
		x86_64-unknown-linux-gnu)
			case "${XDG_CONFIG_HOME:-}" in
			/*) config="$XDG_CONFIG_HOME/mailctl/config.toml" ;;
			*) config="$HOME/.config/mailctl/config.toml" ;;
			esac
			;;
		esac
	fi
	# Reject invalid paths before downloads; recheck before state verification.
	if [ "$explicit_config" -eq 1 ] || { [ -n "$config" ] && [ -e "$config" ]; }; then
		case "$config" in /*) ;; *) fail '--config must be absolute.' ;; esac
		regular "$config" || fail 'Configuration is missing or not a regular file.'
	fi
	download() {
		curl --fail --silent --show-error --location --max-redirs 5 \
			--connect-timeout 10 --max-time 180 --proto "$protocol" --proto-redir '=https' \
			--max-filesize "$3" --output "$2" "$base_url/$1" || fail 'Candidate download failed; installed files are preserved.'
		[ "$(wc -c <"$2")" -le "$3" ] || fail 'Candidate download exceeded its size limit.'
	}
	manifest="$lock/download/manifest"
	download "manifest-$target.txt" "$manifest" 16384
	awk -F= -v target="$target" '
        NF != 2 || seen[$1]++ {exit 1}
        $1 == "format" || $1 == "compatibility" {if ($2 != "1") exit 1; next}
        $1 == "version" {if ($2 !~ /^[0-9]+\.[0-9]+\.[0-9]+$/) exit 1; next}
        $1 == "target" {if ($2 != target) exit 1; next}
        $1 == "commit" {if (length($2) != 40 || $2 !~ /^[0-9a-f]+$/) exit 1; next}
        $1 ~ /^(cli|mcp)_file$/ {if ($2 !~ /^[a-z0-9._-]+$/) exit 1; next}
        $1 ~ /^(cli|mcp)_sha256$/ {if (length($2) != 64 || $2 !~ /^[0-9a-f]+$/) exit 1; next}
        $1 ~ /^(cli|mcp)_size$/ {if ($2 !~ /^[1-9][0-9]*$/ || $2+0 > 104857600) exit 1; next}
        $1 ~ /^(cli|mcp)_signing$/ {if ($2 != "unsigned" && ($2 != "ad-hoc" || target != "aarch64-apple-darwin")) exit 1; next}
        {exit 1}
        END {if (length(seen) != 13) exit 1}
    ' "$manifest" || fail 'Unsupported or malformed candidate manifest.'
	resolved_version=$(value "$manifest" version)
	stable_version "$resolved_version" || fail 'Release manifest has an invalid stable version.'
	[ -z "$requested_version" ] || [ "$resolved_version" = "$version" ] || fail 'Candidate version or target does not match the request.'
	[ "$(value "$manifest" target)" = "$target" ] || fail 'Candidate version or target does not match the request.'
	version=$resolved_version
	# Resolve latest once, then use the immutable release directory for every binary.
	if [ "$github_release" -eq 1 ]; then base_url="https://github.com/ueberBrot/mailctl/releases/download/v$version"; fi
	commit=$(value "$manifest" commit)
	for c in cli mcp; do
		[ "$(value "$manifest" "${c}_file")" = "$(name "$c")-v$version-$target" ] || fail 'Unexpected candidate filename.'
		if ! selected "$c" && [ -n "$(value "$lock/before" "${c}_version")" ]; then
			[ "$(value "$lock/before" "${c}_version")" = "$version" ] && [ "$(value "$lock/before" "${c}_commit")" = "$commit" ] || fail 'Component versions or source commits differ; update both components together.'
		fi
	done
	for c in cli mcp; do
		binary=$(name "$c")
		if selected "$c"; then
			filename="$binary-v$version-$target"
			size=$(value "$manifest" "${c}_size")
			staged="$lock/download/$binary"
			download "$filename" "$staged" "$size"
			checksum=$(value "$manifest" "${c}_sha256")
			[ "$(wc -c <"$staged")" -eq "$size" ] && [ "$(hash "$staged")" = "$checksum" ] || fail "Checksum or size verification failed for $binary."
			chmod 755 "$staged"
			[ "$("./$staged" --version)" = "$binary $version" ] || fail "Candidate $binary reports a different version."
			printf '%s_version=%s\n%s_commit=%s\n%s_sha256=%s\n%s_origin=%s\n' "$c" "$version" "$c" "$commit" "$c" "$checksum" "$c" "$base_url" >>"$lock/after"
		elif [ -n "$(value "$lock/before" "${c}_version")" ]; then
			awk -v prefix="${c}_" 'index($0,prefix)==1' "$lock/before" >>"$lock/after"
		fi
	done
	if [ "$explicit_config" -eq 1 ] || { [ -n "$config" ] && [ -e "$config" ]; }; then
		case "$config" in /*) ;; *) fail '--config must be absolute.' ;; esac
		regular "$config" || fail 'Configuration is missing or not a regular file.'
		for c in $components; do
			staged="$lock/download/$(name "$c")"
			"./$staged" --config "$config" --json state verify >"$lock/download/state-result" 2>"$lock/download/state-error" || fail 'Installation history is incompatible, unavailable, or busy. Stop runtimes and run state verify with a compatible component; installed files are preserved.'
		done
	fi
else
	[ -e "$lock/had-receipt" ] || fail 'No installer-owned components to remove.'
	for c in cli mcp; do
		if ! selected "$c"; then awk -v prefix="${c}_" 'index($0,prefix)==1' "$lock/before" >>"$lock/after"; fi
	done
fi
validate_receipt "$lock/after"
: >"$lock/ready"
for c in $components; do
	binary=$(name "$c")
	# Recheck ownership immediately before replacement/removal.
	previous=$(value "$lock/before" "${c}_sha256")
	if [ -e "$binary" ] || [ -L "$binary" ]; then
		regular "$binary" && [ -n "$previous" ] && [ "$(hash "$binary")" = "$previous" ] || fail "Ownership changed for $binary during installation."
	elif [ -n "$previous" ]; then fail "Owned $binary disappeared during installation."; fi
	if [ "$mode" = install ]; then
		mv -f "$lock/download/$binary" "$binary"
	elif [ -n "$previous" ]; then rm -f "$binary"; fi
done
cp "$lock/after" "$lock/new-receipt"
mv -f "$lock/new-receipt" "$receipt"
: >"$lock/committed"
printf '%s completed in %s. Configuration, credentials, and draft history are preserved.\n' "$mode" "$install_dir"
if [ "$mode" = install ]; then
	printf '  Version: %s\n' "$version"
	for c in $components; do printf '  %s/%s\n' "$install_dir" "$(name "$c")"; done
	case ":${PATH:-}:" in *":$install_dir:"*) ;; *) printf 'Add this directory to PATH: %s\n' "$install_dir" ;; esac
fi
