#!/bin/bash -p
# Update an EXISTING secret in the macOS keychain. Fails if the item does not
# exist (use keychain-add.sh to create it).
#
# Usage:
#   keychain-update.sh <service> <account> [--stdin | --from-clipboard] [--keychain <path>] [--allow-argv]
#
# The value is read from a hidden prompt (TTY), stdin, or the clipboard. It is
# never taken as an argument, so it does not end up in shell history.
set -euo pipefail
PROG=keychain-update

# --- common: keep identical in keychain-add.sh, keychain-update.sh, keychain-get.sh ---
# Fixed environment: every tool is called by absolute path and PATH is reset.
# The `-p` in the shebang stops bash from sourcing $BASH_ENV/$ENV and from
# importing exported functions, so the environment cannot redefine commands.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
IFS=$' \t\n'
SECURITY=/usr/bin/security
MAX_LINE=4000 # `security -i` silently truncates lines over 4095 chars

die() { echo "$PROG: $1" >&2; exit "${2:-1}"; }

# Identifiers can only ever be read as values: no leading "-" (option
# injection), no control or invisible characters, no surrounding whitespace.
validate_name() {
  local kind="$1" v="$2"
  [ -n "$v" ] || die "$kind must not be empty" 2
  [ "${#v}" -le 1020 ] || die "$kind is too long" 2
  case "$v" in
    -*) die "$kind must not start with \"-\"" 2 ;;
    *[[:cntrl:]]*) die "$kind must not contain control characters" 2 ;;
  esac
  [ "$v" = "${v#[[:space:]]}" ] && [ "$v" = "${v%[[:space:]]}" ] || die "$kind must not start or end with whitespace" 2
  if printf '%s' "$v" | /usr/bin/grep -Eq $'\xc2[\x80-\x9f]|\xe2\x80[\x8b-\x8f\xa8-\xae]|\xe2\x81[\xa0-\xa9]|\xef\xbb\xbf'; then
    die "$kind must not contain invisible formatting characters" 2
  fi
}

# A keychain is an absolute path or a bare file name ending in .keychain(-db).
validate_keychain() {
  [ -n "$1" ] || return 0
  validate_name keychain "$1"
  case "$1" in *.keychain|*.keychain-db) ;; *) die "keychain must end in .keychain or .keychain-db" 2 ;; esac
  case "$1" in /*) ;; */*) die "keychain must be an absolute path or a bare file name" 2 ;; esac
  case "/$1/" in */../*) die "keychain must not contain .. segments" 2 ;; esac
}

# --security-bin (testing only): absolute, regular file, owned by root or the
# current user, not writable by group or others.
use_security_bin() {
  local info mode owner
  case "$1" in /*) ;; *) die "--security-bin must be an absolute path" 2 ;; esac
  [ -f "$1" ] || die "--security-bin is not a regular file: $1" 2
  info="$(/usr/bin/stat -L -f '%Lp %u' "$1")"; mode="${info% *}"; owner="${info#* }"
  [ $(( 8#$mode & 8#022 )) -eq 0 ] || die "--security-bin is writable by group or others: $1" 2
  [ "$owner" = 0 ] || [ "$owner" = "$(/usr/bin/id -u)" ] || die "--security-bin must be owned by root or you: $1" 2
  SECURITY="$1"
}

# Read the secret into $value from the clipboard, stdin, or a hidden prompt.
read_value() {
  local source="$1" label="$2" confirm
  if [ "$source" = clipboard ]; then
    value="$(/usr/bin/pbpaste; printf x)"; value="${value%x}"
  elif [ "$source" = stdin ] || [ ! -t 0 ]; then
    value="$(/bin/cat; printf x)"; value="${value%x}"
  else
    read -rsp "$label: " value </dev/tty; echo >&2
    read -rsp "Confirm value: " confirm </dev/tty; echo >&2
    [ "$value" = "$confirm" ] || die "values did not match"
  fi
  value="${value%$'\n'}"; value="${value%$'\r'}" # drop one trailing newline
  [ -n "$value" ] || die "refusing to store an empty value"
}

quote() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }

# Store $value as hex over `security -i` stdin (never argv unless --allow-argv).
# Sets $status. security's output is discarded: it can echo the command line,
# hex-encoded secret included, and no masking rule is safe for short secrets.
write_value() { # $1: extra flag ("-U" to update, "" to add)
  local hex line
  hex="$(printf '%s' "$value" | /usr/bin/xxd -p | /usr/bin/tr -d '\n')"
  line="add-generic-password${1:+ $1} -s $(quote "$service") -a $(quote "$account") -X $hex"
  [ -z "$keychain" ] || line="$line $(quote "$keychain")"
  set +e
  if [ "${#line}" -le "$MAX_LINE" ]; then
    printf '%s\n' "$line" | "$SECURITY" -i >/dev/null 2>&1; status=$?
  elif [ "$allow_argv" = 1 ]; then
    if [ -n "$keychain" ]; then
      "$SECURITY" add-generic-password $1 -s "$service" -a "$account" -X "$hex" "$keychain" >/dev/null 2>&1; status=$?
    else
      "$SECURITY" add-generic-password $1 -s "$service" -a "$account" -X "$hex" >/dev/null 2>&1; status=$?
    fi
  else
    set -e
    die "value is too large (${#value} bytes) to pass over stdin; rerun with --allow-argv (briefly visible via ps)"
  fi
  set -e
}
# --- end common ---

usage() {
  /usr/bin/sed -n '2,9p' "$0" | /usr/bin/sed 's/^# \{0,1\}//' >&2
  exit 2
}

service="" account="" keychain="" source="" allow_argv=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    --stdin) source=stdin ;;
    --from-clipboard) source=clipboard ;;
    --allow-argv) allow_argv=1 ;;
    --keychain) [ $# -ge 2 ] || die "--keychain needs a value" 2; keychain="$2"; shift ;;
    --security-bin) [ $# -ge 2 ] || die "--security-bin needs a value" 2; use_security_bin "$2"; shift ;;
    --) shift; break ;;
    -*) die "unknown option: $1" 2 ;;
    *) if [ -z "$service" ]; then service="$1"; elif [ -z "$account" ]; then account="$1"; else die "too many arguments" 2; fi ;;
  esac
  shift
done
[ $# -eq 0 ] || die "too many arguments" 2
[ -n "$service" ] && [ -n "$account" ] || usage
validate_name service "$service"
validate_name account "$account"
validate_keychain "$keychain"

# The item must already exist (this lookup reads no secret data).
set +e
if [ -n "$keychain" ]; then
  "$SECURITY" find-generic-password -s "$service" -a "$account" "$keychain" >/dev/null 2>&1; status=$?
else
  "$SECURITY" find-generic-password -s "$service" -a "$account" >/dev/null 2>&1; status=$?
fi
set -e
case "$status" in
  0) ;;
  44) die "item not found: service=\"$service\" account=\"$account\" (use keychain-add.sh)" ;;
  *) die "security find-generic-password failed (exit $status)" ;;
esac

read_value "$source" "New value for $service/$account"
write_value -U
case "$status" in
  0) echo "Updated keychain://$service/$account" >&2 ;;
  *) die "security add-generic-password failed (exit $status); output withheld because it may echo the secret" ;;
esac
