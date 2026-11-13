#!/usr/bin/env bash
# Update an EXISTING secret in the macOS keychain. Fails if the item does not
# exist (use keychain-add.sh to create it).
#
# Usage:
#   keychain-update.sh <service> <account> [--stdin | --from-clipboard] [--keychain <path>] [--allow-argv]
#
# The value is read from a hidden prompt (TTY), stdin, or the clipboard. It is
# never taken as an argument, so it does not end up in shell history.
set -euo pipefail

SECURITY="${KEYCHAIN_ENV_SECURITY_BIN:-/usr/bin/security}"
MAX_LINE=4000 # `security -i` silently truncates lines over 4095 chars

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}
die() { echo "keychain-update: $*" >&2; exit "${2:-1}"; }

service="" account="" keychain="" source="" allow_argv=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    --stdin) source=stdin ;;
    --from-clipboard) source=clipboard ;;
    --allow-argv) allow_argv=1 ;;
    --keychain) [ $# -ge 2 ] || die "--keychain needs a value" 2; keychain="$2"; shift ;;
    -*) die "unknown option: $1" 2 ;;
    *) if [ -z "$service" ]; then service="$1"; elif [ -z "$account" ]; then account="$1"; else die "too many arguments" 2; fi ;;
  esac
  shift
done
[ -n "$service" ] && [ -n "$account" ] || usage
case "$service$account$keychain" in *$'\n'*|*$'\r'*) die "names must not contain newlines" 2 ;; esac

# --- the item must already exist (reads no secret data) -----------------------
lookup=(find-generic-password -s "$service" -a "$account")
[ -z "$keychain" ] || lookup+=("$keychain")
set +e
"$SECURITY" "${lookup[@]}" >/dev/null 2>&1; status=$?
set -e
case "$status" in
  0) ;;
  44) die "item not found: service=\"$service\" account=\"$account\" (use keychain-add.sh)" ;;
  *) die "security find-generic-password failed (exit $status)" ;;
esac

# --- read the value -----------------------------------------------------------
if [ "$source" = clipboard ]; then
  value="$(pbpaste; printf x)"; value="${value%x}"
elif [ "$source" = stdin ] || [ ! -t 0 ]; then
  value="$(cat; printf x)"; value="${value%x}"
else
  read -rsp "New value for $service/$account: " value </dev/tty; echo >&2
  read -rsp "Confirm value: " confirm </dev/tty; echo >&2
  [ "$value" = "$confirm" ] || die "values did not match"
fi
value="${value%$'\n'}"; value="${value%$'\r'}" # drop one trailing newline
[ -n "$value" ] || die "refusing to store an empty value"

# --- write: hex over stdin to `security -i`, never argv ------------------------
quote() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }
hex="$(printf '%s' "$value" | xxd -p | tr -d '\n')"
line="add-generic-password -U -s $(quote "$service") -a $(quote "$account") -X $hex"
[ -z "$keychain" ] || line="$line $(quote "$keychain")"

set +e
if [ "${#line}" -le "$MAX_LINE" ]; then
  err="$(printf '%s\n' "$line" | "$SECURITY" -i 2>&1 >/dev/null)"; status=$?
elif [ "$allow_argv" = 1 ]; then
  args=(add-generic-password -U -s "$service" -a "$account" -X "$hex")
  [ -z "$keychain" ] || args+=("$keychain")
  err="$("$SECURITY" "${args[@]}" 2>&1 >/dev/null)"; status=$?
else
  die "value is too large (${#value} chars) to pass over stdin; rerun with --allow-argv (briefly visible via ps)"
fi
set -e

# `security -i` may echo input on errors: redact anything hex-like.
err="$(printf '%s' "$err" | sed -E 's/[0-9a-fA-F]{16,}/[redacted]/g')"
case "$status" in
  0) case "$err" in *"returned"*|*"unknown command"*) die "security failed: $err" ;; esac
     echo "Updated keychain://$service/$account" >&2 ;;
  *) die "security add-generic-password failed (exit $status): $err" ;;
esac
