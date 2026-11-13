#!/usr/bin/env bash
# Print a secret from the macOS keychain to stdout.
#
# Usage:
#   keychain-get.sh <service> <account> [--keychain <path>]
#
# Exit codes: 0 found, 1 not found or error, 2 usage. A trailing newline is
# added only when stdout is a terminal, so API_KEY="$(keychain-get.sh ...)" is exact.
set -euo pipefail

SECURITY="${KEYCHAIN_ENV_SECURITY_BIN:-/usr/bin/security}"

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}
die() { echo "keychain-get: $*" >&2; exit "${2:-1}"; }

service="" account="" keychain=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    --keychain) [ $# -ge 2 ] || die "--keychain needs a value" 2; keychain="$2"; shift ;;
    -*) die "unknown option: $1" 2 ;;
    *) if [ -z "$service" ]; then service="$1"; elif [ -z "$account" ]; then account="$1"; else die "too many arguments" 2; fi ;;
  esac
  shift
done
[ -n "$service" ] && [ -n "$account" ] || usage

# `-w` prints values with non-printable chars (e.g. newlines) as bare hex, which
# is ambiguous. `-g` writes `password: "text"` or `password: 0xHEX  "..."`.
args=(find-generic-password -s "$service" -a "$account" -g)
[ -z "$keychain" ] || args+=("$keychain")
set +e
out="$("$SECURITY" "${args[@]}" 2>&1 >/dev/null)"; status=$?
set -e
case "$status" in
  0) ;;
  44) die "item not found: service=\"$service\" account=\"$account\"" ;;
  36) die "keychain is locked and no GUI is available (run: security unlock-keychain)" ;;
  128) die "access was denied at the keychain prompt" ;;
  *) die "security find-generic-password failed (exit $status)" ;;
esac

line="$(printf '%s\n' "$out" | grep -m1 '^password:' || true)"
[ -n "$line" ] || die "could not parse security output"
rest="${line#password:}"; rest="${rest# }"

if [ -z "$rest" ]; then
  : # empty value
elif [ "${rest#0x}" != "$rest" ]; then
  hex="${rest#0x}"; hex="${hex%% *}"
  printf '%s' "$hex" | xxd -r -p
else
  rest="${rest#\"}"; printf '%s' "${rest%\"}"
fi
[ ! -t 1 ] || echo
