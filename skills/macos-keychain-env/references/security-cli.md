# Raw `security` fallback

Use these when `keychain-env` is unavailable. They're verified on macOS.

If this repo is available, prefer its standalone bash scripts, which handle the
pitfalls below: `bin/keychain-add.sh`, `bin/keychain-update.sh`, and
`bin/keychain-get.sh` (all take `<service> <account>`; add and update read the value
from a hidden prompt, `--stdin`, or `--from-clipboard`).

```bash
# Exists? (reads no secret data; exit 0 = yes, 44 = not found)
security find-generic-password -s my-project -a OPENAI_API_KEY >/dev/null 2>&1; echo $?

# Store from the clipboard without the value touching argv or history.
# `security -i` reads commands from stdin; -X takes hex; -U updates if present.
printf 'add-generic-password -U -s "my-project" -a "OPENAI_API_KEY" -X %s\n' \
  "$(pbpaste | tr -d '\n' | xxd -p | tr -d '\n')" | security -i

# Run a command with one secret (value never printed)
OPENAI_API_KEY="$(security find-generic-password -s my-project -a OPENAI_API_KEY -w)" npm run dev

# Delete (destructive: get approval first)
security delete-generic-password -s my-project -a OPENAI_API_KEY
```

Pitfalls (handled by the package, not by raw commands):

- `-w` on add puts the secret in argv (visible via `ps`). The interactive
  `-w` prompt silently truncates values to 128 bytes.
- `security -i` lines are limited to 4095 characters. Longer lines are split
  and the first part is silently stored truncated (keep values under ~1.9 KB).
- `find-generic-password -w` prints values with non-printable characters
  (e.g. newlines) as bare hex. Use `-g` and parse `password: 0x...` instead.
- Exit codes: 44 not found, 45 duplicate, 36 interaction not allowed (locked
  keychain over SSH), 51 auth failed, 128 user canceled.
