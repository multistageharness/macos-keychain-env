---
name: macos-keychain-env
description: Store and load project secrets (API keys, tokens, passwords, connection strings) from the macOS keychain instead of .env files or hard-coded values. Use when a project needs credentials on macOS, when setting up or editing a .env file, when you find plaintext secrets in .env or source code, when wiring an app, CLI or SDK to read an API key, or when the user mentions keychain, secrets management, or "don't commit my keys". Provides the `keychain-env` CLI (set/check/run/import) and the `macos-keychain-env` Node.js package.
---

# macOS keychain instead of .env

Secrets live in the user's macOS login keychain as generic-password items
(service + account). The repository only holds **references**, in a committed
`.env.keychain` manifest:

```dotenv
# .env.keychain: safe to commit, contains no secrets
OPENAI_API_KEY=keychain://my-project          # account defaults to the var name
DATABASE_URL=keychain://my-project/DATABASE_URL
SENTRY_DSN=keychain://my-project?optional      # missing is not an error
```

At runtime the references are resolved into environment variables. Variables
that are **already set in the environment always win**. CI and Linux therefore
keep working by setting real env vars, and the keychain is never touched there.

## Rules for the agent

1. **Never put a secret value in a file, commit, command line, log, or your reply.**
   That includes `.env`, source code, tests, docs, shell history (`export KEY=...`),
   and `keychain-env set ... <value>`. `set` deliberately has no value argument.
2. **Don't ask the user to paste a secret into chat.** If they already did,
   store it with the `--stdin` flow below, then tell them it has passed through
   the conversation and should be rotated if that matters to them.
3. **Don't read secret values back.** Verify with `keychain-env check` or `has`,
   which read no secret data. Run programs with `keychain-env run`. Avoid
   `keychain-env get`; use it only when the user explicitly asks to see a value.
4. Deleting `.env` files or keychain items is destructive. Name exactly what will
   be lost and get explicit approval first.
5. Make sure `.env` and `.env.*` (but not `.env.keychain`) are in `.gitignore`.

## Getting the CLI

Use the first that works:

```bash
keychain-env help                       # installed globally / on PATH
npx --yes macos-keychain-env help       # from npm (once published)
node <path-to-this-repo>/bin/keychain-env.js help
```

If none is available, use the raw `security` fallback in
[references/security-cli.md](references/security-cli.md).

## Workflows

### A. New secret for a project

1. Pick a **service** name, normally the project/package name (e.g. `my-project`).
   Use the same service for all of a project's secrets.
2. Add the reference to `.env.keychain` (create it if needed):
   `OPENAI_API_KEY=keychain://my-project`
3. Have the **user** store the value. Offer these options, in order of preference:
   - **Own terminal (best):** ask them to run
     `keychain-env set my-project OPENAI_API_KEY`. It prompts twice with hidden input.
   - **Clipboard:** the user copies the secret, then you (or they) run
     `keychain-env set my-project OPENAI_API_KEY --from-clipboard --clear-clipboard`.
     The value is never printed.
   - **Already in your context** (the user pasted it): pipe it via stdin so it
     stays out of argv and shell history. Never echo it back:
     `keychain-env set my-project OPENAI_API_KEY --stdin <<'EOF'` … `EOF`
4. Verify: `keychain-env check` (exit 0 = all required present).

### B. Migrate an existing `.env`

1. Check `.gitignore` covers `.env`.
2. `keychain-env import .env --service my-project`. This stores every non-empty,
   non-reference value and writes or merges `keychain://` lines into `.env.keychain`.
   Values over ~1.9 KB fail with `VALUE_TOO_LARGE`; tell the user, and rerun with
   `--allow-argv` only if they accept the value being briefly visible in `ps`.
   Use `--keys A,B` to import a subset.
3. `keychain-env check` to confirm.
4. `.env` is **not** modified. Ask the user before removing the plaintext values
   or deleting the file (destructive). Mention that previously committed secrets
   remain in git history and should be rotated.

### C. Make the app read from the keychain

Choose by runtime. Details and SDK examples are in
[references/integration.md](references/integration.md).

| Situation | Do this |
|---|---|
| Any command, any language | `keychain-env run -- <cmd> [args]`, e.g. in package.json scripts: `"dev": "keychain-env run -- next dev"` |
| Node app, no code changes | `node --import macos-keychain-env/register app.js` (or `NODE_OPTIONS="--import macos-keychain-env/register"`) |
| Node code, async startup | `await loadEnv()` before reading `process.env` |
| Sync config file (CJS config, jest/next config) | `loadEnvSync()` |
| SDK client / long-running service | `getSecret(ref)` or `secretProvider(ref)` passed to the client, without touching `process.env` |

Replace code like `const key = "sk-..."` with one of the above, and put the
literal into the keychain using workflow A.

### D. Check / debug

- `keychain-env check [--json]` lists present/MISSING per variable, without values.
- `keychain-env has <service> <account>` exits 0 if present, 1 if not.
- Errors carry a `code`:
  - `NOT_FOUND` / `MISSING_SECRETS`: store the item (workflow A).
  - `INTERACTION_NOT_ALLOWED`: the keychain is locked and there is no GUI (SSH).
    The user runs `security unlock-keychain ~/Library/Keychains/login.keychain-db`.
  - `USER_CANCELED`: the user clicked Deny on the access prompt.
  - `TIMEOUT`: an access prompt is probably waiting on screen. Ask the user to answer it.
  - `UNSUPPORTED_PLATFORM`: not macOS. Provide the variables as real env vars instead.

## Security model (tell the user when relevant)

- Items created through `security` trust `/usr/bin/security`, so any process
  running as this user can read them without a prompt. This is the same
  trust level as a `.env` file, but the secrets are encrypted at rest, can't be
  committed by accident, and aren't spread across project folders. For a prompt on every read,
  create items with the Node API using `trustedApps: [""]`.
- Values pass to `security` through stdin, never argv, except for values over
  ~1.9 KB with explicit `--allow-argv`.
