# macos-keychain-env

Use the **macOS keychain** instead of `.env` files or hard-coded keys.

This repo contains:

1. **`macos-keychain-env`**, a dependency-free Node.js package with async and sync
   APIs, a `--import` preload hook, and SDK-friendly secret providers.
2. **`keychain-env`**, a CLI to store, check, and inject secrets into any command
   (any language).
3. **An agent skill** ([`skills/macos-keychain-env`](skills/macos-keychain-env/SKILL.md))
   that teaches coding agents to keep secrets in the keychain and out of files and chat.

Your repository commits a manifest of *references*. The secret values stay in the keychain:

```dotenv
# .env.keychain: safe to commit
OPENAI_API_KEY=keychain://my-project
DATABASE_URL=keychain://my-project/DATABASE_URL
SENTRY_DSN=keychain://my-project?optional
```

Reference format: `keychain://<service>[/<account>][?optional][&keychain=<path>]`. The
account defaults to the variable name, and both parts are percent-decoded.

## Quick start

```bash
npm install macos-keychain-env            # or: npm install -g macos-keychain-env

keychain-env set my-project OPENAI_API_KEY      # hidden prompt
echo 'OPENAI_API_KEY=keychain://my-project' >> .env.keychain
keychain-env check                              # ok / MISSING, never prints values

keychain-env run -- npm run dev                 # any command, any language
node --import macos-keychain-env/register app.js   # Node, zero code changes
```

Migrate an existing `.env`:

```bash
keychain-env import .env --service my-project   # stores values, writes .env.keychain
keychain-env check && rm .env                   # .env itself is never modified by import
```

## Node.js API

```js
import { loadEnv, getSecret, secretProvider, createKeychain } from 'macos-keychain-env';

await loadEnv();                                          // .env.keychain → process.env
await loadEnv({ service: 'my-project', keys: ['A', 'B'] });
const key = await getSecret('keychain://my-project/OPENAI_API_KEY');
const maybe = await getSecret({ service: 'x', account: 'y' }, { optional: true });

const apiKey = secretProvider('keychain://my-project/ANTHROPIC_API_KEY', { ttlMs: 600_000 });
new Anthropic({ apiKey: await apiKey() });                // apiKey.invalidate() after a 401
```

CommonJS works too (`require('macos-keychain-env')`, Node ≥ 20.19). TypeScript
types ship in `index.d.ts`.

| Function | Notes |
|---|---|
| `getSecret(ref, { optional, timeoutMs, signal, cacheTtlMs })` | Throws `SecretNotFoundError` unless `optional` |
| `getSecretSync(ref, opts)` | Blocks; for sync config files |
| `hasSecret(ref)` / `hasSecretSync` | Reads no secret data, so never triggers an access prompt |
| `setSecret(ref, value, { label, comment, trustedApps, allowArgv })` | Creates or updates |
| `deleteSecret(ref)` / `deleteSecretSync` | `true` if deleted, `false` if absent |
| `loadEnv(opts)` / `loadEnvSync(opts)` | Manifest + `keys` + `entries` + `keychain://` values already in env |
| `checkEnv(opts)` | `[{ name, present, optional, ... }]` without reading values |
| `resolveEnv(target?)` | Replace `keychain://` values in an object (default `process.env`) |
| `secretProvider(ref, { ttlMs })` | Lazy cached async getter for SDKs |
| `createKeychain(options)` | Separate client: `keychain`, `timeoutMs`, `concurrency`, `cacheTtlMs`, `service` |

### `loadEnv` semantics

- **Existing env vars win** (`override: false` by default). CI and Linux provide real
  env vars, and the keychain is never queried for them. On non-macOS, a lookup that is
  actually needed throws `UNSUPPORTED_PLATFORM`.
- **All-or-nothing:** if any required secret is missing, it throws `MissingSecretsError`
  listing *all* of them, and nothing is written.
- **Concurrent:** items are fetched in parallel, up to `concurrency` (default 4)
  `security` processes at a time.
- Works with dotenv: `.env` may contain `API_KEY=keychain://my-project`. Run
  `dotenv.config()` first, then `loadEnv()` replaces the reference.
- Returns `{ loaded, skipped, missing }`. These are names only, never values.

## Async design

Reading the keychain means spawning `/usr/bin/security`, which can block on a GUI
access prompt or fail on a locked keychain. The package is built around that:

| Concern | Handling |
|---|---|
| Event loop | Async API uses `spawn`; the sync API is opt-in for sync-only contexts |
| Thundering herd | Concurrent reads of one item share one process (in-flight dedup) |
| Process fan-out | Concurrency limiter (default 4) |
| Prompts / hangs | Per-call `timeoutMs` (default 30 s) → `TIMEOUT` error |
| Cancellation | `AbortSignal`: the caller stops waiting, and a shared read continues for others |
| Repeated reads | Optional `cacheTtlMs` per client; `secretProvider` TTL + `invalidate()` |
| Startup ordering | `register` uses top-level await, so secrets are in place before app code runs |
| Errors | `KeychainError.code`: `NOT_FOUND`, `MISSING_SECRETS`, `INTERACTION_NOT_ALLOWED`, `USER_CANCELED`, `AUTH_FAILED`, `TIMEOUT`, `ABORTED`, `UNSUPPORTED_PLATFORM`, `VALUE_TOO_LARGE`, … Messages never contain values |

## CLI

```
keychain-env set <service> <account> [--stdin | --from-clipboard [--clear-clipboard]] [--label] [--comment]
keychain-env get | has | delete | ref <service> <account>     (or a single keychain:// URI)
keychain-env check [--manifest f] [--json]
keychain-env run [--manifest f] [--no-manifest] [--override] -- <cmd> [args...]
keychain-env import <file> --service <name> [--keys A,B] [--manifest f]
global: --keychain <path>  --timeout <ms>
```

`set` has no value argument on purpose: values come from a hidden prompt, stdin, or
the clipboard, so they never end up in shell history.

## Security notes

- Values are passed to `security` as hex **over stdin** (`security -i`), never argv.
  `security -i` silently truncates lines over 4095 characters, so values over
  ~1.9 KB are refused with `VALUE_TOO_LARGE` unless you pass `allowArgv: true` /
  `--allow-argv`. With that option the value is briefly visible to `ps`.
- Reads use `find-generic-password -g` rather than `-w`, because `-w` prints values
  that contain non-printable characters (e.g. newlines) as ambiguous bare hex.
- Items created via `security` trust `/usr/bin/security` by default, so any process
  running as your user can read them without a prompt. That is the same trust level as
  a `.env` file, but the secrets are encrypted at rest, can't be committed by accident,
  and live in one place. Use `trustedApps: [""]` to require a prompt on every read.
- Error messages redact hex runs and never include values.

## Agent skill

[`skills/macos-keychain-env/SKILL.md`](skills/macos-keychain-env/SKILL.md) tells an
agent to: never write or echo secrets, have the user enter values (hidden prompt or
clipboard), verify with `check` instead of reading values, migrate `.env` files, and
wire apps through `run`, `--import`, or the API.

Install for Claude Code:

```bash
# personal, all projects
ln -s "$PWD/skills/macos-keychain-env" ~/.claude/skills/macos-keychain-env
# or per project
mkdir -p .claude/skills && cp -R skills/macos-keychain-env .claude/skills/
```

The repo also contains `.claude-plugin/plugin.json`, so it can be installed as a plugin.

## Development

```bash
npm test                    # unit tests against a fake `security` binary
npm run test:integration    # macOS only: real login keychain, temporary items cleaned up
```
