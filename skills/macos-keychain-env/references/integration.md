# Integrating `macos-keychain-env`

Install: `npm install macos-keychain-env` (Node >= 20.19; ESM, and `require()` works too).

## Choosing sync vs async

| API | Blocks event loop | Use for |
|---|---|---|
| `loadEnv()` / `getSecret()` | no | app startup, request paths, SDK factories |
| `--import macos-keychain-env/register` | n/a (runs before app) | zero-code adoption |
| `loadEnvSync()` / `getSecretSync()` | yes (one `security` process per item) | synchronous config files only |
| `secretProvider()` | no | long-lived clients; cached with TTL, `invalidate()` on 401 |

Async calls are concurrency-limited (default 4 `security` processes) and
de-duplicated: ten concurrent `getSecret` calls for one item spawn one process.
Each call accepts `{ timeoutMs, signal }`. A keychain access prompt blocks
until answered, so the default 30 s timeout matters.

## Applications

```js
// ESM entry point
import { loadEnv } from 'macos-keychain-env';
await loadEnv();                          // .env.keychain + keychain:// values in process.env
const app = (await import('./server.js')).default;
```

```js
// Explicit list, no manifest
await loadEnv({ service: 'my-project', keys: ['OPENAI_API_KEY', 'DATABASE_URL'] });
```

Works alongside dotenv: a `.env` may contain `API_KEY=keychain://my-project`,
and `loadEnv()` (which runs `resolveEnv`) replaces it after `dotenv.config()`.

Manifests must be approved first (`keychain-env trust`), or loading fails with
`UNTRUSTED_MANIFEST`. `keychain://` values in the environment may only name services the
app's code or trusted manifest already uses; pass `allowedServices` to set an explicit list.

`loadEnv` is all-or-nothing. If any required secret is missing, it throws
`MissingSecretsError` (listing all of them) and sets nothing.

## CLIs

```js
#!/usr/bin/env node
import { getSecret, KeychainError } from 'macos-keychain-env';

const token =
  process.env.MYCLI_TOKEN ??                              // env/CI wins
  (await getSecret('keychain://mycli/token', { optional: true }));
if (!token) {
  console.error('Not logged in. Run: keychain-env set mycli token');
  process.exit(1);
}
```

A `login` command can store a token with `setSecret('keychain://mycli/token', token)`.

## SDKs / libraries

Accept a value or an async provider, and never read secrets at import time:

```js
import { secretProvider } from 'macos-keychain-env';

const apiKey = secretProvider('keychain://my-project/ANTHROPIC_API_KEY', { ttlMs: 10 * 60_000 });

export async function client() {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  return new Anthropic({ apiKey: await apiKey() });
}
// on 401: apiKey.invalidate(); then retry once.
```

AWS-style credential provider:

```js
import { getSecret } from 'macos-keychain-env';
const credentials = async () => ({
  accessKeyId: await getSecret('keychain://aws-dev/access-key-id'),
  secretAccessKey: await getSecret('keychain://aws-dev/secret-access-key'),
});
```

Custom client (separate keychain file, caching):

```js
import { createKeychain } from 'macos-keychain-env';
const kc = createKeychain({ keychain: '/path/team.keychain-db', cacheTtlMs: 60_000, timeoutMs: 10_000 });
```

## Non-Node runtimes

```bash
keychain-env run -- python app.py
keychain-env run --manifest config/.env.keychain -- go run .
keychain-env run --override -- ./script.sh    # keychain beats existing env
```

Exit codes and signals pass through to the child process.

## CI and non-macOS

Set the variables directly. Values that are already set are never looked up.
On non-macOS, any lookup that is actually needed fails with `UNSUPPORTED_PLATFORM`.
`KEYCHAIN_ENV_DISABLE=1` turns off the `register` preload.
