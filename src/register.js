/**
 * Preload entry point, the keychain equivalent of `dotenv/config`:
 *
 *   node --import macos-keychain-env/register app.js
 *
 * Loads `.env.keychain` (if present) and resolves any `keychain://` values
 * already in process.env before the app starts. The manifest must have been
 * approved with `keychain-env trust`; startup fails otherwise. Works for ESM and CommonJS
 * apps. Top-level await guarantees secrets are in place before app code runs.
 *
 * Configure with environment variables:
 *   KEYCHAIN_ENV_MANIFEST   manifest path (default .env.keychain)
 *   KEYCHAIN_ENV_SERVICE    default service for bare `VAR` manifest lines
 *   KEYCHAIN_ENV_OVERRIDE=1 overwrite variables that are already set
 *   KEYCHAIN_ENV_DISABLE=1  skip loading entirely
 */
import { loadEnv } from './index.js';

if (process.env.KEYCHAIN_ENV_DISABLE !== '1') {
  await loadEnv({
    manifest: process.env.KEYCHAIN_ENV_MANIFEST || undefined,
    service: process.env.KEYCHAIN_ENV_SERVICE || undefined,
    override: process.env.KEYCHAIN_ENV_OVERRIDE === '1',
  });
}
