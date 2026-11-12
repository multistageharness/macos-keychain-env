import { chmodSync, mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createKeychain } from '../src/index.js';

export const FAKE_SECURITY = fileURLToPath(new URL('./fixtures/fake-security.js', import.meta.url));
export const CLI = fileURLToPath(new URL('../bin/keychain-env.js', import.meta.url));
chmodSync(FAKE_SECURITY, 0o755);

/** A temp dir + client wired to the fake `security`. Env vars configure the fake. */
export function fakeKeychain(options = {}, { delayMs = 0 } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'kcenv-test-'));
  const env = {
    FAKE_KEYCHAIN_STORE: path.join(dir, 'store.json'),
    FAKE_KEYCHAIN_LOG: path.join(dir, 'calls.log'),
    FAKE_KEYCHAIN_DELAY_MS: String(delayMs),
  };
  Object.assign(process.env, env);
  const kc = createKeychain({ securityPath: FAKE_SECURITY, ...options });
  const calls = () =>
    existsSync(env.FAKE_KEYCHAIN_LOG) ? readFileSync(env.FAKE_KEYCHAIN_LOG, 'utf8').split('\n').filter(Boolean) : [];
  return { kc, dir, env, calls };
}
