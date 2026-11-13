import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createKeychain } from '../src/index.js';

const FAKE_SECURITY_JS = fileURLToPath(new URL('./fixtures/fake-security.js', import.meta.url));
export const CLI = fileURLToPath(new URL('../bin/keychain-env.js', import.meta.url));

const sq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;

/**
 * A temp dir with a per-test fake `security` executable. The client runs
 * binaries with a fixed environment, so the fake's settings are baked into a
 * wrapper script rather than passed through env vars.
 */
export function fakeKeychain(options = {}, { delayMs = 0, failEcho = false } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'kcenv-test-'));
  const log = path.join(dir, 'calls.log');
  const securityBin = path.join(dir, 'security');
  const trustStore = path.join(dir, 'trust', 'trusted-manifests.json');
  writeFileSync(
    securityBin,
    [
      '#!/bin/sh',
      `FAKE_KEYCHAIN_STORE=${sq(path.join(dir, 'store.json'))} FAKE_KEYCHAIN_LOG=${sq(log)} \\`,
      `FAKE_KEYCHAIN_DELAY_MS=${delayMs} FAKE_KEYCHAIN_FAIL_ECHO=${failEcho ? 1 : 0} \\`,
      `exec ${sq(process.execPath)} ${sq(FAKE_SECURITY_JS)} "$@"`,
      '',
    ].join('\n'),
  );
  chmodSync(securityBin, 0o755);
  const kc = createKeychain({ securityPath: securityBin, trustStore, ...options });
  const calls = () => (existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean) : []);
  /** CLI flags that point keychain-env at this fake and trust store. */
  const cliFlags = ['--security-bin', securityBin, '--trust-store', trustStore];
  return { kc, dir, securityBin, trustStore, cliFlags, calls };
}
