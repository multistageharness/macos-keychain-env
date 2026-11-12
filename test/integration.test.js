// Exercises the real /usr/bin/security against the login keychain.
// Opt in with: npm run test:integration   (creates and deletes temporary items)
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, test } from 'node:test';
import { createKeychain, SecretNotFoundError } from '../src/index.js';

const enabled = process.platform === 'darwin' && process.env.KEYCHAIN_ENV_INTEGRATION === '1';
const service = `macos-keychain-env-test-${randomUUID()}`;
const kc = createKeychain({ securityPath: '/usr/bin/security' });

after(async () => {
  if (!enabled) return;
  for (const account of ['plain', 'tricky', 'large', 'env']) await kc.delete({ service, account }).catch(() => {});
});

test('real keychain round-trip', { skip: !enabled && 'set KEYCHAIN_ENV_INTEGRATION=1 on macOS' }, async () => {
  await kc.set({ service, account: 'plain' }, 'plain-value');
  assert.equal(await kc.get({ service, account: 'plain' }), 'plain-value');

  const tricky = 'line1\nline2 "quoted" \\ back ünï 🔑';
  await kc.set({ service, account: 'tricky' }, tricky, { label: 'macos-keychain-env test' });
  assert.equal(await kc.get({ service, account: 'tricky' }), tricky);
  assert.equal(kc.getSync({ service, account: 'tricky' }), tricky);

  await kc.set({ service, account: 'tricky' }, 'updated');
  assert.equal(await kc.get({ service, account: 'tricky' }), 'updated');

  const large = 'x'.repeat(10_000);
  await assert.rejects(kc.set({ service, account: 'large' }, large), { code: 'VALUE_TOO_LARGE' });
  await kc.set({ service, account: 'large' }, large, { allowArgv: true });
  assert.equal((await kc.get({ service, account: 'large' })).length, 10_000);

  await kc.set({ service, account: 'env' }, 'from-keychain');
  const target = {};
  await kc.loadEnv({ target, manifest: false, entries: { MY_VAR: { service, account: 'env' } } });
  assert.deepEqual(target, { MY_VAR: 'from-keychain' });

  assert.equal(await kc.has({ service, account: 'plain' }), true);
  assert.equal(await kc.delete({ service, account: 'plain' }), true);
  await assert.rejects(kc.get({ service, account: 'plain' }), SecretNotFoundError);
});
