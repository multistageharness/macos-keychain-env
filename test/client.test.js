import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { MissingSecretsError, SecretNotFoundError, trustManifest } from '../src/index.js';
import { fakeKeychain } from './helpers.js';

test('set/get/has/delete round-trip, including awkward values', async () => {
  const { kc } = fakeKeychain();
  const values = ['simple', 'with "quotes" and \\ backslash', 'multi\nline\nvalue', 'ünïcødé 🔑', ' padded '];
  for (const [i, v] of values.entries()) {
    await kc.set({ service: 'svc', account: `k${i}` }, v);
    assert.equal(await kc.get(`keychain://svc/k${i}`), v);
    assert.equal(kc.getSync({ service: 'svc', account: `k${i}` }), v);
  }
  assert.equal(await kc.has('keychain://svc/k0'), true);
  assert.equal(await kc.delete('keychain://svc/k0'), true);
  assert.equal(await kc.delete('keychain://svc/k0'), false);
  assert.equal(kc.hasSync('keychain://svc/k0'), false);
});

test('missing items throw SecretNotFoundError unless optional', async () => {
  const { kc } = fakeKeychain();
  await assert.rejects(kc.get('keychain://svc/nope'), SecretNotFoundError);
  assert.equal(await kc.get('keychain://svc/nope', { optional: true }), undefined);
  assert.equal(await kc.get('keychain://svc/nope?optional'), undefined);
  assert.throws(() => kc.getSync('keychain://svc/nope'), { code: 'NOT_FOUND' });
});

test('concurrent reads of the same item share one security process', async () => {
  const { kc, calls } = fakeKeychain({}, { delayMs: 100 });
  await kc.set('keychain://svc/shared', 'v');
  const before = calls().length;
  const results = await Promise.all(Array.from({ length: 10 }, () => kc.get('keychain://svc/shared')));
  assert.deepEqual(new Set(results), new Set(['v']));
  assert.equal(calls().length - before, 1);
});

test('concurrency limit bounds parallel security processes', async () => {
  const { kc } = fakeKeychain({ concurrency: 2 }, { delayMs: 150 });
  for (let i = 0; i < 4; i++) await kc.set(`keychain://svc/c${i}`, String(i));
  const start = Date.now();
  await Promise.all([0, 1, 2, 3].map((i) => kc.get(`keychain://svc/c${i}`)));
  // 4 reads, 2 at a time, ~150ms+ each => at least two waves.
  assert.ok(Date.now() - start >= 280, `took ${Date.now() - start}ms`);
});

test('cacheTtlMs avoids repeated spawns', async () => {
  const { kc, calls } = fakeKeychain({ cacheTtlMs: 60_000 });
  await kc.set('keychain://svc/cached', 'v1');
  const before = calls().length;
  await kc.get('keychain://svc/cached');
  await kc.get('keychain://svc/cached');
  assert.equal(calls().length - before, 1);
  await kc.set('keychain://svc/cached', 'v2'); // set invalidates
  assert.equal(await kc.get('keychain://svc/cached'), 'v2');
});

test('timeout and AbortSignal', async () => {
  const { kc } = fakeKeychain({}, { delayMs: 500 });
  await assert.rejects(kc.get('keychain://svc/x', { timeoutMs: 50 }), { code: 'TIMEOUT' });
  const ac = new AbortController();
  const p = kc.get('keychain://svc/y', { signal: ac.signal });
  ac.abort();
  await assert.rejects(p, { name: 'AbortError' });
});

test('loadEnv: manifest, keys, entries, refs in env, existing values win', async () => {
  const { kc, dir, trustStore } = fakeKeychain();
  await kc.set('keychain://app/A', 'a-secret');
  await kc.set('keychain://app/B', 'b-secret');
  await kc.set('keychain://app/token', 'c-secret');
  await kc.set('keychain://app/D', 'd-secret');
  writeFileSync(path.join(dir, '.env.keychain'), 'A=keychain://app\nOPT=keychain://app/none?optional\n');
  trustManifest('.env.keychain', { cwd: dir, store: trustStore });
  const target = { B: 'from-ci', C: 'keychain://app/token' };
  const result = await kc.loadEnv({ cwd: dir, target, keys: ['B'], service: 'app', entries: { D: 'keychain://app/D' } });
  assert.deepEqual(target, { A: 'a-secret', B: 'from-ci', C: 'c-secret', D: 'd-secret' });
  assert.deepEqual(result.skipped, ['B']);
  assert.deepEqual(result.missing, ['OPT']);
  assert.deepEqual(new Set(result.loaded), new Set(['A', 'C', 'D']));

  const overridden = { B: 'from-ci' };
  await kc.loadEnv({ cwd: dir, target: overridden, keys: ['B'], service: 'app', manifest: false, override: true });
  assert.equal(overridden.B, 'b-secret');
});

test('loadEnv is all-or-nothing when required secrets are missing', async () => {
  const { kc, dir } = fakeKeychain();
  await kc.set('keychain://app/A', 'a');
  const target = {};
  await assert.rejects(
    kc.loadEnv({ cwd: dir, target, entries: { A: 'keychain://app/A', B: 'keychain://app/B', C: 'keychain://app/C' } }),
    (err) => err instanceof MissingSecretsError && err.missing.map((m) => m.name).join() === 'B,C',
  );
  assert.deepEqual(target, {});
});

test('loadEnv does not touch the keychain when nothing needs fetching', async () => {
  const { kc, calls } = fakeKeychain();
  const before = calls().length;
  await kc.loadEnv({ target: { A: 'set' }, keys: ['A'], service: 'app', manifest: false });
  assert.equal(calls().length, before);
});

test('loadEnvSync and checkEnv', async () => {
  const { kc, dir, trustStore } = fakeKeychain();
  await kc.set('keychain://app/A', 'a');
  writeFileSync(path.join(dir, 'm.env'), 'A=keychain://app\nB=keychain://app\nC=keychain://app?optional\n');
  trustManifest('m.env', { cwd: dir, store: trustStore });
  const checks = await kc.checkEnv({ cwd: dir, manifest: 'm.env' });
  assert.deepEqual(
    checks.map((c) => [c.name, c.present, c.optional]),
    [
      ['A', true, false],
      ['B', false, false],
      ['C', false, true],
    ],
  );
  assert.throws(() => kc.loadEnvSync({ cwd: dir, manifest: 'm.env', target: {} }), { code: 'MISSING_SECRETS' });
  assert.throws(() => kc.loadEnvSync({ cwd: dir, manifest: 'missing.env' }), { code: 'MANIFEST_NOT_FOUND' });
});

test('provider caches for ttl and can be invalidated', async () => {
  const { kc, calls } = fakeKeychain();
  await kc.set('keychain://app/token', 't1');
  const token = kc.provider('keychain://app/token', { ttlMs: 60_000 });
  const before = calls().length;
  assert.equal(await token(), 't1');
  assert.equal(await token(), 't1');
  assert.equal(calls().length - before, 1);
  await kc.set('keychain://app/token', 't2');
  assert.equal(await token(), 't1');
  token.invalidate();
  assert.equal(await token(), 't2');
});
