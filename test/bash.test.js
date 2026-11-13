import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { FAKE_SECURITY, fakeKeychain } from './helpers.js';

const script = (name) => fileURLToPath(new URL(`../bin/${name}`, import.meta.url));

function sh(name, args, { env, input } = {}) {
  return spawnSync('/bin/bash', [script(name), ...args], {
    input,
    encoding: 'utf8',
    env: { ...process.env, ...env, KEYCHAIN_ENV_SECURITY_BIN: FAKE_SECURITY },
  });
}

test('keychain-add.sh / keychain-get.sh round-trip awkward values', () => {
  const { env } = fakeKeychain();
  const values = ['plain', 'multi\nline', 'with "quotes" and \\ backslash', 'ünïcødé 🔑', ' padded ', '%s %d'];
  values.forEach((v, i) => {
    assert.equal(sh('keychain-add.sh', ['svc', `a${i}`, '--stdin'], { env, input: `${v}\n` }).status, 0);
    assert.equal(sh('keychain-get.sh', ['svc', `a${i}`], { env }).stdout, v);
  });
});

test('keychain-add.sh refuses existing items; keychain-update.sh refuses missing ones', () => {
  const { env } = fakeKeychain();
  assert.equal(sh('keychain-add.sh', ['svc', 'k', '--stdin'], { env, input: 'one' }).status, 0);
  const dup = sh('keychain-add.sh', ['svc', 'k', '--stdin'], { env, input: 'two' });
  assert.equal(dup.status, 1);
  assert.match(dup.stderr, /already exists/);
  assert.equal(sh('keychain-get.sh', ['svc', 'k'], { env }).stdout, 'one');

  assert.equal(sh('keychain-update.sh', ['svc', 'k', '--stdin'], { env, input: 'two' }).status, 0);
  assert.equal(sh('keychain-get.sh', ['svc', 'k'], { env }).stdout, 'two');

  const missing = sh('keychain-update.sh', ['svc', 'nope', '--stdin'], { env, input: 'x' });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /not found/);
  assert.equal(sh('keychain-get.sh', ['svc', 'nope'], { env }).status, 1);
});

test('bash scripts: usage errors, empty and oversize values', () => {
  const { env } = fakeKeychain();
  assert.equal(sh('keychain-get.sh', ['only-one'], { env }).status, 2);
  assert.equal(sh('keychain-add.sh', ['svc', 'k', '--bogus'], { env }).status, 2);
  assert.equal(sh('keychain-add.sh', ['svc', 'k', '--stdin'], { env, input: '' }).status, 1);
  const big = 'Z'.repeat(5000);
  const refused = sh('keychain-add.sh', ['svc', 'big', '--stdin'], { env, input: big });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /too large/);
  assert.equal(sh('keychain-add.sh', ['svc', 'big', '--stdin', '--allow-argv'], { env, input: big }).status, 0);
  assert.equal(sh('keychain-get.sh', ['svc', 'big'], { env }).stdout, big);
});
