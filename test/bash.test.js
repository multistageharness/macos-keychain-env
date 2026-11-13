import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { fakeKeychain } from './helpers.js';

const script = (name) => fileURLToPath(new URL(`../bin/${name}`, import.meta.url));

/** Execute the script directly so its `#!/bin/bash -p` shebang is honored. */
function sh(fake, name, args, { input, env } = {}) {
  const flags = fake ? ['--security-bin', fake.securityBin] : [];
  return spawnSync(script(name), [...args, ...flags], {
    input,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('keychain-add.sh / keychain-get.sh round-trip awkward values', () => {
  const fake = fakeKeychain();
  const values = ['plain', 'multi\nline', 'with "quotes" and \\ backslash', 'ünïcødé 🔑', ' padded ', '%s %d'];
  values.forEach((v, i) => {
    assert.equal(sh(fake, 'keychain-add.sh', ['svc', `a${i}`, '--stdin'], { input: `${v}\n` }).status, 0);
    assert.equal(sh(fake, 'keychain-get.sh', ['svc', `a${i}`]).stdout, v);
  });
});

test('keychain-add.sh refuses existing items; keychain-update.sh refuses missing ones', () => {
  const fake = fakeKeychain();
  assert.equal(sh(fake, 'keychain-add.sh', ['svc', 'k', '--stdin'], { input: 'one' }).status, 0);
  const dup = sh(fake, 'keychain-add.sh', ['svc', 'k', '--stdin'], { input: 'two' });
  assert.equal(dup.status, 1);
  assert.match(dup.stderr, /already exists/);
  assert.equal(sh(fake, 'keychain-get.sh', ['svc', 'k']).stdout, 'one');

  assert.equal(sh(fake, 'keychain-update.sh', ['svc', 'k', '--stdin'], { input: 'two' }).status, 0);
  assert.equal(sh(fake, 'keychain-get.sh', ['svc', 'k']).stdout, 'two');

  const missing = sh(fake, 'keychain-update.sh', ['svc', 'nope', '--stdin'], { input: 'x' });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /not found/);
  assert.equal(sh(fake, 'keychain-get.sh', ['svc', 'nope']).status, 1);
});

test('bash scripts: usage errors, empty and oversize values', () => {
  const fake = fakeKeychain();
  assert.equal(sh(fake, 'keychain-get.sh', ['only-one']).status, 2);
  const invalid = sh(fake, 'keychain-get.sh', ['svc', 'acct', '--keychain', '-A']);
  assert.equal(invalid.status, 2);
  assert.equal(invalid.stderr, 'keychain-get: keychain must not start with "-"\n');
  assert.equal(sh(fake, 'keychain-add.sh', ['svc', 'k', '--bogus']).status, 2);
  assert.equal(sh(fake, 'keychain-add.sh', ['svc', 'k', '--stdin'], { input: '' }).status, 1);
  const big = 'Z'.repeat(5000);
  const refused = sh(fake, 'keychain-add.sh', ['svc', 'big', '--stdin'], { input: big });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /too large/);
  assert.equal(sh(fake, 'keychain-add.sh', ['svc', 'big', '--stdin', '--allow-argv'], { input: big }).status, 0);
  assert.equal(sh(fake, 'keychain-get.sh', ['svc', 'big']).stdout, big);
});

test('bash scripts share an identical hardened common block', () => {
  const block = (name) => {
    const src = readFileSync(script(name), 'utf8');
    return src.slice(src.indexOf('# --- common:'), src.indexOf('# --- end common ---'));
  };
  const add = block('keychain-add.sh');
  assert.ok(add.length > 1000);
  assert.equal(block('keychain-update.sh'), add);
  assert.equal(block('keychain-get.sh'), add);
  for (const name of ['keychain-add.sh', 'keychain-update.sh', 'keychain-get.sh']) {
    assert.match(readFileSync(script(name), 'utf8'), /^#!\/bin\/bash -p\n/);
  }
});
