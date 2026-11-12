import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { CLI, FAKE_SECURITY, fakeKeychain } from './helpers.js';

function cli(args, { env, cwd, input } = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    input,
    encoding: 'utf8',
    env: { ...process.env, ...env, KEYCHAIN_ENV_SECURITY_BIN: FAKE_SECURITY },
  });
}

test('set via stdin, get, has, delete', () => {
  const { env } = fakeKeychain();
  assert.equal(cli(['set', 'svc', 'acct', '--stdin'], { env, input: 's3cret\n' }).status, 0);
  assert.equal(cli(['get', 'keychain://svc/acct'], { env }).stdout, 's3cret');
  assert.equal(cli(['has', 'svc', 'acct'], { env }).status, 0);
  assert.equal(cli(['delete', 'svc', 'acct'], { env }).status, 0);
  assert.equal(cli(['has', 'svc', 'acct'], { env }).status, 1);
  const missing = cli(['get', 'svc', 'acct'], { env });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /not found/);
});

test('run injects secrets into a child process and propagates the exit code', () => {
  const { env, dir } = fakeKeychain();
  cli(['set', 'app', 'API_KEY', '--stdin'], { env, input: 'k-123' });
  writeFileSync(path.join(dir, '.env.keychain'), 'API_KEY=keychain://app\n');
  const script = 'process.stdout.write(process.env.API_KEY); process.exit(7)';
  const r = cli(['run', '--', process.execPath, '-e', script], { env, cwd: dir });
  assert.equal(r.stdout, 'k-123');
  assert.equal(r.status, 7);

  const ci = cli(['run', '--', process.execPath, '-e', 'process.stdout.write(process.env.API_KEY)'], {
    env: { ...env, API_KEY: 'from-ci' },
    cwd: dir,
  });
  assert.equal(ci.stdout, 'from-ci');
});

test('run fails before starting the command when a secret is missing', () => {
  const { env, dir } = fakeKeychain();
  writeFileSync(path.join(dir, '.env.keychain'), 'NOPE=keychain://app\n');
  const r = cli(['run', '--', process.execPath, '-e', 'console.log("ran")'], { env, cwd: dir });
  assert.equal(r.status, 1);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /Missing 1 required secret/);
});

test('import moves .env values into the keychain and writes a manifest', () => {
  const { env, dir } = fakeKeychain();
  writeFileSync(path.join(dir, '.env'), 'A=alpha\nB="beta value"\nEMPTY=\nC=keychain://shared/C\n');
  writeFileSync(path.join(dir, '.env.keychain'), '# existing\nA=keychain://old\nKEEP=keychain://keep\n');
  const r = cli(['import', '.env', '--service', 'proj'], { env, cwd: dir });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(
    readFileSync(path.join(dir, '.env.keychain'), 'utf8'),
    '# existing\nA=keychain://proj\nKEEP=keychain://keep\nB=keychain://proj\nC=keychain://shared/C\n',
  );
  assert.equal(readFileSync(path.join(dir, '.env'), 'utf8').includes('alpha'), true, '.env is left untouched');
  assert.equal(cli(['get', 'proj', 'B'], { env }).stdout, 'beta value');
  assert.match(r.stderr, /Skipped empty: EMPTY/);
});

test('check reports status without printing values', () => {
  const { env, dir } = fakeKeychain();
  cli(['set', 'app', 'A', '--stdin'], { env, input: 'super-secret-value' });
  writeFileSync(path.join(dir, '.env.keychain'), 'A=keychain://app\nB=keychain://app\n');
  const r = cli(['check'], { env, cwd: dir });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /ok\s+A/);
  assert.match(r.stdout, /MISSING B/);
  assert.ok(!r.stdout.includes('super-secret-value'));
  const json = JSON.parse(cli(['check', '--json'], { env, cwd: dir }).stdout);
  assert.deepEqual(
    json.map((e) => e.present),
    [true, false],
  );
});

test('usage errors exit 2', () => {
  assert.equal(cli(['bogus']).status, 2);
  assert.equal(cli(['get', 'only-one']).status, 2);
  assert.match(execFileSync(process.execPath, [CLI, 'help'], { encoding: 'utf8' }), /keychain-env run/);
});
