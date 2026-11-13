import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { CLI, fakeKeychain } from './helpers.js';

/** Run the CLI; `fake.cliFlags` are inserted right after the command name. */
function cli(fake, [command, ...args], { env, cwd, input } = {}) {
  const argv = fake ? [command, ...fake.cliFlags, ...args] : [command, ...args];
  return spawnSync(process.execPath, [CLI, ...argv], {
    cwd,
    input,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('set via stdin, get, has, delete', () => {
  const fake = fakeKeychain();
  assert.equal(cli(fake, ['set', 'svc', 'acct', '--stdin'], { input: 's3cret\n' }).status, 0);
  assert.equal(cli(fake, ['get', 'keychain://svc/acct']).stdout, 's3cret');
  assert.equal(cli(fake, ['has', 'svc', 'acct']).status, 0);
  assert.equal(cli(fake, ['delete', 'svc', 'acct']).status, 0);
  assert.equal(cli(fake, ['has', 'svc', 'acct']).status, 1);
  const missing = cli(fake, ['get', 'svc', 'acct']);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /not found/);
});

test('run injects secrets from a trusted manifest and propagates the exit code', () => {
  const fake = fakeKeychain();
  const { dir } = fake;
  cli(fake, ['set', 'app', 'API_KEY', '--stdin'], { input: 'k-123' });
  writeFileSync(path.join(dir, '.env.keychain'), 'API_KEY=keychain://app\n');
  const script = 'process.stdout.write(process.env.API_KEY); process.exit(7)';

  const untrusted = cli(fake, ['run', '--', process.execPath, '-e', script], { cwd: dir });
  assert.equal(untrusted.status, 1);
  assert.equal(untrusted.stdout, '');
  assert.match(untrusted.stderr, /not trusted/);

  assert.equal(cli(fake, ['trust', '--yes'], { cwd: dir }).status, 0);
  const r = cli(fake, ['run', '--', process.execPath, '-e', script], { cwd: dir });
  assert.equal(r.stdout, 'k-123');
  assert.equal(r.status, 7);

  const ci = cli(fake, ['run', '--', process.execPath, '-e', 'process.stdout.write(process.env.API_KEY)'], {
    env: { API_KEY: 'from-ci' },
    cwd: dir,
  });
  assert.equal(ci.stdout, 'from-ci');
});

test('run fails before starting the command when a secret is missing', () => {
  const fake = fakeKeychain();
  writeFileSync(path.join(fake.dir, '.env.keychain'), 'NOPE=keychain://app\n');
  cli(fake, ['trust', '--yes'], { cwd: fake.dir });
  const r = cli(fake, ['run', '--', process.execPath, '-e', 'console.log("ran")'], { cwd: fake.dir });
  assert.equal(r.status, 1);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /Missing 1 required secret/);
});

test('trust without --yes is refused when not interactive', () => {
  const fake = fakeKeychain();
  writeFileSync(path.join(fake.dir, '.env.keychain'), 'A=keychain://app\n');
  const r = cli(fake, ['trust'], { cwd: fake.dir });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /pass --yes/);
  assert.match(r.stderr, /Services: app/);
});

test('import moves .env values into the keychain, writes and trusts a manifest', () => {
  const fake = fakeKeychain();
  const { dir } = fake;
  writeFileSync(path.join(dir, '.env'), 'A=alpha\nB="beta value"\nEMPTY=\nC=keychain://proj/C\n');
  const r = cli(fake, ['import', '.env', '--service', 'proj'], { cwd: dir });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /The manifest is trusted/);
  const manifest = readFileSync(path.join(dir, '.env.keychain'), 'utf8');
  assert.match(manifest, /^A=keychain:\/\/proj$/m);
  assert.match(manifest, /^B=keychain:\/\/proj$/m);
  assert.match(manifest, /^C=keychain:\/\/proj\/C$/m);
  assert.equal(readFileSync(path.join(dir, '.env'), 'utf8').includes('alpha'), true, '.env is left untouched');
  assert.equal(cli(fake, ['get', 'proj', 'B']).stdout, 'beta value');
  assert.match(r.stderr, /Skipped empty: EMPTY/);
  assert.equal(cli(fake, ['check'], { cwd: dir }).status, 1, 'C is missing but the manifest is usable');
});

test('import does not auto-trust references to other services or unreviewed manifests', () => {
  const fake = fakeKeychain();
  const { dir } = fake;
  writeFileSync(path.join(dir, '.env'), 'A=alpha\nSTOLEN=keychain://victim/token\n');
  const r = cli(fake, ['import', '.env', '--service', 'proj'], { cwd: dir });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /run `keychain-env trust`/);
  assert.match(cli(fake, ['check'], { cwd: dir }).stderr, /not trusted/);

  const other = fakeKeychain();
  writeFileSync(path.join(other.dir, '.env.keychain'), 'KEEP=keychain://victim/token\n');
  writeFileSync(path.join(other.dir, '.env'), 'A=alpha\n');
  const merged = cli(other, ['import', '.env', '--service', 'proj'], { cwd: other.dir });
  assert.match(merged.stderr, /was not trusted/);
  assert.match(cli(other, ['check'], { cwd: other.dir }).stderr, /not trusted/);
});

test('check reports status without printing values', () => {
  const fake = fakeKeychain();
  cli(fake, ['set', 'app', 'A', '--stdin'], { input: 'super-secret-value' });
  writeFileSync(path.join(fake.dir, '.env.keychain'), 'A=keychain://app\nB=keychain://app\n');
  cli(fake, ['trust', '--yes'], { cwd: fake.dir });
  const r = cli(fake, ['check'], { cwd: fake.dir });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /ok\s+A/);
  assert.match(r.stdout, /MISSING B/);
  assert.ok(!r.stdout.includes('super-secret-value'));
  const json = JSON.parse(cli(fake, ['check', '--json'], { cwd: fake.dir }).stdout);
  assert.deepEqual(
    json.map((e) => e.present),
    [true, false],
  );
});

test('usage errors exit 2', () => {
  assert.equal(cli(null, ['bogus']).status, 2);
  assert.equal(cli(null, ['get', 'only-one']).status, 2);
  assert.match(execFileSync(process.execPath, [CLI, 'help'], { encoding: 'utf8' }), /keychain-env trust/);
});
