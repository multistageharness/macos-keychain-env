// Regression tests for the security findings:
//   F1 unvalidated keychain reference parameters
//   F2 cross-service secret access via untrusted manifests / env references
//   F3 incomplete redaction of short secrets
//   F4 unqualified binary execution (PATH / environment hijacking)
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { describe, test } from 'node:test';
import { createKeychain, parseManifest, parseRef, redact, trustManifest } from '../src/index.js';
import { planSet } from '../src/security.js';
import { fakeKeychain } from './helpers.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const script = (name) => path.join(ROOT, 'bin', name);
const code = (c) => ({ code: c });

describe('F1: keychain reference validation', () => {
  test('parseRef rejects tampered or option-like references', () => {
    for (const bad of [
      'keychain://svc/acct?keychain=-A', // option injection via positional keychain
      'keychain://svc/acct?evil=1', // unknown parameter
      'keychain://svc/acct?optional&optional', // repeated parameter
      'keychain://svc/acct?optional=maybe',
      'keychain://svc/acct#frag',
      'keychain://svc/', // empty account
      'keychain://-s/acct',
      'keychain://svc/-A',
      'keychain://svc%0Ainjected/acct', // newline
      'keychain://svc%E2%80%8B/acct', // zero-width space (lookalike)
      'keychain://%20svc/acct', // leading whitespace
      'keychain://svc/acct?keychain=relative/dir/x.keychain-db',
      'keychain://svc/acct?keychain=%2Ftmp%2F..%2Fx.keychain-db',
      'keychain://svc/acct?keychain=%2Ftmp%2Fnot-a-keychain',
      `keychain://${'s'.repeat(256)}/acct`,
    ]) {
      assert.throws(() => parseRef(bad), code('INVALID_REF'), bad);
    }
    assert.deepEqual(parseRef('keychain://svc/acct?keychain=%2Ftmp%2Fteam.keychain-db&optional=false'), {
      service: 'svc',
      account: 'acct',
      optional: false,
      keychain: '/tmp/team.keychain-db',
    });
  });

  test('object references must have exactly the documented shape', async () => {
    const { kc, calls } = fakeKeychain();
    await assert.rejects(kc.get({ service: 'svc', account: 'a', extra: 1 }), code('INVALID_REF'));
    await assert.rejects(kc.get({ service: 'svc', account: 'a', optional: 'yes' }), code('INVALID_REF'));
    await assert.rejects(kc.get({ service: ['svc'], account: 'a' }), code('INVALID_REF'));
    await assert.rejects(kc.has({ service: 'svc', account: 'a', keychain: '-h' }), code('INVALID_REF'));
    assert.equal(calls().length, 0, 'nothing reached the security binary');
  });

  test('set options cannot inject flags', () => {
    const ref = { service: 'svc', account: 'acct' };
    assert.throws(() => planSet({ ...ref, keychain: '-A' }, 'v'), code('INVALID_ARGUMENT'));
    assert.throws(() => planSet(ref, 'v', { label: '-A' }), code('INVALID_ARGUMENT'));
    assert.throws(() => planSet(ref, 'v', { trustedApps: ['relative/app'] }), code('INVALID_ARGUMENT'));
    assert.throws(() => planSet(ref, 'v', { trustedApps: '/Applications/X.app' }), code('INVALID_ARGUMENT'));
    assert.doesNotThrow(() => planSet(ref, 'v', { trustedApps: ['', '/Applications/X.app'] }));
    assert.throws(() => createKeychain({ keychain: '-A' }), code('INVALID_ARGUMENT'));
    assert.throws(() => createKeychain({ allowedServices: ['-x'] }), code('INVALID_ARGUMENT'));
  });

  test('manifests reject protected, invalid and duplicate variable names', () => {
    for (const bad of [
      'PATH=keychain://svc',
      'NODE_OPTIONS=keychain://svc',
      'DYLD_INSERT_LIBRARIES=keychain://svc',
      'LD_PRELOAD=keychain://svc',
      'KEYCHAIN_ENV_SERVICE=keychain://svc',
      'BAD-NAME=keychain://svc',
      'A=keychain://svc\nA=keychain://svc',
      'A=keychain://svc/acct?keychain=-A',
    ]) {
      assert.throws(() => parseManifest(bad), code('INVALID_MANIFEST'), bad);
    }
  });

  test('bash scripts reject option-like and invisible identifiers before calling security', () => {
    const fake = fakeKeychain();
    const run = (args) => spawnSync(script('keychain-get.sh'), [...args, '--security-bin', fake.securityBin]);
    for (const args of [
      ['-A', 'acct'],
      ['svc', '-A'],
      ['svc', 'acct', '--keychain', '-A'],
      ['svc', 'acct', '--keychain', 'relative/x.keychain-db'],
      ['svc', 'acct', '--keychain', '/tmp/x'],
      ['svc​', 'acct'],
      ['svc\u0085', 'acct'],
      [' svc', 'acct'],
      ['svc\tx', 'acct'],
    ]) {
      assert.equal(run(args).status, 2, JSON.stringify(args));
    }
    assert.equal(fake.calls().length, 0);
  });
});

describe('F2: manifest and service boundaries', () => {
  test('an unapproved manifest is refused before any keychain access', async () => {
    const { kc, dir, calls } = fakeKeychain();
    writeFileSync(path.join(dir, '.env.keychain'), 'STOLEN=keychain://other-project/token\n');
    await assert.rejects(kc.loadEnv({ cwd: dir, target: {} }), code('UNTRUSTED_MANIFEST'));
    await assert.rejects(kc.checkEnv({ cwd: dir }), code('UNTRUSTED_MANIFEST'));
    assert.throws(() => kc.loadEnvSync({ cwd: dir, target: {} }), code('UNTRUSTED_MANIFEST'));
    assert.equal(calls().length, 0);
  });

  test('approval is pinned to content and to the approved services', async () => {
    const { kc, dir, trustStore } = fakeKeychain();
    await kc.set('keychain://app/A', 'a');
    const file = path.join(dir, '.env.keychain');
    writeFileSync(file, 'A=keychain://app\n');
    trustManifest('.env.keychain', { cwd: dir, store: trustStore });
    const target = {};
    await kc.loadEnv({ cwd: dir, target });
    assert.equal(target.A, 'a');

    writeFileSync(file, 'A=keychain://app\nB=keychain://victim/token\n');
    await assert.rejects(kc.loadEnv({ cwd: dir, target: {} }), /changed since it was approved/);

    // Bare lines resolve through the default service: approval must cover it.
    writeFileSync(file, 'A\n');
    trustManifest('.env.keychain', { cwd: dir, store: trustStore, defaultService: 'app' });
    await kc.loadEnv({ cwd: dir, target: {}, service: 'app' });
    await assert.rejects(kc.loadEnv({ cwd: dir, target: {}, service: 'victim' }), /service "victim" was not approved/);
  });

  test('keychain:// values from the environment cannot reach other services', async () => {
    const { kc, dir, calls, trustStore } = fakeKeychain();
    await kc.set('keychain://app/A', 'a');
    await kc.set('keychain://victim/token', 'stolen');
    const before = calls().length;

    await assert.rejects(
      kc.loadEnv({ cwd: dir, target: { X: 'keychain://victim/token' } }),
      code('SERVICE_NOT_ALLOWED'),
    );
    await assert.rejects(
      kc.resolveEnv({ X: 'keychain://victim/token' }),
      code('SERVICE_NOT_ALLOWED'),
    );
    // Same service as trusted code, but a different keychain file: refused.
    await assert.rejects(
      kc.loadEnv({ keys: ['A'], service: 'app', manifest: false, target: { X: 'keychain://app/A?keychain=%2Ftmp%2Fo.keychain-db' } }),
      code('SERVICE_NOT_ALLOWED'),
    );
    assert.equal(calls().length, before, 'refused before spawning security');

    // A service the app itself uses is fine, and allowedServices can opt in explicitly.
    const t1 = { X: 'keychain://app/A' };
    await kc.loadEnv({ cwd: dir, keys: ['A'], service: 'app', target: t1 });
    assert.equal(t1.X, 'a');
    const t2 = { X: 'keychain://victim/token' };
    await kc.loadEnv({ cwd: dir, target: t2, allowedServices: ['victim'] });
    assert.equal(t2.X, 'stolen');

    // A trusted manifest's services also count.
    writeFileSync(path.join(dir, '.env.keychain'), 'A=keychain://app\n');
    trustManifest('.env.keychain', { cwd: dir, store: trustStore });
    const t3 = { Y: 'keychain://app/A' };
    await kc.loadEnv({ cwd: dir, target: t3 });
    assert.equal(t3.Y, 'a');
  });

  test('allowedServices caps every source, including code', async () => {
    const { kc } = fakeKeychain({ allowedServices: ['app'] });
    await assert.rejects(
      kc.loadEnv({ manifest: false, target: {}, entries: { T: 'keychain://victim/token' } }),
      code('SERVICE_NOT_ALLOWED'),
    );
  });

  test('requireTrustedManifest: false is an explicit code-level opt-out', async () => {
    const { kc, dir } = fakeKeychain({ requireTrustedManifest: false });
    await kc.set('keychain://app/A', 'a');
    writeFileSync(path.join(dir, '.env.keychain'), 'A=keychain://app\n');
    const target = {};
    await kc.loadEnv({ cwd: dir, target });
    assert.equal(target.A, 'a');
  });

  test('the trust store must be private to the user', () => {
    const { dir, trustStore } = fakeKeychain();
    writeFileSync(path.join(dir, '.env.keychain'), 'A=keychain://app\n');
    trustManifest('.env.keychain', { cwd: dir, store: trustStore });
    chmodSync(trustStore, 0o666);
    assert.throws(() => trustManifest('.env.keychain', { cwd: dir, store: trustStore }), code('UNSAFE_TRUST_STORE'));

    const linkDir = path.join(dir, 'linked');
    mkdirSync(linkDir, { mode: 0o700 });
    const link = path.join(linkDir, 'trusted.json');
    symlinkSync(trustStore, link);
    assert.throws(() => trustManifest('.env.keychain', { cwd: dir, store: link }), code('UNSAFE_TRUST_STORE'));
    assert.throws(() => trustManifest('.env.keychain', { cwd: dir, store: 'relative.json' }), code('UNSAFE_TRUST_STORE'));
  });

  test('the --import preload refuses an untrusted manifest', () => {
    const { dir } = fakeKeychain();
    writeFileSync(path.join(dir, '.env.keychain'), 'STOLEN=keychain://other-project/token\n');
    const r = spawnSync(
      process.execPath,
      ['--import', path.join(ROOT, 'src', 'register.js'), '-e', 'console.log("app started")'],
      { cwd: dir, encoding: 'utf8' },
    );
    assert.notEqual(r.status, 0);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /not trusted/);
  });
});

describe('F3: redaction of short secrets', () => {
  test('redact masks known secrets of any length in plain and hex forms', () => {
    assert.equal(redact('pin=7 hex=37 HEX=37', ['7']), 'pin=[redacted] hex=[redacted] HEX=[redacted]');
    assert.equal(redact('token ab / 6162 / 6162', ['ab']), 'token [redacted] / [redacted] / [redacted]');
    assert.equal(redact('k=Zq9 5a7139 5A7139', ['Zq9']), 'k=[redacted] [redacted] [redacted]');
    assert.equal(redact('add-generic-password -X 3132 x'), 'add-generic-password -X [redacted] x');
    assert.equal(redact('cmd -w "short" next'), 'cmd -w [redacted] next');
    assert.equal(redact('password: "1234"\nok'), 'password: [redacted]\nok');
    assert.equal(redact('blob 0xDEADBEEF and deadbeefcafe'), 'blob [redacted] and [redacted]');
  });

  test('write failures never surface security output, whatever the secret length', async () => {
    const { kc } = fakeKeychain({}, { failEcho: true });
    for (const secret of ['7', '12', 'ab', 'Zq9', 'PIN9', 'sk-short']) {
      const hex = Buffer.from(secret).toString('hex');
      const err = await kc.set('keychain://svc/pin', secret).then(
        () => assert.fail('expected failure'),
        (e) => e,
      );
      const everything = `${err.message}\n${err.stack}\n${inspect(err, { depth: 5 })}`;
      assert.ok(!everything.toLowerCase().includes(hex), `hex of ${JSON.stringify(secret)} leaked`);
      assert.ok(!everything.includes('-X'), 'command line leaked');
      assert.match(err.message, /output withheld/);
    }
  });

  test('CLI and bash write failures do not echo short secrets', () => {
    const fake = fakeKeychain({}, { failEcho: true });
    const hex = Buffer.from('42').toString('hex');
    const cli = spawnSync(
      process.execPath,
      [path.join(ROOT, 'bin', 'keychain-env.js'), 'set', ...fake.cliFlags, 'svc', 'pin', '--stdin'],
      { input: '42', encoding: 'utf8' },
    );
    assert.equal(cli.status, 1);
    assert.ok(!`${cli.stdout}${cli.stderr}`.includes(hex), cli.stderr);

    for (const name of ['keychain-add.sh', 'keychain-update.sh']) {
      const r = spawnSync(script(name), ['svc', 'pin', '--stdin', '--security-bin', fake.securityBin], {
        input: '42',
        encoding: 'utf8',
      });
      assert.equal(r.status, 1, name);
      assert.ok(!`${r.stdout}${r.stderr}`.includes(hex), `${name}: ${r.stderr}`);
    }
  });
});

describe('F4: binary execution', () => {
  test('KEYCHAIN_ENV_SECURITY_BIN in the environment is ignored', () => {
    const { dir } = fakeKeychain();
    const marker = path.join(dir, 'hijacked');
    const evil = path.join(dir, 'evil-security');
    writeFileSync(evil, `#!/bin/sh\ntouch '${marker}'\nexit 44\n`);
    chmodSync(evil, 0o755);
    // Uses the real /usr/bin/security for a read-only existence check of an item
    // that cannot exist; it reads no secret data and never prompts.
    const r = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { hasSecret } from '${path.join(ROOT, 'src', 'index.js')}';
         console.log(await hasSecret('keychain://macos-keychain-env-hijack-test/none'));`,
      ],
      { encoding: 'utf8', env: { ...process.env, KEYCHAIN_ENV_SECURITY_BIN: evil } },
    );
    assert.equal(existsSync(marker), false, 'attacker binary ran');
    if (process.platform === 'darwin') assert.equal(r.stdout.trim(), 'false', r.stderr);
  });

  test('securityPath must be a safe absolute executable', () => {
    const { dir } = fakeKeychain();
    assert.throws(() => createKeychain({ securityPath: 'security' }), code('INVALID_ARGUMENT'));
    assert.throws(() => createKeychain({ securityPath: './security' }), code('INVALID_ARGUMENT'));
    const writable = path.join(dir, 'writable-security');
    writeFileSync(writable, '#!/bin/sh\nexit 0\n');
    chmodSync(writable, 0o777);
    assert.throws(() => createKeychain({ securityPath: writable }), code('UNSAFE_BINARY'));
    assert.throws(() => createKeychain({ securityPath: dir }), code('UNSAFE_BINARY'));
  });

  test('security runs with a fixed environment, not the caller\'s', async () => {
    const { dir } = fakeKeychain();
    const dump = path.join(dir, 'env.txt');
    const bin = path.join(dir, 'env-dumper');
    writeFileSync(bin, `#!/bin/sh\n/usr/bin/env > '${dump}'\nexit 44\n`);
    chmodSync(bin, 0o755);
    const saved = { ...process.env };
    Object.assign(process.env, {
      PATH: `${dir}:${process.env.PATH}`,
      DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib',
      INJECTED_SECRET_HINT: 'x',
      LC_ALL: 'tr_TR.UTF-8',
    });
    try {
      assert.equal(await createKeychain({ securityPath: bin }).has('keychain://svc/acct'), false);
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
    const env = Object.fromEntries(
      readFileSync(dump, 'utf8')
        .trim()
        .split('\n')
        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
    );
    assert.equal(env.PATH, '/usr/bin:/bin:/usr/sbin:/sbin');
    assert.equal(env.LC_ALL, 'C');
    assert.equal(env.DYLD_INSERT_LIBRARIES, undefined);
    assert.equal(env.INJECTED_SECRET_HINT, undefined);
  });

  test('CLI helper binaries are invoked by absolute path', () => {
    const src = readFileSync(path.join(ROOT, 'bin', 'keychain-env.js'), 'utf8');
    assert.match(src, /const PBPASTE = '\/usr\/bin\/pbpaste'/);
    assert.match(src, /const PBCOPY = '\/usr\/bin\/pbcopy'/);
    assert.doesNotMatch(src, /execFileSync\('pb/);
    for (const name of ['keychain-add.sh', 'keychain-update.sh', 'keychain-get.sh']) {
      const sh = readFileSync(script(name), 'utf8');
      // Every external tool is referenced by absolute path.
      assert.doesNotMatch(sh, /(^|[|;(]\s*|\$\()\s*(pbpaste|xxd|tr|sed|grep|cat|stat|id)\b/m, name);
    }
  });

  test('bash scripts ignore PATH, BASH_ENV and exported functions', () => {
    const fake = fakeKeychain();
    const { dir } = fake;
    const evilDir = path.join(dir, 'evil-bin');
    mkdirSync(evilDir);
    const marker = path.join(dir, 'hijacked');
    for (const tool of ['security', 'xxd', 'tr', 'sed', 'grep', 'cat', 'stat', 'id', 'pbpaste']) {
      writeFileSync(path.join(evilDir, tool), `#!/bin/sh\necho ${tool} >> '${marker}'\nexit 0\n`);
      chmodSync(path.join(evilDir, tool), 0o755);
    }
    const bashEnv = path.join(dir, 'bash_env.sh');
    writeFileSync(bashEnv, `echo BASH_ENV >> '${marker}'\n`);
    const env = {
      ...process.env,
      PATH: `${evilDir}:${process.env.PATH}`,
      BASH_ENV: bashEnv,
      ENV: bashEnv,
      'BASH_FUNC_grep%%': `() { echo func >> '${marker}'; }`,
      'BASH_FUNC_grep()': `() { echo func >> '${marker}'; }`,
    };
    const flags = ['--security-bin', fake.securityBin];
    const add = spawnSync(script('keychain-add.sh'), ['svc', 'k', '--stdin', ...flags], { input: 'v1', env });
    assert.equal(add.status, 0, String(add.stderr));
    const upd = spawnSync(script('keychain-update.sh'), ['svc', 'k', '--stdin', ...flags], { input: 'v2', env });
    assert.equal(upd.status, 0, String(upd.stderr));
    const get = spawnSync(script('keychain-get.sh'), ['svc', 'k', ...flags], { env, encoding: 'utf8' });
    assert.equal(get.stdout, 'v2');
    assert.equal(existsSync(marker), false, existsSync(marker) ? readFileSync(marker, 'utf8') : '');
  });

  test('bash --security-bin must be a safe absolute executable', () => {
    const { dir } = fakeKeychain();
    const writable = path.join(dir, 'writable-security');
    writeFileSync(writable, '#!/bin/sh\nexit 0\n');
    chmodSync(writable, 0o777);
    for (const bin of ['security', writable, dir]) {
      const r = spawnSync(script('keychain-get.sh'), ['svc', 'acct', '--security-bin', bin]);
      assert.equal(r.status, 2, bin);
    }
  });
});
