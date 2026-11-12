import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatRef, parseDotenv, parseManifest, parseRef } from '../src/refs.js';
import { MAX_INTERACTIVE_LINE, parsePasswordOutput, planSet } from '../src/security.js';
import { redact } from '../src/errors.js';

test('parseRef: service/account, defaults, params, percent-encoding', () => {
  assert.deepEqual(parseRef('keychain://myapp/API_KEY'), { service: 'myapp', account: 'API_KEY', optional: false });
  assert.deepEqual(parseRef('keychain://myapp', 'TOKEN'), { service: 'myapp', account: 'TOKEN', optional: false });
  assert.deepEqual(parseRef('keychain://my%20app/a%2Fb?optional&keychain=%2Ftmp%2Fx.keychain-db'), {
    service: 'my app',
    account: 'a/b',
    optional: true,
    keychain: '/tmp/x.keychain-db',
  });
  assert.equal(parseRef('keychain://svc/acct/with/slashes').account, 'acct/with/slashes');
  assert.throws(() => parseRef('keychain://svc'), { code: 'INVALID_REF' });
  assert.throws(() => parseRef('https://x'), { code: 'INVALID_REF' });
});

test('formatRef round-trips and omits account equal to the var name', () => {
  assert.equal(formatRef({ service: 'myapp', account: 'API_KEY' }, 'API_KEY'), 'keychain://myapp');
  const ref = { service: 'my app', account: 'u@x.com', optional: true, keychain: '/k db' };
  assert.deepEqual(parseRef(formatRef(ref)), ref);
});

test('parsePasswordOutput handles quoted, hex and empty forms', () => {
  assert.equal(parsePasswordOutput('password: "plain-Value 123"\n'), 'plain-Value 123');
  assert.equal(parsePasswordOutput('password: "has "quotes" inside"\n'), 'has "quotes" inside');
  assert.equal(
    parsePasswordOutput('keychain: "x"\npassword: 0x6C696E65310A6C696E653220227122  "line1\\012line2 "q""\n'),
    'line1\nline2 "q"',
  );
  assert.equal(parsePasswordOutput('password: \nkeychain: "/x"\n'), '');
  assert.equal(parsePasswordOutput('no password line'), undefined);
});

test('planSet keeps the value out of argv and escapes names', () => {
  const plan = planSet({ service: 'svc "q" \\ x', account: 'a b' }, 'top secret');
  assert.deepEqual(plan.args, ['-i']);
  assert.ok(!plan.args.join(' ').includes('top secret'));
  assert.equal(
    plan.input,
    `add-generic-password -U -s "svc \\"q\\" \\\\ x" -a "a b" -X ${Buffer.from('top secret').toString('hex')}\n`,
  );
});

test('planSet refuses oversize values unless allowArgv', () => {
  const big = 'x'.repeat(MAX_INTERACTIVE_LINE);
  assert.throws(() => planSet({ service: 's', account: 'a' }, big), { code: 'VALUE_TOO_LARGE' });
  const plan = planSet({ service: 's', account: 'a' }, big, { allowArgv: true });
  assert.equal(plan.input, undefined);
  assert.deepEqual(plan.args.slice(0, 6), ['add-generic-password', '-U', '-s', 's', '-a', 'a']);
});

test('planSet rejects newlines in names', () => {
  assert.throws(() => planSet({ service: 'a\nb', account: 'x' }, 'v'), { code: 'INVALID_ARGUMENT' });
});

test('redact strips long hex runs from stderr', () => {
  assert.equal(redact('unknown command "41414141414141414141"'), 'unknown command "[redacted]"');
});

test('parseDotenv handles quotes, export, comments and multi-line values', () => {
  const src = [
    '# comment',
    'export A=1',
    'B="two words" # trailing',
    "C='single $quoted'",
    'D="line1\\nline2"',
    'E=',
    'F="multi',
    'line"',
    'G=keychain://svc/G',
  ].join('\n');
  assert.deepEqual(parseDotenv(src), [
    ['A', '1'],
    ['B', 'two words'],
    ['C', 'single $quoted'],
    ['D', 'line1\nline2'],
    ['E', ''],
    ['F', 'multi\nline'],
    ['G', 'keychain://svc/G'],
  ]);
});

test('parseManifest accepts refs and bare names, rejects plaintext values', () => {
  const entries = parseManifest('# x\nA=keychain://svc/acct\nB # note\nC=keychain://svc?optional\n', {
    defaultService: 'def',
  });
  assert.deepEqual(entries, [
    { name: 'A', service: 'svc', account: 'acct', optional: false },
    { name: 'B', service: 'def', account: 'B', optional: false },
    { name: 'C', service: 'svc', account: 'C', optional: true },
  ]);
  assert.throws(() => parseManifest('A=sk-live-123'), { code: 'INVALID_MANIFEST' });
  assert.throws(() => parseManifest('A'), { code: 'INVALID_MANIFEST' });
});
