#!/usr/bin/env node
// Stand-in for /usr/bin/security used by unit tests. Stores items in the JSON
// file named by $FAKE_KEYCHAIN_STORE and mimics the real tool's output format
// and exit codes. $FAKE_KEYCHAIN_DELAY_MS adds latency; $FAKE_KEYCHAIN_LOG
// appends one line per invocation (to count process spawns);
// $FAKE_KEYCHAIN_FAIL_ECHO=1 makes `-i` fail and echo its input like the real
// tool does. The settings are baked into a per-test wrapper (test/helpers.js).
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';

const store = process.env.FAKE_KEYCHAIN_STORE;
const load = () => (existsSync(store) ? JSON.parse(readFileSync(store, 'utf8')) : {});
const save = (db) => writeFileSync(store, JSON.stringify(db));
const key = (s, a, k) => `${k ?? ''}|${s}|${a}`;

function opts(argv) {
  const o = { flags: new Set(), rest: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (/^-[saXlj]$/.test(a)) o[a[1]] = argv[++i];
    else if (a === '-T') (o.T ??= []).push(argv[++i]);
    else if (/^-[A-Za-z]$/.test(a)) o.flags.add(a[1]);
    else o.rest.push(a);
  }
  return o;
}

// Tokenise a `security -i` line: double quotes with backslash escapes.
function tokenize(line) {
  const out = [];
  let cur = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      cur ??= '';
      for (i++; i < line.length && line[i] !== '"'; i++) cur += line[i] === '\\' ? line[++i] : line[i];
    } else if (c === ' ') {
      if (cur !== null) out.push(cur);
      cur = null;
    } else cur = (cur ?? '') + c;
  }
  if (cur !== null) out.push(cur);
  return out;
}

const notFound = () => {
  process.stderr.write('security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n');
  return 44;
};

function exec([cmd, ...argv]) {
  const o = opts(argv);
  const db = load();
  const k = key(o.s, o.a, o.rest[0]);
  switch (cmd) {
    case 'find-generic-password': {
      if (!(k in db)) return notFound();
      process.stdout.write(`keychain: "/fake.keychain-db"\nattributes:\n    "acct"<blob>="${o.a}"\n`);
      if (o.flags.has('g')) {
        const buf = Buffer.from(db[k], 'hex');
        const text = buf.toString('utf8');
        const printable = /^[\x20-\x7e]*$/.test(text);
        process.stderr.write(
          buf.length === 0
            ? 'password: \n'
            : printable
              ? `password: "${text}"\n`
              : `password: 0x${buf.toString('hex').toUpperCase()}  "${text.replace(/\n/g, '\\012')}"\n`,
        );
      }
      return 0;
    }
    case 'add-generic-password': {
      if (!o.flags.has('U') && k in db) return 45;
      db[k] = o.X ?? Buffer.from(o.w ?? '').toString('hex');
      save(db);
      return 0;
    }
    case 'delete-generic-password': {
      if (!(k in db)) return notFound();
      delete db[k];
      save(db);
      process.stdout.write('password has been deleted.\n');
      return 0;
    }
    default:
      process.stderr.write(`security: unknown command "${cmd}"\n`);
      return 1;
  }
}

const args = process.argv.slice(2);
if (process.env.FAKE_KEYCHAIN_LOG) appendFileSync(process.env.FAKE_KEYCHAIN_LOG, `${args.join(' ')}\n`);
const delay = Number(process.env.FAKE_KEYCHAIN_DELAY_MS ?? 0);
if (delay) await new Promise((r) => setTimeout(r, delay));

if (args[0] === '-i') {
  let input = '';
  for await (const c of process.stdin) input += c;
  let code = 0;
  if (process.env.FAKE_KEYCHAIN_FAIL_ECHO === '1') {
    // Mimic real `security -i` on a split line: it echoes the input on stderr.
    process.stderr.write(`security: unknown command "${input.trim()}"\n${input.trim()}: returned 1\n`);
    process.exit(1);
  }
  for (const line of input.split('\n').filter(Boolean)) code = exec(tokenize(line)) || code;
  process.exitCode = code;
} else {
  process.exitCode = exec(args);
}
