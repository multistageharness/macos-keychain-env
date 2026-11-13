#!/usr/bin/env node
/**
 * keychain-env — manage and inject macOS keychain secrets.
 * Run `keychain-env help` for usage.
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  DEFAULT_MANIFEST,
  KeychainError,
  createKeychain,
  formatRef,
  isRef,
  parseDotenv,
  parseManifest,
  parseRef,
  trustManifest,
  untrustManifest,
} from '../src/index.js';
import { validateEnvName } from '../src/refs.js';
import { safeEnv } from '../src/security.js';
import { assertManifestTrusted, defaultTrustStore, loadManifest } from '../src/trust.js';

// Absolute paths: never resolve helper binaries through PATH.
const PBPASTE = '/usr/bin/pbpaste';
const PBCOPY = '/usr/bin/pbcopy';

const USAGE = `keychain-env — use the macOS keychain instead of .env files

Usage:
  keychain-env set <service> <account> [options]   Store a secret (hidden prompt, stdin, or clipboard)
  keychain-env get <service> <account>             Print a secret to stdout
  keychain-env has <service> <account>             Exit 0 if the item exists (reads no secret data)
  keychain-env delete <service> <account>          Remove an item
  keychain-env check [--manifest f]                List manifest entries as present/missing (no values)
  keychain-env run [--manifest f] -- <cmd> [args]  Run a command with secrets injected as env vars
  keychain-env import <file> --service <name>      Move values from a .env file into the keychain
                                                   and write keychain:// references to the manifest
  keychain-env ref <service> <account>             Print the keychain:// reference for an item
  keychain-env trust [--manifest f] [--yes]        Review and approve a manifest (required before use)
  keychain-env untrust [--manifest f]              Revoke a manifest approval

<service> <account> may also be given as one keychain://service/account URI.

Options:
  --keychain <path>    Use a specific keychain file instead of the default search list
  --manifest <file>    Manifest of VAR=keychain://... lines (default ${DEFAULT_MANIFEST})
  --no-manifest        Do not read a manifest (run/check)
  --service <name>     Default service for bare VAR lines in the manifest; required for import
  --override           run: replace variables that are already set in the environment
  --stdin              set: read the value from stdin (one trailing newline is removed)
  --from-clipboard     set: read the value from the clipboard (pbpaste)
  --clear-clipboard    set: clear the clipboard afterwards
  --label <text>       set: keychain item label
  --comment <text>     set: keychain item comment
  --allow-argv         set/import: allow values over ~1.9 KB, passed to security via argv
  --keys A,B           import: only import these variables
  --allow-service <s>  Only allow these services (repeatable or comma-separated); also permits
                       keychain:// values from the environment that name them
  --yes                trust: approve without the interactive confirmation
  --timeout <ms>       Per-operation timeout (default 30000)
  --json               check: machine-readable output

Trust:
  A manifest can name ANY keychain item, so run/check/the Node preload refuse a manifest until
  you approve it with \`keychain-env trust\`. The approval pins its content and services; any edit
  requires approving again. keychain:// values found in the environment (e.g. a .env file) may only
  name services that a trusted manifest or --allow-service already permits.

Advanced (testing):
  --security-bin <abs path>   Use another security binary (must be owned by you/root, not writable by others)
  --trust-store <abs path>    Use another trust store file

Environment:
  Variables already set in the environment win over the keychain unless --override is used,
  so CI and non-macOS systems can provide them directly.
`;

const FLAGS_WITH_VALUE = new Set([
  'keychain',
  'manifest',
  'service',
  'label',
  'comment',
  'keys',
  'timeout',
  'allow-service',
  'security-bin',
  'trust-store',
]);
const REPEATABLE = new Set(['allow-service']);
const BOOLEAN_FLAGS = new Set([
  'no-manifest',
  'override',
  'stdin',
  'from-clipboard',
  'clear-clipboard',
  'allow-argv',
  'json',
  'yes',
  'help',
]);

class UsageError extends Error {}

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  let rest = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      rest = argv.slice(i + 1);
      break;
    }
    if (arg === '-h') {
      flags.help = true;
    } else if (arg.startsWith('--')) {
      const [name, inline] = arg.slice(2).split(/=(.*)/s, 2);
      if (FLAGS_WITH_VALUE.has(name)) {
        const value = inline ?? argv[++i];
        if (value === undefined) throw new UsageError(`--${name} needs a value`);
        if (REPEATABLE.has(name)) (flags[name] ??= []).push(...value.split(',').map((v) => v.trim()).filter(Boolean));
        else flags[name] = value;
      } else if (BOOLEAN_FLAGS.has(name)) {
        flags[name] = true;
      } else {
        throw new UsageError(`Unknown option --${name}`);
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags, rest };
}

function refFromArgs(args) {
  let ref;
  if (args.length === 1 && isRef(args[0])) ref = parseRef(args[0]);
  else if (args.length === 2) ref = { service: args[0], account: args[1] };
  else throw new UsageError('Expected <service> <account> or keychain://service/account');
  return ref;
}

function stripOneNewline(s) {
  return s.replace(/\r?\n$/, '');
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

/** Prompt on the TTY without echoing input. */
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const { stdin, stderr } = process;
    stderr.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const done = (fn, arg) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      stderr.write('\n');
      fn(arg);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') return done(resolve, value);
        if (ch === '\u0003') return done(reject, new KeychainError('Canceled', { code: 'CANCELED' }));
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function readSecretValue(flags, ref) {
  if (flags['from-clipboard']) {
    return stripOneNewline(execFileSync(PBPASTE, { encoding: 'utf8', env: safeEnv() }));
  }
  if (flags.stdin || !process.stdin.isTTY) return stripOneNewline(await readStdin());
  const first = await promptHidden(`Value for ${ref.service}/${ref.account}: `);
  const second = await promptHidden('Confirm value: ');
  if (first !== second) throw new UsageError('Values did not match');
  return first;
}

function timeoutOf(flags) {
  if (flags.timeout === undefined) return undefined;
  const n = Number(flags.timeout);
  if (!Number.isFinite(n) || n < 0) throw new UsageError('--timeout must be a number of milliseconds');
  return n;
}

function envOptions(flags) {
  return {
    manifest: flags['no-manifest'] ? false : flags.manifest,
    service: flags.service,
    timeoutMs: timeoutOf(flags),
    allowedServices: flags['allow-service'],
    trustStore: flags['trust-store'],
  };
}

function trustStoreOf(flags) {
  const store = flags['trust-store'] ?? defaultTrustStore();
  if (!path.isAbsolute(store)) throw new UsageError('--trust-store must be an absolute path');
  return store;
}

async function confirm(question) {
  if (!process.stdin.isTTY) return false;
  process.stderr.write(question);
  const answer = await new Promise((resolve) => {
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    process.stdin.once('data', (d) => {
      process.stdin.pause();
      resolve(String(d).trim().toLowerCase());
    });
  });
  return answer === 'y' || answer === 'yes';
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const commands = {
  async set({ positional, flags }, kc) {
    const ref = refFromArgs(positional);
    const value = await readSecretValue(flags, ref);
    if (value === '') throw new UsageError('Refusing to store an empty value');
    await kc.set(ref, value, {
      label: flags.label,
      comment: flags.comment,
      allowArgv: Boolean(flags['allow-argv']),
    });
    if (flags['clear-clipboard']) execFileSync(PBCOPY, { input: '', env: safeEnv() });
    process.stderr.write(`Stored ${formatRef(ref)}\n`);
  },

  async get({ positional, flags }, kc) {
    const value = await kc.get(refFromArgs(positional));
    process.stdout.write(process.stdout.isTTY ? `${value}\n` : value);
  },

  async has({ positional, flags }, kc) {
    const present = await kc.has(refFromArgs(positional));
    process.stderr.write(present ? 'present\n' : 'missing\n');
    return present ? 0 : 1;
  },

  async delete({ positional, flags }, kc) {
    const ref = refFromArgs(positional);
    const deleted = await kc.delete(ref);
    process.stderr.write(deleted ? `Deleted ${formatRef(ref)}\n` : `Not found: ${formatRef(ref)}\n`);
    return deleted ? 0 : 1;
  },

  async ref({ positional, flags }) {
    process.stdout.write(`${formatRef(refFromArgs(positional))}\n`);
  },

  async check({ flags }, kc) {
    const results = await kc.checkEnv({ ...envOptions(flags), target: {} });
    if (flags.json) {
      process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
    } else if (results.length === 0) {
      process.stdout.write(`No entries (looked for ${flags.manifest ?? DEFAULT_MANIFEST}).\n`);
    } else {
      for (const r of results) {
        const status = r.present ? 'ok     ' : r.optional ? 'absent ' : 'MISSING';
        process.stdout.write(`${status} ${r.name.padEnd(28)} ${formatRef(r, r.name)}\n`);
      }
    }
    return results.some((r) => !r.present && !r.optional) ? 1 : 0;
  },

  async trust({ flags }) {
    const file = flags.manifest ?? DEFAULT_MANIFEST;
    const store = trustStoreOf(flags);
    const manifest = loadManifest(file, { defaultService: flags.service });
    if (!manifest) throw new KeychainError(`Manifest not found: ${file}`, { code: 'MANIFEST_NOT_FOUND' });
    process.stderr.write(`Manifest ${manifest.path} requests:\n`);
    for (const e of manifest.entries) {
      process.stderr.write(`  ${e.name.padEnd(28)} ${formatRef(e, e.name)}${e.optional ? ' (optional)' : ''}\n`);
    }
    const services = [...new Set(manifest.entries.map((e) => e.service))].sort();
    process.stderr.write(`Services: ${services.join(', ') || '(none)'}\n`);
    if (!flags.yes && !(await confirm('Allow processes started from this manifest to read these items? [y/N] '))) {
      process.stderr.write(process.stdin.isTTY ? 'Not trusted.\n' : 'Not trusted (non-interactive: pass --yes).\n');
      return 1;
    }
    trustManifest(file, { defaultService: flags.service, store });
    process.stderr.write(`Trusted ${manifest.path}\n`);
    return 0;
  },

  async untrust({ flags }) {
    const file = flags.manifest ?? DEFAULT_MANIFEST;
    const removed = untrustManifest(file, { store: trustStoreOf(flags) });
    process.stderr.write(removed ? `Revoked trust for ${file}\n` : `${file} was not trusted\n`);
    return removed ? 0 : 1;
  },

  async run({ flags, rest }, kc) {
    if (rest.length === 0) throw new UsageError('Usage: keychain-env run [options] -- <command> [args...]');
    const env = { ...process.env };
    await kc.loadEnv({ ...envOptions(flags), target: env, override: Boolean(flags.override) });
    const child = spawn(rest[0], rest.slice(1), { stdio: 'inherit', env });
    const forward = (sig) => () => child.kill(sig);
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, forward(sig));
    return new Promise((resolve, reject) => {
      child.on('error', (err) =>
        reject(err.code === 'ENOENT' ? new UsageError(`Command not found: ${rest[0]}`) : err),
      );
      child.on('exit', (code, signal) => {
        if (signal) {
          process.removeAllListeners(signal);
          process.kill(process.pid, signal);
        }
        resolve(code ?? 1);
      });
    });
  },

  async import({ positional, flags }, kc) {
    if (positional.length !== 1) throw new UsageError('Usage: keychain-env import <file> --service <name>');
    if (!flags.service) throw new UsageError('import requires --service <name>');
    const file = positional[0];
    const manifestPath = flags.manifest ?? DEFAULT_MANIFEST;
    if (path.resolve(file) === path.resolve(manifestPath)) {
      throw new UsageError('The source file and the manifest must be different files');
    }
    const store = trustStoreOf(flags);
    // Re-approve the merged manifest only if nothing unreviewed is carried over:
    // either there was no manifest, or the existing one was already trusted.
    const before = loadManifest(manifestPath);
    let carryTrust = !before;
    if (before) {
      try {
        assertManifestTrusted(before, { store });
        carryTrust = true;
      } catch {
        carryTrust = false;
      }
    }
    const only = flags.keys ? new Set(flags.keys.split(',').map((k) => k.trim())) : undefined;
    const entries = parseDotenv(readFileSync(file, 'utf8')).filter(([k]) => !only || only.has(k));

    // Validate everything before writing anything to the keychain.
    for (const [name, value] of entries) {
      validateEnvName(name, { where: file });
      if (isRef(value)) {
        // A reference copied from the source file was not reviewed by the user;
        // do not let it ride along on an automatic approval.
        if (parseRef(value, name).service !== flags.service) carryTrust = false;
      }
    }

    const refs = new Map();
    const skipped = [];
    for (const [name, value] of entries) {
      if (isRef(value)) {
        refs.set(name, value);
      } else if (value === '') {
        skipped.push(name);
      } else {
        const ref = { service: flags.service, account: name, keychain: flags.keychain };
        await kc.set(ref, value, { allowArgv: Boolean(flags['allow-argv']) });
        refs.set(name, formatRef(ref, name));
        process.stderr.write(`Stored ${name} -> ${formatRef(ref, name)}\n`);
      }
    }

    // Merge into an existing manifest: replace matching lines, append new ones.
    const lines = existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8').replace(/\n$/, '').split('\n') : [
      '# Secrets for this project live in the macOS keychain. This file holds only references',
      '# and is safe to commit. Load with: keychain-env run -- <cmd>, or',
      '# node --import macos-keychain-env/register app.js',
    ];
    const seen = new Set();
    const merged = lines.map((line) => {
      const m = /^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*=/.exec(line);
      if (m && refs.has(m[1])) {
        seen.add(m[1]);
        return `${m[1]}=${refs.get(m[1])}`;
      }
      return line;
    });
    for (const [name, ref] of refs) if (!seen.has(name)) merged.push(`${name}=${ref}`);
    const output = `${merged.join('\n')}\n`;
    parseManifest(output, { file: manifestPath }); // validate before writing
    writeFileSync(manifestPath, output);
    if (carryTrust) trustManifest(manifestPath, { store });

    process.stderr.write(
      `\nImported ${refs.size} variable(s) into ${manifestPath}.` +
        (skipped.length ? ` Skipped empty: ${skipped.join(', ')}.` : '') +
        (carryTrust
          ? ` The manifest is trusted.`
          : ` The existing manifest was not trusted, so review it and run \`keychain-env trust\`.`) +
        `\n${file} was NOT modified. Verify with \`keychain-env check\`, then remove the plaintext values from ${file}.\n`,
    );
  },
};

async function main(argv) {
  const [command, ...args] = argv;
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (command === '--version' || command === 'version') {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    process.stdout.write(`${pkg.version}\n`);
    return 0;
  }
  const handler = Object.hasOwn(commands, command) ? commands[command] : undefined;
  if (!handler) throw new UsageError(`Unknown command: ${command}`);
  const parsed = parseArgs(args);
  if (parsed.flags.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  const kc = createKeychain({
    timeoutMs: timeoutOf(parsed.flags) ?? 30_000,
    keychain: parsed.flags.keychain,
    securityPath: parsed.flags['security-bin'],
    trustStore: parsed.flags['trust-store'] === undefined ? undefined : trustStoreOf(parsed.flags),
  });
  return (await handler(parsed, kc)) ?? 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    if (err instanceof UsageError) {
      process.stderr.write(`keychain-env: ${err.message}\nRun \`keychain-env help\` for usage.\n`);
      process.exitCode = 2;
    } else if (err instanceof KeychainError) {
      process.stderr.write(`keychain-env: ${err.message}\n`);
      process.exitCode = 1;
    } else {
      process.stderr.write(`keychain-env: ${err?.stack ?? err}\n`);
      process.exitCode = 1;
    }
  },
);
