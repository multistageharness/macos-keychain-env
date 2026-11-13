/**
 * Thin, dependency-free wrapper around macOS `/usr/bin/security`.
 *
 * Design notes (verified against `security` on macOS):
 * - Reads use `find-generic-password -g`. Plain `-w` prints printable values
 *   verbatim but non-printable ones (e.g. containing "\n") as bare hex, which
 *   is ambiguous. `-g` marks hex output with a `0x` prefix.
 * - Writes go through `security -i` on stdin with `-X <hex>`, so the value never
 *   appears in argv (visible to every user via `ps`) and needs no escaping.
 * - `security -i` reads lines into a 4096-byte buffer; longer lines are split
 *   and the first part is SILENTLY stored truncated. We therefore refuse lines
 *   over MAX_INTERACTIVE_LINE and only fall back to argv when explicitly allowed.
 * - The `-w` prompt path truncates silently at 128 bytes, so it is never used.
 */
import { spawn, spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { userInfo } from 'node:os';
import path from 'node:path';
import { KeychainError, errorFromExit } from './errors.js';

export const DEFAULT_SECURITY_PATH = '/usr/bin/security';
export const MAX_INTERACTIVE_LINE = 4000;
export const MAX_NAME_LENGTH = 255;
const MAX_KEYCHAIN_PATH = 1024;

// ---------------------------------------------------------------------------
// Binary resolution and process environment
//
// The binary is never looked up on PATH or taken from an environment variable:
// a rogue .env (loaded by dotenv before us) must not be able to swap in a
// program that would receive secrets on stdin. Only code can override it, via
// the `securityPath` option, and the override must be a safe absolute path.
// ---------------------------------------------------------------------------

const verifiedBinaries = new Set();

/** Throw unless `file` is an absolute, regular file only root or this user can modify. */
export function assertSafeExecutable(file, what = 'securityPath') {
  if (typeof file !== 'string' || !path.isAbsolute(file) || /[\0-\x1f\x7f]/.test(file)) {
    throw new KeychainError(`${what} must be an absolute path`, { code: 'INVALID_ARGUMENT' });
  }
  if (verifiedBinaries.has(file)) return file;
  let st;
  try {
    st = statSync(file);
  } catch {
    throw new KeychainError(`${what} does not exist: ${file}`, {
      code: process.platform === 'darwin' ? 'SECURITY_NOT_FOUND' : 'UNSUPPORTED_PLATFORM',
    });
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  if (!st.isFile()) throw new KeychainError(`${what} is not a regular file: ${file}`, { code: 'UNSAFE_BINARY' });
  if (st.mode & 0o022) {
    throw new KeychainError(`${what} is writable by group or others: ${file}`, { code: 'UNSAFE_BINARY' });
  }
  if (st.uid !== 0 && st.uid !== uid) {
    throw new KeychainError(`${what} must be owned by root or the current user: ${file}`, { code: 'UNSAFE_BINARY' });
  }
  verifiedBinaries.add(file);
  return file;
}

export function securityPath(opts = {}) {
  return opts.securityPath === undefined ? DEFAULT_SECURITY_PATH : assertSafeExecutable(opts.securityPath);
}

/**
 * Minimal, fixed environment for child processes. Nothing from process.env is
 * passed through, so PATH, DYLD_*, locale or other injected variables cannot
 * change which binaries run or how their output is formatted.
 */
export function safeEnv() {
  const { username, homedir } = userInfo();
  return {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: homedir,
    USER: username,
    LOGNAME: username,
    LANG: 'C',
    LC_ALL: 'C',
  };
}

export function assertSupported(opts = {}) {
  if (process.platform !== 'darwin' && opts.securityPath === undefined) {
    throw new KeychainError(
      `The macOS keychain is not available on platform "${process.platform}". ` +
        'Provide the variables through the environment instead (existing env vars always take precedence).',
      { code: 'UNSUPPORTED_PLATFORM' },
    );
  }
}

// ---------------------------------------------------------------------------
// Identifier validation
//
// Everything that reaches `security` is validated so it can only ever be read
// as the value it is meant to be: no option-like leading "-", no control or
// invisible formatting characters, no surrounding whitespace, bounded length.
// ---------------------------------------------------------------------------

// C0/C1 controls, DEL, and zero-width / bidi formatting characters (lookalike tampering).
const FORBIDDEN_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;

function invalid(message) {
  return new KeychainError(message, { code: 'INVALID_ARGUMENT' });
}

/** Validate a service, account, label or comment. */
export function validateName(kind, value, { max = MAX_NAME_LENGTH } = {}) {
  if (typeof value !== 'string' || value.length === 0) throw invalid(`Keychain ${kind} must be a non-empty string`);
  if (value.length > max) throw invalid(`Keychain ${kind} must be at most ${max} characters`);
  if (FORBIDDEN_CHARS.test(value)) throw invalid(`Keychain ${kind} must not contain control or invisible characters`);
  if (value.trim() !== value) throw invalid(`Keychain ${kind} must not start or end with whitespace`);
  if (value.startsWith('-')) throw invalid(`Keychain ${kind} must not start with "-"`);
}

/**
 * A keychain is either a bare file name (`team.keychain-db`, resolved by macOS
 * in ~/Library/Keychains) or an absolute path, and must end in `.keychain` or
 * `.keychain-db`.
 */
export function validateKeychain(value) {
  if (value === undefined) return;
  validateName('keychain', value, { max: MAX_KEYCHAIN_PATH });
  if (!/\.keychain(-db)?$/.test(value)) throw invalid('Keychain path must end in .keychain or .keychain-db');
  if (value.includes('/') && !path.isAbsolute(value)) throw invalid('Keychain path must be absolute or a bare file name');
  if (value.split('/').includes('..')) throw invalid('Keychain path must not contain ".." segments');
}

export function validateTrustedApp(value) {
  if (value === '') return; // `-T ""` trusts no app, so every read prompts.
  validateName('trusted app', value, { max: MAX_KEYCHAIN_PATH });
  if (!path.isAbsolute(value)) throw invalid('trustedApps entries must be absolute paths (or "" for none)');
}

export function validateRef({ service, account, keychain }) {
  validateName('service', service);
  validateName('account', account);
  validateKeychain(keychain);
}

/** Quote an argument for the `security -i` command-line parser. */
function quoteInteractive(value) {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

// ---------------------------------------------------------------------------
// Argument builders
// ---------------------------------------------------------------------------

export function findArgs({ service, account, keychain }, { withPassword = true } = {}) {
  const args = ['find-generic-password', '-s', service, '-a', account];
  if (withPassword) args.push('-g');
  if (keychain) args.push(keychain);
  return args;
}

export function deleteArgs({ service, account, keychain }) {
  const args = ['delete-generic-password', '-s', service, '-a', account];
  if (keychain) args.push(keychain);
  return args;
}

/**
 * Plan how to store a value. Returns `{ args, input }` for spawning.
 * @param {{ service: string, account: string, keychain?: string }} ref
 * @param {string|Buffer} value
 * @param {{ label?: string, comment?: string, trustedApps?: string[], allowArgv?: boolean }} [opts]
 */
export function planSet(ref, value, opts = {}) {
  validateRef(ref);
  if (typeof value !== 'string' && !Buffer.isBuffer(value)) {
    throw new KeychainError('Secret value must be a string or Buffer', { code: 'INVALID_ARGUMENT' });
  }
  const hex = Buffer.from(value).toString('hex');

  // Each entry is [flag, value]; values get quoted for the interactive parser.
  const pairs = [['-s', ref.service], ['-a', ref.account]];
  if (opts.label !== undefined) {
    validateName('label', opts.label);
    pairs.push(['-l', opts.label]);
  }
  if (opts.comment !== undefined) {
    validateName('comment', opts.comment, { max: 1024 });
    pairs.push(['-j', opts.comment]);
  }
  if (opts.trustedApps !== undefined && !Array.isArray(opts.trustedApps)) {
    throw new KeychainError('trustedApps must be an array', { code: 'INVALID_ARGUMENT' });
  }
  for (const app of opts.trustedApps ?? []) {
    validateTrustedApp(app);
    pairs.push(['-T', app]);
  }

  const tail = ref.keychain ? ` ${quoteInteractive(ref.keychain)}` : '';
  const line = `add-generic-password -U ${pairs
    .map(([flag, v]) => `${flag} ${quoteInteractive(v)}`)
    .join(' ')} -X ${hex}${tail}`;
  if (line.length <= MAX_INTERACTIVE_LINE) {
    return { args: ['-i'], input: `${line}\n`, interactive: true };
  }
  if (!opts.allowArgv) {
    throw new KeychainError(
      `Secret for service="${ref.service}" account="${ref.account}" is too large (${Buffer.byteLength(value)} bytes) ` +
        'to pass to `security` over stdin. Pass { allowArgv: true } (CLI: --allow-argv) to send it as a ' +
        'command-line argument instead; it is then briefly visible to other processes via `ps`.',
      { code: 'VALUE_TOO_LARGE', service: ref.service, account: ref.account },
    );
  }
  const args = ['add-generic-password', '-U', ...pairs.flat(), '-X', hex];
  if (ref.keychain) args.push(ref.keychain);
  return { args, input: undefined, interactive: false };
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/**
 * Parse the `password:` line emitted by `find-generic-password -g`.
 * Formats:  `password: "text"` | `password: 0xHEX  "escaped"` | `password: ` (empty)
 * @returns {string|undefined}
 */
export function parsePasswordOutput(output) {
  const match = /^password:(.*)$/m.exec(output);
  if (!match) return undefined;
  const rest = match[1].trim();
  if (rest === '') return '';
  const hex = /^0x([0-9A-Fa-f]*)/.exec(rest);
  if (hex) return Buffer.from(hex[1], 'hex').toString('utf8');
  if (rest.startsWith('"') && rest.endsWith('"') && rest.length >= 2) return rest.slice(1, -1);
  return undefined;
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

/**
 * Run `security` asynchronously.
 * @returns {Promise<{ exitCode: number|null, stdout: string, stderr: string }>}
 */
export function runSecurity(args, { input, timeoutMs, signal, ...opts } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal));
      return;
    }
    let child;
    try {
      child = spawn(securityPath(opts), args, { stdio: ['pipe', 'pipe', 'pipe'], env: safeEnv() });
    } catch (err) {
      reject(spawnError(err, opts));
      return;
    }
    const out = [];
    const err = [];
    let settled = false;
    let timer;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      fn(value);
    };
    const onAbort = () => {
      child.kill('SIGTERM');
      finish(reject, abortError(signal));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        child.kill('SIGTERM');
        finish(
          reject,
          new KeychainError(
            `security ${args[0]} timed out after ${timeoutMs}ms. A keychain access prompt may be waiting ` +
              'for a response, or the keychain is locked.',
            { code: 'TIMEOUT' },
          ),
        );
      }, timeoutMs);
      timer.unref?.();
    }
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    child.on('error', (e) => finish(reject, spawnError(e, opts)));
    child.on('close', (exitCode) =>
      finish(resolve, {
        exitCode,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      }),
    );
    child.stdin.on('error', () => {}); // EPIPE if security exits early; reported via exit code.
    child.stdin.end(input ?? '');
  });
}

/** Synchronous variant of runSecurity. Blocks the event loop. */
export function runSecuritySync(args, { input, timeoutMs, ...opts } = {}) {
  const r = spawnSync(securityPath(opts), args, {
    input: input ?? '',
    env: safeEnv(),
    timeout: timeoutMs > 0 ? timeoutMs : undefined,
    encoding: 'utf8',
  });
  if (r.error) {
    if (r.error.code === 'ETIMEDOUT') {
      throw new KeychainError(`security ${args[0]} timed out after ${timeoutMs}ms`, { code: 'TIMEOUT' });
    }
    throw spawnError(r.error, opts);
  }
  return { exitCode: r.status, stdout: r.stdout, stderr: r.stderr };
}

// Node's spawn errors carry `spawnargs`, which hold the hex-encoded value when
// writing via argv. Never attach the raw error: keep only non-sensitive fields.
function spawnError(err, opts) {
  if (err instanceof KeychainError) return err;
  const cause = { code: err?.code, errno: err?.errno, syscall: err?.syscall };
  if (err?.code === 'ENOENT') {
    return new KeychainError(`macOS security tool not found at ${securityPath(opts)}`, {
      code: process.platform === 'darwin' ? 'SECURITY_NOT_FOUND' : 'UNSUPPORTED_PLATFORM',
      cause,
    });
  }
  return new KeychainError(`Failed to run security (${err?.code ?? 'unknown error'})`, { cause });
}

function abortError(signal) {
  const reason = signal?.reason;
  if (reason instanceof Error) return reason;
  const e = new KeychainError('Keychain operation aborted', { code: 'ABORTED' });
  e.name = 'AbortError';
  return e;
}

// ---------------------------------------------------------------------------
// Result interpretation (shared by sync and async paths)
// ---------------------------------------------------------------------------

export function interpretGet(r, ref) {
  if (r.exitCode !== 0) throw errorFromExit({ ...r, op: 'find-generic-password', ...ref });
  const value = parsePasswordOutput(r.stderr) ?? parsePasswordOutput(r.stdout);
  if (value === undefined) {
    throw new KeychainError(
      `Could not parse password from security output (service="${ref.service}" account="${ref.account}")`,
      { code: 'PARSE_ERROR', service: ref.service, account: ref.account },
    );
  }
  return value;
}

export function interpretHas(r, ref) {
  if (r.exitCode === 0) return true;
  if (r.exitCode === 44) return false;
  throw errorFromExit({ ...r, op: 'find-generic-password', ...ref });
}

export function interpretSet(r, ref) {
  // `security -i` propagates the command's exit status; also treat a reported
  // "returned <status>" or "unknown command" on stderr as failure, defensively.
  if (r.exitCode !== 0 || /returned -?\d+/.test(r.stderr) || /unknown command/.test(r.stderr)) {
    // stderr can echo the command line, including the hex-encoded value, and no
    // length-based heuristic can reliably mask a short secret. Withhold it.
    throw errorFromExit({ exitCode: r.exitCode, stderr: '', op: 'add-generic-password', withheld: true, ...ref });
  }
}

export function interpretDelete(r, ref) {
  if (r.exitCode === 0) return true;
  if (r.exitCode === 44) return false;
  throw errorFromExit({ ...r, op: 'delete-generic-password', ...ref });
}
