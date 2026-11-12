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
import { KeychainError, errorFromExit, redact } from './errors.js';

export const DEFAULT_SECURITY_PATH = '/usr/bin/security';
export const MAX_INTERACTIVE_LINE = 4000;

export function securityPath(opts = {}) {
  return opts.securityPath ?? process.env.KEYCHAIN_ENV_SECURITY_BIN ?? DEFAULT_SECURITY_PATH;
}

export function assertSupported(opts = {}) {
  if (process.platform !== 'darwin' && !opts.securityPath && !process.env.KEYCHAIN_ENV_SECURITY_BIN) {
    throw new KeychainError(
      `The macOS keychain is not available on platform "${process.platform}". ` +
        'Provide the variables through the environment instead (existing env vars always take precedence).',
      { code: 'UNSUPPORTED_PLATFORM' },
    );
  }
}

function validateName(kind, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new KeychainError(`Keychain ${kind} must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
  }
  if (/[\0\r\n]/.test(value)) {
    throw new KeychainError(`Keychain ${kind} must not contain newlines or NUL`, { code: 'INVALID_ARGUMENT' });
  }
}

export function validateRef({ service, account }) {
  validateName('service', service);
  validateName('account', account);
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
  if (opts.label) pairs.push(['-l', opts.label]);
  if (opts.comment) pairs.push(['-j', opts.comment]);
  for (const app of opts.trustedApps ?? []) {
    // An empty string is meaningful: `-T ""` trusts no app, so every read prompts.
    if (typeof app !== 'string' || /[\0\r\n]/.test(app)) {
      throw new KeychainError('trustedApps entries must be strings without newlines', { code: 'INVALID_ARGUMENT' });
    }
    pairs.push(['-T', app]);
  }
  if (opts.label) validateName('label', opts.label);
  if (opts.comment) validateName('comment', opts.comment);

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
      child = spawn(securityPath(opts), args, { stdio: ['pipe', 'pipe', 'pipe'] });
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

function spawnError(err, opts) {
  if (err?.code === 'ENOENT') {
    return new KeychainError(`macOS security tool not found at ${securityPath(opts)}`, {
      code: process.platform === 'darwin' ? 'SECURITY_NOT_FOUND' : 'UNSUPPORTED_PLATFORM',
      cause: err,
    });
  }
  return new KeychainError(`Failed to run security: ${err?.message ?? err}`, { cause: err });
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
    throw errorFromExit({ ...r, stderr: redact(r.stderr), op: 'add-generic-password', ...ref });
  }
}

export function interpretDelete(r, ref) {
  if (r.exitCode === 0) return true;
  if (r.exitCode === 44) return false;
  throw errorFromExit({ ...r, op: 'delete-generic-password', ...ref });
}
