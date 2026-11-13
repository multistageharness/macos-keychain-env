/**
 * Error types. Messages never contain secret values: callers can safely log
 * them. `code` is a stable string you can branch on.
 */

export class KeychainError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, exitCode?: number|null, service?: string, account?: string, cause?: unknown }} [details]
   */
  constructor(message, details = {}) {
    super(message, details.cause === undefined ? undefined : { cause: details.cause });
    this.name = 'KeychainError';
    this.code = details.code ?? 'KEYCHAIN_ERROR';
    this.exitCode = details.exitCode ?? null;
    this.service = details.service;
    this.account = details.account;
  }
}

export class SecretNotFoundError extends KeychainError {
  constructor(service, account) {
    super(`Keychain item not found: service="${service}" account="${account}"`, {
      code: 'NOT_FOUND',
      exitCode: 44,
      service,
      account,
    });
    this.name = 'SecretNotFoundError';
  }
}

export class MissingSecretsError extends KeychainError {
  /** @param {Array<{ name: string, service: string, account: string }>} missing */
  constructor(missing) {
    const list = missing.map((m) => `${m.name} (keychain://${m.service}/${m.account})`).join(', ');
    super(`Missing ${missing.length} required secret(s) in the macOS keychain: ${list}`, {
      code: 'MISSING_SECRETS',
    });
    this.name = 'MissingSecretsError';
    this.missing = missing;
  }
}

// `security` exits with the low byte of the Security.framework OSStatus.
const EXIT_CODES = {
  44: ['NOT_FOUND', 'item not found (errSecItemNotFound)'],
  45: ['DUPLICATE_ITEM', 'item already exists (errSecDuplicateItem)'],
  36: [
    'INTERACTION_NOT_ALLOWED',
    'user interaction is not allowed; the keychain is probably locked and there is no GUI session (e.g. SSH). Run `security unlock-keychain` first',
  ],
  51: ['AUTH_FAILED', 'authorization failed or the keychain password was wrong (errSecAuthFailed)'],
  128: ['USER_CANCELED', 'the user denied or canceled the keychain access prompt'],
};

/**
 * Remove secret material from text before it is shown or logged.
 *
 * Every known secret is masked whatever its length, in plain, hex (both cases)
 * and `0x`-hex forms, so a 2-character PIN is masked as reliably as a 64-character
 * key. On top of that, generic patterns catch material we were not told about:
 * `password:` lines from `security -g`, `-X <hex>` / `-w <value>` arguments, and
 * any run of 8+ hex digits.
 * @param {unknown} text
 * @param {Array<string|Buffer>} [secrets]
 */
export function redact(text, secrets = []) {
  let out = String(text ?? '');
  const needles = new Set();
  for (const secret of secrets) {
    if (secret === undefined || secret === null) continue;
    const buf = Buffer.from(secret);
    if (buf.length === 0) continue;
    needles.add(buf.toString('utf8'));
    needles.add(buf.toString('hex'));
    needles.add(buf.toString('hex').toUpperCase());
  }
  // Longest first so a secret that contains another is masked whole.
  for (const needle of [...needles].sort((x, y) => y.length - x.length)) {
    out = out.split(needle).join('[redacted]');
  }
  return out
    .replace(/^(\s*password:).*$/gim, '$1 [redacted]')
    .replace(/(\s-[XwpP])\s+("[^"]*"|\S+)/g, '$1 [redacted]')
    .replace(/\b(?:0x)?[0-9a-fA-F]{8,}\b/g, '[redacted]')
    .trim();
}

/**
 * Turn a failed `security` invocation into a KeychainError.
 * @param {{ exitCode: number|null, stderr: string, op: string, service?: string, account?: string, withheld?: boolean }} r
 */
export function errorFromExit({ exitCode, stderr, op, service, account, withheld = false }) {
  if (exitCode === 44 && service !== undefined) return new SecretNotFoundError(service, account);
  const known = exitCode == null ? undefined : EXIT_CODES[exitCode];
  const detail = withheld
    ? 'security output withheld because it may echo the secret'
    : redact(stderr).split('\n').filter(Boolean).pop();
  const where = service === undefined ? '' : ` (service="${service}" account="${account}")`;
  const message = `security ${op} failed${where}: ${known ? known[1] : `exit code ${exitCode}`}${
    detail ? ` — ${detail}` : ''
  }`;
  return new KeychainError(message, {
    code: known ? known[0] : 'KEYCHAIN_ERROR',
    exitCode,
    service,
    account,
  });
}
