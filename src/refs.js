/**
 * Secret references and env-file parsing.
 *
 * A reference names a keychain item without containing the secret:
 *
 *   keychain://<service>/<account>[?optional][&keychain=<path>]
 *
 * `service` and `account` are percent-decoded. If `account` is omitted, the
 * environment variable name is used (`API_KEY=keychain://myapp` reads account
 * "API_KEY" of service "myapp").
 *
 * References can live in a committed `.env.keychain` manifest, or directly as
 * values in a regular `.env` / the process environment.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { KeychainError } from './errors.js';

export const SCHEME = 'keychain://';
export const DEFAULT_MANIFEST = '.env.keychain';

export function isRef(value) {
  return typeof value === 'string' && value.startsWith(SCHEME);
}

/**
 * @param {string} uri
 * @param {string} [defaultAccount] used when the URI has no account segment
 * @returns {{ service: string, account: string, keychain?: string, optional: boolean }}
 */
export function parseRef(uri, defaultAccount) {
  if (!isRef(uri)) {
    throw new KeychainError(`Not a keychain reference (expected ${SCHEME}<service>/<account>): ${uri}`, {
      code: 'INVALID_REF',
    });
  }
  const body = uri.slice(SCHEME.length);
  const q = body.indexOf('?');
  const location = q === -1 ? body : body.slice(0, q);
  const params = new URLSearchParams(q === -1 ? '' : body.slice(q + 1));
  const slash = location.indexOf('/');
  const rawService = slash === -1 ? location : location.slice(0, slash);
  const rawAccount = slash === -1 ? '' : location.slice(slash + 1);
  let service;
  let account;
  try {
    service = decodeURIComponent(rawService);
    account = rawAccount ? decodeURIComponent(rawAccount) : defaultAccount;
  } catch {
    throw new KeychainError(`Invalid percent-encoding in keychain reference: ${uri}`, { code: 'INVALID_REF' });
  }
  if (!service || !account) {
    throw new KeychainError(`Keychain reference needs a service and an account: ${uri}`, { code: 'INVALID_REF' });
  }
  const ref = { service, account, optional: params.has('optional') && params.get('optional') !== 'false' };
  if (params.get('keychain')) ref.keychain = params.get('keychain');
  return ref;
}

export function formatRef({ service, account, keychain, optional }, varName) {
  const enc = (s) => encodeURIComponent(s).replace(/%40/g, '@').replace(/%3A/g, ':');
  let uri = `${SCHEME}${enc(service)}`;
  if (account !== varName) uri += `/${enc(account)}`;
  const params = [];
  if (optional) params.push('optional');
  if (keychain) params.push(`keychain=${encodeURIComponent(keychain)}`);
  return params.length ? `${uri}?${params.join('&')}` : uri;
}

/**
 * Normalise anything accepted as a secret reference.
 * @param {string | { service: string, account: string, keychain?: string }} input
 */
export function toRef(input, defaultAccount) {
  if (typeof input === 'string') return parseRef(input, defaultAccount);
  if (input && typeof input === 'object') {
    return {
      service: input.service,
      account: input.account ?? defaultAccount,
      keychain: input.keychain,
      optional: Boolean(input.optional),
    };
  }
  throw new KeychainError('Secret reference must be a keychain:// string or { service, account }', {
    code: 'INVALID_REF',
  });
}

/**
 * Minimal dotenv-compatible parser: `KEY=value`, optional `export`, `#`
 * comments, single/double/backtick quotes, multi-line double-quoted values with
 * \n escapes. Returns entries in file order.
 * @returns {Array<[string, string]>}
 */
export function parseDotenv(source) {
  const entries = [];
  const re =
    /^[^\S\n]*(?:export[^\S\n]+)?([\w.-]+)[^\S\n]*=[^\S\n]*('(?:\\'|[^'])*'|"(?:\\"|[^"])*"|`(?:\\`|[^`])*`|[^#\r\n]*)?[^\S\r\n]*(?:#.*)?$/gm;
  const text = String(source).replace(/\r\n?/g, '\n');
  let m;
  while ((m = re.exec(text)) !== null) {
    const key = m[1];
    let value = (m[2] ?? '').trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'" || quote === '`') && value.endsWith(quote) && value.length >= 2) {
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\"/g, '"');
    }
    entries.push([key, value]);
  }
  return entries;
}

/**
 * Parse a manifest. Each line is `VAR=keychain://...`; a bare `VAR` (or
 * `VAR=`) uses `defaultService` with account `VAR`.
 * @returns {Array<{ name: string, service: string, account: string, keychain?: string, optional: boolean }>}
 */
export function parseManifest(source, { defaultService, file } = {}) {
  const out = [];
  const lines = String(source).replace(/\r\n?/g, '\n').split('\n');
  lines.forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) return;
    const m = /^(?:export\s+)?([A-Za-z_][\w.-]*)\s*(?:=\s*(.*))?$/.exec(line);
    const where = `${file ?? 'manifest'}:${i + 1}`;
    if (!m) throw new KeychainError(`Cannot parse ${where}: ${raw}`, { code: 'INVALID_MANIFEST' });
    const [, name, rawValue = ''] = m;
    const value = rawValue.replace(/^(['"])(.*)\1$/, '$2');
    if (value === '') {
      if (!defaultService) {
        throw new KeychainError(`${where}: ${name} has no keychain:// reference and no default service is set`, {
          code: 'INVALID_MANIFEST',
        });
      }
      out.push({ name, service: defaultService, account: name, optional: false });
    } else if (isRef(value)) {
      out.push({ name, ...parseRef(value, name) });
    } else {
      throw new KeychainError(
        `${where}: ${name} must be a keychain:// reference. Manifests must not contain secret values.`,
        { code: 'INVALID_MANIFEST' },
      );
    }
  });
  return out;
}

/** Read a manifest file if it exists. Returns `undefined` if it does not. */
export function readManifest(file = DEFAULT_MANIFEST, { cwd = process.cwd(), defaultService } = {}) {
  const full = path.resolve(cwd, file);
  if (!existsSync(full)) return undefined;
  return parseManifest(readFileSync(full, 'utf8'), { defaultService, file: path.relative(cwd, full) || full });
}
