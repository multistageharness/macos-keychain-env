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
import { validateRef } from './security.js';

export const SCHEME = 'keychain://';
export const DEFAULT_MANIFEST = '.env.keychain';

export function isRef(value) {
  return typeof value === 'string' && value.startsWith(SCHEME);
}

const REF_PARAMS = new Set(['optional', 'keychain']);
const REF_KEYS = new Set(['service', 'account', 'keychain', 'optional', 'name']);

/**
 * POSIX-style environment variable name. Manifests may not target variables
 * that change how programs are loaded or executed.
 */
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PROTECTED_ENV = /^(PATH|HOME|SHELL|IFS|ENV|BASH_ENV|NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|PYTHONPATH|PYTHONSTARTUP|PERL5LIB|PERL5OPT|RUBYOPT|RUBYLIB|LD_[A-Z_]+|DYLD_[A-Z_]+|KEYCHAIN_ENV_[A-Z_]+)$/;

export function validateEnvName(name, { where = 'variable' } = {}) {
  if (typeof name !== 'string' || !ENV_NAME.test(name)) {
    throw new KeychainError(`${where}: invalid environment variable name "${name}"`, { code: 'INVALID_REF' });
  }
  if (PROTECTED_ENV.test(name)) {
    throw new KeychainError(`${where}: ${name} cannot be loaded from the keychain (it controls program execution)`, {
      code: 'INVALID_REF',
    });
  }
}

function refError(message) {
  return new KeychainError(message, { code: 'INVALID_REF' });
}

/** Run identifier validation, reporting failures as INVALID_REF. */
function checked(ref, uri) {
  try {
    validateRef(ref);
  } catch (err) {
    throw refError(`Invalid keychain reference${uri ? ` ${uri}` : ''}: ${err.message}`);
  }
  return ref;
}

/**
 * Strictly parse `keychain://<service>[/<account>][?optional][&keychain=<path>]`.
 * Unknown or repeated query parameters, fragments, empty segments and invalid
 * identifiers are rejected rather than ignored.
 * @param {string} uri
 * @param {string} [defaultAccount] used when the URI has no account segment
 * @returns {{ service: string, account: string, keychain?: string, optional: boolean }}
 */
export function parseRef(uri, defaultAccount) {
  if (!isRef(uri)) throw refError(`Not a keychain reference (expected ${SCHEME}<service>/<account>): ${uri}`);
  if (uri.length > 2048) throw refError('Keychain reference is too long');
  const body = uri.slice(SCHEME.length);
  if (body.includes('#')) throw refError(`Keychain reference must not contain a fragment: ${uri}`);
  const q = body.indexOf('?');
  const location = q === -1 ? body : body.slice(0, q);
  const slash = location.indexOf('/');
  const rawService = slash === -1 ? location : location.slice(0, slash);
  const rawAccount = slash === -1 ? undefined : location.slice(slash + 1);
  if (rawAccount === '') throw refError(`Keychain reference has an empty account: ${uri}`);

  const params = {};
  if (q !== -1) {
    for (const part of body.slice(q + 1).split('&')) {
      const eq = part.indexOf('=');
      const key = eq === -1 ? part : part.slice(0, eq);
      if (!REF_PARAMS.has(key)) throw refError(`Unknown parameter "${key}" in keychain reference: ${uri}`);
      if (key in params) throw refError(`Repeated parameter "${key}" in keychain reference: ${uri}`);
      params[key] = eq === -1 ? undefined : part.slice(eq + 1);
    }
  }
  if ('optional' in params && ![undefined, 'true', 'false'].includes(params.optional)) {
    throw refError(`"optional" must be bare, "true" or "false": ${uri}`);
  }
  if ('keychain' in params && !params.keychain) throw refError(`"keychain" needs a value: ${uri}`);

  let service;
  let account;
  let keychain;
  try {
    service = decodeURIComponent(rawService);
    account = rawAccount === undefined ? defaultAccount : decodeURIComponent(rawAccount);
    keychain = params.keychain === undefined ? undefined : decodeURIComponent(params.keychain);
  } catch {
    throw refError(`Invalid percent-encoding in keychain reference: ${uri}`);
  }
  if (!service || !account) throw refError(`Keychain reference needs a service and an account: ${uri}`);
  const ref = { service, account, optional: 'optional' in params && params.optional !== 'false' };
  if (keychain !== undefined) ref.keychain = keychain;
  return checked(ref, uri);
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
 * Normalise anything accepted as a secret reference. Objects must have exactly
 * the documented shape: unknown keys and wrongly typed fields are rejected.
 * @param {string | { service: string, account: string, keychain?: string, optional?: boolean }} input
 */
export function toRef(input, defaultAccount) {
  if (typeof input === 'string') return parseRef(input, defaultAccount);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw refError('Secret reference must be a keychain:// string or { service, account }');
  }
  for (const key of Object.keys(input)) {
    if (!REF_KEYS.has(key)) throw refError(`Unknown field "${key}" in secret reference`);
  }
  if (input.optional !== undefined && typeof input.optional !== 'boolean') {
    throw refError('Secret reference field "optional" must be a boolean');
  }
  const ref = {
    service: input.service,
    account: input.account ?? defaultAccount,
    optional: Boolean(input.optional),
  };
  if (input.keychain !== undefined) ref.keychain = input.keychain;
  return checked(ref);
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
  const seen = new Set();
  const lines = String(source).replace(/\r\n?/g, '\n').split('\n');
  lines.forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) return;
    const m = /^(?:export\s+)?([^\s=]+)\s*(?:=\s*(.*))?$/.exec(line);
    const where = `${file ?? 'manifest'}:${i + 1}`;
    if (!m) throw new KeychainError(`Cannot parse ${where}`, { code: 'INVALID_MANIFEST' });
    const [, name, rawValue = ''] = m;
    try {
      validateEnvName(name, { where });
    } catch (err) {
      throw new KeychainError(err.message, { code: 'INVALID_MANIFEST' });
    }
    if (seen.has(name)) throw new KeychainError(`${where}: ${name} is defined twice`, { code: 'INVALID_MANIFEST' });
    seen.add(name);
    const value = rawValue.replace(/^(['"])(.*)\1$/, '$2');
    if (value === '') {
      if (!defaultService) {
        throw new KeychainError(`${where}: ${name} has no keychain:// reference and no default service is set`, {
          code: 'INVALID_MANIFEST',
        });
      }
      out.push({ name, ...checked({ service: defaultService, account: name, optional: false }) });
    } else if (isRef(value)) {
      try {
        out.push({ name, ...parseRef(value, name) });
      } catch (err) {
        throw new KeychainError(`${where}: ${err.message}`, { code: 'INVALID_MANIFEST' });
      }
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
