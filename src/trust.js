/**
 * Manifest trust store.
 *
 * A `.env.keychain` manifest arrives with the repository, so it is untrusted
 * input: a cloned project could otherwise map variables to *another* project's
 * keychain items (`keychain://aws-prod/secret`) and receive them via `run` or
 * the preload. Like `direnv allow`, a manifest is honored only after the user
 * approves it with `keychain-env trust`. The approval pins the manifest's
 * SHA-256 and the exact services and keychains it may read; any edit, or any
 * service outside the approved set, makes it untrusted again.
 *
 * The store lives at ~/.config/keychain-env/trusted-manifests.json. The home
 * directory comes from the user database (not $HOME) and the file must be a
 * private regular file owned by the current user, so neither environment
 * variables nor other users can substitute their own approvals.
 */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import path from 'node:path';
import { KeychainError } from './errors.js';
import { parseManifest } from './refs.js';

const STORE_VERSION = 1;

export function defaultTrustStore() {
  return path.join(userInfo().homedir, '.config', 'keychain-env', 'trusted-manifests.json');
}

function storeError(message) {
  return new KeychainError(message, { code: 'UNSAFE_TRUST_STORE' });
}

function assertPrivate(p, { dir }) {
  const st = lstatSync(p);
  const uid = typeof process.getuid === 'function' ? process.getuid() : st.uid;
  if (st.isSymbolicLink()) throw storeError(`Trust store path must not be a symlink: ${p}`);
  if (dir ? !st.isDirectory() : !st.isFile()) throw storeError(`Unexpected file type in trust store path: ${p}`);
  if (st.uid !== uid) throw storeError(`Trust store path must be owned by the current user: ${p}`);
  if (st.mode & 0o022) throw storeError(`Trust store path must not be writable by group or others: ${p}`);
}

function readStore(store) {
  if (!path.isAbsolute(store)) throw storeError('Trust store path must be absolute');
  if (!existsSync(store)) return { version: STORE_VERSION, manifests: {} };
  assertPrivate(path.dirname(store), { dir: true });
  assertPrivate(store, { dir: false });
  let data;
  try {
    data = JSON.parse(readFileSync(store, 'utf8'));
  } catch {
    throw storeError(`Trust store is not valid JSON: ${store}`);
  }
  if (data?.version !== STORE_VERSION || typeof data.manifests !== 'object' || data.manifests === null) {
    throw storeError(`Unrecognized trust store format: ${store}`);
  }
  return data;
}

function writeStore(store, data) {
  const dir = path.dirname(store);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivate(dir, { dir: true });
  if (existsSync(store)) assertPrivate(store, { dir: false });
  const tmp = `${store}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  renameSync(tmp, store);
}

export function digest(content) {
  return createHash('sha256').update(content).digest('hex');
}

const unique = (xs) => [...new Set(xs)].sort();

/**
 * Read a manifest by real path. Returns undefined if it does not exist.
 * @returns {{ path: string, content: string, entries: ReturnType<typeof parseManifest> } | undefined}
 */
export function loadManifest(file, { cwd = process.cwd(), defaultService } = {}) {
  const full = path.resolve(cwd, file);
  if (!existsSync(full)) return undefined;
  const real = realpathSync(full);
  const content = readFileSync(real, 'utf8');
  return { path: real, content, entries: parseManifest(content, { defaultService, file: path.relative(cwd, full) || full }) };
}

/** Approve a manifest's current content and the services/keychains it uses. */
export function trustManifest(file, { cwd, defaultService, store = defaultTrustStore() } = {}) {
  const manifest = loadManifest(file, { cwd, defaultService });
  if (!manifest) throw new KeychainError(`Manifest not found: ${file}`, { code: 'MANIFEST_NOT_FOUND' });
  const data = readStore(store);
  const record = {
    sha256: digest(manifest.content),
    services: unique(manifest.entries.map((e) => e.service)),
    keychains: unique(manifest.entries.map((e) => e.keychain).filter(Boolean)),
    trustedAt: new Date().toISOString(),
  };
  data.manifests[manifest.path] = record;
  writeStore(store, data);
  return { path: manifest.path, entries: manifest.entries, ...record };
}

export function untrustManifest(file, { cwd = process.cwd(), store = defaultTrustStore() } = {}) {
  const full = path.resolve(cwd, file);
  const real = existsSync(full) ? realpathSync(full) : full;
  const data = readStore(store);
  if (!(real in data.manifests)) return false;
  delete data.manifests[real];
  writeStore(store, data);
  return true;
}

/** Throw UNTRUSTED_MANIFEST unless `manifest` matches an approval exactly. */
export function assertManifestTrusted(manifest, { store = defaultTrustStore() } = {}) {
  const record = readStore(store).manifests[manifest.path];
  const fail = (why) =>
    new KeychainError(
      `Manifest ${manifest.path} is not trusted (${why}). It can request any keychain item, so review it ` +
        'and approve it with `keychain-env trust` before secrets are loaded from it.',
      { code: 'UNTRUSTED_MANIFEST' },
    );
  if (!record) throw fail('never approved');
  if (record.sha256 !== digest(manifest.content)) throw fail('changed since it was approved');
  const services = new Set(record.services);
  const keychains = new Set(record.keychains);
  for (const e of manifest.entries) {
    if (!services.has(e.service)) throw fail(`service "${e.service}" was not approved`);
    if (e.keychain && !keychains.has(e.keychain)) throw fail(`keychain "${e.keychain}" was not approved`);
  }
}
