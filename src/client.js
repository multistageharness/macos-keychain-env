/**
 * Keychain client: async + sync APIs over `security`, with
 * - in-flight de-duplication (N concurrent reads of one item = 1 process),
 * - a concurrency limit (avoid spawning dozens of `security` processes),
 * - optional TTL cache,
 * - per-call timeout and AbortSignal support.
 */
import { KeychainError, MissingSecretsError, SecretNotFoundError } from './errors.js';
import { DEFAULT_MANIFEST, isRef, parseRef, toRef, validateEnvName } from './refs.js';
import { assertManifestTrusted, loadManifest } from './trust.js';
import {
  assertSafeExecutable,
  assertSupported,
  deleteArgs,
  findArgs,
  interpretDelete,
  interpretGet,
  interpretHas,
  interpretSet,
  planSet,
  runSecurity,
  runSecuritySync,
  validateKeychain,
  validateName,
  validateRef,
} from './security.js';

const DEFAULTS = {
  timeoutMs: 30_000,
  concurrency: 4,
  cacheTtlMs: 0,
};

function createLimiter(max) {
  let active = 0;
  const queue = [];
  const next = () => {
    if (active >= max || queue.length === 0) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    Promise.resolve()
      .then(fn)
      .then(resolve, reject)
      .finally(() => {
        active--;
        next();
      });
  };
  return (fn) =>
    new Promise((resolve, reject) => {
      queue.push({ fn, resolve, reject });
      next();
    });
}

/** Stop waiting on `promise` when `signal` aborts (the shared work keeps running). */
function withSignal(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(signal.reason ?? abortError());
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? abortError());
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener('abort', onAbort);
        reject(e);
      },
    );
  });
}

function abortError() {
  const e = new KeychainError('Keychain operation aborted', { code: 'ABORTED' });
  e.name = 'AbortError';
  return e;
}

const keyOf = ({ service, account, keychain }) => `${keychain ?? ''}\0${service}\0${account}`;

/**
 * @param {import('../index').KeychainOptions} [options]
 * @returns {import('../index').Keychain}
 */
export function createKeychain(options = {}) {
  const config = { ...DEFAULTS, ...options };
  // Validate configuration up front so a bad value fails at construction time.
  if (config.securityPath !== undefined) assertSafeExecutable(config.securityPath);
  validateKeychain(config.keychain);
  if (config.service !== undefined) validateName('service', config.service);
  if (config.allowedServices !== undefined) {
    if (!Array.isArray(config.allowedServices)) {
      throw new KeychainError('allowedServices must be an array', { code: 'INVALID_ARGUMENT' });
    }
    config.allowedServices.forEach((svc) => validateName('service', svc));
  }
  const limit = createLimiter(Math.max(1, config.concurrency));
  const inflight = new Map();
  const cache = new Map();

  const runOpts = (o = {}) => ({
    securityPath: config.securityPath,
    timeoutMs: o.timeoutMs ?? config.timeoutMs,
  });
  const resolveRef = (input) => {
    const ref = toRef(input);
    if (ref.keychain === undefined && config.keychain) ref.keychain = config.keychain;
    validateRef(ref);
    return ref;
  };

  function readCache(key) {
    const hit = cache.get(key);
    if (!hit) return undefined;
    if (hit.expires <= Date.now()) {
      cache.delete(key);
      return undefined;
    }
    return hit;
  }

  function writeCache(key, value, ttl) {
    if (ttl > 0) cache.set(key, { value, expires: Date.now() + ttl });
  }

  // -------------------------------------------------------------------------
  // Single-item operations
  // -------------------------------------------------------------------------

  async function get(input, o = {}) {
    const ref = resolveRef(input);
    const optional = o.optional ?? ref.optional;
    const key = keyOf(ref);
    const ttl = o.cacheTtlMs ?? config.cacheTtlMs;
    const hit = ttl > 0 ? readCache(key) : undefined;
    if (hit) return hit.value;

    let pending = inflight.get(key);
    if (!pending) {
      assertSupported(config);
      pending = limit(() => runSecurity(findArgs(ref), runOpts(o)))
        .then((r) => interpretGet(r, ref))
        .finally(() => inflight.delete(key));
      inflight.set(key, pending);
    }
    try {
      const value = await withSignal(pending, o.signal);
      writeCache(key, value, ttl);
      return value;
    } catch (err) {
      if (optional && err instanceof SecretNotFoundError) return undefined;
      throw err;
    }
  }

  function getSync(input, o = {}) {
    const ref = resolveRef(input);
    const optional = o.optional ?? ref.optional;
    const key = keyOf(ref);
    const ttl = o.cacheTtlMs ?? config.cacheTtlMs;
    const hit = ttl > 0 ? readCache(key) : undefined;
    if (hit) return hit.value;
    assertSupported(config);
    try {
      const value = interpretGet(runSecuritySync(findArgs(ref), runOpts(o)), ref);
      writeCache(key, value, ttl);
      return value;
    } catch (err) {
      if (optional && err instanceof SecretNotFoundError) return undefined;
      throw err;
    }
  }

  async function has(input, o = {}) {
    const ref = resolveRef(input);
    assertSupported(config);
    // Without -g no secret data is read, so this never triggers an access prompt.
    const r = await withSignal(limit(() => runSecurity(findArgs(ref, { withPassword: false }), runOpts(o))), o.signal);
    return interpretHas(r, ref);
  }

  function hasSync(input, o = {}) {
    const ref = resolveRef(input);
    assertSupported(config);
    return interpretHas(runSecuritySync(findArgs(ref, { withPassword: false }), runOpts(o)), ref);
  }

  async function set(input, value, o = {}) {
    const ref = resolveRef(input);
    const plan = planSet(ref, value, { ...config, ...o });
    assertSupported(config);
    const r = await withSignal(
      limit(() => runSecurity(plan.args, { ...runOpts(o), input: plan.input })),
      o.signal,
    );
    interpretSet(r, ref);
    cache.delete(keyOf(ref));
  }

  function setSync(input, value, o = {}) {
    const ref = resolveRef(input);
    const plan = planSet(ref, value, { ...config, ...o });
    assertSupported(config);
    interpretSet(runSecuritySync(plan.args, { ...runOpts(o), input: plan.input }), ref);
    cache.delete(keyOf(ref));
  }

  async function del(input, o = {}) {
    const ref = resolveRef(input);
    assertSupported(config);
    const r = await withSignal(limit(() => runSecurity(deleteArgs(ref), runOpts(o))), o.signal);
    cache.delete(keyOf(ref));
    return interpretDelete(r, ref);
  }

  function delSync(input, o = {}) {
    const ref = resolveRef(input);
    assertSupported(config);
    const r = runSecuritySync(deleteArgs(ref), runOpts(o));
    cache.delete(keyOf(ref));
    return interpretDelete(r, ref);
  }

  // -------------------------------------------------------------------------
  // Environment loading
  // -------------------------------------------------------------------------

  /**
   * Work out which variables to fetch, without touching the keychain.
   *
   * Trust boundary: code-supplied `keys` / `entries` and approved manifests
   * are trusted. `keychain://` values found in the environment (often from a
   * repository's .env) are not: they may only name services and keychains that
   * the trusted sources already use. `allowedServices` additionally caps every
   * source.
   */
  function planEnv(o = {}) {
    const target = o.target ?? process.env;
    const cwd = o.cwd ?? process.cwd();
    const service = o.service ?? config.service;
    const allowedList = o.allowedServices ?? config.allowedServices;
    const allowed = allowedList === undefined ? undefined : new Set(allowedList);
    const requireTrust = o.requireTrustedManifest ?? config.requireTrustedManifest ?? true;
    const trustStore = o.trustStore ?? config.trustStore;
    const entries = new Map();
    const trustedServices = new Set();
    const trustedKeychains = new Set(config.keychain ? [config.keychain] : []);
    const add = (e, trusted) => {
      entries.set(e.name, e);
      if (trusted) {
        trustedServices.add(e.service);
        if (e.keychain) trustedKeychains.add(e.keychain);
      }
    };
    const notAllowed = (name, why) =>
      new KeychainError(`${name}: ${why}`, { code: 'SERVICE_NOT_ALLOWED' });

    if (o.manifest !== false) {
      const file = typeof o.manifest === 'string' ? o.manifest : DEFAULT_MANIFEST;
      const manifest = loadManifest(file, { cwd, defaultService: service });
      if (!manifest && typeof o.manifest === 'string') {
        throw new KeychainError(`Manifest not found: ${file}`, { code: 'MANIFEST_NOT_FOUND' });
      }
      if (manifest) {
        if (requireTrust) assertManifestTrusted(manifest, { store: trustStore });
        for (const e of manifest.entries) add(e, true);
      }
    }
    if (o.keys) {
      if (!service) throw new KeychainError('`keys` requires a `service`', { code: 'INVALID_ARGUMENT' });
      for (const name of o.keys) add({ name, ...toRef({ service, account: name }) }, true);
    }
    for (const [name, refInput] of Object.entries(o.entries ?? {})) {
      add({ name, ...toRef(refInput, name) }, true);
    }
    if (o.resolveRefs !== false) {
      for (const [name, value] of Object.entries(target)) {
        if (!isRef(value)) continue;
        let ref;
        try {
          validateEnvName(name, { where: 'environment' });
          ref = parseRef(value, name);
        } catch (err) {
          throw new KeychainError(`${name}: ${err.message}`, { code: 'INVALID_REF' });
        }
        const permitted = allowed ?? trustedServices;
        if (!permitted.has(ref.service)) {
          throw notAllowed(
            name,
            `keychain:// reference to service "${ref.service}" came from the environment, but that service is not ` +
              'used by this app\'s code or trusted manifest. Add it to `allowedServices` (CLI: --allow-service) if intended.',
          );
        }
        if (ref.keychain && !trustedKeychains.has(ref.keychain)) {
          throw notAllowed(name, `keychain "${ref.keychain}" from the environment is not used by a trusted source`);
        }
        add({ name, ...ref }, false);
      }
    }
    if (allowed) {
      for (const e of entries.values()) {
        if (!allowed.has(e.service)) throw notAllowed(e.name, `service "${e.service}" is not in allowedServices`);
      }
    }

    const fetch = [];
    const skipped = [];
    for (const e of entries.values()) {
      if (e.keychain === undefined && config.keychain) e.keychain = config.keychain;
      const current = target[e.name];
      if (!o.override && current !== undefined && current !== '' && !isRef(current)) skipped.push(e.name);
      else fetch.push(e);
    }
    return { target, fetch, skipped };
  }

  function applyEnv({ target, fetch, skipped }, values) {
    const missing = [];
    const loaded = [];
    fetch.forEach((e, i) => {
      if (values[i] === undefined) missing.push(e);
    });
    const required = missing.filter((e) => !e.optional);
    if (required.length) {
      throw new MissingSecretsError(required.map(({ name, service, account }) => ({ name, service, account })));
    }
    // All-or-nothing: only write once every required secret was found.
    fetch.forEach((e, i) => {
      if (values[i] === undefined) {
        // An unresolved optional ref must not leak through as a value.
        if (isRef(target[e.name])) delete target[e.name];
        return;
      }
      target[e.name] = values[i];
      loaded.push(e.name);
    });
    return { loaded, skipped, missing: missing.map((e) => e.name) };
  }

  async function loadEnv(o = {}) {
    const plan = planEnv(o);
    const values = await Promise.all(
      plan.fetch.map((e) => get(e, { optional: true, signal: o.signal, timeoutMs: o.timeoutMs })),
    );
    return applyEnv(plan, values);
  }

  function loadEnvSync(o = {}) {
    const plan = planEnv(o);
    const values = plan.fetch.map((e) => getSync(e, { optional: true, timeoutMs: o.timeoutMs }));
    return applyEnv(plan, values);
  }

  /** Check which entries exist, without reading any secret data. */
  async function checkEnv(o = {}) {
    const plan = planEnv({ ...o, override: true, target: o.target ?? {} });
    const present = await Promise.all(plan.fetch.map((e) => has(e, { signal: o.signal })));
    return plan.fetch.map((e, i) => ({
      name: e.name,
      service: e.service,
      account: e.account,
      optional: e.optional,
      present: present[i],
    }));
  }

  // -------------------------------------------------------------------------
  // Lazy providers for SDKs that accept an async credential callback
  // -------------------------------------------------------------------------

  function provider(input, o = {}) {
    const ref = resolveRef(input);
    const ttlMs = o.ttlMs ?? 5 * 60_000;
    let current;
    const fn = async (callOpts = {}) => {
      if (current && current.expires > Date.now()) return current.value;
      const value = await get(ref, { ...o, ...callOpts, cacheTtlMs: 0 });
      if (ttlMs > 0) current = { value, expires: Date.now() + ttlMs };
      return value;
    };
    fn.invalidate = () => {
      current = undefined;
    };
    return fn;
  }

  return {
    get,
    getSync,
    has,
    hasSync,
    set,
    setSync,
    delete: del,
    deleteSync: delSync,
    loadEnv,
    loadEnvSync,
    checkEnv,
    resolveEnv: (target = process.env, o = {}) => loadEnv({ ...o, target, manifest: false, resolveRefs: true }),
    provider,
    clearCache: () => cache.clear(),
    options: Object.freeze({ ...config }),
  };
}
