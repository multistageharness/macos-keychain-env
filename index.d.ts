/// <reference types="node" />

/** A keychain item: generic password identified by service + account. */
export interface SecretRef {
  service: string;
  account: string;
  /** Path to a specific keychain file; defaults to the user's search list. */
  keychain?: string;
  /** For env loading: a missing item is not an error. */
  optional?: boolean;
}

/** `keychain://<service>/<account>[?optional][&keychain=<path>]` or a SecretRef object. */
export type SecretInput = string | SecretRef;

export interface KeychainOptions {
  /** Per-operation timeout in ms (default 30000). Covers time spent on access prompts. */
  timeoutMs?: number;
  /** Max concurrent `security` processes (default 4). */
  concurrency?: number;
  /** Cache successful reads for this many ms (default 0 = no cache). */
  cacheTtlMs?: number;
  /** Default keychain file for refs that do not name one. */
  keychain?: string;
  /** Default service for bare manifest lines and `keys`. */
  service?: string;
  /** Path to the `security` binary (default /usr/bin/security, or $KEYCHAIN_ENV_SECURITY_BIN). */
  securityPath?: string;
}

export interface CallOptions {
  timeoutMs?: number;
  /** Stop waiting. A read shared with other callers keeps running for them. */
  signal?: AbortSignal;
}

export interface GetOptions extends CallOptions {
  /** Resolve `undefined` instead of throwing SecretNotFoundError. */
  optional?: boolean;
  cacheTtlMs?: number;
}

export interface SetOptions extends CallOptions {
  label?: string;
  comment?: string;
  /**
   * Apps allowed to read without a prompt. Default: only /usr/bin/security (the creator).
   * `[""]` trusts no app, so every read shows a keychain prompt.
   */
  trustedApps?: string[];
  /** Allow values over ~1.9 KB, which must be passed to `security` via argv (visible in `ps`). */
  allowArgv?: boolean;
}

export interface LoadEnvOptions extends CallOptions {
  /** Manifest path, or false to skip. Default: `.env.keychain` if it exists. */
  manifest?: string | false;
  /** Explicit mapping of VAR -> reference. */
  entries?: Record<string, SecretInput>;
  /** Shorthand: load these names from `service` (account = variable name). */
  keys?: string[];
  service?: string;
  /** Replace values already present in `target` (default false: existing values win). */
  override?: boolean;
  /** Replace `keychain://` values already present in `target` (default true). */
  resolveRefs?: boolean;
  /** Object to populate (default process.env). */
  target?: Record<string, string | undefined>;
  /** Base directory for the manifest (default process.cwd()). */
  cwd?: string;
}

export interface LoadEnvResult {
  /** Variable names set from the keychain. Never contains values. */
  loaded: string[];
  /** Variables left alone because they were already set. */
  skipped: string[];
  /** Optional variables that were not found. */
  missing: string[];
}

export interface CheckEntry {
  name: string;
  service: string;
  account: string;
  optional: boolean;
  present: boolean;
}

export interface ProviderOptions extends GetOptions {
  /** How long to reuse a fetched value (default 5 minutes; 0 = always re-read). */
  ttlMs?: number;
}

export interface SecretProvider {
  (options?: CallOptions): Promise<string>;
  /** Drop the cached value so the next call re-reads the keychain (e.g. after a 401). */
  invalidate(): void;
}

export interface Keychain {
  get(ref: SecretInput, options: GetOptions & { optional: true }): Promise<string | undefined>;
  get(ref: SecretInput, options?: GetOptions): Promise<string>;
  getSync(ref: SecretInput, options: GetOptions & { optional: true }): string | undefined;
  getSync(ref: SecretInput, options?: GetOptions): string;
  has(ref: SecretInput, options?: CallOptions): Promise<boolean>;
  hasSync(ref: SecretInput, options?: CallOptions): boolean;
  set(ref: SecretInput, value: string | Buffer, options?: SetOptions): Promise<void>;
  setSync(ref: SecretInput, value: string | Buffer, options?: SetOptions): void;
  /** Resolves true if deleted, false if it did not exist. */
  delete(ref: SecretInput, options?: CallOptions): Promise<boolean>;
  deleteSync(ref: SecretInput, options?: CallOptions): boolean;
  /** Fetch all secrets concurrently; writes nothing unless every required one is found. */
  loadEnv(options?: LoadEnvOptions): Promise<LoadEnvResult>;
  /** Blocking variant for synchronous config files. */
  loadEnvSync(options?: Omit<LoadEnvOptions, 'signal'>): LoadEnvResult;
  /** Report which entries exist, without reading secret data. */
  checkEnv(options?: LoadEnvOptions): Promise<CheckEntry[]>;
  /** Replace every `keychain://` value in `target` (default process.env). */
  resolveEnv(target?: Record<string, string | undefined>, options?: CallOptions): Promise<LoadEnvResult>;
  /** Lazy, cached async getter for SDKs that accept a credential callback. */
  provider(ref: SecretInput, options?: ProviderOptions): SecretProvider;
  clearCache(): void;
  readonly options: Readonly<KeychainOptions>;
}

export declare function createKeychain(options?: KeychainOptions): Keychain;

export declare const keychain: Keychain;
export default keychain;

export declare const getSecret: Keychain['get'];
export declare const getSecretSync: Keychain['getSync'];
export declare const hasSecret: Keychain['has'];
export declare const hasSecretSync: Keychain['hasSync'];
export declare const setSecret: Keychain['set'];
export declare const setSecretSync: Keychain['setSync'];
export declare const deleteSecret: Keychain['delete'];
export declare const deleteSecretSync: Keychain['deleteSync'];
export declare const loadEnv: Keychain['loadEnv'];
export declare const loadEnvSync: Keychain['loadEnvSync'];
export declare const checkEnv: Keychain['checkEnv'];
export declare const resolveEnv: Keychain['resolveEnv'];
export declare const secretProvider: Keychain['provider'];

export type KeychainErrorCode =
  | 'KEYCHAIN_ERROR'
  | 'NOT_FOUND'
  | 'MISSING_SECRETS'
  | 'DUPLICATE_ITEM'
  | 'INTERACTION_NOT_ALLOWED'
  | 'AUTH_FAILED'
  | 'USER_CANCELED'
  | 'TIMEOUT'
  | 'ABORTED'
  | 'UNSUPPORTED_PLATFORM'
  | 'SECURITY_NOT_FOUND'
  | 'VALUE_TOO_LARGE'
  | 'PARSE_ERROR'
  | 'INVALID_ARGUMENT'
  | 'INVALID_REF'
  | 'INVALID_MANIFEST'
  | 'MANIFEST_NOT_FOUND';

export declare class KeychainError extends Error {
  code: KeychainErrorCode | (string & {});
  exitCode: number | null;
  service?: string;
  account?: string;
}
export declare class SecretNotFoundError extends KeychainError {}
export declare class MissingSecretsError extends KeychainError {
  missing: Array<{ name: string; service: string; account: string }>;
}

export declare const DEFAULT_MANIFEST: '.env.keychain';
export declare function isRef(value: unknown): value is string;
export declare function parseRef(uri: string, defaultAccount?: string): Required<Pick<SecretRef, 'service' | 'account'>> & SecretRef & { optional: boolean };
export declare function formatRef(ref: SecretRef, varName?: string): string;
export declare function parseDotenv(source: string): Array<[string, string]>;
export declare function parseManifest(source: string, options?: { defaultService?: string; file?: string }): Array<SecretRef & { name: string; optional: boolean }>;
export declare function readManifest(file?: string, options?: { cwd?: string; defaultService?: string }): Array<SecretRef & { name: string; optional: boolean }> | undefined;
