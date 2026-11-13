/**
 * macos-keychain-env — read secrets from the macOS keychain instead of .env files.
 *
 * The named exports use a shared default client. Use `createKeychain()` for
 * one with its own settings (keychain file, timeouts, cache, concurrency).
 */
import { createKeychain } from './client.js';

export { createKeychain } from './client.js';
export { KeychainError, MissingSecretsError, SecretNotFoundError } from './errors.js';
export { DEFAULT_MANIFEST, formatRef, isRef, parseDotenv, parseManifest, parseRef, readManifest } from './refs.js';
export { redact } from './errors.js';
export { defaultTrustStore, trustManifest, untrustManifest } from './trust.js';

export const keychain = createKeychain();

export const getSecret = keychain.get;
export const getSecretSync = keychain.getSync;
export const hasSecret = keychain.has;
export const hasSecretSync = keychain.hasSync;
export const setSecret = keychain.set;
export const setSecretSync = keychain.setSync;
export const deleteSecret = keychain.delete;
export const deleteSecretSync = keychain.deleteSync;
export const loadEnv = keychain.loadEnv;
export const loadEnvSync = keychain.loadEnvSync;
export const checkEnv = keychain.checkEnv;
export const resolveEnv = keychain.resolveEnv;
export const secretProvider = keychain.provider;

export default keychain;
