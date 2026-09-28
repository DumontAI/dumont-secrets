import { randomBytes } from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { isAccountEmail } from './autounlock.js';
import { auditFile, configFile, currentPathEnvironment, lockFile, sessionFile, type PathEnvironment } from './paths.js';
import type { ScopeConfig, SecretsConfig } from './types.js';

export class SecretsConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretsConfigError';
  }
}

export const DEFAULT_SERVER_URL = 'https://secret.getdumont.ai';
const MAX_CONFIG_BYTES = 64 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

function boundedInt(env: NodeJS.ProcessEnv, name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new SecretsConfigError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function parseBoolean(env: NodeJS.ProcessEnv, name: string): boolean | null {
  const raw = env[name]?.trim().toLowerCase();
  if (!raw) return null;
  if (raw === 'true' || raw === '1') return true;
  if (raw === 'false' || raw === '0') return false;
  throw new SecretsConfigError(`${name} must be true or false`);
}

/** The server URL the user's `bw` must be configured for. HTTPS, or loopback HTTP for a local test vault. */
export function parseServerUrl(env: NodeJS.ProcessEnv): URL {
  const raw = env.DUMONT_SECRETS_SERVER_URL?.trim() || DEFAULT_SERVER_URL;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SecretsConfigError('DUMONT_SECRETS_SERVER_URL must be a valid URL');
  }
  const loopbackHttp = url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !loopbackHttp) {
    throw new SecretsConfigError('DUMONT_SECRETS_SERVER_URL must use HTTPS');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new SecretsConfigError('DUMONT_SECRETS_SERVER_URL must not contain credentials, query parameters, or fragments');
  }
  return url;
}

export function parseBwBin(env: NodeJS.ProcessEnv): string {
  const bin = env.DUMONT_SECRETS_BW_BIN?.trim() || 'bw';
  if (bin !== 'bw' && !isAbsolute(bin)) {
    throw new SecretsConfigError('DUMONT_SECRETS_BW_BIN must be "bw" or an absolute path');
  }
  return bin;
}

function name(value: unknown, where: string): string {
  // Names are data from the user; refuse control characters so they can never
  // smuggle a line into the audit log or a response.
  if (typeof value !== 'string' || value.length < 1 || value.length > 200 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new SecretsConfigError(`${where} must hold names or ids of 1-200 printable characters`);
  }
  return value;
}

function nameList(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) {
    throw new SecretsConfigError(`${where} must be a non-empty array of names or ids (leave it out for "all")`);
  }
  return [...new Set(value.map(item => name(item, where)))];
}

export interface LocalConfigFile {
  readonly scope: ScopeConfig;
  readonly allowSet: boolean | null;
  readonly allowRotate: boolean;
  /** Opt-in auto-unlock with the password in the OS credential store (default false). */
  readonly autoUnlock: boolean;
  /** The bw account auto-unlock may log in again with when bw is logged out. */
  readonly accountEmail: string | null;
}

const KNOWN_KEYS = new Set([
  'version', 'organizations', 'read_collections', 'value_collections', 'write_collection', 'allow_set', 'allow_rotate',
  'auto_unlock', 'account_email',
]);
const NO_SCOPE: ScopeConfig = { organizations: null, readCollections: null, writeCollection: null, valueCollections: null };

/**
 * The local scope file (`mcp.json`). Every key is optional:
 *   organizations      names or ids; default every organization you belong to
 *   read_collections   names or ids; default every collection of those organizations
 *   value_collections  names or ids whose values secrets_get_secret may return;
 *                      secrets_get_secret is disabled while it is unset
 *   write_collection   name or id; writes are disabled while it is unset
 *   allow_rotate       lets generate/set replace an existing key (default false)
 *   allow_set          enables secrets_set_secret (default false)
 *   auto_unlock        unlock bw by itself with the password in the OS credential
 *                      store (default false; written by dumont-secrets-unlock
 *                      --setup-auto / --disable-auto)
 *   account_email      the bw account auto-unlock logs in with when bw is logged out
 */
export function parseLocalConfig(raw: string): LocalConfigFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SecretsConfigError('the MCP config file must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SecretsConfigError('the MCP config file must be a JSON object');
  }
  const record = parsed as Record<string, unknown>;
  const unknown = Object.keys(record).find(key => !KNOWN_KEYS.has(key));
  if (unknown !== undefined) {
    throw new SecretsConfigError(
      'the MCP config file may only contain version, organizations, read_collections, value_collections, write_collection, ' +
        'allow_rotate, allow_set, auto_unlock and account_email',
    );
  }
  if (record.version !== undefined && record.version !== 1) throw new SecretsConfigError('the MCP config version must be 1');
  for (const key of ['allow_set', 'allow_rotate', 'auto_unlock'] as const) {
    if (record[key] !== undefined && typeof record[key] !== 'boolean') throw new SecretsConfigError(`${key} must be true or false`);
  }
  if (record.account_email !== undefined && record.account_email !== null && !isAccountEmail(record.account_email)) {
    throw new SecretsConfigError('account_email must be an email address');
  }
  return {
    scope: {
      organizations: record.organizations === undefined ? null : nameList(record.organizations, 'organizations'),
      readCollections: record.read_collections === undefined ? null : nameList(record.read_collections, 'read_collections'),
      writeCollection: record.write_collection === undefined || record.write_collection === null
        ? null
        : name(record.write_collection, 'write_collection'),
      valueCollections: record.value_collections === undefined ? null : nameList(record.value_collections, 'value_collections'),
    },
    allowSet: typeof record.allow_set === 'boolean' ? record.allow_set : null,
    allowRotate: record.allow_rotate === true,
    autoUnlock: record.auto_unlock === true,
    accountEmail: isAccountEmail(record.account_email) ? record.account_email : null,
  };
}

/**
 * Change keys of the local config file, keeping every other key as it is.
 * The file is validated before and after the change, written to a new 0600 file
 * in the same (0700 when created) directory and renamed over the old one. A
 * config file that is a symlink is refused (the rename would replace the link).
 */
export function updateLocalConfig(path: string, change: (record: Record<string, unknown>) => void): void {
  let record: Record<string, unknown> = {};
  let exists = true;
  try {
    const info = lstatSync(path);
    if (info.isSymbolicLink()) throw new SecretsConfigError(`${path} is a symlink; edit it by hand`);
    if (!info.isFile()) throw new SecretsConfigError(`${path} is not a regular file`);
  } catch (error) {
    if (error instanceof SecretsConfigError) throw error;
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new SecretsConfigError('the MCP config file cannot be read');
    exists = false;
  }
  if (exists) {
    let raw: Buffer;
    try {
      raw = readFileSync(path);
    } catch {
      throw new SecretsConfigError('the MCP config file cannot be read');
    }
    if (raw.byteLength > MAX_CONFIG_BYTES) throw new SecretsConfigError('the MCP config file is larger than 64 KiB');
    parseLocalConfig(raw.toString('utf8'));
    record = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
  }
  change(record);
  const body = `${JSON.stringify(record, null, 2)}\n`;
  parseLocalConfig(body);
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const temp = join(dir, `.mcp.json.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(temp, 'wx', 0o600);
  try {
    writeSync(fd, body);
    fsyncSync(fd);
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(temp); } catch { /* already gone */ }
    throw error;
  }
  closeSync(fd);
  try {
    renameSync(temp, path);
  } catch (error) {
    try { unlinkSync(temp); } catch { /* already gone */ }
    throw error;
  }
}

export function loadLocalConfig(path: string, read: (path: string) => Buffer = p => readFileSync(p)): LocalConfigFile {
  let raw: Buffer;
  try {
    raw = read(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { scope: NO_SCOPE, allowSet: null, allowRotate: false, autoUnlock: false, accountEmail: null };
    }
    throw new SecretsConfigError('the MCP config file cannot be read');
  }
  if (raw.byteLength > MAX_CONFIG_BYTES) throw new SecretsConfigError('the MCP config file is larger than 64 KiB');
  return parseLocalConfig(raw.toString('utf8'));
}

export function loadSecretsConfig(paths: PathEnvironment = currentPathEnvironment()): SecretsConfig {
  const env = paths.env;
  const file = configFile(paths);
  const local = loadLocalConfig(file);
  const rateLimitPerMinute = boundedInt(env, 'DUMONT_SECRETS_RATE_LIMIT', 60, 1, 600);
  const writeRateLimitPerMinute = boundedInt(env, 'DUMONT_SECRETS_WRITE_RATE_LIMIT', 10, 1, 600);
  return {
    bw: {
      bin: parseBwBin(env),
      serverUrl: parseServerUrl(env),
      timeoutMs: boundedInt(env, 'DUMONT_SECRETS_BW_TIMEOUT_MS', 30000, 1000, 120000),
      syncMaxAgeSeconds: boundedInt(env, 'DUMONT_SECRETS_SYNC_MAX_AGE_SECONDS', 60, 0, 3600),
    },
    scope: local.scope,
    configFile: file,
    sessionFile: sessionFile(paths),
    auditFile: auditFile(paths),
    lockFile: lockFile(paths),
    allowSet: parseBoolean(env, 'DUMONT_SECRETS_ALLOW_SET') ?? local.allowSet ?? false,
    allowRotate: local.allowRotate,
    autoUnlock: local.autoUnlock,
    accountEmail: local.accountEmail,
    rateLimitPerMinute,
    writeRateLimitPerMinute: Math.min(writeRateLimitPerMinute, rateLimitPerMinute),
  };
}
