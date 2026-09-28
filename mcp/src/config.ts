import { statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { RoleNames, SecretsConfig } from './types.js';

// OIDC parsing is adapted from the Bugit MCP (DumontAI/dumont-bugit mcp/src/config.ts).
// Differences: OIDC with JWT access tokens is the only mode (no shared static
// bearer, no introspection), tokens must come from an allowlisted client of
// this server's own ZITADEL project, and three role keys replace the single role.

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const ROLE_KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,100}$/;
const EMAIL_PATTERN = /^[^\s@]{1,64}@[^\s@]{1,190}$/;

export class SecretsConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretsConfigError';
  }
}

function boundedInt(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new SecretsConfigError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function parseBoolean(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = env[name]?.trim().toLowerCase();
  if (!raw) return fallback;
  if (raw === 'true' || raw === '1') return true;
  if (raw === 'false' || raw === '0') return false;
  throw new SecretsConfigError(`${name} must be true or false`);
}

function parseCsv(env: NodeJS.ProcessEnv, name: string): string[] {
  return (env[name] ?? '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
}

function parseOrigins(env: NodeJS.ProcessEnv): string[] {
  const origins = parseCsv(env, 'MCP_ALLOWED_ORIGINS');
  for (const origin of origins) {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new SecretsConfigError('MCP_ALLOWED_ORIGINS must contain valid origins');
    }
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') ||
        url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
      throw new SecretsConfigError('MCP_ALLOWED_ORIGINS must contain origin-only URLs');
    }
  }
  return origins.map(origin => new URL(origin).origin);
}

function parseHosts(env: NodeJS.ProcessEnv): string[] {
  return [...new Set(parseCsv(env, 'MCP_ALLOWED_HOSTS').map(host => host.toLowerCase()))];
}

function validateHttpsUrl(raw: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SecretsConfigError(`${name} must be a valid URL`);
  }
  if (url.protocol !== 'https:') {
    throw new SecretsConfigError(`${name} must use HTTPS`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new SecretsConfigError(`${name} must not contain credentials, query parameters, or fragments`);
  }
  if (url.pathname === '/') url.pathname = '';
  return url;
}

function requiredHttpsUrl(env: NodeJS.ProcessEnv, name: string): URL {
  const raw = env[name]?.trim();
  if (!raw) throw new SecretsConfigError(`${name} is required`);
  return validateHttpsUrl(raw, name);
}

function parseOidcAudience(env: NodeJS.ProcessEnv): string {
  const audience = env.MCP_OIDC_AUDIENCE?.trim() ?? '';
  if (!audience || /\s/.test(audience) || audience.length > 200) {
    throw new SecretsConfigError('MCP_OIDC_AUDIENCE is required and must be one non-empty value without whitespace');
  }
  return audience;
}

function parseOptionalToken(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim() ?? '';
  if (value && /[\r\n]/.test(value)) {
    throw new SecretsConfigError(`${name} must not contain newlines`);
  }
  return value;
}

function parseRoleNames(env: NodeJS.ProcessEnv): RoleNames {
  const names = {
    meta: parseOptionalToken(env, 'SECRETS_MCP_ROLE_META') || 'secrets_meta',
    reader: parseOptionalToken(env, 'SECRETS_MCP_ROLE_READER') || 'secrets_reader',
    writer: parseOptionalToken(env, 'SECRETS_MCP_ROLE_WRITER') || 'secrets_writer',
  };
  for (const [logical, key] of Object.entries(names)) {
    if (!ROLE_KEY_PATTERN.test(key)) {
      throw new SecretsConfigError(`SECRETS_MCP_ROLE_${logical.toUpperCase()} must be 1-100 characters of [A-Za-z0-9_.:-]`);
    }
  }
  if (new Set(Object.values(names)).size !== 3) {
    throw new SecretsConfigError('SECRETS_MCP_ROLE_META, SECRETS_MCP_ROLE_READER and SECRETS_MCP_ROLE_WRITER must be three different role keys');
  }
  return names;
}

/**
 * Token introspection (opaque DCR tokens) is deliberately NOT supported: DCR
 * clients share the project audience of every other DCR MCP, so a token
 * minted for one of them could be replayed here. Any introspection setting is
 * a configuration error, so it cannot be switched on by an env line.
 */
function refuseIntrospection(env: NodeJS.ProcessEnv): void {
  const stray = Object.keys(env).find(name => name.startsWith('MCP_OIDC_INTROSPECTION_') && env[name]?.trim());
  if (stray) {
    throw new SecretsConfigError(`${stray} is not supported: this server accepts only JWT access tokens from its own ZITADEL client`);
  }
}

function parseClientIds(env: NodeJS.ProcessEnv): string[] {
  const ids = [...new Set(parseCsv(env, 'MCP_OIDC_ALLOWED_CLIENT_IDS'))];
  if (ids.length === 0 || ids.some(id => !/^[A-Za-z0-9@._:-]{1,200}$/.test(id))) {
    throw new SecretsConfigError('MCP_OIDC_ALLOWED_CLIENT_IDS is required: the client id(s) of this server\'s own ZITADEL app');
  }
  return ids;
}

function requiredAbsolutePath(env: NodeJS.ProcessEnv, name: string): string {
  const value = parseOptionalToken(env, name);
  if (!value) throw new SecretsConfigError(`${name} is required`);
  if (!isAbsolute(value)) throw new SecretsConfigError(`${name} must be an absolute path`);
  return value;
}

// The proven path. The vault's loopback port also parses, but is untested with the CLI.
const DEFAULT_BW_SERVER_URL = 'https://secret.getdumont.ai';

function parseBwServerUrl(env: NodeJS.ProcessEnv): URL {
  const raw = env.BW_SERVER_URL?.trim() || DEFAULT_BW_SERVER_URL;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SecretsConfigError('BW_SERVER_URL must be a valid URL');
  }
  // The public vault URL, or the vault's own loopback port on this host.
  const loopbackHttp = url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !loopbackHttp) {
    throw new SecretsConfigError('BW_SERVER_URL must use HTTPS or loopback HTTP');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new SecretsConfigError('BW_SERVER_URL must not contain credentials, query parameters, or fragments');
  }
  return url;
}

function parseBwBin(env: NodeJS.ProcessEnv): string {
  const bin = parseOptionalToken(env, 'BW_BIN') || 'bw';
  if (bin !== 'bw' && !isAbsolute(bin)) {
    throw new SecretsConfigError('BW_BIN must be "bw" or an absolute path');
  }
  return bin;
}

export function loadSecretsConfig(env: NodeJS.ProcessEnv = process.env): SecretsConfig {
  const httpHost = env.MCP_HTTP_HOST?.trim() || '127.0.0.1';
  const allowedHosts = parseHosts(env);
  if (!LOOPBACK_HOSTS.has(httpHost) && allowedHosts.length === 0) {
    throw new SecretsConfigError('MCP_ALLOWED_HOSTS is required for non-loopback HTTP binding');
  }

  const mode = env.MCP_AUTH_MODE?.trim().toLowerCase() || 'oidc';
  if (mode !== 'oidc') {
    throw new SecretsConfigError('MCP_AUTH_MODE must be oidc: this server has no shared-bearer mode');
  }

  const oidcIssuer = requiredHttpsUrl(env, 'MCP_OIDC_ISSUER');
  const oidcJwksUrl = requiredHttpsUrl(env, 'MCP_OIDC_JWKS_URL');
  const resourceUrl = requiredHttpsUrl(env, 'MCP_RESOURCE_URL');
  const oidcAudience = parseOidcAudience(env);
  refuseIntrospection(env);
  const oidcAllowedClientIds = parseClientIds(env);
  const email = parseOptionalToken(env, 'BW_EMAIL');
  if (!EMAIL_PATTERN.test(email)) {
    throw new SecretsConfigError('BW_EMAIL is required and must be the machine account e-mail');
  }
  const organizationId = parseOptionalToken(env, 'BW_ORGANIZATION_ID');
  // Passed to bw as an argument value: it must never start with '-'.
  if (organizationId && !/^[0-9a-fA-F][0-9a-fA-F-]{7,63}$/.test(organizationId)) {
    throw new SecretsConfigError('BW_ORGANIZATION_ID must be an organization id');
  }
  const rateLimitPerMinute = boundedInt(env, 'SECRETS_MCP_RATE_LIMIT', 30, 1, 600);
  const writeRateLimitPerMinute = boundedInt(env, 'SECRETS_MCP_WRITE_RATE_LIMIT', 10, 1, 600);

  return {
    httpPort: boundedInt(env, 'MCP_HTTP_PORT', 3015, 1, 65535),
    httpHost,
    allowedOrigins: parseOrigins(env),
    allowedHosts,
    oidcIssuer,
    oidcJwksUrl,
    oidcAudience,
    oidcAllowedClientIds,
    oidcAllowedOrgId: parseOptionalToken(env, 'MCP_OIDC_ALLOWED_ORG_ID'),
    oidcAllowedSubjects: parseCsv(env, 'MCP_OIDC_ALLOWED_SUBJECTS'),
    resourceUrl,
    roleNames: parseRoleNames(env),
    bw: {
      bin: parseBwBin(env),
      serverUrl: parseBwServerUrl(env),
      email,
      passwordFile: requiredAbsolutePath(env, 'BW_PASSWORD_FILE'),
      appDataDir: requiredAbsolutePath(env, 'BW_APPDATA_DIR'),
      timeoutMs: boundedInt(env, 'BW_TIMEOUT_MS', 30000, 1000, 120000),
      organizationId,
      syncMaxAgeSeconds: boundedInt(env, 'SECRETS_MCP_SYNC_MAX_AGE_SECONDS', 60, 0, 3600),
    },
    policyFile: requiredAbsolutePath(env, 'SECRETS_MCP_POLICY_FILE'),
    allowSet: parseBoolean(env, 'SECRETS_MCP_ALLOW_SET', false),
    rateLimitPerMinute,
    writeRateLimitPerMinute: Math.min(writeRateLimitPerMinute, rateLimitPerMinute),
  };
}

export interface FileCheckDependencies {
  readonly stat?: (path: string) => { isFile(): boolean; mode: number; uid: number };
  readonly uid?: number;
}

/**
 * Startup check of the password file WITHOUT reading it: `bw` reads it
 * itself through --passwordfile, so the password never enters this process.
 * It must be a regular file, owned by the service user, mode 0600 or tighter.
 */
export function checkPasswordFile(config: SecretsConfig, dependencies: FileCheckDependencies = {}): void {
  const stat = dependencies.stat ?? statSync;
  const uid = dependencies.uid ?? process.getuid?.() ?? -1;
  let info;
  try {
    info = stat(config.bw.passwordFile);
  } catch {
    throw new SecretsConfigError('BW_PASSWORD_FILE does not exist or cannot be inspected');
  }
  if (!info.isFile()) throw new SecretsConfigError('BW_PASSWORD_FILE must be a regular file');
  if ((info.mode & 0o077) !== 0) {
    throw new SecretsConfigError('BW_PASSWORD_FILE must not be readable by group or others (chmod 0600)');
  }
  if (info.uid !== uid) {
    throw new SecretsConfigError('BW_PASSWORD_FILE must be owned by the user this service runs as');
  }
}
