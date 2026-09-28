import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkPasswordFile, loadSecretsConfig } from '../src/config.js';
import { accessFor, loadPolicy, parsePolicy } from '../src/policy.js';
import { BASE_ENV, principal } from './fixtures.js';

describe('configuration', () => {
  it('has safe defaults: loopback 3015, set disabled, 30/10 per minute, the three role keys', () => {
    const config = loadSecretsConfig(BASE_ENV);
    expect(config).toMatchObject({
      httpHost: '127.0.0.1',
      httpPort: 3015,
      allowSet: false,
      rateLimitPerMinute: 30,
      writeRateLimitPerMinute: 10,
      roleNames: { meta: 'secrets_meta', reader: 'secrets_reader', writer: 'secrets_writer' },
      oidcAllowedClientIds: ['secrets-mcp-client'],
    });
    expect(config.bw).toMatchObject({ bin: 'bw', email: 'machine-account@example.test', timeoutMs: 30000, organizationId: '' });
    const { BW_SERVER_URL: _unused, ...withoutServer } = BASE_ENV;
    expect(loadSecretsConfig(withoutServer).bw.serverUrl.href).toBe('https://secret.getdumont.ai/');
  });

  it('accepts a loopback vault URL, several client ids and renamed roles', () => {
    const config = loadSecretsConfig({
      ...BASE_ENV,
      BW_SERVER_URL: 'http://127.0.0.1:8080',
      MCP_OIDC_ALLOWED_CLIENT_IDS: 'client-a, client-b',
      SECRETS_MCP_ROLE_META: 'vault_meta',
      SECRETS_MCP_ALLOW_SET: 'true',
    });
    expect(config.bw.serverUrl.href).toBe('http://127.0.0.1:8080/');
    expect(config.oidcAllowedClientIds).toEqual(['client-a', 'client-b']);
    expect(config.roleNames.meta).toBe('vault_meta');
    expect(config.allowSet).toBe(true);
  });

  it.each([
    [{ MCP_AUTH_MODE: 'static' }, /no shared-bearer mode/],
    [{ MCP_OIDC_AUDIENCE: '' }, /MCP_OIDC_AUDIENCE is required/],
    [{ MCP_OIDC_ISSUER: 'http://issuer.example.test' }, /MCP_OIDC_ISSUER must use HTTPS/],
    [{ MCP_RESOURCE_URL: '' }, /MCP_RESOURCE_URL is required/],
    [{ BW_SERVER_URL: 'http://vault.example.test' }, /HTTPS or loopback HTTP/],
    [{ BW_SERVER_URL: 'https://user:pass@vault.example.test' }, /must not contain credentials/],
    [{ BW_EMAIL: 'not-an-email' }, /BW_EMAIL/],
    [{ BW_PASSWORD_FILE: 'relative/path' }, /BW_PASSWORD_FILE must be an absolute path/],
    [{ BW_PASSWORD_FILE: '' }, /BW_PASSWORD_FILE is required/],
    [{ BW_APPDATA_DIR: '' }, /BW_APPDATA_DIR is required/],
    [{ BW_BIN: 'node_modules/.bin/bw' }, /BW_BIN/],
    [{ SECRETS_MCP_POLICY_FILE: '' }, /SECRETS_MCP_POLICY_FILE is required/],
    [{ SECRETS_MCP_ALLOW_SET: 'yes' }, /SECRETS_MCP_ALLOW_SET must be true or false/],
    [{ SECRETS_MCP_RATE_LIMIT: '0' }, /SECRETS_MCP_RATE_LIMIT/],
    [{ SECRETS_MCP_ROLE_READER: 'secrets_meta' }, /three different role keys/],
    [{ SECRETS_MCP_ROLE_WRITER: 'has space' }, /SECRETS_MCP_ROLE_WRITER/],
    [{ MCP_HTTP_HOST: '0.0.0.0' }, /MCP_ALLOWED_HOSTS is required/],
    [{ BW_ORGANIZATION_ID: '--session' }, /BW_ORGANIZATION_ID/],
    [{ MCP_OIDC_ALLOWED_CLIENT_IDS: '' }, /MCP_OIDC_ALLOWED_CLIENT_IDS is required/],
    [{ MCP_OIDC_ALLOWED_CLIENT_IDS: 'has space' }, /MCP_OIDC_ALLOWED_CLIENT_IDS is required/],
    [{ MCP_OIDC_INTROSPECTION_URL: 'https://issuer.example.test/oauth/v2/introspect' }, /MCP_OIDC_INTROSPECTION_URL is not supported/],
    [{ MCP_OIDC_INTROSPECTION_CLIENT_SECRET: 'introspection-secret-value' }, /MCP_OIDC_INTROSPECTION_CLIENT_SECRET is not supported/],
  ])('refuses %j', (override, message) => {
    expect(() => loadSecretsConfig({ ...BASE_ENV, ...override })).toThrow(message);
  });

  it('checks the password file without reading it: regular file, 0600, owned by the service user', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-mcp-config-'));
    const file = join(dir, 'bw-password');
    writeFileSync(file, 'x');
    const config = loadSecretsConfig({ ...BASE_ENV, BW_PASSWORD_FILE: file });
    chmodSync(file, 0o644);
    expect(() => checkPasswordFile(config)).toThrow(/chmod 0600/);
    chmodSync(file, 0o600);
    expect(() => checkPasswordFile(config)).not.toThrow();
    expect(() => checkPasswordFile(config, { uid: 99999 })).toThrow(/owned by the user/);
    expect(() => checkPasswordFile(loadSecretsConfig({ ...BASE_ENV, BW_PASSWORD_FILE: join(dir, 'missing') }))).toThrow(/does not exist/);
    expect(() => checkPasswordFile(loadSecretsConfig({ ...BASE_ENV, BW_PASSWORD_FILE: dir }))).toThrow(/regular file/);
  });
});

describe('collection policy file', () => {
  it('ships an example that parses', () => {
    const policy = loadPolicy(join(import.meta.dirname, '..', 'policy.example.json'));
    expect(policy.writeCollection).toBe('MCP/writable');
    expect(policy.metaCollections.length).toBeGreaterThan(0);
    // The example is a placeholder: no ids, no hosts, only names.
    const raw = readFileSync(join(import.meta.dirname, '..', 'policy.example.json'), 'utf8');
    expect(raw).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-/i);
  });

  it.each([
    ['not json', /valid JSON/],
    [JSON.stringify({ version: 2, roles: {} }), /version must be 1/],
    [JSON.stringify({ version: 1, roles: { meta: { read_collections: ['A'] }, reader: { read_collections: ['A'] } } }), /roles.writer is required/],
    [JSON.stringify({ version: 1, roles: { meta: { read_collections: [] }, reader: { read_collections: ['A'] }, writer: { write_collection: 'W' } } }), /non-empty array/],
    [JSON.stringify({ version: 1, roles: { meta: { read_collections: ['A'] }, reader: { read_collections: ['A'] }, writer: { write_collection: ['W'] } } }), /write_collection/],
    [JSON.stringify({ version: 1, roles: { meta: { read_collections: ['A'] }, reader: { read_collections: ['A'] }, writer: { write_collection: 'W', read_collections: ['X'] } } }), /writer takes only write_collection/],
    [JSON.stringify({ version: 1, roles: { admin: {}, meta: { read_collections: ['A'] }, reader: { read_collections: ['A'] }, writer: { write_collection: 'W' } } }), /only contain meta, reader and writer/],
    [JSON.stringify({ version: 1, roles: { meta: { read_collections: ['bad\nname'] }, reader: { read_collections: ['A'] }, writer: { write_collection: 'W' } } }), /printable/],
  ])('refuses a malformed policy (%#)', (raw, message) => {
    expect(() => parsePolicy(raw)).toThrow(message);
  });

  it('applies the hierarchy: reader => meta, writer => meta only', () => {
    const policy = parsePolicy(JSON.stringify({
      version: 1,
      roles: {
        meta: { read_collections: ['Meta'] },
        reader: { read_collections: ['Read'] },
        writer: { write_collection: 'Write' },
      },
    }));
    expect(accessFor(principal(['meta']), policy)).toMatchObject({ canMeta: true, canRead: false, canWrite: false, metaCollections: ['Meta'], readCollections: [] });
    expect(accessFor(principal(['reader']), policy)).toMatchObject({ canMeta: true, canRead: true, canWrite: false, metaCollections: ['Meta', 'Read'], readCollections: ['Read'] });
    expect(accessFor(principal(['writer']), policy)).toMatchObject({ canMeta: true, canRead: false, canWrite: true, metaCollections: ['Meta', 'Write'], readCollections: [], writeCollection: 'Write' });
  });
});
