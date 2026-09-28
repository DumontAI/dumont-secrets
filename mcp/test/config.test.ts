import { chmodSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadSecretsConfig, parseLocalConfig, SecretsConfigError, updateLocalConfig } from '../src/config.js';
import { auditFile, configFile, sessionDir, type PathEnvironment } from '../src/paths.js';

function paths(overrides: Partial<PathEnvironment> & { env?: NodeJS.ProcessEnv } = {}): PathEnvironment {
  return {
    env: {},
    platform: 'linux',
    home: '/home/person',
    uid: 1000,
    ownedDir: () => false,
    ...overrides,
  };
}

describe('per-user paths', () => {
  it('Linux: XDG_RUNTIME_DIR when it is ours, then /run/user/<uid>, then ~/.cache', () => {
    const owned = (dirs: string[]) => (path: string) => dirs.includes(path);
    expect(sessionDir(paths({ env: { XDG_RUNTIME_DIR: '/run/user/1000' }, ownedDir: owned(['/run/user/1000']) })))
      .toBe('/run/user/1000/dumont-secrets');
    // A client started without XDG_RUNTIME_DIR still finds the same directory.
    expect(sessionDir(paths({ ownedDir: owned(['/run/user/1000']) }))).toBe('/run/user/1000/dumont-secrets');
    expect(sessionDir(paths({ env: { XDG_RUNTIME_DIR: '/tmp/not-mine' } }))).toBe('/home/person/.cache/dumont-secrets');
    expect(sessionDir(paths({ env: { XDG_RUNTIME_DIR: 'relative' } }))).toBe('/home/person/.cache/dumont-secrets');
  });

  it('macOS: ~/Library/Caches and ~/Library/Logs', () => {
    const mac = paths({ platform: 'darwin', home: '/Users/person', env: { XDG_RUNTIME_DIR: '/x' }, ownedDir: () => true });
    expect(sessionDir(mac)).toBe('/Users/person/Library/Caches/dumont-secrets');
    expect(auditFile(mac)).toBe('/Users/person/Library/Logs/dumont-secrets/audit.log');
    expect(configFile(mac)).toBe('/Users/person/.config/dumont-secrets/mcp.json');
  });

  it('XDG and explicit overrides', () => {
    const p = paths({ env: { XDG_STATE_HOME: '/state', XDG_CONFIG_HOME: '/conf' } });
    expect(auditFile(p)).toBe('/state/dumont-secrets/audit.log');
    expect(configFile(p)).toBe('/conf/dumont-secrets/mcp.json');
    const o = paths({ env: { DUMONT_SECRETS_SESSION_DIR: '/s', DUMONT_SECRETS_AUDIT_LOG: '/a.log', DUMONT_SECRETS_MCP_CONFIG: '/c.json' } });
    expect(sessionDir(o)).toBe('/s');
    expect(auditFile(o)).toBe('/a.log');
    expect(configFile(o)).toBe('/c.json');
    expect(auditFile(paths())).toBe('/home/person/.local/state/dumont-secrets/audit.log');
  });
});

describe('local scope config', () => {
  it('every key is optional; defaults are all organizations, all collections, no writes', () => {
    expect(parseLocalConfig('{}')).toEqual({
      scope: { organizations: null, readCollections: null, writeCollection: null, valueCollections: null },
      allowSet: null,
      allowRotate: false,
      autoUnlock: false,
      accountEmail: null,
    });
    expect(parseLocalConfig(JSON.stringify({
      version: 1, organizations: ['Example Org', 'Example Org'], read_collections: ['Infra/example'], write_collection: 'MCP/writable',
      value_collections: ['Infra/example'], allow_set: true, allow_rotate: true, auto_unlock: true, account_email: 'person@example.test',
    }))).toEqual({
      scope: { organizations: ['Example Org'], readCollections: ['Infra/example'], writeCollection: 'MCP/writable', valueCollections: ['Infra/example'] },
      allowSet: true,
      allowRotate: true,
      autoUnlock: true,
      accountEmail: 'person@example.test',
    });
  });

  it('refuses unknown keys, empty lists, control characters and a wrong version', () => {
    for (const raw of [
      'nope', '[]', '{"roles":{}}', '{"organizations":[]}', '{"organizations":"Example"}',
      '{"read_collections":["a\\nb"]}', '{"write_collection":""}', '{"version":2}', '{"allow_set":"yes"}',
      '{"value_collections":[]}', '{"allow_rotate":1}', '{"auto_unlock":"true"}', '{"auto_unlock":1}',
      '{"account_email":"not-an-email"}', '{"account_email":"-o@x.test"}', '{"account_email":"a b@x.test"}',
      '{"account_email":"a@x.test\\n"}', '{"auto_unlock_password":"x"}',
    ]) {
      expect(() => parseLocalConfig(raw), raw).toThrow(SecretsConfigError);
    }
  });

  it('updateLocalConfig merges keys, keeps the others, writes 0600, and refuses an invalid file or a symlink', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-config-'));
    const file = join(dir, 'nested', 'mcp.json');
    // Created from nothing, in a 0700 directory.
    updateLocalConfig(file, record => { record.auto_unlock = true; record.account_email = 'person@example.test'; });
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, 'nested')).mode & 0o777).toBe(0o700);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ auto_unlock: true, account_email: 'person@example.test' });
    // An existing file (too open on purpose): other keys and their order are kept; the mode becomes 0600.
    const existing = { version: 1, organizations: ['Example Org'], value_collections: ['Infra/example'], write_collection: 'MCP/writable', allow_rotate: true };
    writeFileSync(file, JSON.stringify(existing), { mode: 0o644 });
    chmodSync(file, 0o644);
    updateLocalConfig(file, record => { record.auto_unlock = true; record.account_email = 'person@example.test'; });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ ...existing, auto_unlock: true, account_email: 'person@example.test' });
    expect(Object.keys(JSON.parse(readFileSync(file, 'utf8')) as object)).toEqual([...Object.keys(existing), 'auto_unlock', 'account_email']);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    updateLocalConfig(file, record => { record.auto_unlock = false; delete record.account_email; });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ ...existing, auto_unlock: false });
    expect(readdirSync(join(dir, 'nested'))).toEqual(['mcp.json']);
    // An invalid file is not overwritten.
    writeFileSync(file, '{"roles":{}}');
    expect(() => updateLocalConfig(file, record => { record.auto_unlock = true; })).toThrow(SecretsConfigError);
    expect(readFileSync(file, 'utf8')).toBe('{"roles":{}}');
    // A change that would make it invalid is not written.
    writeFileSync(file, '{}');
    expect(() => updateLocalConfig(file, record => { record.account_email = 'nope'; })).toThrow(SecretsConfigError);
    expect(readFileSync(file, 'utf8')).toBe('{}');
    // A symlink is refused (the rename would replace the link).
    const link = join(dir, 'link.json');
    symlinkSync(file, link);
    expect(() => updateLocalConfig(link, record => { record.auto_unlock = true; })).toThrow('symlink');
  });

  it('loads env + file, env wins for allow_set, a missing file means defaults', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-config-'));
    const file = join(dir, 'mcp.json');
    const base = paths({ home: dir, env: { DUMONT_SECRETS_MCP_CONFIG: file } });
    const missing = loadSecretsConfig(base);
    expect(missing.scope).toEqual({ organizations: null, readCollections: null, writeCollection: null, valueCollections: null });
    expect(missing.allowRotate).toBe(false);
    expect(missing.allowSet).toBe(false);
    expect(missing.bw.serverUrl.href).toBe('https://secret.getdumont.ai/');
    expect(missing.rateLimitPerMinute).toBe(60);
    expect(missing.writeRateLimitPerMinute).toBe(10);
    writeFileSync(file, JSON.stringify({ write_collection: 'MCP/writable', allow_set: true }));
    expect(loadSecretsConfig(base).allowSet).toBe(true);
    expect(loadSecretsConfig(paths({ home: dir, env: { DUMONT_SECRETS_MCP_CONFIG: file, DUMONT_SECRETS_ALLOW_SET: 'false' } })).allowSet).toBe(false);
    writeFileSync(file, '{"write_collection":');
    expect(() => loadSecretsConfig(base)).toThrow('valid JSON');
  });

  it('refuses a non-HTTPS server, a relative bw path and out-of-range limits', () => {
    for (const env of [
      { DUMONT_SECRETS_SERVER_URL: 'http://vault.example.test' },
      { DUMONT_SECRETS_SERVER_URL: 'https://user:pw@vault.example.test' },
      { DUMONT_SECRETS_BW_BIN: 'bin/bw' },
      { DUMONT_SECRETS_RATE_LIMIT: '0' },
      { DUMONT_SECRETS_ALLOW_SET: 'maybe' },
    ]) {
      const dir = mkdtempSync(join(tmpdir(), 'secrets-config-'));
      expect(() => loadSecretsConfig(paths({ home: dir, env: { ...env, DUMONT_SECRETS_MCP_CONFIG: join(dir, 'none.json') } }))).toThrow(SecretsConfigError);
    }
    const dir = mkdtempSync(join(tmpdir(), 'secrets-config-'));
    const loopback = loadSecretsConfig(paths({ home: dir, env: { DUMONT_SECRETS_SERVER_URL: 'http://127.0.0.1:8080', DUMONT_SECRETS_MCP_CONFIG: join(dir, 'none.json') } }));
    expect(loopback.bw.serverUrl.origin).toBe('http://127.0.0.1:8080');
  });
});
