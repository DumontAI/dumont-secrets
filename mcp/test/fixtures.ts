import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryTransport, type JSONRPCMessage } from '@modelcontextprotocol/server';
import { RateLimiter } from '../src/audit.js';
import { BwVault, type BwRunner } from '../src/bw.js';
import { parsePolicy, type SecretsPolicy } from '../src/policy.js';
import { SecretsService } from '../src/secrets.js';
import { createSecretsServer, type ToolContext } from '../src/tools.js';
import type { LogicalRole, Principal, SecretsConfig } from '../src/types.js';
import { readState, runFakeBw, writeState } from './fixtures/fake-bw.mjs';

export const FAKE_BW = join(import.meta.dirname, 'fixtures', 'fake-bw.mjs');

// Sentinels: if any of these shows up where it must not, a test fails.
export const SENTINEL_INFRA = 'SENTINEL-infra-value-0001';
export const SENTINEL_OTHER = 'SENTINEL-other-value-0002';
export const SENTINEL_HIDDEN = 'SENTINEL-hidden-bank-0003';
export const SENTINEL_FIELD = 'SENTINEL-field-apikey-0004';
export const SENTINEL_LOGIN = 'SENTINEL-login-password-0005';
export const SENTINEL_WRITABLE = 'SENTINEL-writable-keep-0006';
export const SENTINEL_SHARED = 'SENTINEL-shared-item-0008';
export const SENTINELS = [SENTINEL_INFRA, SENTINEL_OTHER, SENTINEL_HIDDEN, SENTINEL_FIELD, SENTINEL_LOGIN, SENTINEL_WRITABLE, SENTINEL_SHARED];
export const MACHINE_PASSWORD = 'fake-machine-password-not-real';
export const INFRA_ITEM = 'svc: example-auth';
export const LOGIN_ITEM = 'svc: example dashboard';
export const SHARED_ITEM = 'shared: hidden and writable';

export const WRITABLE_NOTES = `# header comment kept byte-for-byte\r\nEXISTING=${SENTINEL_WRITABLE}\r\n\r\n  spaced_key = spaced value  \r\nLAST=last-line-no-newline`;

export function initialState() {
  return {
    serverUrl: null,
    email: 'machine-account@example.test',
    password: MACHINE_PASSWORD,
    loggedIn: false,
    sessions: [] as string[],
    logins: 0,
    unlocks: 0,
    syncs: 0,
    writes: 0,
    delayMs: 0,
    calls: [] as Array<{ args: string[]; hadSession: boolean; stdin: boolean }>,
    collections: [
      { object: 'collection', id: 'col-infra', organizationId: 'org-test', name: 'Infra/hel1', externalId: null },
      { object: 'collection', id: 'col-writable', organizationId: 'org-test', name: 'MCP/writable', externalId: null },
      { object: 'collection', id: 'col-hidden', organizationId: 'org-test', name: 'Finance/private', externalId: null },
      // Exists in the vault, but the machine account is not a member: the fake
      // CLI never lists it and strips it from items, like the real one.
      { object: 'collection', id: 'col-nonmember', organizationId: 'org-test', name: 'Ops/restricted', externalId: null, member: false },
    ] as Array<{ object: string; id: string; organizationId: string; name: string; externalId: null; member?: boolean }>,
    items: [
      {
        object: 'item', id: 'item-infra', organizationId: 'org-test', collectionIds: ['col-infra'], type: 2,
        name: INFRA_ITEM, notes: `EXAMPLE_ADMIN_TOKEN=${SENTINEL_INFRA}\nOTHER_KEY=${SENTINEL_OTHER}\n`,
        secureNote: { type: 0 }, fields: [], login: null, revisionDate: '2026-09-01T00:00:00.000Z',
      },
      {
        object: 'item', id: 'item-login', organizationId: 'org-test', collectionIds: ['col-infra'], type: 1,
        name: LOGIN_ITEM, notes: null,
        fields: [{ name: 'api_key', value: SENTINEL_FIELD, type: 1 }],
        login: { username: 'admin-user-name', password: SENTINEL_LOGIN, totp: null },
        revisionDate: '2026-09-02T00:00:00.000Z',
      },
      {
        object: 'item', id: 'item-writable', organizationId: 'org-test', collectionIds: ['col-writable'], type: 2,
        name: 'app: generated', notes: WRITABLE_NOTES, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-03T00:00:00.000Z',
      },
      {
        object: 'item', id: 'item-hidden', organizationId: 'org-test', collectionIds: ['col-hidden'], type: 2,
        name: 'finance: bank', notes: `BANK_TOKEN=${SENTINEL_HIDDEN}`, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-04T00:00:00.000Z',
      },
      {
        // Shared into a hidden collection AND the writable one: never writable.
        object: 'item', id: 'item-shared', organizationId: 'org-test', collectionIds: ['col-hidden', 'col-writable'], type: 2,
        name: SHARED_ITEM, notes: `SHARED_KEY=${SENTINEL_SHARED}`, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-05T00:00:00.000Z',
      },
    ],
  };
}

export type FakeState = ReturnType<typeof initialState>;

export interface FakeVaultDir {
  readonly dir: string;
  readonly passwordFile: string;
  state(): FakeState;
  update(change: (state: FakeState) => void): void;
  overlaps(): string;
}

export function makeVaultDir(change?: (state: FakeState) => void): FakeVaultDir {
  const dir = mkdtempSync(join(tmpdir(), 'secrets-mcp-test-'));
  const passwordFile = join(dir, 'bw-password');
  writeFileSync(passwordFile, `${MACHINE_PASSWORD}\n`);
  chmodSync(passwordFile, 0o600);
  const state = initialState();
  change?.(state);
  writeState(dir, state);
  return {
    dir,
    passwordFile,
    state: () => readState(dir) as FakeState,
    update: fn => {
      const current = readState(dir) as FakeState;
      fn(current);
      writeState(dir, current);
    },
    overlaps: () => {
      try {
        return readFileSync(join(dir, 'fake-state.json.overlap'), 'utf8');
      } catch {
        return '';
      }
    },
  };
}

/** In-process runner over the same fake, with an async gap so overlapping calls would be visible. */
export function inProcessRunner(
  tracker = { active: 0, maxActive: 0, calls: 0 },
  before?: (args: readonly string[]) => void,
): BwRunner & { tracker: typeof tracker } {
  const runner = (async (args, options) => {
    tracker.active += 1;
    tracker.calls += 1;
    tracker.maxActive = Math.max(tracker.maxActive, tracker.active);
    try {
      await new Promise(resolve => setTimeout(resolve, 2));
      before?.(args);
      const result = runFakeBw([...args], options.env, options.input ?? '');
      return { code: result.code, stdout: result.stdout, stderr: result.stderr ?? '', timedOut: false };
    } finally {
      tracker.active -= 1;
    }
  }) as BwRunner & { tracker: typeof tracker };
  runner.tracker = tracker;
  return runner;
}

export const BASE_ENV = {
  MCP_RESOURCE_URL: 'https://secret.example.test/mcp',
  MCP_OIDC_ISSUER: 'https://issuer.example.test',
  MCP_OIDC_JWKS_URL: 'https://issuer.example.test/oauth/v2/keys',
  MCP_OIDC_AUDIENCE: 'secrets-mcp-project',
  MCP_OIDC_ALLOWED_CLIENT_IDS: 'secrets-mcp-client',
  BW_SERVER_URL: 'https://vault.example.test',
  BW_EMAIL: 'machine-account@example.test',
  BW_PASSWORD_FILE: '/etc/dumont-secrets-mcp/bw-password',
  BW_APPDATA_DIR: '/var/lib/dumont-secrets-mcp/bw',
  SECRETS_MCP_POLICY_FILE: '/etc/dumont-secrets-mcp/policy.json',
};

export const POLICY_JSON = JSON.stringify({
  version: 1,
  roles: {
    meta: { read_collections: ['Infra/hel1', 'MCP/writable'] },
    reader: { read_collections: ['Infra/hel1', 'MCP/writable'] },
    writer: { write_collection: 'MCP/writable' },
  },
});

export function testPolicy(): SecretsPolicy {
  return parsePolicy(POLICY_JSON);
}

export function testConfig(overrides: Partial<SecretsConfig> = {}, vault?: FakeVaultDir): SecretsConfig {
  return {
    httpPort: 0,
    httpHost: '127.0.0.1',
    allowedOrigins: [],
    allowedHosts: [],
    oidcIssuer: new URL('https://issuer.example.test'),
    oidcJwksUrl: new URL('https://issuer.example.test/oauth/v2/keys'),
    oidcAudience: 'secrets-mcp-project',
    oidcAllowedClientIds: ['secrets-mcp-client'],
    oidcAllowedOrgId: '',
    oidcAllowedSubjects: [],
    resourceUrl: new URL('https://secret.example.test/mcp'),
    roleNames: { meta: 'secrets_meta', reader: 'secrets_reader', writer: 'secrets_writer' },
    bw: {
      bin: FAKE_BW,
      serverUrl: new URL('https://vault.example.test'),
      email: 'machine-account@example.test',
      passwordFile: vault?.passwordFile ?? '/nonexistent/bw-password',
      appDataDir: vault?.dir ?? '/nonexistent/appdata',
      timeoutMs: 10_000,
      organizationId: '',
      syncMaxAgeSeconds: 60,
    },
    policyFile: '/nonexistent/policy.json',
    allowSet: false,
    rateLimitPerMinute: 1000,
    writeRateLimitPerMinute: 1000,
    ...overrides,
  };
}

export function principal(roles: LogicalRole[], sub = 'user-1', email: string | null = 'person@example.test'): Principal {
  return { sub, email, roles: new Set(roles) };
}

export interface Harness {
  readonly vault: FakeVaultDir;
  readonly audit: string[];
  readonly logs: string[];
  readonly context: ToolContext;
  readonly runner: ReturnType<typeof inProcessRunner>;
  /** Moves the vault client's clock (sync throttle, auth back-off). */
  advance(ms: number): void;
  call(roles: LogicalRole[], tool: string, args: Record<string, unknown>, sub?: string): Promise<ToolAnswer>;
}

export interface ToolAnswer {
  readonly isError: boolean;
  readonly structured: Record<string, unknown>;
  readonly text: string;
  readonly raw: string;
}

export function harness(options: {
  config?: Partial<SecretsConfig>;
  state?: (state: FakeState) => void;
  /** Runs before each bw command, e.g. to change the vault between a list and a get. */
  beforeBw?: (args: readonly string[], vault: FakeVaultDir) => void;
} = {}): Harness {
  const vault = makeVaultDir(options.state);
  const config = testConfig(options.config ?? {}, vault);
  const audit: string[] = [];
  const logs: string[] = [];
  const runner = inProcessRunner(undefined, options.beforeBw ? args => options.beforeBw!(args, vault) : undefined);
  let clock = Date.now();
  const bwVault = new BwVault(config.bw, { runner, now: () => clock, log: line => { logs.push(line); } });
  const context: ToolContext = {
    config,
    policy: testPolicy(),
    service: new SecretsService({ vault: bwVault, log: line => { logs.push(line); } }),
    limiter: new RateLimiter(config.rateLimitPerMinute, config.writeRateLimitPerMinute),
    audit: line => { audit.push(line); },
  };
  return {
    vault,
    audit,
    logs,
    context,
    runner,
    advance: ms => { clock += ms; },
    call: (roles, tool, args, sub = 'user-1') => callTool(createSecretsServer(context, principal(roles, sub)), tool, args),
  };
}

function isResponse(message: JSONRPCMessage, id: number): boolean {
  return 'id' in message && message.id === id;
}

export async function rpc(transport: InMemoryTransport, message: JSONRPCMessage & { id: number }): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const previous = transport.onmessage;
    transport.onmessage = (response) => {
      if (!isResponse(response, message.id)) return;
      transport.onmessage = previous;
      resolve(response as Record<string, unknown>);
    };
    void transport.send(message).catch(reject);
  });
}

export async function callTool(
  server: ReturnType<typeof createSecretsServer>,
  name: string,
  args: Record<string, unknown>,
): Promise<ToolAnswer> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await clientTransport.start();
  try {
    await rpc(clientTransport, {
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
    });
    await clientTransport.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const response = await rpc(clientTransport, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } });
    const result = (response.result ?? {}) as { isError?: boolean; structuredContent?: Record<string, unknown>; content?: Array<{ text?: string }> };
    return {
      isError: result.isError === true || response.error !== undefined,
      structured: result.structuredContent ?? {},
      text: (result.content ?? []).map(part => part.text ?? '').join('\n'),
      raw: JSON.stringify(response),
    };
  } finally {
    await clientTransport.close();
    await server.close();
  }
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
