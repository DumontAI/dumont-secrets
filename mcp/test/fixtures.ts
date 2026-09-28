import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryTransport, type JSONRPCMessage } from '@modelcontextprotocol/server';
import { RateLimiter } from '../src/audit.js';
import { BwVault, type BwRunner } from '../src/bw.js';
import { SecretsService } from '../src/secrets.js';
import { createSecretsServer, type ToolContext } from '../src/tools.js';
import { sessionLocked, type BwConfig, type ScopeConfig } from '../src/types.js';
import { readState, runFakeBw, writeState } from './fixtures/fake-bw.mjs';

export const FAKE_BW = join(import.meta.dirname, 'fixtures', 'fake-bw.mjs');
export const SERVER_URL = 'https://vault.example.test';

// Sentinels: if any of these shows up where it must not, a test fails.
export const SENTINEL_INFRA = 'SENTINEL-infra-value-0001';
export const SENTINEL_OTHER = 'SENTINEL-other-value-0002';
export const SENTINEL_HIDDEN = 'SENTINEL-hidden-bank-0003';
export const SENTINEL_FIELD = 'SENTINEL-field-apikey-0004';
export const SENTINEL_LOGIN = 'SENTINEL-login-password-0005';
export const SENTINEL_WRITABLE = 'SENTINEL-writable-keep-0006';
export const SENTINEL_SHARED = 'SENTINEL-shared-item-0008';
export const SENTINEL_PERSONAL = 'SENTINEL-personal-vault-0009';
export const SENTINEL_OTHER_ORG = 'SENTINEL-other-org-0010';
export const SENTINELS = [
  SENTINEL_INFRA, SENTINEL_OTHER, SENTINEL_HIDDEN, SENTINEL_FIELD, SENTINEL_LOGIN,
  SENTINEL_WRITABLE, SENTINEL_SHARED, SENTINEL_PERSONAL, SENTINEL_OTHER_ORG,
];
export const MASTER_PASSWORD = 'fake-master-password-not-real';
export const INFRA_ITEM = 'svc: example-auth';
export const LOGIN_ITEM = 'svc: example dashboard';
export const SHARED_ITEM = 'shared: finance and writable';
export const HIDDEN_ITEM = 'finance: bank';
export const PERSONAL_ITEM = 'personal: my bank';
export const OTHER_ORG_ITEM = 'partner: api';

export const WRITABLE_NOTES = `# header comment kept byte-for-byte\r\nEXISTING=${SENTINEL_WRITABLE}\r\n\r\n  spaced_key = spaced value  \r\nLAST=last-line-no-newline`;

export function initialState() {
  return {
    serverUrl: SERVER_URL as string | null,
    email: 'person@example.test',
    password: MASTER_PASSWORD,
    loggedIn: true,
    sessions: [] as string[],
    logins: 0,
    unlocks: 0,
    syncs: 0,
    writes: 0,
    delayMs: 0,
    calls: [] as Array<{ args: string[]; hadSession: boolean; stdin: boolean; leakedEnv: string[]; passwordInEnv: boolean }>,
    organizations: [
      { object: 'organization', id: 'org-test', name: 'Example Org', status: 2, type: 2, enabled: true },
      { object: 'organization', id: 'org-other', name: 'Partner Org', status: 2, type: 2, enabled: true },
    ],
    collections: [
      { object: 'collection', id: 'col-infra', organizationId: 'org-test', name: 'Infra/example', externalId: null },
      { object: 'collection', id: 'col-writable', organizationId: 'org-test', name: 'MCP/writable', externalId: null },
      { object: 'collection', id: 'col-hidden', organizationId: 'org-test', name: 'Finance/private', externalId: null },
      { object: 'collection', id: 'col-partner', organizationId: 'org-other', name: 'Partner/shared', externalId: null },
      // Exists in the vault, but this person is not a member: the fake CLI
      // never lists it and strips it from items, like the real one.
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
        name: HIDDEN_ITEM, notes: `BANK_TOKEN=${SENTINEL_HIDDEN}`, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-04T00:00:00.000Z',
      },
      {
        // Shared into another collection AND the writable one: never writable.
        object: 'item', id: 'item-shared', organizationId: 'org-test', collectionIds: ['col-hidden', 'col-writable'], type: 2,
        name: SHARED_ITEM, notes: `SHARED_KEY=${SENTINEL_SHARED}`, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-05T00:00:00.000Z',
      },
      {
        // Another organization the person belongs to.
        object: 'item', id: 'item-partner', organizationId: 'org-other', collectionIds: ['col-partner'], type: 2,
        name: OTHER_ORG_ITEM, notes: `PARTNER_KEY=${SENTINEL_OTHER_ORG}`, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-06T00:00:00.000Z',
      },
      {
        // The person's own vault: must be invisible to the MCP, always.
        object: 'item', id: 'item-personal', organizationId: null, collectionIds: [], type: 2,
        name: PERSONAL_ITEM, notes: `PERSONAL_KEY=${SENTINEL_PERSONAL}`, secureNote: { type: 0 }, fields: [], login: null,
        revisionDate: '2026-09-07T00:00:00.000Z',
      },
    ] as Array<Record<string, unknown> & { id: string; name: string; organizationId: string | null; collectionIds: string[]; notes: string | null; revisionDate: string }>,
  };
}

export type FakeState = ReturnType<typeof initialState>;

export interface FakeVaultDir {
  readonly dir: string;
  /** A per-test directory for the session file, lock and audit log. */
  readonly home: string;
  state(): FakeState;
  update(change: (state: FakeState) => void): void;
  overlaps(): string;
  /** Unlock the fake as the helper would and return the session key. */
  unlock(): string;
}

export function makeVaultDir(change?: (state: FakeState) => void): FakeVaultDir {
  const dir = mkdtempSync(join(tmpdir(), 'secrets-mcp-test-'));
  const home = join(dir, 'home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const state = initialState();
  change?.(state);
  writeState(dir, state);
  return {
    dir,
    home,
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
    unlock: () => {
      const result = runFakeBw(['unlock', '--raw'], { BITWARDENCLI_APPDATA_DIR: dir }, `${MASTER_PASSWORD}\n`);
      if (result.code !== 0) throw new Error('fake unlock failed');
      return result.stdout.trim();
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

export function testBwConfig(overrides: Partial<BwConfig> = {}): BwConfig {
  return {
    bin: FAKE_BW,
    serverUrl: new URL(SERVER_URL),
    timeoutMs: 10_000,
    syncMaxAgeSeconds: 60,
    ...overrides,
  };
}

/** The environment the MCP would inherit, with things that must never reach bw. */
export function baseEnv(vault: FakeVaultDir): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    HOME: vault.home,
    BITWARDENCLI_APPDATA_DIR: vault.dir,
    BW_SESSION: 'inherited-session-must-not-be-used-000000',
    BW_PASSWORD: MASTER_PASSWORD,
    BW_CLIENTSECRET: 'client-secret-must-not-pass',
    SENTINEL_ENV: 'x',
  };
}

export const DEFAULT_SCOPE: ScopeConfig = {
  organizations: null, readCollections: null, writeCollection: 'MCP/writable', valueCollections: ['Infra/example', 'MCP/writable'],
};

export interface Harness {
  readonly vault: FakeVaultDir;
  readonly audit: string[];
  readonly logs: string[];
  readonly context: ToolContext;
  readonly runner: ReturnType<typeof inProcessRunner>;
  /** The session key the MCP reads; set to null to simulate a locked session file. */
  session: string | null;
  /** Moves the vault client's clock (sync throttle, status trust). */
  advance(ms: number): void;
  call(tool: string, args: Record<string, unknown>): Promise<ToolAnswer>;
}

export interface ToolAnswer {
  readonly isError: boolean;
  readonly structured: Record<string, unknown>;
  readonly text: string;
  readonly raw: string;
}

export function harness(options: {
  scope?: Partial<ScopeConfig>;
  allowSet?: boolean;
  allowRotate?: boolean;
  rateLimitPerMinute?: number;
  writeRateLimitPerMinute?: number;
  bw?: Partial<BwConfig>;
  state?: (state: FakeState) => void;
  /** Runs before each bw command, e.g. to change the vault between a list and a get. */
  beforeBw?: (args: readonly string[], vault: FakeVaultDir) => void;
} = {}): Harness {
  const vault = makeVaultDir(options.state);
  const audit: string[] = [];
  const logs: string[] = [];
  const runner = inProcessRunner(undefined, options.beforeBw ? args => options.beforeBw!(args, vault) : undefined);
  let clock = Date.now();
  const scope: ScopeConfig = { ...DEFAULT_SCOPE, ...(options.scope ?? {}) };
  const h = {
    vault,
    audit,
    logs,
    runner,
    session: vault.state().loggedIn ? vault.unlock() : null,
  } as { -readonly [K in keyof Harness]?: Harness[K] } & { session: string | null };
  const bwVault = new BwVault(testBwConfig(options.bw ?? {}), {
    runner,
    session: () => {
      if (!h.session) throw sessionLocked();
      return h.session;
    },
    now: () => clock,
    log: line => { logs.push(line); },
    baseEnv: baseEnv(vault),
  });
  const context: ToolContext = {
    allowSet: options.allowSet ?? false,
    allowRotate: options.allowRotate ?? true,
    service: new SecretsService({ vault: bwVault, scope, log: line => { logs.push(line); } }),
    limiter: new RateLimiter(options.rateLimitPerMinute ?? 1000, options.writeRateLimitPerMinute ?? 1000),
    audit: line => { audit.push(line); },
  };
  h.context = context;
  h.advance = ms => { clock += ms; };
  h.call = (tool, args) => callTool(createSecretsServer(context), tool, args);
  return h as Harness;
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

export function errorCode(answer: { structured: Record<string, unknown> }): unknown {
  return (answer.structured.error as { code?: unknown } | undefined)?.code;
}

export function errorMessage(answer: { structured: Record<string, unknown> }): unknown {
  return (answer.structured.error as { message?: unknown } | undefined)?.message;
}

export function containsAnySentinel(text: string, except: string[] = []): string | undefined {
  return SENTINELS.filter(sentinel => !except.includes(sentinel)).find(sentinel => text.includes(sentinel));
}
