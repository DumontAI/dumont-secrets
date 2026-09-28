import { execFile } from 'node:child_process';
import type { BwItem } from './notes.js';
import { SecretsError, SessionExpired, sessionLocked, type BwConfig } from './types.js';

// The user's own Bitwarden CLI, driven as a subprocess. Rules learned from the
// host `secret` wrapper and kept here:
//   - execFile, never a shell; arguments never carry a value; item JSON goes in
//     on stdin (argv is world-readable in /proc/<pid>/cmdline).
//   - This class never logs in, never unlocks and never sees the master
//     password. The session key comes from the file `dumont-secrets-unlock`
//     (or opt-in auto-unlock, autounlock.ts, through the `recover` hook) wrote,
//     read afresh for every operation, and reaches bw only through the
//     child's environment (BW_SESSION), never argv, never a log.
//   - bw exits 0 even when the session is dead, so every JSON answer is
//     parsed and validated; a non-JSON answer means "re-check the status".
//   - Concurrent bw processes have logged the CLI out: every call goes through
//     one in-process mutex AND a cross-process lock file (other MCP processes).
//   - `bw create`/`bw edit` print the whole item back. stdout is parsed and
//     dropped; stderr is never read into anything that leaves this module.
//   - Personal-vault items (organizationId null) are dropped right here, as
//     soon as the JSON is parsed: nothing above this module ever sees one.

export interface BwRunOptions {
  readonly env: Record<string, string>;
  readonly input?: string;
  readonly timeoutMs: number;
}

export interface BwRunResult {
  readonly code: number | null;
  readonly stdout: string;
  /**
   * Only ever tested against fixed patterns inside this module (the vault's
   * "out of date" refusal); never logged, returned or put in an error.
   */
  readonly stderr?: string;
  readonly timedOut: boolean;
}

export type BwRunner = (args: readonly string[], options: BwRunOptions) => Promise<BwRunResult>;

/** Where the session key comes from; throws SESSION_LOCKED when there is none. */
export type SessionSource = () => string;

/** Serialises bw runs across processes (see lock.ts). Tests pass a no-op. */
export interface CrossProcessLock {
  run<T>(fn: () => Promise<T>): Promise<T>;
}

const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
// Ids come from bw's own JSON; the first character may not be '-' so an id can never read as an option.
const ITEM_ID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const MAX_WAITERS = 32;
const COLLECTION_CACHE_MS = 60_000;
// How long a verified `bw status` (unlocked, right server) is trusted for the same session key.
export const STATUS_TRUST_MS = 60_000;
// Floor between two READ-side syncs (list, miss). Writes always force a sync
// first, so a read-modify-write starts from the vault's current copy; if the
// item still changed in between, the vault refuses the edit as "out of date"
// and the call ends in VAULT_CONFLICT.
export const SYNC_THROTTLE_MS = 30_000;
// The vault's refusal of an edit made from a stale copy (src/api/core/ciphers.rs).
const OUT_OF_DATE = /copy of this cipher is out of date/i;

// The only variables of the user's environment passed on to bw: what it needs
// to find its own data directory (HOME / XDG_CONFIG_HOME / BITWARDENCLI_APPDATA_DIR)
// and to reach the server (proxy, extra CA). Never an inherited BW_SESSION,
// BW_PASSWORD, BW_CLIENTSECRET or anything else.
export const PASSED_ENV = [
  'PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR',
  'BITWARDENCLI_APPDATA_DIR', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
  'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy',
] as const;

export function bwEnvironment(base: NodeJS.ProcessEnv, session: string | null): Record<string, string> {
  const env: Record<string, string> = {};
  for (const name of PASSED_ENV) {
    const value = base[name];
    if (typeof value === 'string' && value !== '') env[name] = value;
  }
  env.PATH ??= '/usr/local/bin:/usr/bin:/bin';
  env.BW_NOINTERACTION = 'true';
  env.LANG = 'C.UTF-8';
  if (session) env.BW_SESSION = session;
  return env;
}

export function execFileRunner(bin: string): BwRunner {
  return (args, options) => new Promise(resolve => {
    const child = execFile(bin, [...args], {
      env: options.env,
      timeout: options.timeoutMs,
      killSignal: 'SIGKILL',
      maxBuffer: MAX_OUTPUT_BYTES,
      windowsHide: true,
      shell: false,
      encoding: 'utf8',
    }, (error, stdout, stderr) => {
      const failure = error as (NodeJS.ErrnoException & { killed?: boolean; code?: unknown }) | null;
      const code = failure ? (typeof failure.code === 'number' ? failure.code : null) : 0;
      resolve({
        code,
        stdout: typeof stdout === 'string' ? stdout : '',
        stderr: typeof stderr === 'string' ? stderr : '',
        timedOut: Boolean(failure?.killed),
      });
    });
    child.stdin?.on('error', () => undefined);
    child.stdin?.end(options.input ?? '');
  });
}

/** One operation at a time, FIFO; refuses when the queue is already long. */
export class Mutex {
  private tail: Promise<void> = Promise.resolve();
  private waiting = 0;

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.waiting >= MAX_WAITERS) {
      throw new SecretsError('VAULT_UNAVAILABLE', 'The vault is busy; retry shortly', true);
    }
    this.waiting += 1;
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>(resolve => { release = resolve; });
    try {
      await previous;
      return await fn();
    } finally {
      this.waiting -= 1;
      release();
    }
  }
}

export interface BwCollection {
  readonly id: string;
  readonly name: string;
  readonly organizationId: string;
}

export interface BwOrganization {
  readonly id: string;
  readonly name: string;
}

class NotJson extends Error {
  constructor(public readonly result: BwRunResult) {
    super('bw answer was not JSON');
  }
}

export function normalizedServer(url: unknown): string {
  if (typeof url !== 'string' || !url) return '';
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`;
  } catch {
    return '';
  }
}

export function serverMismatch(serverUrl: URL): SecretsError {
  const url = normalizedServer(serverUrl.href);
  return new SecretsError(
    'VAULT_SERVER_MISMATCH',
    `Your Bitwarden CLI is not configured for ${url}. In your terminal run: bw logout; bw config server ${url}; ` +
      'bw login --sso; dumont-secrets-unlock',
  );
}

function encodeJson(value: unknown): string {
  // What `bw encode` does: base64 of the JSON text.
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

function isOrganizationItem(item: unknown): item is BwItem {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
  const organizationId = (item as Record<string, unknown>).organizationId;
  return typeof organizationId === 'string' && organizationId !== '';
}

export interface VaultOperations {
  /** `force` bypasses the read-side throttle; only writes use it. */
  sync(options?: { force?: boolean }): Promise<void>;
  syncIfStale(): Promise<void>;
  listOrganizations(): Promise<BwOrganization[]>;
  listCollections(): Promise<BwCollection[]>;
  /** Organization items only: personal-vault items never leave this module. */
  listItems(): Promise<BwItem[]>;
  getItem(id: string): Promise<BwItem>;
  createItem(item: Record<string, unknown>): Promise<string>;
  editItem(id: string, item: Record<string, unknown>): Promise<void>;
}

export interface BwVaultDependencies {
  readonly runner?: BwRunner;
  readonly session: SessionSource;
  /**
   * Called under the cross-process lock when the session source reported an
   * expired session: removes the file if it is still expired and returns true,
   * in which case `bw lock` is run too.
   */
  readonly expire?: () => boolean;
  readonly lock?: CrossProcessLock;
  readonly now?: () => number;
  /** Operational log (stderr): fixed event names only, never bw output. */
  readonly log?: (line: string) => void;
  readonly baseEnv?: NodeJS.ProcessEnv;
  /**
   * Auto-unlock hook. Called (outside the lock file, inside the mutex) when an
   * operation ended in SESSION_LOCKED before it sent any write to bw. Resolves
   * to null when the vault was unlocked (the operation is then retried ONCE), or
   * to the error to answer instead.
   */
  readonly recover?: (locked: SecretsError) => Promise<SecretsError | null>;
}

const NO_LOCK: CrossProcessLock = { run: fn => fn() };

export class BwVault {
  private readonly mutex = new Mutex();
  private readonly runner: BwRunner;
  private readonly lock: CrossProcessLock;
  private readonly now: () => number;
  private readonly log: (line: string) => void;
  private readonly baseEnv: NodeJS.ProcessEnv;
  private readonly sessionSource: SessionSource;
  private readonly expire: (() => boolean) | null;
  private readonly recover: ((locked: SecretsError) => Promise<SecretsError | null>) | null;
  /** The session key of the operation in progress; null outside an operation. */
  private session: string | null = null;
  /** True once the operation in progress has sent a create/edit to bw: it is then never retried. */
  private wrote = false;
  private verified: { session: string; at: number } | null = null;
  private lastSyncAt = 0;
  private syncedSession: string | null = null;
  private collections: { at: number; session: string; list: BwCollection[] } | null = null;

  constructor(private readonly config: BwConfig, dependencies: BwVaultDependencies) {
    this.runner = dependencies.runner ?? execFileRunner(config.bin);
    this.lock = dependencies.lock ?? NO_LOCK;
    this.now = dependencies.now ?? Date.now;
    this.log = dependencies.log ?? (line => { process.stderr.write(`${line}\n`); });
    this.baseEnv = dependencies.baseEnv ?? process.env;
    this.sessionSource = dependencies.session;
    this.expire = dependencies.expire ?? null;
    this.recover = dependencies.recover ?? null;
  }

  /** An expired session: remove the file and `bw lock`, under the lock, then answer SESSION_LOCKED. */
  private async expireSession(): Promise<never> {
    const expire = this.expire;
    if (expire) {
      try {
        await this.lock.run(async () => {
          if (!expire()) return;
          this.log('dumont-secrets-mcp session outcome=expired action=bw_lock');
          await this.runner(['lock'], { env: bwEnvironment(this.baseEnv, null), timeoutMs: this.config.timeoutMs });
        });
      } catch {
        this.log('dumont-secrets-mcp session outcome=expired action=bw_lock_failed');
      }
    }
    this.verified = null;
    throw sessionLocked();
  }

  /**
   * Run one whole operation (reads + read-modify-write) under the mutex, with
   * the session key read afresh from its file and checked against `bw status`.
   */
  withLock<T>(operation: (ops: VaultOperations) => Promise<T>): Promise<T> {
    return this.mutex.run(async () => {
      try {
        return await this.attempt(operation);
      } catch (error) {
        // Auto-unlock (when configured): only for a locked vault, and only when
        // nothing was written yet, so a retry can never write twice.
        const recover = this.recover;
        if (!recover || !(error instanceof SecretsError) || error.code !== 'SESSION_LOCKED' || this.wrote) throw error;
        const replacement = await recover(error);
        if (replacement) throw replacement;
        this.verified = null;
        return await this.attempt(operation);
      }
    });
  }

  private async attempt<T>(operation: (ops: VaultOperations) => Promise<T>): Promise<T> {
    this.wrote = false;
    try {
      this.session = this.sessionSource();
    } catch (error) {
      if (error instanceof SessionExpired) await this.expireSession();
      throw error;
    }
    try {
      await this.ensureVerified(false);
      return await operation(this.operations());
    } finally {
      this.session = null;
    }
  }

  private operations(): VaultOperations {
    return {
      sync: options => this.sync(options?.force === true),
      syncIfStale: async () => {
        const maxAge = this.config.syncMaxAgeSeconds * 1000;
        if (this.syncedSession !== this.session || this.lastSyncAt === 0 || this.now() - this.lastSyncAt >= maxAge) await this.sync();
      },
      listOrganizations: () => this.listOrganizations(),
      listCollections: () => this.listCollections(),
      listItems: () => this.listItems(),
      getItem: id => this.getItem(id),
      createItem: item => this.createItem(item),
      editItem: (id, item) => this.editItem(id, item),
    };
  }

  private async run(args: readonly string[], input?: string): Promise<BwRunResult> {
    let result: BwRunResult;
    try {
      result = await this.lock.run(() => this.runner(args, {
        env: bwEnvironment(this.baseEnv, this.session),
        timeoutMs: this.config.timeoutMs,
        ...(input === undefined ? {} : { input }),
      }));
    } catch (error) {
      if (error instanceof SecretsError) throw error;
      this.log('dumont-secrets-mcp bw outcome=spawn_failed');
      throw new SecretsError('VAULT_UNAVAILABLE', 'The Bitwarden CLI (bw) could not be started; is it installed and on PATH?', true);
    }
    if (result.timedOut) {
      this.log(`dumont-secrets-mcp bw outcome=timeout command=${args[0] ?? ''}`);
      throw new SecretsError('VAULT_UNAVAILABLE', 'The vault did not answer in time', true);
    }
    return result;
  }

  private async runJson(args: readonly string[], input?: string): Promise<unknown> {
    const result = await this.run(args, input);
    const text = result.stdout.trim();
    if (result.code !== 0 || !(text.startsWith('{') || text.startsWith('['))) throw new NotJson(result);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new NotJson(result);
    }
  }

  /**
   * `bw status` with the current session: the CLI must point at the configured
   * server and say "unlocked". Anything else is SESSION_LOCKED (or a server
   * mismatch). Trusted for STATUS_TRUST_MS per session key.
   */
  private async ensureVerified(force: boolean): Promise<void> {
    const session = this.session;
    if (!session) throw sessionLocked();
    if (!force && this.verified && this.verified.session === session && this.now() - this.verified.at < STATUS_TRUST_MS) return;
    this.verified = null;
    let parsed: unknown;
    try {
      parsed = await this.runJson(['status']);
    } catch (error) {
      if (!(error instanceof NotJson)) throw error;
      this.log('dumont-secrets-mcp bw outcome=status_unreadable');
      throw new SecretsError('VAULT_UNAVAILABLE', 'The Bitwarden CLI status could not be read', true);
    }
    const record = parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
    const status = typeof record.status === 'string' ? record.status : '';
    if (normalizedServer(record.serverUrl) !== normalizedServer(this.config.serverUrl.href)) {
      this.log('dumont-secrets-mcp bw outcome=server_mismatch');
      throw serverMismatch(this.config.serverUrl);
    }
    if (status !== 'unlocked') {
      this.log(`dumont-secrets-mcp bw outcome=${status === 'unauthenticated' ? 'unauthenticated' : 'locked'}`);
      throw sessionLocked();
    }
    this.verified = { session, at: this.now() };
  }

  /** A command that needs an unlocked vault: on a non-JSON answer, re-check the status once. */
  private async withSession(args: readonly string[], input?: string): Promise<unknown> {
    try {
      return await this.runJson(args, input);
    } catch (error) {
      if (!(error instanceof NotJson)) throw error;
      // A stale-copy refusal is not a session problem: no recheck, no retry here.
      if (OUT_OF_DATE.test(error.result.stdout) || OUT_OF_DATE.test(error.result.stderr ?? '')) {
        this.log(`dumont-secrets-mcp bw outcome=out_of_date command=${args[0] ?? ''}`);
        throw new SecretsError('VAULT_CONFLICT', 'The item changed in the vault while it was being written; retry the call', true);
      }
    }
    this.log(`dumont-secrets-mcp bw outcome=session_recheck command=${args[0] ?? ''}`);
    // Throws SESSION_LOCKED / VAULT_SERVER_MISMATCH when that is what went wrong.
    await this.ensureVerified(true);
    this.log(`dumont-secrets-mcp bw outcome=unexpected_output command=${args[0] ?? ''}`);
    throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
  }

  private async sync(force = false): Promise<void> {
    if (!force && this.syncedSession === this.session && this.lastSyncAt !== 0 && this.now() - this.lastSyncAt < SYNC_THROTTLE_MS) return;
    const result = await this.run(['sync']);
    if (result.code === 0 && /Syncing complete/i.test(result.stdout)) {
      this.lastSyncAt = this.now();
      this.syncedSession = this.session;
      this.collections = null;
      return;
    }
    this.log('dumont-secrets-mcp bw outcome=sync_failed');
    await this.ensureVerified(true);
    throw new SecretsError('VAULT_UNAVAILABLE', 'The vault could not be synchronised', true);
  }

  private async listOrganizations(): Promise<BwOrganization[]> {
    const parsed = await this.withSession(['list', 'organizations']);
    if (!Array.isArray(parsed)) throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    const list: BwOrganization[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== 'object') continue;
      const { id, name } = entry as Record<string, unknown>;
      if (typeof id === 'string' && typeof name === 'string') list.push({ id, name });
    }
    return list;
  }

  private async listCollections(): Promise<BwCollection[]> {
    const session = this.session ?? '';
    if (this.collections && this.collections.session === session && this.now() - this.collections.at < COLLECTION_CACHE_MS) {
      return this.collections.list;
    }
    const parsed = await this.withSession(['list', 'collections']);
    if (!Array.isArray(parsed)) throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    const list: BwCollection[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== 'object') continue;
      const { id, name, organizationId } = entry as Record<string, unknown>;
      if (typeof id !== 'string' || typeof name !== 'string' || typeof organizationId !== 'string' || !organizationId) continue;
      list.push({ id, name, organizationId });
    }
    this.collections = { at: this.now(), session, list };
    return list;
  }

  private async listItems(): Promise<BwItem[]> {
    const parsed = await this.withSession(['list', 'items']);
    if (!Array.isArray(parsed)) throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    return parsed.filter(isOrganizationItem);
  }

  private async getItem(id: string): Promise<BwItem> {
    if (!ITEM_ID.test(id)) throw new SecretsError('INVALID_ARGUMENT', 'Invalid item id');
    const parsed = await this.withSession(['get', 'item', id]);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    }
    if (!isOrganizationItem(parsed)) throw new SecretsError('ITEM_NOT_FOUND', 'No visible item has this name');
    return parsed;
  }

  private async createItem(item: Record<string, unknown>): Promise<string> {
    // The created item is printed back in full: read its id, drop the rest.
    this.wrote = true;
    const parsed = await this.withSession(['create', 'item'], encodeJson(item));
    const id = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>).id : undefined;
    if (typeof id !== 'string') throw new SecretsError('VAULT_ERROR', 'The vault did not confirm the write');
    return id;
  }

  private async editItem(id: string, item: Record<string, unknown>): Promise<void> {
    if (!ITEM_ID.test(id)) throw new SecretsError('INVALID_ARGUMENT', 'Invalid item id');
    this.wrote = true;
    const parsed = await this.withSession(['edit', 'item', id], encodeJson(item));
    const echoed = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>).id : undefined;
    if (echoed !== id) throw new SecretsError('VAULT_ERROR', 'The vault did not confirm the write');
  }
}
