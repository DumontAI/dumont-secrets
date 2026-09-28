import { execFile } from 'node:child_process';
import type { BwItem } from './notes.js';
import { SecretsError, type BwConfig } from './types.js';

// The Bitwarden CLI, driven as a subprocess. Rules learned from the host
// `secret` wrapper and kept here:
//   - execFile, never a shell; arguments never carry a value or a password:
//     the password is read by bw from --passwordfile, item JSON goes in on
//     stdin (argv is world-readable in /proc/<pid>/cmdline).
//   - BW_SESSION lives in this process's memory only and reaches bw through
//     the child's environment, never argv, never disk.
//   - bw exits 0 even when the session is dead, so every JSON answer is
//     parsed and validated; a non-JSON answer means "re-check the session".
//   - Concurrent bw processes have logged the CLI out: every call goes through
//     one in-process mutex, one operation at a time.
//   - `bw create`/`bw edit` print the whole item back. stdout is parsed and
//     dropped; stderr is never read into anything that leaves this module.

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

const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
const SESSION_KEY = /^[A-Za-z0-9+/=_-]{16,512}$/;
// Ids come from bw's own JSON; the first character may not be '-' so an id can never read as an option.
const ITEM_ID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const MAX_WAITERS = 32;
const COLLECTION_CACHE_MS = 60_000;
// After a failed login/unlock, no new attempt for this long: a wrong password
// must not turn every tool call into a login attempt against the vault.
export const AUTH_BACKOFF_MS = 30_000;
// Floor between two READ-side syncs (list, miss). Writes always force a sync
// first, so a read-modify-write starts from the vault's current copy; if the
// item still changed in between, the vault refuses the edit as "out of date"
// and the call ends in VAULT_CONFLICT.
export const SYNC_THROTTLE_MS = 30_000;
// The vault's refusal of an edit made from a stale copy (src/api/core/ciphers.rs).
const OUT_OF_DATE = /copy of this cipher is out of date/i;

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

class NotJson extends Error {
  constructor(public readonly result: BwRunResult) {
    super('bw answer was not JSON');
  }
}

function normalizedServer(url: unknown): string {
  if (typeof url !== 'string' || !url) return '';
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`;
  } catch {
    return '';
  }
}

function encodeJson(value: unknown): string {
  // What `bw encode` does: base64 of the JSON text.
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

export interface VaultOperations {
  /** `force` bypasses the read-side throttle; only writes use it. */
  sync(options?: { force?: boolean }): Promise<void>;
  syncIfStale(): Promise<void>;
  listCollections(): Promise<BwCollection[]>;
  listItems(): Promise<BwItem[]>;
  getItem(id: string): Promise<BwItem>;
  createItem(item: Record<string, unknown>): Promise<string>;
  editItem(id: string, item: Record<string, unknown>): Promise<void>;
}

export interface BwVaultDependencies {
  readonly runner?: BwRunner;
  readonly now?: () => number;
  /** Operational log: fixed event names only, never bw output. */
  readonly log?: (line: string) => void;
  readonly basePath?: string;
}

export class BwVault {
  private readonly mutex = new Mutex();
  private readonly runner: BwRunner;
  private readonly now: () => number;
  private readonly log: (line: string) => void;
  private readonly basePath: string;
  private session: string | null = null;
  private lastSyncAt = 0;
  private lastAuthFailureAt: number | null = null;
  private collections: { at: number; list: BwCollection[] } | null = null;

  constructor(private readonly config: BwConfig, dependencies: BwVaultDependencies = {}) {
    this.runner = dependencies.runner ?? execFileRunner(config.bin);
    this.now = dependencies.now ?? Date.now;
    this.log = dependencies.log ?? (line => { process.stderr.write(`${line}\n`); });
    this.basePath = dependencies.basePath ?? process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin';
  }

  /**
   * Startup self-test: open (or re-open) the session once and log the outcome
   * as a fixed line, `secrets-mcp vault outcome=unlocked|failed`, with no
   * detail. The apply waits for `unlocked` after a restart.
   */
  async selfTest(): Promise<boolean> {
    try {
      await this.mutex.run(() => this.ensureSession(false));
      this.log('secrets-mcp vault outcome=unlocked');
      return true;
    } catch {
      this.log('secrets-mcp vault outcome=failed');
      return false;
    }
  }

  /** Run one whole operation (reads + read-modify-write) under the lock. */
  withLock<T>(operation: (ops: VaultOperations) => Promise<T>): Promise<T> {
    return this.mutex.run(() => operation(this.operations()));
  }

  private operations(): VaultOperations {
    return {
      sync: options => this.sync(options?.force === true),
      syncIfStale: async () => {
        const maxAge = this.config.syncMaxAgeSeconds * 1000;
        if (this.lastSyncAt === 0 || this.now() - this.lastSyncAt >= maxAge) await this.sync();
      },
      listCollections: () => this.listCollections(),
      listItems: () => this.listItems(),
      getItem: id => this.getItem(id),
      createItem: item => this.createItem(item),
      editItem: (id, item) => this.editItem(id, item),
    };
  }

  private env(): Record<string, string> {
    const env: Record<string, string> = {
      PATH: this.basePath,
      HOME: this.config.appDataDir,
      BITWARDENCLI_APPDATA_DIR: this.config.appDataDir,
      BW_NOINTERACTION: 'true',
      LANG: 'C.UTF-8',
    };
    if (this.session) env.BW_SESSION = this.session;
    return env;
  }

  private async run(args: readonly string[], input?: string): Promise<BwRunResult> {
    let result: BwRunResult;
    try {
      result = await this.runner(args, {
        env: this.env(),
        timeoutMs: this.config.timeoutMs,
        ...(input === undefined ? {} : { input }),
      });
    } catch {
      this.log('secrets-mcp bw outcome=spawn_failed');
      throw new SecretsError('VAULT_UNAVAILABLE', 'The vault client could not be started', true);
    }
    if (result.timedOut) {
      this.log(`secrets-mcp bw outcome=timeout command=${args[0] ?? ''}`);
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

  /** A command that needs an unlocked vault: re-establish the session once if the answer is not JSON. */
  private async withSession(args: readonly string[], input?: string): Promise<unknown> {
    await this.ensureSession(false);
    try {
      return await this.runJson(args, input);
    } catch (error) {
      if (!(error instanceof NotJson)) throw error;
      // A stale-copy refusal is not a session problem: no recheck, no retry here.
      if (OUT_OF_DATE.test(error.result.stdout) || OUT_OF_DATE.test(error.result.stderr ?? '')) {
        this.log(`secrets-mcp bw outcome=out_of_date command=${args[0] ?? ''}`);
        throw new SecretsError('VAULT_CONFLICT', 'The item changed in the vault while it was being written; retry the call', true);
      }
    }
    this.log(`secrets-mcp bw outcome=session_recheck command=${args[0] ?? ''}`);
    await this.ensureSession(true);
    try {
      return await this.runJson(args, input);
    } catch (error) {
      if (!(error instanceof NotJson)) throw error;
      this.log(`secrets-mcp bw outcome=unexpected_output command=${args[0] ?? ''}`);
      throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    }
  }

  private async status(): Promise<{ status: string; serverUrl: string }> {
    let parsed: unknown;
    try {
      parsed = await this.runJson(['status']);
    } catch (error) {
      if (!(error instanceof NotJson)) throw error;
      throw new SecretsError('VAULT_UNAVAILABLE', 'The vault client status could not be read', true);
    }
    const record = parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
    return {
      status: typeof record.status === 'string' ? record.status : '',
      serverUrl: normalizedServer(record.serverUrl),
    };
  }

  private async sessionFrom(args: readonly string[]): Promise<string> {
    if (this.lastAuthFailureAt !== null && this.now() - this.lastAuthFailureAt < AUTH_BACKOFF_MS) {
      throw new SecretsError('VAULT_UNAVAILABLE', 'The vault session could not be opened; retry later', true);
    }
    let result: BwRunResult;
    try {
      result = await this.run(args);
    } catch (error) {
      this.lastAuthFailureAt = this.now();
      throw error;
    }
    const key = result.stdout.trim();
    if (result.code !== 0 || !SESSION_KEY.test(key)) {
      this.lastAuthFailureAt = this.now();
      this.log(`secrets-mcp bw outcome=${args[0]}_failed`);
      throw new SecretsError('VAULT_UNAVAILABLE', 'The vault session could not be opened', true);
    }
    this.lastAuthFailureAt = null;
    return key;
  }

  /** Log in / unlock the machine account as needed. The password is read by bw from its file. */
  private async ensureSession(force: boolean): Promise<void> {
    if (this.session && !force) return;
    const wanted = normalizedServer(this.config.serverUrl.href);
    let { status, serverUrl } = await this.status();
    if (status === 'unlocked' && this.session && serverUrl === wanted) {
      // The session is fine; whatever failed was not the session.
      if (force) throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
      return;
    }
    if (status !== 'unauthenticated' && serverUrl !== wanted) {
      await this.run(['logout']);
      this.session = null;
      status = 'unauthenticated';
    }
    if (status === 'unauthenticated') {
      this.session = null;
      if (serverUrl !== wanted) {
        const configured = await this.run(['config', 'server', this.config.serverUrl.href]);
        if (configured.code !== 0) {
          this.log('secrets-mcp bw outcome=config_server_failed');
          throw new SecretsError('VAULT_UNAVAILABLE', 'The vault client could not be configured', true);
        }
      }
      this.session = await this.sessionFrom(['login', this.config.email, '--passwordfile', this.config.passwordFile, '--raw']);
      this.log('secrets-mcp bw outcome=logged_in');
    } else {
      this.session = null;
      this.session = await this.sessionFrom(['unlock', '--passwordfile', this.config.passwordFile, '--raw']);
      this.log('secrets-mcp bw outcome=unlocked');
    }
    this.lastSyncAt = 0;
    this.collections = null;
  }

  private async sync(force = false): Promise<void> {
    if (!force && this.lastSyncAt !== 0 && this.now() - this.lastSyncAt < SYNC_THROTTLE_MS) return;
    await this.ensureSession(false);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const result = await this.run(['sync']);
      if (result.code === 0 && /Syncing complete/i.test(result.stdout)) {
        this.lastSyncAt = this.now();
        this.collections = null;
        return;
      }
      if (attempt === 0) {
        this.log('secrets-mcp bw outcome=session_recheck command=sync');
        await this.ensureSession(true);
      }
    }
    this.log('secrets-mcp bw outcome=sync_failed');
    throw new SecretsError('VAULT_UNAVAILABLE', 'The vault could not be synchronised', true);
  }

  private async listCollections(): Promise<BwCollection[]> {
    if (this.collections && this.now() - this.collections.at < COLLECTION_CACHE_MS) return this.collections.list;
    const args = ['list', 'collections'];
    if (this.config.organizationId) args.push('--organizationid', this.config.organizationId);
    const parsed = await this.withSession(args);
    if (!Array.isArray(parsed)) throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    const list: BwCollection[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== 'object') continue;
      const { id, name, organizationId } = entry as Record<string, unknown>;
      if (typeof id !== 'string' || typeof name !== 'string' || typeof organizationId !== 'string') continue;
      if (this.config.organizationId && organizationId !== this.config.organizationId) continue;
      list.push({ id, name, organizationId });
    }
    this.collections = { at: this.now(), list };
    return list;
  }

  private async listItems(): Promise<BwItem[]> {
    const args = ['list', 'items'];
    if (this.config.organizationId) args.push('--organizationid', this.config.organizationId);
    const parsed = await this.withSession(args);
    if (!Array.isArray(parsed)) throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    return parsed.filter((item): item is BwItem => Boolean(item) && typeof item === 'object' && !Array.isArray(item));
  }

  private async getItem(id: string): Promise<BwItem> {
    if (!ITEM_ID.test(id)) throw new SecretsError('INVALID_ARGUMENT', 'Invalid item id');
    const parsed = await this.withSession(['get', 'item', id]);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new SecretsError('VAULT_ERROR', 'The vault returned an unexpected answer');
    }
    return parsed as BwItem;
  }

  private async createItem(item: Record<string, unknown>): Promise<string> {
    // The created item is printed back in full: read its id, drop the rest.
    const parsed = await this.withSession(['create', 'item'], encodeJson(item));
    const id = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>).id : undefined;
    if (typeof id !== 'string') throw new SecretsError('VAULT_ERROR', 'The vault did not confirm the write');
    return id;
  }

  private async editItem(id: string, item: Record<string, unknown>): Promise<void> {
    if (!ITEM_ID.test(id)) throw new SecretsError('INVALID_ARGUMENT', 'Invalid item id');
    const parsed = await this.withSession(['edit', 'item', id], encodeJson(item));
    const echoed = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>).id : undefined;
    if (echoed !== id) throw new SecretsError('VAULT_ERROR', 'The vault did not confirm the write');
  }
}
