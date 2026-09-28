import { bwEnvironment, normalizedServer, type CrossProcessLock } from './bw.js';
import { CredStoreError, type CredentialBackend } from './credstore.js';
import type { PathEnvironment } from './paths.js';
import { readSessionFile, SESSION_KEY_PATTERN, sessionFingerprint, writeSessionFile } from './session.js';
import type { WatchdogStart } from './watchdog.js';

// Auto-unlock (opt-in, per machine): unlock the person's own bw with the master
// password kept in the operating system's credential store (credstore.ts),
// without a person at the keyboard. Used by `dumont-secrets-unlock --auto` and
// --setup-auto (to verify), and by the MCP when auto_unlock is on and a call
// finds the vault locked.
//
// The password is read from the store into a Buffer right before bw runs, handed
// to bw ONLY through the bw child's environment (`bw unlock --passwordenv
// DUMONT_BW_PW --raw`), and the Buffer is zeroed right after. While that bw runs
// (a second or two), /proc/<pid>/environ of the bw process shows it to processes
// of the same user (and root) — which can already ask the credential store for
// it anyway; that is the trade-off auto-unlock accepts. It never goes into argv,
// a log line, the session file, the config file or this process's own
// environment. A FIFO with --passwordfile was considered and rejected: it needs
// an external mkfifo, and a bw that fails before opening the FIFO leaves the
// writer blocked.
//
// The whole routine runs under the shared bw lock file, so two MCP processes (or
// the MCP and the helper) never unlock at the same time: the second one finds
// the session the first wrote and uses it.

export const PASSWORD_ENV = 'DUMONT_BW_PW';
export const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000;
const MIN_TTL_MS = 5 * 60 * 1000;
const MAX_TTL_MS = 12 * 60 * 60 * 1000;
export const AUTO_UNLOCK_BACKOFF_MS = 30_000;

export function parseDuration(raw: string): number | null {
  const match = /^(\d{1,4})\s*(m|min|h)?$/i.exec(raw.trim());
  if (!match) return null;
  const amount = Number(match[1]);
  const unit = (match[2] ?? 'h').toLowerCase();
  const ms = unit === 'h' ? amount * 3_600_000 : amount * 60_000;
  return ms >= MIN_TTL_MS && ms <= MAX_TTL_MS ? ms : null;
}

/** DUMONT_SECRETS_SESSION_TTL, or the 2h default when unset or invalid. */
export function sessionTtl(env: NodeJS.ProcessEnv): number {
  const raw = env.DUMONT_SECRETS_SESSION_TTL?.trim();
  return (raw ? parseDuration(raw) : null) ?? DEFAULT_TTL_MS;
}

const EMAIL = /^[^\s@\-][^\s@]{0,127}@[^\s@]{1,253}$/;
export function isAccountEmail(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 254 && EMAIL.test(value) && !/[\u0000-\u001f\u007f]/.test(value);
}

export interface BwResult {
  readonly code: number | null;
  readonly stdout: string;
}

/** A non-interactive bw run (stdin closed). Never takes the lock itself. */
export type BwCall = (args: readonly string[], env: Record<string, string>) => Promise<BwResult>;

export interface BwStatus {
  readonly status: string;
  readonly serverUrl: string;
  readonly userEmail: string | null;
}

export async function bwStatus(run: BwCall, env: NodeJS.ProcessEnv, session: string | null): Promise<BwStatus | null> {
  let result: BwResult;
  try {
    result = await run(['status'], bwEnvironment(env, session));
  } catch {
    return null;
  }
  const text = result.stdout.trim();
  if (result.code !== 0 || !text.startsWith('{')) return null;
  try {
    const record = JSON.parse(text) as Record<string, unknown>;
    return {
      status: typeof record.status === 'string' ? record.status : '',
      serverUrl: normalizedServer(record.serverUrl),
      userEmail: isAccountEmail(record.userEmail) ? record.userEmail : null,
    };
  } catch {
    return null;
  }
}

export type AutoUnlockFailure =
  | 'not_enabled'
  | 'backend_unavailable'
  | 'backend_failed'
  | 'no_password'
  | 'status_unreadable'
  | 'server_mismatch'
  | 'unauthenticated'
  | 'login_failed'
  | 'unlock_failed'
  | 'session_write_failed'
  | 'lock_busy'
  | 'unexpected';

export type AutoUnlockResult =
  | { readonly ok: true; readonly expiresAt: Date; readonly mode: 'reused' | 'unlock' | 'login' }
  | { readonly ok: false; readonly reason: AutoUnlockFailure };

export interface AutoUnlockContext {
  readonly paths: PathEnvironment;
  /** Normalized server URL bw must report. */
  readonly serverUrl: string;
  readonly sessionFile: string;
  readonly lockFile: string;
  readonly bin: string;
  readonly lock: CrossProcessLock;
  readonly backend: CredentialBackend | null;
  readonly runBw: BwCall;
  readonly accountEmail: string | null;
  readonly ttlMs: number;
  readonly startWatchdog: (start: WatchdogStart) => void;
  readonly now?: () => number;
}

function fail(reason: AutoUnlockFailure): AutoUnlockResult {
  return { ok: false, reason };
}

/**
 * Unlock (or, when bw is logged out and an account email is recorded, log in)
 * with the stored password. `force` unlocks even when a valid session exists
 * (--setup-auto uses it to prove the stored password works).
 */
export async function performAutoUnlock(context: AutoUnlockContext, options: { force?: boolean } = {}): Promise<AutoUnlockResult> {
  const now = context.now ?? Date.now;
  const backend = context.backend;
  if (!backend) return fail('backend_unavailable');
  let watchdog: WatchdogStart | null = null;
  let result: AutoUnlockResult;
  try {
    result = await context.lock.run(async () => {
      const current = readSessionFile(context.sessionFile, { uid: context.paths.uid, now });
      const status = await bwStatus(context.runBw, context.paths.env, current.state === 'unlocked' ? current.session : null);
      if (!status) return fail('status_unreadable');
      if (status.serverUrl !== context.serverUrl) return fail('server_mismatch');
      // Someone (another MCP process, the helper) unlocked while we waited for the lock.
      if (!options.force && current.state === 'unlocked' && status.status === 'unlocked') {
        return { ok: true, expiresAt: current.expiresAt, mode: 'reused' } as const;
      }
      const login = status.status === 'unauthenticated';
      if (login && !context.accountEmail) return fail('unauthenticated');

      let password: Buffer | null;
      try {
        password = await backend.read();
      } catch (error) {
        return fail(error instanceof CredStoreError ? 'backend_failed' : 'unexpected');
      }
      if (!password || password.length === 0) return fail('no_password');

      // The password goes to bw through ITS environment only; bwEnvironment sets
      // BW_NOINTERACTION, so bw never waits on a prompt (2FA included).
      const childEnv: Record<string, string> = bwEnvironment(context.paths.env, null);
      let answer: BwResult;
      try {
        childEnv[PASSWORD_ENV] = password.toString('utf8');
        answer = await context.runBw(
          login
            ? ['login', context.accountEmail as string, '--passwordenv', PASSWORD_ENV, '--raw']
            : ['unlock', '--passwordenv', PASSWORD_ENV, '--raw'],
          childEnv,
        );
      } catch {
        return fail(login ? 'login_failed' : 'unlock_failed');
      } finally {
        password.fill(0);
        delete childEnv[PASSWORD_ENV];
      }
      const key = answer.stdout.trim();
      if (answer.code !== 0 || !SESSION_KEY_PATTERN.test(key)) return fail(login ? 'login_failed' : 'unlock_failed');
      const after = await bwStatus(context.runBw, context.paths.env, key);
      if (!after || after.status !== 'unlocked' || after.serverUrl !== context.serverUrl) return fail('unlock_failed');
      let expiresAt: Date;
      try {
        expiresAt = writeSessionFile(context.sessionFile, key, context.ttlMs, { uid: context.paths.uid, now });
      } catch {
        return fail('session_write_failed');
      }
      const watchdogEnv = { ...bwEnvironment(context.paths.env, null) };
      const poll = context.paths.env.DUMONT_SECRETS_WATCHDOG_POLL_MS;
      if (poll) watchdogEnv.DUMONT_SECRETS_WATCHDOG_POLL_MS = poll;
      watchdog = { sessionFile: context.sessionFile, fingerprint: sessionFingerprint(key), lockFile: context.lockFile, bin: context.bin, env: watchdogEnv };
      return { ok: true, expiresAt, mode: login ? 'login' : 'unlock' } as const;
    });
  } catch {
    return fail('lock_busy');
  }
  if (watchdog) {
    try {
      context.startWatchdog(watchdog);
    } catch {
      // The TTL still applies to the MCP; bw stays unlocked until something locks it.
    }
  }
  return result;
}

export interface AutoUnlockSettings {
  readonly enabled: boolean;
  readonly accountEmail: string | null;
}

export type AutoUnlockAttempt = AutoUnlockResult | { readonly ok: false; readonly reason: 'backoff'; readonly cause: AutoUnlockFailure };

/**
 * The MCP side: one auto-unlock at a time per process (concurrent callers share
 * the one in flight), and after a failure no new attempt for 30 s (each attempt
 * can mean a powershell.exe or bw start, and a wrong stored password must not
 * hammer the vault). Log lines are fixed: outcome and a failure class, nothing
 * else.
 */
export class AutoUnlocker {
  private inflight: Promise<AutoUnlockAttempt> | null = null;
  private lastFailure: { at: number; reason: AutoUnlockFailure } | null = null;
  private readonly now: () => number;
  private readonly backoffMs: number;

  constructor(private readonly deps: {
    /** Read afresh on every attempt: enabling or disabling needs no client restart. */
    readonly settings: () => AutoUnlockSettings;
    readonly perform: (accountEmail: string | null) => Promise<AutoUnlockResult>;
    readonly log: (line: string) => void;
    readonly now?: () => number;
    readonly backoffMs?: number;
  }) {
    this.now = deps.now ?? Date.now;
    this.backoffMs = deps.backoffMs ?? AUTO_UNLOCK_BACKOFF_MS;
  }

  unlock(): Promise<AutoUnlockAttempt> {
    if (this.inflight) return this.inflight;
    let settings: AutoUnlockSettings;
    try {
      settings = this.deps.settings();
    } catch {
      settings = { enabled: false, accountEmail: null };
    }
    if (!settings.enabled) return Promise.resolve({ ok: false, reason: 'not_enabled' });
    if (this.lastFailure && this.now() - this.lastFailure.at < this.backoffMs) {
      this.deps.log(`dumont-secrets-mcp auto_unlock outcome=failed reason=backoff`);
      return Promise.resolve({ ok: false, reason: 'backoff', cause: this.lastFailure.reason });
    }
    const attempt = (async (): Promise<AutoUnlockAttempt> => {
      let result: AutoUnlockResult;
      try {
        result = await this.deps.perform(settings.accountEmail);
      } catch {
        result = { ok: false, reason: 'unexpected' };
      }
      if (result.ok) {
        this.lastFailure = null;
        this.deps.log('dumont-secrets-mcp auto_unlock outcome=ok');
      } else {
        this.lastFailure = { at: this.now(), reason: result.reason };
        this.deps.log(`dumont-secrets-mcp auto_unlock outcome=failed reason=${result.reason}`);
      }
      return result;
    })();
    this.inflight = attempt.finally(() => { this.inflight = null; });
    return this.inflight;
  }
}
