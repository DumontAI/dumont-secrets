import { randomBytes } from 'node:crypto';
import { closeSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { bwEnvironment, normalizedServer, type CrossProcessLock } from './bw.js';
import { CredStoreError, type CredentialBackend } from './credstore.js';
import type { PathEnvironment } from './paths.js';
import {
  ensureSessionDir, readSessionFile, SESSION_KEY_PATTERN, sessionFingerprint, writeSessionFile,
} from './session.js';
import { SecretsError } from './types.js';
import type { WatchdogStart } from './watchdog.js';

// Auto-unlock (opt-in, per machine): unlock the person's own bw with the master
// password kept in the operating system's credential store (credstore.ts),
// without a person at the keyboard. Used by `dumont-secrets-unlock --auto` and
// --setup-auto (to verify), and by the MCP when auto_unlock is on and a call
// finds the vault locked.
//
// The password is read from the store into a Buffer, handed to bw ONLY through
// the bw child's environment (`bw unlock --passwordenv DUMONT_BW_PW --raw`), and
// the Buffer is zeroed right after. Honest limits of that zeroing: to put it in
// a child's environment Node needs a JavaScript string, and strings are
// immutable, so that copy (and any copy inside child_process) stays in this
// process's memory until the garbage collector reuses it; the same holds for
// PowerShell's managed strings on the Windows side. While that bw runs (a second
// or two), /proc/<pid>/environ of the bw process shows it to processes of the
// same user (and root) — which can already ask the credential store for it
// anyway; that is the trade-off auto-unlock accepts. It never goes into argv, a
// log line, the session file, the config file or this process's own
// environment. A FIFO with --passwordfile was considered and rejected: it needs
// an external mkfifo, and a bw that fails before opening the FIFO leaves the
// writer blocked.
//
// Locking. Every bw run of the routine happens under the shared bw lock file,
// so two MCP processes (or the MCP and the helper) never unlock at the same time:
// the second one finds the session the first wrote and uses it. The credential
// store is read BEFORE the lock is taken (powershell.exe can take seconds), and
// the locked section has a fixed time budget below the lock's staleMs, so a slow
// step can never make another process judge a live lock stale.
//
// Logging in again (bw logged out) is guarded harder than unlocking: a failed
// login is recorded in `auto-login.json` next to the session file and is not
// retried by the MCP until a person acts (`dumont-secrets-unlock --auto` or
// `--setup-auto`, or their own `bw login`), and the MCP never attempts a login
// more than once per 15 minutes across all its processes. So an account with
// two-step login, or a wrong stored password, cannot flood the vault with login
// attempts.

export const PASSWORD_ENV = 'DUMONT_BW_PW';
export const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000;
const MIN_TTL_MS = 5 * 60 * 1000;
const MAX_TTL_MS = 12 * 60 * 60 * 1000;
export const AUTO_UNLOCK_BACKOFF_MS = 30_000;
export const LOGIN_FLOOR_MS = 15 * 60 * 1000;
/** staleMs of every bw.lock user that may hold it for an auto-unlock (MCP and helper). */
export const AUTO_UNLOCK_LOCK_STALE_MS = 65_000;
/** What the locked section may take in total: below staleMs with a margin. */
export const AUTO_UNLOCK_LOCK_BUDGET_MS = AUTO_UNLOCK_LOCK_STALE_MS - 5_000;

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

function sameAccount(a: string | null, b: string | null): boolean {
  return a !== null && b !== null && a.toLowerCase() === b.toLowerCase();
}

export interface BwResult {
  readonly code: number | null;
  readonly stdout: string;
}

/** A non-interactive bw run (stdin closed). Never takes the lock itself. */
export type BwCall = (args: readonly string[], env: Record<string, string>, timeoutMs?: number) => Promise<BwResult>;

export interface BwStatus {
  readonly status: string;
  readonly serverUrl: string;
  readonly userEmail: string | null;
}

export async function bwStatus(run: BwCall, env: NodeJS.ProcessEnv, session: string | null, timeoutMs?: number): Promise<BwStatus | null> {
  let result: BwResult;
  try {
    result = await run(['status'], bwEnvironment(env, session), timeoutMs);
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

// ---------------------------------------------------------------------------
// auto-login.json: the cross-process record of login attempts.

export type LoginFailure = 'login_failed' | 'account_mismatch';

export interface LoginRecord {
  /** Last time any process ATTEMPTED `bw login` automatically (ms since epoch). */
  readonly lastAttemptAt: number | null;
  /** Set when that attempt failed; cleared only by a person (or a login that works). */
  readonly failedAt: number | null;
  readonly reason: LoginFailure | null;
}

const NO_LOGIN_RECORD: LoginRecord = { lastAttemptAt: null, failedAt: null, reason: null };

export function loginRecordPath(sessionFile: string): string {
  return join(dirname(sessionFile), 'auto-login.json');
}

export function readLoginRecord(sessionFile: string): LoginRecord {
  try {
    const raw = readFileSync(loginRecordPath(sessionFile), 'utf8');
    if (raw.length > 1024) return NO_LOGIN_RECORD;
    const record = JSON.parse(raw) as Record<string, unknown>;
    const num = (value: unknown) => (typeof value === 'number' && Number.isFinite(value) ? value : null);
    const reason = record.reason === 'login_failed' || record.reason === 'account_mismatch' ? record.reason : null;
    return { lastAttemptAt: num(record.last_attempt_at), failedAt: num(record.failed_at), reason };
  } catch {
    return NO_LOGIN_RECORD;
  }
}

function writeLoginRecord(sessionFile: string, record: LoginRecord, uid: number): void {
  const path = loginRecordPath(sessionFile);
  ensureSessionDir(dirname(path), { uid });
  const temp = join(dirname(path), `.auto-login.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(temp, 'wx', 0o600);
  try {
    writeSync(fd, JSON.stringify({
      version: 1, last_attempt_at: record.lastAttemptAt, failed_at: record.failedAt, reason: record.reason,
    }));
  } finally {
    closeSync(fd);
  }
  renameSync(temp, path);
}

/** A person acted (--auto, --setup-auto, or their own bw login): lift the sticky login failure. */
export function clearLoginFailure(sessionFile: string): boolean {
  const record = readLoginRecord(sessionFile);
  if (record.failedAt === null) return false;
  try {
    unlinkSync(loginRecordPath(sessionFile));
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------

export type AutoUnlockFailure =
  | 'not_enabled'
  | 'backend_unavailable'
  | 'backend_failed'
  | 'no_password'
  | 'status_unreadable'
  | 'server_mismatch'
  | 'account_mismatch'
  | 'unauthenticated'
  | 'login_failed'
  | 'login_blocked'
  | 'login_backoff'
  | 'unlock_failed'
  | 'session_write_failed'
  | 'lock_busy'
  | 'unexpected';

/** Failures that mean "a person has to log in to bw" (the MCP's AUTO_LOGIN_FAILED_MESSAGE). */
export const LOGIN_FAILURES: ReadonlySet<AutoUnlockFailure> = new Set([
  'unauthenticated', 'login_failed', 'login_blocked', 'login_backoff', 'account_mismatch',
]);

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
  /** Total time the locked section may take; must be below the lock's staleMs. */
  readonly lockBudgetMs?: number;
  readonly backend: CredentialBackend | null;
  readonly runBw: BwCall;
  readonly accountEmail: string | null;
  readonly ttlMs: number;
  readonly startWatchdog: (start: WatchdogStart) => void;
  readonly now?: () => number;
}

export interface AutoUnlockOptions {
  /** Unlock even when a valid session exists (--setup-auto proves the stored password). */
  readonly force?: boolean;
  /**
   * A person asked (dumont-secrets-unlock --auto / --setup-auto): a sticky login
   * failure is lifted and the 15-minute login floor does not apply.
   */
  readonly byPerson?: boolean;
}

function fail(reason: AutoUnlockFailure): AutoUnlockResult {
  return { ok: false, reason };
}

/** Per-step timeouts for the locked section: 3 status-sized steps + 1 unlock/login, summing to the budget. */
export function stepTimeouts(budgetMs: number): { statusMs: number; actionMs: number } {
  const statusMs = Math.max(1_000, Math.floor(budgetMs * 0.15));
  return { statusMs, actionMs: Math.max(1_000, budgetMs - 3 * statusMs) };
}

/**
 * Unlock (or, when bw is logged out and an account email is recorded, log in)
 * with the stored password.
 */
export async function performAutoUnlock(context: AutoUnlockContext, options: AutoUnlockOptions = {}): Promise<AutoUnlockResult> {
  const now = context.now ?? Date.now;
  const backend = context.backend;
  if (!backend) return fail('backend_unavailable');
  const { statusMs, actionMs } = stepTimeouts(context.lockBudgetMs ?? AUTO_UNLOCK_LOCK_BUDGET_MS);
  const uid = context.paths.uid;
  const env = context.paths.env;

  if (options.byPerson) clearLoginFailure(context.sessionFile);

  // Login guard: may the automatic routine try `bw login` now?
  const loginRefusal = (): AutoUnlockFailure | null => {
    if (!context.accountEmail) return 'unauthenticated';
    if (options.byPerson) return null;
    const record = readLoginRecord(context.sessionFile);
    if (record.failedAt !== null) return 'login_blocked';
    if (record.lastAttemptAt !== null && now() - record.lastAttemptAt < LOGIN_FLOOR_MS) return 'login_backoff';
    return null;
  };

  // Step 1, short lock: is there anything to do at all? Decides whether to read the store.
  let pre: { status: BwStatus | null; sessionValid: boolean };
  try {
    pre = await context.lock.run(async () => {
      const current = readSessionFile(context.sessionFile, { uid, now });
      const session = current.state === 'unlocked' ? current.session : null;
      return { status: await bwStatus(context.runBw, env, session, statusMs), sessionValid: session !== null };
    });
  } catch (error) {
    return fail(lockFailure(error));
  }
  if (!pre.status) return fail('status_unreadable');
  if (pre.status.serverUrl !== context.serverUrl) return fail('server_mismatch');
  if (!options.force && pre.sessionValid && pre.status.status === 'unlocked') {
    const current = readSessionFile(context.sessionFile, { uid, now });
    if (current.state === 'unlocked') return { ok: true, expiresAt: current.expiresAt, mode: 'reused' };
  }
  if (pre.status.status === 'unauthenticated') {
    const refused = loginRefusal();
    if (refused) return fail(refused);
  } else {
    // Someone logged in (their own bw login): a recorded login failure no longer applies.
    clearLoginFailure(context.sessionFile);
    if (context.accountEmail && pre.status.userEmail && !sameAccount(pre.status.userEmail, context.accountEmail)) {
      return fail('account_mismatch');
    }
  }

  // Step 2, no lock held: read the stored password (powershell.exe may take seconds).
  let password: Buffer | null;
  try {
    password = await backend.read();
  } catch (error) {
    return fail(error instanceof CredStoreError ? 'backend_failed' : 'unexpected');
  }
  if (!password || password.length === 0) {
    password?.fill(0);
    return fail('no_password');
  }

  // Step 3, locked, with a fixed budget: recheck, unlock or log in, verify, write.
  let watchdog: WatchdogStart | null = null;
  let result: AutoUnlockResult;
  try {
    result = await context.lock.run(async (): Promise<AutoUnlockResult> => {
      const current = readSessionFile(context.sessionFile, { uid, now });
      const session = current.state === 'unlocked' ? current.session : null;
      const status = await bwStatus(context.runBw, env, session, statusMs);
      if (!status) return fail('status_unreadable');
      if (status.serverUrl !== context.serverUrl) return fail('server_mismatch');
      // Another process unlocked while we read the store: the password is not needed.
      if (!options.force && session && status.status === 'unlocked' && current.state === 'unlocked') {
        return { ok: true, expiresAt: current.expiresAt, mode: 'reused' };
      }
      const login = status.status === 'unauthenticated';
      if (login) {
        const refused = loginRefusal();
        if (refused) return fail(refused);
        // Recorded BEFORE the attempt: a crash mid-login still counts against the floor.
        writeLoginRecord(context.sessionFile, { lastAttemptAt: now(), failedAt: null, reason: null }, uid);
      } else if (context.accountEmail && status.userEmail && !sameAccount(status.userEmail, context.accountEmail)) {
        return fail('account_mismatch');
      }

      // The password goes to bw through ITS environment only; bwEnvironment sets
      // BW_NOINTERACTION, so bw never waits on a prompt (2FA included).
      const childEnv: Record<string, string> = bwEnvironment(env, null);
      let answer: BwResult | null = null;
      try {
        childEnv[PASSWORD_ENV] = password.toString('utf8');
        answer = await context.runBw(
          login
            ? ['login', context.accountEmail as string, '--passwordenv', PASSWORD_ENV, '--raw']
            : ['unlock', '--passwordenv', PASSWORD_ENV, '--raw'],
          childEnv,
          actionMs,
        );
      } catch {
        answer = null;
      } finally {
        password.fill(0);
        delete childEnv[PASSWORD_ENV];
      }
      const key = answer?.stdout.trim() ?? '';
      const markLoginFailed = (reason: LoginFailure) => {
        writeLoginRecord(context.sessionFile, { lastAttemptAt: now(), failedAt: now(), reason }, uid);
      };
      if (!answer || answer.code !== 0 || !SESSION_KEY_PATTERN.test(key)) {
        if (login) markLoginFailed('login_failed');
        return fail(login ? 'login_failed' : 'unlock_failed');
      }
      const after = await bwStatus(context.runBw, env, key, statusMs);
      if (!after || after.status !== 'unlocked' || after.serverUrl !== context.serverUrl) {
        if (login) markLoginFailed('login_failed');
        return fail(login ? 'login_failed' : 'unlock_failed');
      }
      if (context.accountEmail && !sameAccount(after.userEmail, context.accountEmail)) {
        // Unlocked as someone else: never hand that session to the MCP.
        await context.runBw(['lock'], bwEnvironment(env, null), statusMs).catch(() => null);
        if (login) markLoginFailed('account_mismatch');
        return fail('account_mismatch');
      }
      let expiresAt: Date;
      try {
        expiresAt = writeSessionFile(context.sessionFile, key, context.ttlMs, { uid, now });
      } catch {
        return fail('session_write_failed');
      }
      const watchdogEnv = { ...bwEnvironment(env, null) };
      const poll = env.DUMONT_SECRETS_WATCHDOG_POLL_MS;
      if (poll) watchdogEnv.DUMONT_SECRETS_WATCHDOG_POLL_MS = poll;
      watchdog = { sessionFile: context.sessionFile, fingerprint: sessionFingerprint(key), lockFile: context.lockFile, bin: context.bin, env: watchdogEnv };
      return { ok: true, expiresAt, mode: login ? 'login' : 'unlock' };
    });
  } catch (error) {
    return fail(lockFailure(error));
  } finally {
    password.fill(0);
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

/** Only the lock file's own "busy" answer is lock_busy (retryable, no back-off). */
function lockFailure(error: unknown): AutoUnlockFailure {
  return error instanceof SecretsError && error.code === 'VAULT_UNAVAILABLE' ? 'lock_busy' : 'unexpected';
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
 * hammer the vault). A busy lock file is not a failure of the attempt and sets
 * no back-off. Logins have their own, stricter guard (auto-login.json). Log lines
 * are fixed: outcome and a failure class, nothing else.
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
      this.deps.log('dumont-secrets-mcp auto_unlock outcome=failed reason=backoff');
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
        if (result.reason !== 'lock_busy') this.lastFailure = { at: this.now(), reason: result.reason };
        this.deps.log(`dumont-secrets-mcp auto_unlock outcome=failed reason=${result.reason}`);
      }
      return result;
    })();
    this.inflight = attempt.finally(() => { this.inflight = null; });
    return this.inflight;
  }
}
