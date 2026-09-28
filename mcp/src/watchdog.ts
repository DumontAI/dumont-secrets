#!/usr/bin/env node
import { execFile, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FileLock } from './lock.js';
import { isMainModule } from './runtime.js';
import { expireSessionFile, peekSessionFile, sessionFingerprint } from './session.js';

// The unlock watchdog: a small detached node process started by
// dumont-secrets-unlock. It holds no key (only the session's sha256
// fingerprint, in argv), polls the session file, and:
//   - exits as soon as the file is gone or holds another session (--lock, or a
//     new unlock: that one starts its own watchdog);
//   - at the file's expiry, if the file still holds ITS session, removes it and
//     runs `bw lock` under the shared lock file, then exits.
// So an expired session is locked in bw even when no MCP call happens to see it.

export const DEFAULT_POLL_MS = 30_000;
const MIN_POLL_MS = 200;
// Never outlive the longest TTL by much, whatever happens to the clock or the file.
export const MAX_LIFETIME_MS = 12 * 60 * 60 * 1000 + 10 * 60 * 1000;

export interface WatchdogOptions {
  readonly sessionFile: string;
  readonly fingerprint: string;
  readonly pollMs: number;
}

export interface WatchdogDependencies {
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  /** Runs `fn` under the shared bw lock file. */
  readonly underLock: <T>(fn: () => Promise<T>) => Promise<T>;
  readonly bwLock: () => Promise<void>;
}

export type WatchdogOutcome = 'gone' | 'replaced' | 'locked' | 'lifetime';

export interface WatchdogStart {
  readonly sessionFile: string;
  readonly fingerprint: string;
  readonly lockFile: string;
  readonly bin: string;
  readonly env: Record<string, string>;
}

/**
 * Start this file as a detached node process, its own session/process group (no
 * setsid binary needed), unref'd. Used by the unlock helper and by the MCP's
 * auto-unlock: every session written gets its own watchdog.
 */
export function startDetachedWatchdog(start: WatchdogStart): void {
  const script = fileURLToPath(new URL('./watchdog.js', import.meta.url));
  const child = spawn(process.execPath, [script, start.sessionFile, start.fingerprint, start.lockFile, start.bin], {
    detached: true,
    stdio: 'ignore',
    env: start.env,
    shell: false,
  });
  child.on('error', () => undefined);
  child.unref();
}

export async function runWatchdog(options: WatchdogOptions, deps: WatchdogDependencies): Promise<WatchdogOutcome> {
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const started = now();
  for (;;) {
    const peeked = peekSessionFile(options.sessionFile, { now });
    if (typeof peeked === 'string') return 'gone';
    if (sessionFingerprint(peeked.session) !== options.fingerprint) return 'replaced';
    const left = peeked.expiresAt.getTime() - now();
    if (left <= 0) {
      const removed = await deps.underLock(async () => {
        if (!expireSessionFile(options.sessionFile, { now, fingerprint: options.fingerprint })) return false;
        await deps.bwLock();
        return true;
      });
      return removed ? 'locked' : 'replaced';
    }
    if (now() - started > MAX_LIFETIME_MS) return 'lifetime';
    await sleep(Math.max(MIN_POLL_MS, Math.min(options.pollMs, left)));
  }
}

if (isMainModule(import.meta.url)) {
  // argv: <session file> <fingerprint> <lock file> <bw bin>. The environment is
  // the allowlisted bw environment the helper passed (never a session key).
  const [sessionFile, fingerprint, lockPath, bin] = process.argv.slice(2);
  const poll = Number(process.env.DUMONT_SECRETS_WATCHDOG_POLL_MS);
  if (sessionFile && fingerprint && /^[0-9a-f]{64}$/.test(fingerprint) && lockPath && bin) {
    const lock = new FileLock({ path: lockPath, waitMs: 60_000, staleMs: 120_000 });
    void runWatchdog(
      { sessionFile, fingerprint, pollMs: Number.isFinite(poll) && poll > 0 ? poll : DEFAULT_POLL_MS },
      {
        underLock: fn => lock.run(fn),
        bwLock: () => new Promise(resolve => {
          const env: Record<string, string> = {};
          for (const [name, value] of Object.entries(process.env)) if (typeof value === 'string') env[name] = value;
          const child = execFile(bin, ['lock'], { env, timeout: 30_000, killSignal: 'SIGKILL', shell: false }, () => resolve());
          child.stdin?.end();
        }),
      },
    ).catch(() => undefined).finally(() => { process.exit(0); });
  } else {
    process.exit(64);
  }
}
