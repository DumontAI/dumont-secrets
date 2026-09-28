import { randomBytes } from 'node:crypto';
import { closeSync, linkSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { ensureSessionDir } from './session.js';
import { SecretsError } from './types.js';

/**
 * A cross-process lock file around each non-interactive `bw` run. The
 * in-process mutex keeps one MCP process to one `bw` at a time, but every
 * Claude Code / Dumont Code session starts its own MCP process, the unlock
 * helper and its watchdog run `bw` too, all on the same `bw` data directory,
 * and concurrent `bw` processes have logged the CLI out.
 *
 *   acquire   create the file exclusively ('wx'), holding "<pid> <ms> <nonce>"
 *   stale     the owner pid is dead, or the lock is older than `staleMs`
 *   takeover  rename the stale file to a private name (only one process can win
 *             that rename); if what was moved is not the stale content that was
 *             judged (a new owner slipped in), put it back with link(), which
 *             never overwrites; then compete for 'wx' again
 *   release   remove the file only if it still holds our own token
 *
 * A tripwire against accidents between cooperating processes, not a security
 * boundary: anything running as the user can remove it.
 */
export interface FileLockOptions {
  readonly path: string;
  readonly waitMs: number;
  readonly staleMs: number;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly pidAlive?: (pid: number) => boolean;
}

function defaultPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function readText(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

export class FileLock {
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly pidAlive: (pid: number) => boolean;

  constructor(private readonly options: FileLockOptions) {
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
    this.pidAlive = options.pidAlive ?? defaultPidAlive;
  }

  private tryAcquire(token: string): boolean {
    try {
      const fd = openSync(this.options.path, 'wx', 0o600);
      try {
        writeSync(fd, token);
      } finally {
        closeSync(fd);
      }
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      return false;
    }
  }

  private isStale(content: string): boolean {
    const [pidText, atText] = content.trim().split(/\s+/);
    const pid = Number(pidText);
    const at = Number(atText);
    if (!Number.isInteger(pid) || pid <= 0 || !Number.isFinite(at)) return true;
    if (this.now() - at > this.options.staleMs) return true;
    return pid !== process.pid && !this.pidAlive(pid);
  }

  /** Move a stale lock out of the way without ever removing a live one. */
  private takeOver(judged: string): void {
    const aside = `${this.options.path}.stale.${process.pid}.${randomBytes(4).toString('hex')}`;
    try {
      renameSync(this.options.path, aside);
    } catch {
      return; // someone else moved or released it first
    }
    const moved = readText(aside);
    if (moved !== judged) {
      // A new owner created the lock between our look and our rename: give it back.
      try { linkSync(aside, this.options.path); } catch { /* a newer lock exists; ours stays aside */ }
    }
    try { unlinkSync(aside); } catch { /* already gone */ }
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    try {
      ensureSessionDir(dirname(this.options.path));
    } catch {
      throw new SecretsError('VAULT_UNAVAILABLE', 'The local lock directory could not be prepared', true);
    }
    const nonce = randomBytes(8).toString('hex');
    const deadline = this.now() + this.options.waitMs;
    let delay = 25;
    let token: string;
    for (;;) {
      token = `${process.pid} ${this.now()} ${nonce}\n`;
      if (this.tryAcquire(token)) break;
      const content = readText(this.options.path);
      if (content !== null && this.isStale(content)) {
        this.takeOver(content);
        continue;
      }
      if (this.now() >= deadline) {
        throw new SecretsError('VAULT_UNAVAILABLE', 'Another Dumont Secrets process is using the vault client; retry shortly', true);
      }
      await this.sleep(delay);
      delay = Math.min(delay * 2, 250);
    }
    try {
      return await fn();
    } finally {
      // Only our own lock: after a (wrong) takeover by someone else, theirs stays.
      if (readText(this.options.path) === token) {
        try { unlinkSync(this.options.path); } catch { /* already gone */ }
      }
    }
  }
}
