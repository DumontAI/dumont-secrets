import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * The session file shared by `dumont-secrets-unlock` (writer) and the MCP
 * (reader). It holds the `bw` session key the user's own `bw unlock` printed,
 * plus an expiry. Never the master password: that is typed into `bw` itself.
 *
 *   directory  0700, owned by the user
 *   file       0600, owned by the user, a regular file (not a symlink)
 *   content    {"version":1,"session":"<key>","created_at":"<iso>","expires_at":"<iso>"}
 *
 * Anything else (missing, expired, corrupt, too open, someone else's) reads as
 * "locked". The reason is returned for the helper's --status and the MCP's
 * stderr line; it never carries the key.
 */
export const SESSION_KEY_PATTERN = /^[A-Za-z0-9+/=_-]{16,512}$/;
const MAX_SESSION_FILE_BYTES = 4096;

export type SessionState =
  | { readonly state: 'unlocked'; readonly session: string; readonly expiresAt: Date; readonly createdAt: Date | null }
  | { readonly state: 'locked'; readonly reason: LockedReason; readonly expiresAt?: Date };

export type LockedReason = 'missing' | 'expired' | 'corrupt' | 'insecure_permissions' | 'wrong_owner' | 'not_a_file';

export interface SessionFileDependencies {
  readonly uid?: number;
  readonly now?: () => number;
}

function currentUid(dependencies: SessionFileDependencies): number {
  return dependencies.uid ?? process.getuid?.() ?? -1;
}

/** The directory must be ours and closed to group/other; the file too, and a plain file. */
function checkOwnership(path: string, uid: number): LockedReason | null {
  let dirInfo;
  let fileInfo;
  try {
    dirInfo = lstatSync(dirname(path));
    fileInfo = lstatSync(path);
  } catch {
    return 'missing';
  }
  if (!dirInfo.isDirectory() || !fileInfo.isFile()) return 'not_a_file';
  if (dirInfo.uid !== uid || fileInfo.uid !== uid) return 'wrong_owner';
  if ((dirInfo.mode & 0o077) !== 0 || (fileInfo.mode & 0o077) !== 0) return 'insecure_permissions';
  return null;
}

function parseDate(value: unknown): Date | null {
  if (typeof value !== 'string') return null;
  const at = Date.parse(value);
  return Number.isFinite(at) ? new Date(at) : null;
}

/** The file's content whatever its expiry, after the same ownership checks; null when unusable. */
export function peekSessionFile(path: string, dependencies: SessionFileDependencies = {}):
  { session: string; expiresAt: Date; createdAt: Date | null } | LockedReason {
  const refused = checkOwnership(path, currentUid(dependencies));
  if (refused) return refused;
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch {
    return 'missing';
  }
  if (raw.byteLength > MAX_SESSION_FILE_BYTES) return 'corrupt';
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    return 'corrupt';
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'corrupt';
  const record = parsed as Record<string, unknown>;
  const expiresAt = parseDate(record.expires_at);
  if (record.version !== 1 || typeof record.session !== 'string' || !SESSION_KEY_PATTERN.test(record.session) || !expiresAt) {
    return 'corrupt';
  }
  return { session: record.session, expiresAt, createdAt: parseDate(record.created_at) };
}

export function readSessionFile(path: string, dependencies: SessionFileDependencies = {}): SessionState {
  const now = (dependencies.now ?? Date.now)();
  const peeked = peekSessionFile(path, dependencies);
  if (typeof peeked === 'string') return { state: 'locked', reason: peeked };
  if (peeked.expiresAt.getTime() <= now) return { state: 'locked', reason: 'expired', expiresAt: peeked.expiresAt };
  return { state: 'unlocked', ...peeked };
}

/** sha256 of a session key: lets the watchdog recognise "its" session without holding the key in argv. */
export function sessionFingerprint(session: string): string {
  return createHash('sha256').update(session).digest('hex');
}

/**
 * Remove the session file when it is (still) expired, or (with `fingerprint`)
 * when it still holds that session. Returns true when a file was removed, so the
 * caller then runs `bw lock`. A file rewritten by a new unlock in the meantime is
 * left alone.
 */
export function expireSessionFile(
  path: string,
  options: SessionFileDependencies & { fingerprint?: string } = {},
): boolean {
  const now = (options.now ?? Date.now)();
  const peeked = peekSessionFile(path, options);
  if (typeof peeked === 'string') return false;
  const matches = options.fingerprint !== undefined
    ? sessionFingerprint(peeked.session) === options.fingerprint && peeked.expiresAt.getTime() <= now
    : peeked.expiresAt.getTime() <= now;
  return matches ? deleteSessionFile(path) : false;
}

/** Create the session directory 0700 (or tighten one we own). Refuses a directory owned by someone else. */
export function ensureSessionDir(dir: string, dependencies: SessionFileDependencies = {}): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const info = lstatSync(dir);
  if (!info.isDirectory()) throw new Error('session path is not a directory');
  if (info.uid !== currentUid(dependencies)) throw new Error('session directory is owned by another user');
  if ((info.mode & 0o777) !== 0o700) chmodSync(dir, 0o700);
}

/**
 * Atomic write: a new 0600 file created exclusively in the same directory,
 * fsync'd, then renamed over the old one. A reader sees the old file or the
 * new one, never half of it; umask cannot widen an explicit 0600 create.
 */
export function writeSessionFile(
  path: string,
  session: string,
  ttlMs: number,
  dependencies: SessionFileDependencies = {},
): Date {
  if (!SESSION_KEY_PATTERN.test(session)) throw new Error('refusing to store an unexpected session key');
  const now = (dependencies.now ?? Date.now)();
  const expiresAt = new Date(now + ttlMs);
  ensureSessionDir(dirname(path), dependencies);
  const body = JSON.stringify({
    version: 1,
    session,
    created_at: new Date(now).toISOString(),
    expires_at: expiresAt.toISOString(),
  });
  const temp = join(dirname(path), `.session.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(temp, 'wx', 0o600);
  try {
    writeSync(fd, body);
    fsyncSync(fd);
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(temp); } catch { /* already gone */ }
    throw error;
  }
  closeSync(fd);
  try {
    renameSync(temp, path);
  } catch (error) {
    try { unlinkSync(temp); } catch { /* already gone */ }
    throw error;
  }
  return expiresAt;
}

/** Returns true when a file was removed. */
export function deleteSessionFile(path: string): boolean {
  try {
    unlinkSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}
