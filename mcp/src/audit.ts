import { appendFileSync, chmodSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * One JSON line per tool call, appended to a local file only you can read
 * (0600, in a 0700 directory). It says which tool, which item/key/collection,
 * and how it ended. It NEVER carries a value, the notes, bw output, or the
 * session key: only the fields below, each a name or a code.
 */
export interface AuditRecord {
  readonly ts: string;
  readonly tool: string;
  readonly item: string | null;
  readonly key: string | null;
  readonly collection: string | null;
  readonly outcome: 'ok' | 'denied' | 'error';
  readonly error_code: string | null;
  readonly latency_ms: number;
  /** Present only when the output guard replaced a write's answer after the vault changed. */
  readonly guard?: 'fired';
}

export type AuditSink = (line: string) => void;

const MAX_FIELD = 256;

function bounded(value: string | null): string | null {
  if (value === null) return null;
  // JSON.stringify escapes control characters; the bound keeps one line small.
  return value.length > MAX_FIELD ? `${value.slice(0, MAX_FIELD)}…` : value;
}

export function auditLine(record: AuditRecord): string {
  return JSON.stringify({
    ...record,
    item: bounded(record.item),
    key: bounded(record.key),
    collection: bounded(record.collection),
  });
}

export const AUDIT_ROTATE_BYTES = 5 * 1024 * 1024;
export const AUDIT_KEEP = 3;

/**
 * Append to `path`, rotating at ~5 MB to path.1 .. path.3 (the oldest is
 * dropped). A failure to write is reported once on stderr and never changes a
 * tool's answer.
 */
export function fileAuditSink(
  path: string,
  options: { rotateBytes?: number; keep?: number; log?: (line: string) => void } = {},
): AuditSink {
  const rotateBytes = options.rotateBytes ?? AUDIT_ROTATE_BYTES;
  const keep = options.keep ?? AUDIT_KEEP;
  const log = options.log ?? (line => { process.stderr.write(`${line}\n`); });
  let reported = false;
  let prepared = false;
  return line => {
    try {
      if (!prepared) {
        mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
        prepared = true;
      }
      let size = 0;
      try {
        const info = statSync(path);
        size = info.size;
        if ((info.mode & 0o077) !== 0) chmodSync(path, 0o600);
      } catch {
        size = 0;
      }
      if (size + line.length + 1 > rotateBytes && size > 0) {
        try { unlinkSync(`${path}.${keep}`); } catch { /* not there */ }
        for (let index = keep - 1; index >= 1; index -= 1) {
          try { renameSync(`${path}.${index}`, `${path}.${index + 1}`); } catch { /* not there */ }
        }
        renameSync(path, `${path}.1`);
      }
      appendFileSync(path, `${line}\n`, { mode: 0o600 });
    } catch {
      if (!reported) {
        reported = true;
        log('dumont-secrets-mcp audit outcome=write_failed');
      }
    }
  };
}

const WINDOW_MS = 60_000;

/**
 * A brake for a runaway agent, per MCP process: a sliding one-minute window
 * over all tools, and over writes separately.
 */
export class RateLimiter {
  private all: number[] = [];
  private writes: number[] = [];

  constructor(
    private readonly perMinute: number,
    private readonly writesPerMinute: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Records the call and returns true when it is within both limits. */
  allow(isWrite: boolean): boolean {
    const current = this.now();
    this.all = this.all.filter(at => current - at < WINDOW_MS);
    this.writes = this.writes.filter(at => current - at < WINDOW_MS);
    if (this.all.length >= this.perMinute) return false;
    if (isWrite && this.writes.length >= this.writesPerMinute) return false;
    this.all.push(current);
    if (isWrite) this.writes.push(current);
    return true;
  }
}
