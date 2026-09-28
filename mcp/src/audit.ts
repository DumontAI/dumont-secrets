/**
 * One JSON line per tool call on stderr (the service journal). It says who,
 * which tool, which item/key/collection, and how it ended. It NEVER carries a
 * value, the notes, bw output, or the bearer token: only the fields below,
 * each a name or a code.
 */
export interface AuditRecord {
  readonly ts: string;
  readonly event: 'secrets.mcp.tool';
  readonly tool: string;
  readonly sub: string;
  readonly email: string | null;
  readonly roles: readonly string[];
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

export const stderrAuditSink: AuditSink = line => {
  process.stderr.write(`${line}\n`);
};

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

const WINDOW_MS = 60_000;
const MAX_TRACKED_SUBJECTS = 10_000;

/** Per-subject sliding one-minute window: all tools, and writes separately. */
export class RateLimiter {
  private readonly calls = new Map<string, { all: number[]; writes: number[] }>();

  constructor(
    private readonly perMinute: number,
    private readonly writesPerMinute: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Records the call and returns true when it is within both limits. */
  allow(subject: string, isWrite: boolean): boolean {
    const current = this.now();
    let entry = this.calls.get(subject);
    if (!entry) {
      if (this.calls.size >= MAX_TRACKED_SUBJECTS) {
        const oldest = this.calls.keys().next().value;
        if (oldest !== undefined) this.calls.delete(oldest);
      }
      entry = { all: [], writes: [] };
      this.calls.set(subject, entry);
    }
    entry.all = entry.all.filter(at => current - at < WINDOW_MS);
    entry.writes = entry.writes.filter(at => current - at < WINDOW_MS);
    if (entry.all.length >= this.perMinute) return false;
    if (isWrite && entry.writes.length >= this.writesPerMinute) return false;
    entry.all.push(current);
    if (isWrite) entry.writes.push(current);
    return true;
  }
}
