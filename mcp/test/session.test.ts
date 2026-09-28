import { chmodSync, mkdirSync, mkdtempSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { deleteSessionFile, expireSessionFile, readSessionFile, sessionFingerprint, writeSessionFile } from '../src/session.js';
import { sessionSourceFor } from '../src/stdio.js';
import { SESSION_LOCKED_MESSAGE, SecretsError, SessionExpired, type SecretsConfig } from '../src/types.js';

const KEY = 'c2Vzc2lvbi1rZXktZm9yLXRlc3RzLW9ubHktMDAwMDAwMDA=';

function sessionPath(): string {
  const base = mkdtempSync(join(tmpdir(), 'secrets-session-'));
  return join(base, 'dumont-secrets', 'session.json');
}

describe('session file', () => {
  it('writes atomically, 0600 in a 0700 directory, and reads back', () => {
    const path = sessionPath();
    const expiresAt = writeSessionFile(path, KEY, 60_000);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700);
    const state = readSessionFile(path);
    expect(state).toMatchObject({ state: 'unlocked', session: KEY });
    expect(state.state === 'unlocked' && state.expiresAt.getTime()).toBe(expiresAt.getTime());
    // No temp file left behind; a second write replaces the first.
    writeSessionFile(path, KEY.replace('c2', 'd3'), 60_000);
    expect(readdirSync(join(path, '..'))).toEqual(['session.json']);
  });

  it('tightens a directory it owns that was left open', () => {
    const path = sessionPath();
    mkdirSync(join(path, '..'), { recursive: true, mode: 0o755 });
    chmodSync(join(path, '..'), 0o755);
    writeSessionFile(path, KEY, 60_000);
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700);
  });

  it('missing, expired and corrupt files read as locked', () => {
    const path = sessionPath();
    expect(readSessionFile(path)).toEqual({ state: 'locked', reason: 'missing' });
    let clock = 1_000_000;
    writeSessionFile(path, KEY, 60_000, { now: () => clock });
    clock += 60_000;
    expect(readSessionFile(path, { now: () => clock })).toMatchObject({ state: 'locked', reason: 'expired' });
    for (const body of ['not json', '[]', JSON.stringify({ version: 1, session: 'short', expires_at: '2999-01-01T00:00:00Z' }),
      JSON.stringify({ version: 2, session: KEY, expires_at: '2999-01-01T00:00:00Z' }),
      JSON.stringify({ version: 1, session: KEY, expires_at: 'never' }), 'x'.repeat(5000)]) {
      writeFileSync(path, body, { mode: 0o600 });
      expect(readSessionFile(path)).toMatchObject({ state: 'locked', reason: 'corrupt' });
    }
  });

  it('refuses a file or directory readable by group or others, a symlink, or another owner', () => {
    const path = sessionPath();
    writeSessionFile(path, KEY, 60_000);
    chmodSync(path, 0o640);
    expect(readSessionFile(path)).toEqual({ state: 'locked', reason: 'insecure_permissions' });
    chmodSync(path, 0o604);
    expect(readSessionFile(path)).toEqual({ state: 'locked', reason: 'insecure_permissions' });
    chmodSync(path, 0o600);
    chmodSync(join(path, '..'), 0o750);
    expect(readSessionFile(path)).toEqual({ state: 'locked', reason: 'insecure_permissions' });
    chmodSync(join(path, '..'), 0o700);
    expect(readSessionFile(path, { uid: (process.getuid?.() ?? 0) + 1 })).toEqual({ state: 'locked', reason: 'wrong_owner' });
    const link = join(path, '..', 'link.json');
    symlinkSync(path, link);
    expect(readSessionFile(link)).toEqual({ state: 'locked', reason: 'not_a_file' });
    expect(readSessionFile(path)).toMatchObject({ state: 'unlocked' });
  });

  it('delete reports whether there was a file', () => {
    const path = sessionPath();
    expect(deleteSessionFile(path)).toBe(false);
    writeSessionFile(path, KEY, 60_000);
    expect(deleteSessionFile(path)).toBe(true);
    expect(readSessionFile(path)).toEqual({ state: 'locked', reason: 'missing' });
  });
});

describe('MCP session source', () => {
  it('throws SESSION_LOCKED with the fixed message, and logs the reason once, never the key', () => {
    const path = sessionPath();
    const logs: string[] = [];
    const source = sessionSourceFor({ sessionFile: path } as SecretsConfig, line => { logs.push(line); });
    for (let i = 0; i < 3; i += 1) {
      const error = (() => { try { source(); return null; } catch (caught) { return caught; } })();
      expect(error).toBeInstanceOf(SecretsError);
      expect((error as SecretsError).code).toBe('SESSION_LOCKED');
      expect((error as SecretsError).message).toBe(SESSION_LOCKED_MESSAGE);
    }
    expect(logs).toEqual(['dumont-secrets-mcp session outcome=locked reason=missing']);
    writeSessionFile(path, KEY, 60_000);
    expect(source()).toBe(KEY);
    chmodSync(path, 0o644);
    expect(() => source()).toThrow(SESSION_LOCKED_MESSAGE);
    expect(logs.at(-1)).toBe('dumont-secrets-mcp session outcome=locked reason=insecure_permissions');
    expect(logs.join('\n')).not.toContain(KEY);
  });

  it('the fixed message sends the user to a separate terminal window', () => {
    expect(SESSION_LOCKED_MESSAGE).toBe(
      'Vault locked. Ask the user to run dumont-secrets-unlock in a separate terminal window (it needs an interactive terminal), then retry.',
    );
  });

  it('an expired file surfaces as SessionExpired; expireSessionFile removes only an expired (or matching) file', () => {
    const path = sessionPath();
    let clock = 1_000_000;
    writeSessionFile(path, KEY, 60_000, { now: () => clock });
    const source = sessionSourceFor({ sessionFile: path } as SecretsConfig, () => undefined);
    expect(expireSessionFile(path, { now: () => clock })).toBe(false);
    clock += 60_000;
    expect(expireSessionFile(path, { now: () => clock, fingerprint: sessionFingerprint('other-key-000000000000') })).toBe(false);
    expect(expireSessionFile(path, { now: () => clock, fingerprint: sessionFingerprint(KEY) })).toBe(true);
    expect(readSessionFile(path)).toEqual({ state: 'locked', reason: 'missing' });
    writeSessionFile(path, KEY, 1, { now: () => Date.now() - 10 });
    const error = (() => { try { source(); return null; } catch (caught) { return caught; } })();
    expect(error).toBeInstanceOf(SessionExpired);
    expect((error as SessionExpired).code).toBe('SESSION_LOCKED');
  });
});
