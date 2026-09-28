import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FileLock } from '../src/lock.js';
import { readSessionFile, sessionFingerprint, writeSessionFile } from '../src/session.js';
import { SecretsError } from '../src/types.js';
import { runWatchdog } from '../src/watchdog.js';

const KEY = 'c2Vzc2lvbi1rZXktZm9yLXdhdGNoZG9nLTAwMDAwMDAw';
const OTHER = 'b3RoZXItc2Vzc2lvbi1rZXktZm9yLXdhdGNoZG9nLTAw';

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'secrets-watchdog-'));
  const file = join(dir, 'dumont-secrets', 'session.json');
  let clock = 1_000_000;
  const locks: number[] = [];
  const sleeps: number[] = [];
  const deps = {
    now: () => clock,
    sleep: async (ms: number) => { sleeps.push(ms); clock += ms; },
    underLock: <T>(fn: () => Promise<T>) => fn(),
    bwLock: async () => { locks.push(clock); },
  };
  return { file, deps, locks, sleeps, advance: (ms: number) => { clock += ms; }, now: () => clock };
}

describe('expiry watchdog', () => {
  it('at the expiry of its own session: removes the file and runs bw lock', async () => {
    const t = setup();
    writeSessionFile(t.file, KEY, 90_000, { now: t.now });
    const outcome = await runWatchdog({ sessionFile: t.file, fingerprint: sessionFingerprint(KEY), pollMs: 30_000 }, t.deps);
    expect(outcome).toBe('locked');
    expect(t.locks).toEqual([1_090_000]);
    expect(t.sleeps).toEqual([30_000, 30_000, 30_000]);
    expect(readSessionFile(t.file)).toEqual({ state: 'locked', reason: 'missing' });
  });

  it('exits without locking when the user re-unlocked (another session) or locked (--lock)', async () => {
    const replaced = setup();
    writeSessionFile(replaced.file, KEY, 90_000, { now: replaced.now });
    const sleep = replaced.deps.sleep;
    let first = true;
    const outcome = await runWatchdog({ sessionFile: replaced.file, fingerprint: sessionFingerprint(KEY), pollMs: 30_000 }, {
      ...replaced.deps,
      sleep: async ms => {
        if (first) { first = false; writeSessionFile(replaced.file, OTHER, 60 * 60_000, { now: replaced.now }); }
        await sleep(ms);
      },
    });
    expect(outcome).toBe('replaced');
    expect(replaced.locks).toEqual([]);
    expect(readSessionFile(replaced.file, { now: replaced.now })).toMatchObject({ state: 'unlocked', session: OTHER });

    const gone = setup();
    const outcome2 = await runWatchdog({ sessionFile: gone.file, fingerprint: sessionFingerprint(KEY), pollMs: 30_000 }, gone.deps);
    expect(outcome2).toBe('gone');
    expect(gone.locks).toEqual([]);
  });

  it('never locks a session that replaced its own between the check and the lock', async () => {
    const t = setup();
    writeSessionFile(t.file, KEY, 1_000, { now: t.now });
    t.advance(2_000);
    const outcome = await runWatchdog({ sessionFile: t.file, fingerprint: sessionFingerprint(KEY), pollMs: 30_000 }, {
      ...t.deps,
      underLock: async fn => { writeSessionFile(t.file, OTHER, 60_000, { now: t.now }); return fn(); },
    });
    expect(outcome).toBe('replaced');
    expect(t.locks).toEqual([]);
  });
});

describe('file lock ownership', () => {
  it('a stale lock is moved aside by rename, and release removes only our own token', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-lock-'));
    const path = join(dir, 'bw.lock');
    writeFileSync(path, `999999999 ${Date.now()} deadbeef\n`);
    const lock = new FileLock({ path, waitMs: 200, staleMs: 60_000, pidAlive: () => false });
    let during = '';
    await lock.run(async () => {
      during = readFileSync(path, 'utf8');
      // Someone wrongly takes the lock over while we hold it: our release must not remove theirs.
      writeFileSync(path, `424242 ${Date.now()} intruder\n`);
    });
    expect(during.startsWith(`${process.pid} `)).toBe(true);
    expect(readFileSync(path, 'utf8')).toContain('intruder');
  });

  it('a live lock is waited for and then reported busy', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-lock-'));
    const path = join(dir, 'bw.lock');
    writeFileSync(path, `${process.pid + 1} ${Date.now()} live\n`);
    const lock = new FileLock({ path, waitMs: 50, staleMs: 60_000, pidAlive: () => true });
    const error = await lock.run(async () => 'ran').catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
    expect(readFileSync(path, 'utf8')).toContain('live');
  });

  it('many concurrent holders never overlap', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-lock-'));
    const path = join(dir, 'bw.lock');
    let active = 0;
    let max = 0;
    await Promise.all(Array.from({ length: 8 }, () => new FileLock({ path, waitMs: 10_000, staleMs: 60_000 }).run(async () => {
      active += 1;
      max = Math.max(max, active);
      await new Promise(resolve => setTimeout(resolve, 5));
      active -= 1;
    })));
    expect(max).toBe(1);
  });
});
