import { execFile, spawn } from 'node:child_process';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BwVault } from '../src/bw.js';
import { sessionDir, type PathEnvironment } from '../src/paths.js';
import { SecretsService, Taint } from '../src/secrets.js';
import { sessionSourceFor } from '../src/stdio.js';
import type { SecretsConfig } from '../src/types.js';
import { parseDuration, runUnlock, type BwResult, type UnlockDependencies, type WatchdogStart } from '../src/unlock.js';
import { expireSessionFile, readSessionFile, sessionFingerprint, writeSessionFile } from '../src/session.js';
import { DEFAULT_SCOPE, FAKE_BW, INFRA_ITEM, makeVaultDir, MASTER_PASSWORD, SENTINEL_INFRA, SERVER_URL, testBwConfig, type FakeVaultDir } from './fixtures.js';

function runFake(args: readonly string[], env: Record<string, string>): Promise<BwResult> {
  return new Promise(resolve => {
    const child = execFile(FAKE_BW, [...args], { env, encoding: 'utf8' }, (error, stdout) => {
      const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : 1) : 0;
      resolve({ code, stdout });
    });
    child.stdin?.end();
  });
}

interface Run {
  readonly code: number;
  readonly out: string;
  readonly err: string;
  readonly unlockEnv: Record<string, string> | null;
  readonly watchdogs: WatchdogStart[];
}

/**
 * The helper against the fake bw as a real subprocess. The "terminal" is
 * mocked: bw's stdin gets `typed` (what the person types), exactly as it would
 * read it from the TTY; the helper itself never receives it.
 */
async function unlock(vault: FakeVaultDir, argv: string[], options: { typed?: string; tty?: boolean; env?: NodeJS.ProcessEnv } = {}): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  let unlockEnv: Record<string, string> | null = null;
  const watchdogs: WatchdogStart[] = [];
  const paths: PathEnvironment = {
    env: {
      PATH: process.env.PATH,
      HOME: vault.home,
      BITWARDENCLI_APPDATA_DIR: vault.dir,
      DUMONT_SECRETS_SESSION_DIR: join(vault.home, 'session'),
      DUMONT_SECRETS_SERVER_URL: SERVER_URL,
      BW_SESSION: 'stale-session-from-the-shell-000000',
      ...options.env,
    },
    platform: 'linux',
    home: vault.home,
    uid: process.getuid?.() ?? 0,
    ownedDir: () => false,
  };
  const deps: UnlockDependencies = {
    paths,
    runBw: runFake,
    interactiveUnlock: env => new Promise(resolve => {
      unlockEnv = env;
      const child = spawn(FAKE_BW, ['unlock', '--raw'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      child.stdout.on('data', chunk => { stdout += String(chunk); });
      child.stderr.on('data', chunk => { err.push(`[bw] ${String(chunk)}`); });
      child.on('close', code => resolve({ code, stdout }));
      child.stdin.end(options.typed ?? '');
    }),
    startWatchdog: start => { watchdogs.push(start); },
    stdinIsTty: options.tty ?? true,
    out: line => { out.push(line); },
    err: line => { err.push(line); },
  };
  const code = await runUnlock(argv, deps);
  return { code, out: out.join('\n'), err: err.join('\n'), unlockEnv, watchdogs };
}

function sessionPath(vault: FakeVaultDir): string {
  return join(vault.home, 'session', 'session.json');
}

describe('dumont-secrets-unlock', () => {
  it('unlocks with the password typed into bw, stores only the key, 0600, and never prints it', async () => {
    const vault = makeVaultDir();
    const run = await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    expect(run.code).toBe(0);
    const state = readSessionFile(sessionPath(vault));
    expect(state.state).toBe('unlocked');
    const key = state.state === 'unlocked' ? state.session : '';
    expect(vault.state().sessions).toEqual([key]);
    expect(statSync(sessionPath(vault)).mode & 0o777).toBe(0o600);
    expect(statSync(join(vault.home, 'session')).mode & 0o777).toBe(0o700);
    // Default TTL: 2 hours.
    const hours = state.state === 'unlocked' ? (state.expiresAt.getTime() - Date.now()) / 3_600_000 : 0;
    expect(hours).toBeGreaterThan(1.9);
    expect(hours).toBeLessThanOrEqual(2);
    // One watchdog, told only the fingerprint (argv) and an environment without any session.
    expect(run.watchdogs).toHaveLength(1);
    expect(run.watchdogs[0]).toMatchObject({ sessionFile: sessionPath(vault), fingerprint: sessionFingerprint(key), bin: 'bw' });
    expect(JSON.stringify(run.watchdogs[0])).not.toContain(key);
    expect(run.watchdogs[0]!.env).not.toHaveProperty('BW_SESSION');
    expect(run.out).toContain('any program running as you');
    for (const text of [run.out, run.err]) {
      expect(text).not.toContain(key);
      expect(text).not.toContain(MASTER_PASSWORD);
    }
    expect(readFileSync(sessionPath(vault), 'utf8')).not.toContain(MASTER_PASSWORD);
    // The password went to bw on stdin: never argv, never the environment.
    const calls = vault.state().calls;
    expect(JSON.stringify(calls.map(call => call.args))).not.toContain(MASTER_PASSWORD);
    expect(calls.every(call => !call.passwordInEnv)).toBe(true);
    expect(calls.find(call => call.args[0] === 'unlock')).toMatchObject({ args: ['unlock', '--raw'], stdin: true });
    // An inherited BW_SESSION is not handed to bw unlock.
    expect(run.unlockEnv).not.toHaveProperty('BW_SESSION');
    expect(run.unlockEnv).not.toHaveProperty('BW_NOINTERACTION');
  });

  it('the MCP then works with that session file, in the same process or a new one', async () => {
    const vault = makeVaultDir();
    expect((await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` })).code).toBe(0);
    const config = { sessionFile: sessionPath(vault) } as SecretsConfig;
    const { execFileRunner } = await import('../src/bw.js');
    const bw = new BwVault(testBwConfig(), {
      runner: execFileRunner(FAKE_BW), session: sessionSourceFor(config, () => undefined), log: () => undefined,
      baseEnv: { PATH: process.env.PATH, BITWARDENCLI_APPDATA_DIR: vault.dir },
    });
    const svc = new SecretsService({ vault: bw, scope: DEFAULT_SCOPE, log: () => undefined });
    expect((await svc.getSecret(INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint())).value).toBe(SENTINEL_INFRA);
    // --lock: file gone, bw locked; the MCP answers SESSION_LOCKED.
    const locked = await unlock(vault, ['--lock']);
    expect(locked.code).toBe(0);
    expect(readSessionFile(sessionPath(vault))).toEqual({ state: 'locked', reason: 'missing' });
    expect(vault.state().sessions).toEqual([]);
    const error = await svc.getSecret(INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint()).catch(caught => caught);
    expect((error as { code?: string }).code).toBe('SESSION_LOCKED');
  }, 30_000);

  it('a wrong password stores nothing', async () => {
    const vault = makeVaultDir();
    const run = await unlock(vault, [], { typed: 'wrong-password\n' });
    expect(run.code).toBe(1);
    expect(run.err).toContain('Unlock failed; nothing was stored.');
    expect(readSessionFile(sessionPath(vault))).toEqual({ state: 'locked', reason: 'missing' });
  });

  it('not logged in: tells the person how to log in (SSO or email) and does not unlock', async () => {
    const vault = makeVaultDir(state => { state.loggedIn = false; });
    const run = await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    expect(run.code).toBe(3);
    expect(run.err).toContain('bw login --sso');
    expect(run.err).toContain('bw login <your email>');
    expect(vault.state().calls.map(call => call.args[0])).toEqual(['status']);
  });

  it('bw configured for another server: refuses with the commands to fix it', async () => {
    const vault = makeVaultDir(state => { state.serverUrl = 'https://vault.bitwarden.com'; });
    const run = await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    expect(run.code).toBe(2);
    expect(run.err).toContain(`bw config server ${SERVER_URL}`);
    expect(vault.state().unlocks).toBe(0);
  });

  it('without a terminal it refuses instead of hanging on a prompt nobody sees', async () => {
    const vault = makeVaultDir();
    const run = await unlock(vault, [], { tty: false, typed: `${MASTER_PASSWORD}\n` });
    expect(run.code).toBe(4);
    expect(run.err).toContain('needs an interactive terminal');
    expect(run.err).toContain('separate terminal window');
    expect(vault.state().unlocks).toBe(0);
    // The test-only environment switch (there is no command-line flag for it).
    const piped = await unlock(vault, [], { tty: false, typed: `${MASTER_PASSWORD}\n`, env: { DUMONT_SECRETS_UNLOCK_ALLOW_NON_TTY: '1' } });
    expect(piped.code).toBe(0);
    expect(piped.unlockEnv).not.toHaveProperty('DUMONT_SECRETS_UNLOCK_ALLOW_NON_TTY');
  });

  it('an expired session is cleaned up by whoever sees it: file removed and bw locked', async () => {
    const vault = makeVaultDir();
    const key = vault.unlock();
    writeSessionFile(sessionPath(vault), key, 60_000, { now: () => Date.now() - 120_000 });
    const status = await unlock(vault, ['--status']);
    expect(status.err).toContain('had expired');
    expect(readSessionFile(sessionPath(vault))).toEqual({ state: 'locked', reason: 'missing' });
    expect(vault.state().sessions).toEqual([]);
    expect(vault.state().calls.some(call => call.args[0] === 'lock')).toBe(true);
  });

  it('the MCP cleans up an expired session too, under the lock, and answers SESSION_LOCKED', async () => {
    const vault = makeVaultDir();
    const key = vault.unlock();
    const file = sessionPath(vault);
    writeSessionFile(file, key, 60_000, { now: () => Date.now() - 120_000 });
    const { execFileRunner } = await import('../src/bw.js');
    const { FileLock } = await import('../src/lock.js');
    const bw = new BwVault(testBwConfig(), {
      runner: execFileRunner(FAKE_BW), session: sessionSourceFor({ sessionFile: file } as SecretsConfig, () => undefined),
      expire: () => expireSessionFile(file), log: () => undefined,
      lock: new FileLock({ path: join(vault.home, 'session', 'bw.lock'), waitMs: 5000, staleMs: 60_000 }),
      baseEnv: { PATH: process.env.PATH, BITWARDENCLI_APPDATA_DIR: vault.dir },
    });
    const svc = new SecretsService({ vault: bw, scope: DEFAULT_SCOPE, log: () => undefined });
    const error = await svc.listItems({}, new Taint()).catch(caught => caught);
    expect((error as { code?: string }).code).toBe('SESSION_LOCKED');
    expect(readSessionFile(file)).toEqual({ state: 'locked', reason: 'missing' });
    expect(vault.state().sessions).toEqual([]);
    expect(vault.state().calls.filter(call => call.args[0] === 'lock')).toHaveLength(1);
  }, 30_000);

  it('already unlocked: says so and does not ask again, unless --force', async () => {
    const vault = makeVaultDir();
    await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    const again = await unlock(vault, []);
    expect(again.code).toBe(0);
    expect(again.out).toMatch(/^Already unlocked until /);
    expect(vault.state().unlocks).toBe(1);
    const forced = await unlock(vault, ['--force', '--ttl', '90m'], { typed: `${MASTER_PASSWORD}\n` });
    expect(forced.code).toBe(0);
    expect(vault.state().unlocks).toBe(2);
    const state = readSessionFile(sessionPath(vault));
    const minutes = state.state === 'unlocked' ? (state.expiresAt.getTime() - Date.now()) / 60_000 : 0;
    expect(minutes).toBeGreaterThan(89);
    expect(minutes).toBeLessThanOrEqual(90);
  });

  it('replaces a session file that is readable by others', async () => {
    const vault = makeVaultDir();
    await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    const { chmodSync } = await import('node:fs');
    chmodSync(sessionPath(vault), 0o644);
    const status = await unlock(vault, ['--status']);
    expect(status.code).toBe(1);
    expect(status.out).toContain('readable by others');
    const run = await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    expect(run.code).toBe(0);
    expect(statSync(sessionPath(vault)).mode & 0o777).toBe(0o600);
  });

  it('--status reports locked / unlocked with the expiry, never the key', async () => {
    const vault = makeVaultDir();
    const before = await unlock(vault, ['--status']);
    expect(before.code).toBe(1);
    expect(before.out).toContain('Session: locked (no session file)');
    await unlock(vault, [], { typed: `${MASTER_PASSWORD}\n` });
    const after = await unlock(vault, ['--status']);
    expect(after.code).toBe(0);
    expect(after.out).toMatch(/Session: unlocked until \d{4}-/);
    expect(after.out).toContain(`bw: unlocked, server ${SERVER_URL}`);
    const key = vault.state().sessions[0]!;
    expect(after.out).not.toContain(key);
    // Expired file.
    const file = sessionPath(vault);
    const body = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    writeFileSync(file, JSON.stringify({ ...body, expires_at: '2020-01-01T00:00:00.000Z' }), { mode: 0o600 });
    const expired = await unlock(vault, ['--status']);
    expect(expired.err).toContain('The previous session had expired');
    expect(expired.out).toContain('Session: locked (no session file)');
  });

  it('rejects bad arguments and TTLs', async () => {
    const vault = makeVaultDir();
    expect((await unlock(vault, ['--bogus'])).code).toBe(64);
    expect((await unlock(vault, ['--ttl', '48h'])).code).toBe(64);
    expect((await unlock(vault, ['--ttl', '13h'])).code).toBe(64);
    expect((await unlock(vault, ['--allow-non-tty'])).code).toBe(64);
    expect((await unlock(vault, [], { env: { DUMONT_SECRETS_SESSION_TTL: '1m' } })).code).toBe(64);
    expect(parseDuration('8h')).toBe(8 * 3_600_000);
    expect(parseDuration('30m')).toBe(30 * 60_000);
    expect(parseDuration('4')).toBe(4 * 3_600_000);
    expect(parseDuration('12h')).toBe(12 * 3_600_000);
    expect(parseDuration('13h')).toBeNull();
    expect((await unlock(vault, ['--help'])).out).toContain('Usage: dumont-secrets-unlock');
  });

  it('uses the same session directory resolution as the MCP', () => {
    const p: PathEnvironment = { env: {}, platform: 'linux', home: '/h', uid: 5, ownedDir: path => path === '/run/user/5' };
    expect(sessionDir(p)).toBe('/run/user/5/dumont-secrets');
  });
});
