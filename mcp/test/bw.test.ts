import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bwEnvironment, BwVault, execFileRunner, STATUS_TRUST_MS, type BwRunner } from '../src/bw.js';
import { FileLock } from '../src/lock.js';
import { SecretsService, Taint } from '../src/secrets.js';
import { SecretsError } from '../src/types.js';
import {
  baseEnv,
  DEFAULT_SCOPE,
  FAKE_BW,
  harness,
  INFRA_ITEM,
  inProcessRunner,
  makeVaultDir,
  MASTER_PASSWORD,
  SENTINEL_INFRA,
  testBwConfig,
  type FakeVaultDir,
} from './fixtures.js';

function service(vault: FakeVaultDir, runner: BwRunner, session: () => string, logs: string[] = [], now?: () => number) {
  const bw = new BwVault(testBwConfig(), { runner, session, log: line => { logs.push(line); }, baseEnv: baseEnv(vault), ...(now ? { now } : {}) });
  return new SecretsService({ vault: bw, scope: DEFAULT_SCOPE, log: line => { logs.push(line); } });
}

describe('bw environment', () => {
  it('passes only an allowlist, never an inherited BW_SESSION, password or client secret', () => {
    const env = bwEnvironment({
      PATH: '/bin', HOME: '/home/x', BITWARDENCLI_APPDATA_DIR: '/data', HTTPS_PROXY: 'http://proxy',
      BW_SESSION: 'inherited', BW_PASSWORD: 'pw', BW_CLIENTSECRET: 'cs', AWS_SECRET_ACCESS_KEY: 'aws',
    }, 'the-session-key');
    expect(env).toEqual({
      PATH: '/bin', HOME: '/home/x', BITWARDENCLI_APPDATA_DIR: '/data', HTTPS_PROXY: 'http://proxy',
      BW_NOINTERACTION: 'true', LANG: 'C.UTF-8', BW_SESSION: 'the-session-key',
    });
    expect(bwEnvironment({}, null)).toEqual({ PATH: '/usr/local/bin:/usr/bin:/bin', BW_NOINTERACTION: 'true', LANG: 'C.UTF-8' });
  });

  it('uses the session from the session source, only through the environment', async () => {
    const vault = makeVaultDir();
    const session = vault.unlock();
    const found = await service(vault, inProcessRunner(), () => session).getSecret(INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint());
    expect(found.value).toBe(SENTINEL_INFRA);
    const calls = vault.state().calls.filter(call => call.args[0] !== 'unlock');
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.hadSession).toBe(true);
      expect(call.leakedEnv).toEqual([]);
      expect(call.passwordInEnv).toBe(false);
      expect(call.args.join(' ')).not.toContain(session);
      expect(call.args.join(' ')).not.toMatch(/--session|--passwordfile|<PASSWORD-IN-ARGV>/);
    }
    // The MCP never logs in or unlocks by itself.
    expect(calls.map(call => call.args[0])).not.toContain('login');
    expect(vault.state().unlocks).toBe(1);
  });
});

describe('status verification', () => {
  it('checks bw status once per session key and trust window', async () => {
    const vault = makeVaultDir();
    let session = vault.unlock();
    let clock = 1_000_000;
    const svc = service(vault, inProcessRunner(), () => session, [], () => clock);
    const statuses = () => vault.state().calls.filter(call => call.args[0] === 'status').length;
    await svc.listKeys(INFRA_ITEM, new Taint());
    await svc.listKeys(INFRA_ITEM, new Taint());
    expect(statuses()).toBe(1);
    clock += STATUS_TRUST_MS;
    await svc.listKeys(INFRA_ITEM, new Taint());
    expect(statuses()).toBe(2);
    // A new unlock (new key in the session file) is verified again at once.
    session = vault.unlock();
    await svc.listKeys(INFRA_ITEM, new Taint());
    expect(statuses()).toBe(3);
  });

  it('a session that dies between the status check and the command is SESSION_LOCKED, not a vault error', async () => {
    const vault = makeVaultDir();
    const session = vault.unlock();
    const logs: string[] = [];
    const svc = service(vault, inProcessRunner(), () => session, logs);
    await svc.listKeys(INFRA_ITEM, new Taint());
    vault.update(state => { state.sessions = []; });
    const error = await svc.listKeys(INFRA_ITEM, new Taint()).catch(caught => caught);
    expect((error as SecretsError).code).toBe('SESSION_LOCKED');
    expect(logs).toContain('dumont-secrets-mcp bw outcome=session_recheck command=list');
    expect(vault.state().unlocks).toBe(1);
  });

  it('maps a timeout to VAULT_UNAVAILABLE', async () => {
    const vault = makeVaultDir();
    const runner: BwRunner = async () => ({ code: null, stdout: '', timedOut: true });
    const error = await service(vault, runner, () => vault.unlock()).getSecret(INFRA_ITEM, 'X', new Taint()).catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
  });

  it('a missing bw binary is VAULT_UNAVAILABLE with an install hint', async () => {
    const vault = makeVaultDir();
    const bw = new BwVault(testBwConfig({ bin: '/nonexistent/bw' }), { session: () => vault.unlock(), log: () => undefined, baseEnv: baseEnv(vault) });
    const svc = new SecretsService({ vault: bw, scope: DEFAULT_SCOPE, log: () => undefined });
    const error = await svc.listItems({}, new Taint()).catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
  });

  it('never lets bw output become an error message', async () => {
    const vault = makeVaultDir();
    const inner = inProcessRunner();
    const runner: BwRunner = async (args, options) => {
      if (args[0] === 'list') return { code: 0, stdout: `mystery output ${SENTINEL_INFRA}`, timedOut: false };
      return inner(args, options);
    };
    const session = vault.unlock();
    const error = await service(vault, runner, () => session).getSecret(INFRA_ITEM, 'X', new Taint()).catch(caught => caught);
    expect(error).toBeInstanceOf(SecretsError);
    expect((error as SecretsError).code).toBe('VAULT_ERROR');
    expect(JSON.stringify({ message: (error as Error).message })).not.toContain(SENTINEL_INFRA);
  });
});

describe('serialization', () => {
  it('never runs two bw processes at once, whatever the callers do', async () => {
    const h = harness();
    const calls = [];
    for (let i = 0; i < 6; i += 1) {
      calls.push(h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }));
      calls.push(h.call('secrets_list_items', {}));
      calls.push(h.call('secrets_generate_secret', { item: 'app: generated', key: `KEY_${i}` }));
    }
    const answers = await Promise.all(calls);
    expect(answers.every(answer => !answer.isError)).toBe(true);
    expect(h.runner.tracker.maxActive).toBe(1);
    expect(h.vault.overlaps()).toBe('');
    const notes = h.vault.state().items.find(item => item.id === 'item-writable')!.notes as string;
    for (let i = 0; i < 6; i += 1) expect(notes).toContain(`KEY_${i}=`);
  });

  it('two MCP processes (two vault clients) share one cross-process lock file', async () => {
    const vault = makeVaultDir();
    const session = vault.unlock();
    const lockPath = join(vault.home, 'bw.lock');
    const tracker = { active: 0, maxActive: 0, calls: 0 };
    const runner = inProcessRunner(tracker);
    const make = () => new SecretsService({
      vault: new BwVault(testBwConfig(), {
        runner, session: () => session, log: () => undefined, baseEnv: baseEnv(vault),
        lock: new FileLock({ path: lockPath, waitMs: 10_000, staleMs: 60_000 }),
      }),
      scope: DEFAULT_SCOPE,
      log: () => undefined,
    });
    const [a, b] = [make(), make()];
    await Promise.all([
      a.listKeys(INFRA_ITEM, new Taint()), b.listKeys(INFRA_ITEM, new Taint()),
      // Two processes writing the same item may legitimately meet VAULT_CONFLICT; what matters is no overlap.
      a.writeKey('app: generated', 'A_KEY', 'generated-value-aaaaaaaa', new Taint()).catch(error => error),
      b.writeKey('app: generated', 'B_KEY', 'generated-value-bbbbbbbb', new Taint()).catch(error => error),
    ]);
    expect(tracker.maxActive).toBe(1);
  });
});

describe('file lock', () => {
  it('takes over a lock whose owner is dead, and times out on a live one', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-lock-'));
    const path = join(dir, 'bw.lock');
    writeFileSync(path, `999999999 ${Date.now()}\n`);
    const dead = new FileLock({ path, waitMs: 100, staleMs: 60_000, pidAlive: () => false });
    expect(await dead.run(async () => 'ran')).toBe('ran');
    writeFileSync(path, `${process.pid + 1} ${Date.now()}\n`);
    const live = new FileLock({ path, waitMs: 60, staleMs: 60_000, pidAlive: () => true });
    const error = await live.run(async () => 'ran').catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
    // An old lock is stale whatever its pid says.
    writeFileSync(path, `${process.pid + 1} ${Date.now() - 120_000}\n`);
    expect(await live.run(async () => 'ran')).toBe('ran');
  });
});

describe('execFile runner against the fake CLI', () => {
  it('reads the vault\'s "out of date" refusal from a real subprocess\'s stderr as VAULT_CONFLICT', async () => {
    const vault = makeVaultDir();
    const session = vault.unlock();
    const real = execFileRunner(FAKE_BW);
    const runner: BwRunner = async (args, options) => {
      if (args[0] === 'edit') {
        vault.update(state => { state.items.find(i => i.id === 'item-writable')!.revisionDate = '2026-09-28T00:00:00.000Z'; });
      }
      return real(args, options);
    };
    const logs: string[] = [];
    const error = await service(vault, runner, () => session, logs)
      .writeKey('app: generated', 'NEW_KEY', 'generated-value-abcdefgh', new Taint()).catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_CONFLICT');
    expect((error as SecretsError).message).not.toMatch(/cipher/i);
    expect(logs.join('\n')).not.toContain('stderr noise');
    expect(vault.state().writes).toBe(0);
  }, 30_000);

  it('drives a real subprocess: stdin for item JSON, stderr dropped, personal items never returned', async () => {
    const vault = makeVaultDir();
    const session = vault.unlock();
    const logs: string[] = [];
    const svc = service(vault, execFileRunner(FAKE_BW), () => session, logs);
    await Promise.all([
      svc.writeKey('svc: via execfile', 'TOKEN', 'generated-value-abcdefgh', new Taint()),
      svc.getSecret(INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint()),
      svc.listKeys(INFRA_ITEM, new Taint()),
    ]);
    const found = await svc.getSecret('svc: via execfile', 'TOKEN', new Taint());
    expect(found.value).toBe('generated-value-abcdefgh');
    const listed = await svc.listItems({}, new Taint());
    expect(listed.items.map(item => item.name)).not.toContain('personal: my bank');
    expect(vault.overlaps()).toBe('');
    expect(logs.join('\n')).not.toContain('stderr noise');
    const create = vault.state().calls.find(call => call.args[0] === 'create')!;
    expect(create).toMatchObject({ args: ['create', 'item'], stdin: true, hadSession: true, leakedEnv: [] });
    expect(JSON.stringify(vault.state().calls)).not.toContain(MASTER_PASSWORD);
  }, 30_000);
});
