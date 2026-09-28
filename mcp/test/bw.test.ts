import { describe, expect, it } from 'vitest';
import { AUTH_BACKOFF_MS, BwVault, execFileRunner, type BwRunner } from '../src/bw.js';
import { SecretsService, Taint } from '../src/secrets.js';
import { accessFor } from '../src/policy.js';
import { SecretsError } from '../src/types.js';
import {
  FAKE_BW,
  harness,
  INFRA_ITEM,
  inProcessRunner,
  makeVaultDir,
  MACHINE_PASSWORD,
  principal,
  SENTINEL_INFRA,
  testConfig,
  testPolicy,
} from './fixtures.js';

function readerAccess() {
  return accessFor(principal(['reader']), testPolicy());
}

describe('startup self-test and login back-off', () => {
  it('logs a fixed unlocked line when the machine account opens a session', async () => {
    const vault = makeVaultDir();
    const logs: string[] = [];
    const bw = new BwVault(testConfig({}, vault).bw, { runner: inProcessRunner(), log: line => { logs.push(line); } });
    expect(await bw.selfTest()).toBe(true);
    expect(logs).toContain('secrets-mcp vault outcome=unlocked');
  });

  it('logs a fixed failed line, and tries to log in at most once per 30 s after a failure', async () => {
    const vault = makeVaultDir(state => { state.password = 'something-else'; });
    const logs: string[] = [];
    let clock = 1_000_000;
    const bw = new BwVault(testConfig({}, vault).bw, { runner: inProcessRunner(), now: () => clock, log: line => { logs.push(line); } });
    const service = new SecretsService({ vault: bw, log: () => undefined });
    expect(await bw.selfTest()).toBe(false);
    expect(logs).toContain('secrets-mcp vault outcome=failed');
    expect(logs.join('\n')).not.toContain(MACHINE_PASSWORD);
    const logins = () => vault.state().calls.filter(call => call.args[0] === 'login').length;
    expect(logins()).toBe(1);
    for (let i = 0; i < 5; i += 1) {
      const error = await service.getSecret(readerAccess(), INFRA_ITEM, 'X', new Taint()).catch(caught => caught);
      expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
    }
    expect(logins()).toBe(1);
    clock += AUTH_BACKOFF_MS;
    // The password is fixed in the meantime: the next attempt after the back-off succeeds.
    vault.update(state => { state.password = MACHINE_PASSWORD; });
    const found = await service.getSecret(readerAccess(), INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint());
    expect(found.value).toBe(SENTINEL_INFRA);
    expect(logins()).toBe(2);
  });
});

describe('bw session handling', () => {
  it('configures the server, logs in with --passwordfile, and keeps the session out of argv', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner: inProcessRunner(), log: () => undefined }) });
    const found = await service.getSecret(readerAccess(), INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint());
    expect(found.value).toBe(SENTINEL_INFRA);
    const state = vault.state();
    expect(state.serverUrl).toBe('https://vault.example.test/');
    expect(state.logins).toBe(1);
    const login = state.calls.find(call => call.args[0] === 'login')!;
    expect(login.args).toEqual(['login', 'machine-account@example.test', '--passwordfile', vault.passwordFile, '--raw']);
    for (const call of state.calls) {
      expect(call.args.join(' ')).not.toContain('<PASSWORD-IN-ARGV>');
      expect(call.args.join(' ')).not.toMatch(/--session/);
    }
  });

  it('re-unlocks transparently when the session dies (bw still exits 0)', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const logs: string[] = [];
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner: inProcessRunner(), log: line => { logs.push(line); } }) });
    await service.getSecret(readerAccess(), INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint());
    // The CLI lost the session (another process, a timeout, a restart of the vault...).
    vault.update(state => { state.sessions = []; });
    const again = await service.getSecret(readerAccess(), INFRA_ITEM, 'OTHER_KEY', new Taint());
    expect(again.value).toBeTruthy();
    expect(vault.state().unlocks).toBe(1);
    expect(logs.some(line => line.includes('session_recheck'))).toBe(true);
    expect(logs.some(line => line.includes('outcome=unlocked'))).toBe(true);
  });

  it('logs in again when the CLI was logged out entirely', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner: inProcessRunner(), log: () => undefined }) });
    await service.getSecret(readerAccess(), INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint());
    vault.update(state => { state.loggedIn = false; state.sessions = []; });
    await service.getSecret(readerAccess(), INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint());
    expect(vault.state().logins).toBe(2);
  });

  it('fails with VAULT_UNAVAILABLE and a fixed message when the password is wrong', async () => {
    const vault = makeVaultDir(state => { state.password = 'something-else'; });
    const config = testConfig({}, vault);
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner: inProcessRunner(), log: () => undefined }) });
    const error = await service.getSecret(readerAccess(), INFRA_ITEM, 'X', new Taint()).catch(caught => caught);
    expect(error).toBeInstanceOf(SecretsError);
    expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
    expect((error as SecretsError).message).not.toContain(MACHINE_PASSWORD);
  });

  it('maps a timeout to VAULT_UNAVAILABLE', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const runner: BwRunner = async () => ({ code: null, stdout: '', timedOut: true });
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner, log: () => undefined }) });
    const error = await service.getSecret(readerAccess(), INFRA_ITEM, 'X', new Taint()).catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_UNAVAILABLE');
  });

  it('never lets bw output become an error message', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const inner = inProcessRunner();
    // After login, every list answers with a non-JSON line that contains a "secret".
    const runner: BwRunner = async (args, options) => {
      if (args[0] === 'list') return { code: 0, stdout: `mystery output ${SENTINEL_INFRA}`, timedOut: false };
      return inner(args, options);
    };
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner, log: () => undefined }) });
    const error = await service.getSecret(readerAccess(), INFRA_ITEM, 'X', new Taint()).catch(caught => caught);
    expect(error).toBeInstanceOf(SecretsError);
    expect(['VAULT_ERROR', 'VAULT_UNAVAILABLE']).toContain((error as SecretsError).code);
    expect(JSON.stringify({ message: (error as Error).message })).not.toContain(SENTINEL_INFRA);
  });
});

describe('serialization', () => {
  it('never runs two bw processes at once, whatever the callers do', async () => {
    const h = harness();
    const calls = [];
    for (let i = 0; i < 6; i += 1) {
      calls.push(h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }));
      calls.push(h.call(['meta'], 'secrets_list_items', {}));
      calls.push(h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: `KEY_${i}` }));
    }
    const answers = await Promise.all(calls);
    expect(answers.every(answer => !answer.isError)).toBe(true);
    expect(h.runner.tracker.maxActive).toBe(1);
    expect(h.vault.overlaps()).toBe('');
    // Read-modify-write under the lock: none of the six concurrent writes was lost.
    const notes = h.vault.state().items.find(item => item.id === 'item-writable')!.notes as string;
    for (let i = 0; i < 6; i += 1) expect(notes).toContain(`KEY_${i}=`);
  });
});

describe('execFile runner against the fake CLI', () => {
  it('reads the vault\'s "out of date" refusal from a real subprocess\'s stderr as VAULT_CONFLICT', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const real = execFileRunner(FAKE_BW);
    const runner: BwRunner = async (args, options) => {
      if (args[0] === 'edit') {
        vault.update(state => { state.items.find(i => i.id === 'item-writable')!.revisionDate = '2026-09-28T00:00:00.000Z'; });
      }
      return real(args, options);
    };
    const logs: string[] = [];
    const service = new SecretsService({ vault: new BwVault(config.bw, { runner, log: line => { logs.push(line); } }) });
    const writer = accessFor(principal(['writer']), testPolicy());
    const error = await service.writeKey(writer, 'app: generated', 'NEW_KEY', 'generated-value-abcdefgh', new Taint()).catch(caught => caught);
    expect((error as SecretsError).code).toBe('VAULT_CONFLICT');
    expect((error as SecretsError).message).not.toMatch(/cipher/i);
    expect(logs.join('\n')).not.toContain('stderr noise');
    expect(vault.state().writes).toBe(0);
  }, 30_000);

  it('drives a real subprocess: stdin for item JSON, stderr dropped, no overlap', async () => {
    const vault = makeVaultDir();
    const config = testConfig({}, vault);
    const logs: string[] = [];
    const bwVault = new BwVault(config.bw, { runner: execFileRunner(FAKE_BW), log: line => { logs.push(line); } });
    const service = new SecretsService({ vault: bwVault, log: line => { logs.push(line); } });
    const writer = accessFor(principal(['writer']), testPolicy());
    const reader = readerAccess();
    await Promise.all([
      service.writeKey(writer, 'svc: via execfile', 'TOKEN', 'generated-value-abcdefgh', new Taint()),
      service.getSecret(reader, INFRA_ITEM, 'EXAMPLE_ADMIN_TOKEN', new Taint()),
      service.listKeys(reader, INFRA_ITEM, new Taint()),
    ]);
    const found = await service.getSecret(reader, 'svc: via execfile', 'TOKEN', new Taint());
    expect(found.value).toBe('generated-value-abcdefgh');
    expect(vault.overlaps()).toBe('');
    expect(logs.join('\n')).not.toContain('stderr noise');
    const create = vault.state().calls.find(call => call.args[0] === 'create')!;
    expect(create).toMatchObject({ args: ['create', 'item'], stdin: true, hadSession: true });
  }, 30_000);
});
