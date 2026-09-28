import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { describe, expect, it } from 'vitest';
import { AutoUnlocker, performAutoUnlock, type AutoUnlockResult } from '../src/autounlock.js';
import { BwVault, type BwRunner } from '../src/bw.js';
import { loadSecretsConfig } from '../src/config.js';
import {
  createBackend, defaultToolRunner, detectBackend, isWsl, promptHiddenLine, selectBackend, type BackendName, type ToolRunner,
} from '../src/credstore.js';
import type { PathEnvironment } from '../src/paths.js';
import { readSessionFile, writeSessionFile } from '../src/session.js';
import { createLocalServer } from '../src/stdio.js';
import { AUTO_LOGIN_FAILED_MESSAGE, AUTO_UNLOCK_FAILED_MESSAGE, SESSION_LOCKED_MESSAGE, SecretsError } from '../src/types.js';
import { runUnlock, type BwResult, type WatchdogStart } from '../src/unlock.js';
import { credCalls, readStored, seedStored } from './fixtures/fake-credtool.mjs';
import {
  FAKE_BW, inProcessRunner, INFRA_ITEM, makeVaultDir, PERSONAL_ITEM, SERVER_URL, testBwConfig, type FakeVaultDir,
} from './fixtures.js';

const FIXTURES = join(import.meta.dirname, 'fixtures');
const FAKE_POWERSHELL = join(FIXTURES, 'fake-powershell.mjs');
const FAKE_SECURITY = join(FIXTURES, 'fake-security.mjs');
const FAKE_SECRET_TOOL = join(FIXTURES, 'fake-secret-tool.mjs');
// The master password for these tests: if it shows up anywhere it must not, a test fails.
const SENTINEL_PW = 'SENTINEL-master-pw-\u00c4\u00d6-0011';
const UID = process.getuid?.() ?? 0;

const BACKEND_ENV: Record<BackendName, Record<string, string>> = {
  dpapi: { DUMONT_SECRETS_CREDSTORE: 'dpapi', DUMONT_SECRETS_POWERSHELL_BIN: FAKE_POWERSHELL },
  keychain: { DUMONT_SECRETS_CREDSTORE: 'keychain', DUMONT_SECRETS_SECURITY_BIN: FAKE_SECURITY },
  libsecret: { DUMONT_SECRETS_CREDSTORE: 'libsecret', DUMONT_SECRETS_SECRET_TOOL_BIN: FAKE_SECRET_TOOL },
};

interface World {
  readonly vault: FakeVaultDir;
  readonly credDir: string;
  readonly env: NodeJS.ProcessEnv;
  readonly paths: PathEnvironment;
  readonly configPath: string;
  readonly sessionPath: string;
}

function world(backend: BackendName = 'libsecret', change?: Parameters<typeof makeVaultDir>[0], extraEnv: Record<string, string> = {}): World {
  const vault = makeVaultDir(state => {
    state.password = SENTINEL_PW;
    change?.(state);
  });
  const credDir = join(vault.dir, 'credstore');
  mkdirSync(credDir, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: vault.home,
    BITWARDENCLI_APPDATA_DIR: vault.dir,
    DUMONT_SECRETS_BW_BIN: FAKE_BW,
    DUMONT_SECRETS_SERVER_URL: SERVER_URL,
    DUMONT_SECRETS_SESSION_DIR: join(vault.home, 'session'),
    DUMONT_SECRETS_AUDIT_LOG: join(vault.home, 'audit.log'),
    DUMONT_SECRETS_MCP_CONFIG: join(vault.home, 'config', 'mcp.json'),
    FAKE_CREDSTORE_DIR: credDir,
    ...BACKEND_ENV[backend],
    ...extraEnv,
  };
  return {
    vault,
    credDir,
    env,
    paths: { env, platform: 'linux', home: vault.home, uid: UID, ownedDir: () => false },
    configPath: join(vault.home, 'config', 'mcp.json'),
    sessionPath: join(vault.home, 'session', 'session.json'),
  };
}

function writeConfig(w: World, record: Record<string, unknown>): void {
  mkdirSync(join(w.vault.home, 'config'), { recursive: true, mode: 0o700 });
  writeFileSync(w.configPath, JSON.stringify(record), { mode: 0o600 });
}

function runFake(args: readonly string[], env: Record<string, string>): Promise<BwResult> {
  return new Promise(resolve => {
    const child = execFile(FAKE_BW, [...args], { env, encoding: 'utf8' }, (error, stdout) => {
      const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : 1) : 0;
      resolve({ code, stdout });
    });
    child.stdin?.end();
  });
}

/** The credential tools with a mocked terminal: an interactive tool reads `typed` on stdin, as from the TTY. */
function typingRunner(typed: string): ToolRunner {
  const real = defaultToolRunner();
  return {
    capture: real.capture,
    interactive: (bin, args, env) => new Promise((resolve, reject) => {
      const child = spawn(bin, [...args], { env, stdio: ['pipe', 'ignore', 'ignore'] });
      child.on('error', reject);
      child.on('close', code => resolve(code));
      child.stdin.end(`${typed}\n`);
    }),
  };
}

interface Run { readonly code: number; readonly out: string; readonly err: string; readonly watchdogs: WatchdogStart[] }

async function cli(w: World, argv: string[], options: { typed?: string; tty?: boolean } = {}): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const watchdogs: WatchdogStart[] = [];
  const code = await runUnlock(argv, {
    paths: w.paths,
    runBw: runFake,
    interactiveUnlock: () => Promise.reject(new Error('the manual prompt must not run here')),
    toolRunner: typingRunner(options.typed ?? SENTINEL_PW),
    promptHidden: async () => Buffer.from(options.typed ?? SENTINEL_PW, 'utf8'),
    startWatchdog: start => { watchdogs.push(start); },
    stdinIsTty: options.tty ?? true,
    out: line => { out.push(line); },
    err: line => { err.push(line); },
  });
  return { code, out: out.join('\n'), err: err.join('\n'), watchdogs };
}

/** Every place the password must never be. */
function expectNoPasswordAnywhere(w: World, texts: string[] = []): void {
  for (const text of texts) expect(text).not.toContain(SENTINEL_PW);
  for (const file of [w.configPath, w.sessionPath, join(w.vault.home, 'audit.log')]) {
    if (existsSync(file)) expect(readFileSync(file, 'utf8')).not.toContain(SENTINEL_PW);
  }
  // Nothing of ours in the scratch home holds it (the fake store keeps it obfuscated in its own dir).
  const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true })
    .flatMap(entry => entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)]);
  for (const file of walk(w.vault.home)) expect(readFileSync(file).includes(Buffer.from(SENTINEL_PW, 'utf8')), file).toBe(false);
  // Never in the argv or the environment of this process.
  expect(process.argv.join(' ')).not.toContain(SENTINEL_PW);
  expect(Object.values(process.env).some(value => value?.includes(SENTINEL_PW))).toBe(false);
  // The credential tools never got it in argv or env.
  for (const call of credCalls(w.credDir)) {
    expect(call.passwordInArgv).toBe(false);
    expect(call.passwordInEnv).toBe(false);
  }
  // bw got it only as DUMONT_BW_PW, only for unlock/login, never in argv.
  for (const call of w.vault.state().calls) {
    expect(call.args.join(' ')).not.toContain('<PASSWORD-IN-ARGV>');
    if (call.args[0] === 'unlock' || call.args[0] === 'login') {
      if (call.passwordInEnv) {
        expect(call.passwordEnvNames).toEqual(['DUMONT_BW_PW']);
        expect(call.noInteraction).toBe(true);
      }
    } else {
      expect(call.passwordInEnv, call.args.join(' ')).toBe(false);
    }
  }
}

describe('credential store selection', () => {
  it('WSL is detected from WSL_DISTRO_NAME or /proc/version; macOS -> keychain; Linux -> libsecret', () => {
    expect(isWsl({ WSL_DISTRO_NAME: 'Ubuntu-24.04' }, () => 'Linux version 6.8.0-generic')).toBe(true);
    expect(isWsl({}, () => 'Linux version 6.6.87.2-microsoft-standard-WSL2 (root@x)')).toBe(true);
    expect(isWsl({}, () => 'Linux version 4.4.0-19041-Microsoft')).toBe(true);
    expect(isWsl({}, () => 'Linux version 6.8.0-45-generic (buildd@lcy02)')).toBe(false);
    expect(isWsl({}, () => { throw new Error('no /proc'); })).toBe(false);
    expect(detectBackend({}, 'linux', () => 'Linux version 6.6.87.2-microsoft-standard-WSL2')).toBe('dpapi');
    expect(detectBackend({ WSL_DISTRO_NAME: 'Debian' }, 'linux', () => 'Linux')).toBe('dpapi');
    expect(detectBackend({}, 'linux', () => 'Linux version 6.8.0-generic')).toBe('libsecret');
    expect(detectBackend({}, 'darwin')).toBe('keychain');
    expect(detectBackend({}, 'win32')).toBeNull();
    expect(detectBackend({ DUMONT_SECRETS_CREDSTORE: 'libsecret' }, 'linux', () => 'microsoft')).toBe('libsecret');
    // No plaintext or "file" store exists to select.
    for (const bad of ['file', 'plaintext', 'fake', 'DPAPI']) {
      expect(() => detectBackend({ DUMONT_SECRETS_CREDSTORE: bad }, 'linux')).toThrow('dpapi, keychain or libsecret');
    }
    expect(selectBackend({}, 'win32')).toBeNull();
  });

  it('refuses a relative tool path and an unsafe DPAPI file override', () => {
    expect(() => createBackend('dpapi', { env: { DUMONT_SECRETS_DPAPI_FILE: "C:\\x';Remove-Item C:\\" } })).toThrow('plain Windows path');
    expect(() => createBackend('dpapi', { env: { DUMONT_SECRETS_DPAPI_FILE: '/mnt/c/x.dpapi' } })).toThrow('plain Windows path');
    expect(createBackend('dpapi', { env: { DUMONT_SECRETS_DPAPI_FILE: 'C:\\Users\\me\\AppData\\Local\\Temp\\t.dpapi' } }).description)
      .toContain('C:\\Users\\me\\AppData\\Local\\Temp\\t.dpapi');
    expect(createBackend('dpapi', { env: {} }).description).toContain('%LOCALAPPDATA%\\DumontSecrets\\bw-master.dpapi');
  });

  for (const name of ['dpapi', 'keychain', 'libsecret'] as const) {
    it(`${name}: store, read, remove through the tool, never with the password in argv or env`, async () => {
      const w = world(name);
      const backend = createBackend(name, { env: w.env, runner: typingRunner(SENTINEL_PW) });
      expect(await backend.unavailable()).toBeNull();
      expect(await backend.read()).toBeNull();
      const errors: string[] = [];
      expect(await backend.store({ promptHidden: async () => Buffer.from(SENTINEL_PW, 'utf8'), err: line => { errors.push(line); } })).toBe(true);
      expect(readStored(w.credDir)?.toString('utf8')).toBe(SENTINEL_PW);
      const read = await backend.read();
      expect(read?.toString('utf8')).toBe(SENTINEL_PW);
      expect(await backend.remove()).toBe(true);
      expect(await backend.read()).toBeNull();
      if (name !== 'libsecret') expect(await backend.remove()).toBe(false);
      expect(credCalls(w.credDir).map(call => call.op)).toContain('store');
      expectNoPasswordAnywhere(w, errors);
    });
  }

  it('a failing tool is an error, not "nothing stored"', async () => {
    const w = world('dpapi', undefined, { FAKE_CREDSTORE_FAIL: 'read' });
    seedStored(w.credDir, SENTINEL_PW);
    const backend = createBackend('dpapi', { env: w.env });
    await expect(backend.read()).rejects.toThrow('could not decrypt');
    // Two reads: the first failed and was retried once.
    expect(credCalls(w.credDir).filter(call => call.op === 'read')).toHaveLength(2);
  });

  it('dpapi: a one-off WSL interop failure on read is retried once', async () => {
    const w = world('dpapi', undefined, { FAKE_CREDSTORE_FAIL_ONCE: 'read' });
    seedStored(w.credDir, SENTINEL_PW);
    const backend = createBackend('dpapi', { env: w.env });
    expect((await backend.read())?.toString('utf8')).toBe(SENTINEL_PW);
  });

  it('libsecret: missing secret-tool or no Secret Service -> unavailable', async () => {
    const missing = createBackend('libsecret', { env: { PATH: '/nonexistent' } });
    expect(await missing.unavailable()).toContain('secret-tool was not found');
    const w = world('libsecret', undefined, { FAKE_SECRET_SERVICE: 'down' });
    const down = createBackend('libsecret', { env: w.env });
    expect(await down.unavailable()).toContain('No Secret Service answered');
    const ps = createBackend('dpapi', { env: { PATH: '/nonexistent', DUMONT_SECRETS_POWERSHELL_BIN: '/nonexistent/powershell.exe' } });
    expect(await ps.unavailable()).toContain('powershell.exe was not found');
  });

  it('promptHiddenLine reads one line from a pipe and never echoes it', async () => {
    const input = new PassThrough() as unknown as NodeJS.ReadStream;
    const output = new PassThrough();
    let shown = '';
    output.on('data', chunk => { shown += String(chunk); });
    const pending = promptHiddenLine('Password: ', input, output);
    (input as unknown as PassThrough).write(`${SENTINEL_PW}\nrest\n`);
    const password = await pending;
    expect(password?.toString('utf8')).toBe(SENTINEL_PW);
    expect(shown).toBe('Password: \n');
  });
});

describe('dumont-secrets-unlock --setup-auto / --auto / --disable-auto / --status', () => {
  it('--setup-auto stores the password, proves it unlocks bw, and turns auto-unlock on (config merged, 0600)', async () => {
    const w = world('libsecret');
    writeConfig(w, { version: 1, value_collections: ['Infra/example'], write_collection: 'MCP/writable' });
    const run = await cli(w, ['--setup-auto']);
    expect(run.code, run.err).toBe(0);
    // The risk is spelled out before the password is asked for.
    expect(run.err).toContain('It does NOT protect it from programs running as YOU');
    expect(run.err).toContain('unlock your WHOLE vault, personal items included');
    expect(run.err.indexOf('WHOLE vault')).toBeLessThan(run.err.indexOf('asks for the password'));
    expect(run.out).toContain('Auto-unlock is ON for person@example.test');
    expect(readStored(w.credDir)?.toString('utf8')).toBe(SENTINEL_PW);
    const config = JSON.parse(readFileSync(w.configPath, 'utf8')) as Record<string, unknown>;
    expect(config).toEqual({
      version: 1, value_collections: ['Infra/example'], write_collection: 'MCP/writable', auto_unlock: true, account_email: 'person@example.test',
    });
    expect(statSync(w.configPath).mode & 0o777).toBe(0o600);
    // Verified by one real unlock through bw --passwordenv, which also wrote a session.
    expect(w.vault.state().unlocks).toBe(1);
    expect(w.vault.state().calls.find(call => call.args[0] === 'unlock')?.args).toEqual(['unlock', '--passwordenv', 'DUMONT_BW_PW', '--raw']);
    expect(readSessionFile(w.sessionPath).state).toBe('unlocked');
    expect(run.watchdogs).toHaveLength(1);
    expectNoPasswordAnywhere(w, [run.out, run.err, JSON.stringify(run.watchdogs)]);

    const status = await cli(w, ['--status']);
    expect(status.code).toBe(0);
    expect(status.out).toContain('Auto-unlock: ON, password in Secret Service via secret-tool');
    expect(status.out).toContain('auto-login as person@example.test');
    expectNoPasswordAnywhere(w, [status.out, status.err]);
  });

  it('a wrong password typed at setup: verification fails, the stored password is removed, config untouched', async () => {
    const w = world('keychain');
    const run = await cli(w, ['--setup-auto'], { typed: 'not-the-password' });
    expect(run.code).toBe(1);
    expect(run.err).toContain('did not unlock bw');
    expect(run.err).toContain('removed again');
    expect(readStored(w.credDir)).toBeNull();
    expect(existsSync(w.configPath)).toBe(false);
    expect(readSessionFile(w.sessionPath).state).toBe('locked');
  });

  it('DPAPI setup asks with our hidden prompt and pipes the password to powershell on stdin', async () => {
    const w = world('dpapi');
    const run = await cli(w, ['--setup-auto']);
    expect(run.code, run.err).toBe(0);
    expect(readStored(w.credDir)?.toString('utf8')).toBe(SENTINEL_PW);
    expect(credCalls(w.credDir).filter(call => call.kind === 'dpapi').map(call => call.op)).toEqual(['store', 'read']);
    expectNoPasswordAnywhere(w, [run.out, run.err]);
  });

  it('refuses without a terminal, when logged out, and when no credential store is available (no plaintext fallback)', async () => {
    const w = world('libsecret');
    expect((await cli(w, ['--setup-auto'], { tty: false })).code).toBe(4);
    const loggedOut = world('libsecret', state => { state.loggedIn = false; });
    const out = await cli(loggedOut, ['--setup-auto']);
    expect(out.code).toBe(3);
    expect(out.err).toContain('bw login <your email>');
    const down = world('libsecret', undefined, { FAKE_SECRET_SERVICE: 'down' });
    const refused = await cli(down, ['--setup-auto']);
    expect(refused.code).toBe(5);
    expect(refused.err).toContain('No Secret Service answered');
    expect(refused.err).toContain('no plaintext-file fallback');
    expect(readStored(down.credDir)).toBeNull();
    expect(existsSync(down.configPath)).toBe(false);
    const missing = world('libsecret', undefined, { DUMONT_SECRETS_SECRET_TOOL_BIN: '/nonexistent/secret-tool' });
    expect((await cli(missing, ['--setup-auto'])).code).toBe(5);
  });

  it('--auto unlocks without a prompt when on, refuses when off; --disable-auto removes the password and turns it off', async () => {
    const w = world('dpapi');
    expect((await cli(w, ['--auto'], { tty: false })).code).toBe(6);
    seedStored(w.credDir, SENTINEL_PW);
    writeConfig(w, { allow_rotate: true, auto_unlock: true, account_email: 'person@example.test' });
    const auto = await cli(w, ['--auto'], { tty: false });
    expect(auto.code, auto.err).toBe(0);
    expect(auto.out).toMatch(/^Unlocked until .*\(auto-unlock\)/);
    const again = await cli(w, ['--auto'], { tty: false });
    expect(again.out).toMatch(/^Already unlocked until /);
    expect(w.vault.state().unlocks).toBe(1);
    const disabled = await cli(w, ['--disable-auto'], { tty: false });
    expect(disabled.code).toBe(0);
    expect(disabled.out).toContain('Stored password removed');
    expect(disabled.out).toContain('Auto-unlock is OFF');
    expect(readStored(w.credDir)).toBeNull();
    expect(JSON.parse(readFileSync(w.configPath, 'utf8'))).toEqual({ allow_rotate: true, auto_unlock: false });
    const status = await cli(w, ['--status']);
    expect(status.out).toContain('Auto-unlock: off');
    // Twice is fine.
    expect((await cli(w, ['--disable-auto'])).code).toBe(0);
    expectNoPasswordAnywhere(w, [auto.out, auto.err, disabled.out, status.out]);
  });

  it('--auto logs in again when bw is logged out; a 2FA account needs a person', async () => {
    const w = world('libsecret', state => { state.loggedIn = false; });
    seedStored(w.credDir, SENTINEL_PW);
    writeConfig(w, { auto_unlock: true, account_email: 'person@example.test' });
    const auto = await cli(w, ['--auto']);
    expect(auto.code, auto.err).toBe(0);
    expect(auto.out).toContain('after logging in again');
    expect(w.vault.state().calls.find(call => call.args[0] === 'login')?.args)
      .toEqual(['login', 'person@example.test', '--passwordenv', 'DUMONT_BW_PW', '--raw']);
    expectNoPasswordAnywhere(w, [auto.out, auto.err]);

    const twoFactor = world('libsecret', state => { state.loggedIn = false; state.twoFactor = true; });
    seedStored(twoFactor.credDir, SENTINEL_PW);
    writeConfig(twoFactor, { auto_unlock: true, account_email: 'person@example.test' });
    const refused = await cli(twoFactor, ['--auto']);
    expect(refused.code).toBe(3);
    expect(refused.err).toContain('run bw login <your email> once');
    expect(readSessionFile(twoFactor.sessionPath).state).toBe('locked');
  });
});

/** A persistent MCP client over the stdio transport (so a test can send concurrent calls). */
function mcpClient() {
  const toServer = new PassThrough();
  const fromServer = new PassThrough();
  const pending = new Map<number, (message: Record<string, unknown>) => void>();
  let buffer = '';
  fromServer.on('data', chunk => {
    buffer += String(chunk);
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      const message = JSON.parse(line) as Record<string, unknown>;
      if (typeof message.id === 'number') pending.get(message.id)?.(message);
    }
  });
  let id = 0;
  const request = (method: string, params: Record<string, unknown>) => {
    id += 1;
    const current = id;
    return new Promise<Record<string, unknown>>(resolve => {
      pending.set(current, resolve);
      toServer.write(`${JSON.stringify({ jsonrpc: '2.0', id: current, method, params })}\n`);
    });
  };
  return {
    transport: new StdioServerTransport(toServer, fromServer),
    request,
    async init() {
      await request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
      toServer.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    },
    async call(name: string, args: Record<string, unknown> = {}) {
      const response = await request('tools/call', { name, arguments: args });
      return response.result as { isError?: boolean; structuredContent?: Record<string, unknown> };
    },
  };
}

async function mcp(w: World, options: { runner?: BwRunner; clock?: { now: number } } = {}) {
  const config = loadSecretsConfig(w.paths);
  const logs: string[] = [];
  const watchdogs: WatchdogStart[] = [];
  const server = createLocalServer(config, w.env, {
    runner: options.runner ?? inProcessRunner(),
    paths: w.paths,
    log: line => { logs.push(line); },
    startWatchdog: start => { watchdogs.push(start); },
    ...(options.clock ? { now: () => options.clock!.now } : {}),
  });
  const client = mcpClient();
  await server.connect(client.transport);
  await client.init();
  return { client, logs, watchdogs, close: () => server.close() };
}

function itemNames(result: { structuredContent?: Record<string, unknown> }): string[] {
  return ((result.structuredContent?.items ?? []) as Array<{ name: string }>).map(item => item.name);
}

function errorOf(result: { structuredContent?: Record<string, unknown> }) {
  return result.structuredContent?.error as { code?: string; message?: string } | undefined;
}

describe('MCP auto-unlock', () => {
  it('off (the default): a locked vault answers the usual SESSION_LOCKED and nothing is read from the store', async () => {
    const w = world('libsecret');
    seedStored(w.credDir, SENTINEL_PW);
    const m = await mcp(w);
    const result = await m.client.call('secrets_list_items');
    expect(errorOf(result)).toEqual(expect.objectContaining({ code: 'SESSION_LOCKED', message: SESSION_LOCKED_MESSAGE }));
    expect(credCalls(w.credDir)).toEqual([]);
    expect(w.vault.state().unlocks).toBe(0);
    await m.close();
  });

  it('on: no session file -> unlocks by itself and answers; expired -> unlocks again; bw locked -> again', async () => {
    const w = world('libsecret');
    seedStored(w.credDir, SENTINEL_PW);
    writeConfig(w, { auto_unlock: true, account_email: 'person@example.test' });
    const m = await mcp(w);
    const first = await m.client.call('secrets_list_items');
    expect(first.isError, JSON.stringify(first)).toBeFalsy();
    expect(itemNames(first)).toContain(INFRA_ITEM);
    expect(itemNames(first)).not.toContain(PERSONAL_ITEM);
    expect(w.vault.state().unlocks).toBe(1);
    expect(readSessionFile(w.sessionPath).state).toBe('unlocked');
    expect(m.watchdogs).toHaveLength(1);
    expect(m.logs).toContain('dumont-secrets-mcp auto_unlock outcome=ok');

    // The TTL ran out: the MCP expires it (bw lock), then unlocks again and retries once.
    const peek = readSessionFile(w.sessionPath);
    const key = peek.state === 'unlocked' ? peek.session : '';
    writeSessionFile(w.sessionPath, key, 60_000, { now: () => Date.now() - 120_000 });
    const second = await m.client.call('secrets_list_items');
    expect(second.isError, JSON.stringify(second)).toBeFalsy();
    expect(w.vault.state().calls.some(call => call.args[0] === 'lock')).toBe(true);
    expect(w.vault.state().unlocks).toBe(2);

    // bw locked behind the MCP's back (bw lock elsewhere): session file valid, bw says locked.
    w.vault.update(state => { state.sessions = []; });
    const third = await m.client.call('secrets_list_keys', { item: INFRA_ITEM });
    expect(third.isError, JSON.stringify(third)).toBeFalsy();
    expect(w.vault.state().unlocks).toBe(3);
    expect(m.logs.filter(line => line.includes('auto_unlock')).every(line => /^dumont-secrets-mcp auto_unlock outcome=(ok|failed reason=[a-z_]+)$/.test(line))).toBe(true);
    expectNoPasswordAnywhere(w, [...m.logs, JSON.stringify([first, second, third])]);
    await m.close();
  }, 30_000);

  it('turning it on needs no client restart (the config is re-read on each attempt)', async () => {
    const w = world('keychain');
    seedStored(w.credDir, SENTINEL_PW);
    const m = await mcp(w);
    expect(errorOf(await m.client.call('secrets_list_items'))?.code).toBe('SESSION_LOCKED');
    writeConfig(w, { auto_unlock: true });
    expect((await m.client.call('secrets_list_items')).isError).toBeFalsy();
    await m.close();
  });

  it('concurrent calls in one process, and two MCP processes, unlock once (single flight under the lock file)', async () => {
    const w = world('dpapi', undefined, { FAKE_CREDSTORE_DELAY_MS: '150' });
    seedStored(w.credDir, SENTINEL_PW);
    writeConfig(w, { auto_unlock: true });
    const a = await mcp(w);
    const b = await mcp(w);
    const results = await Promise.all([
      a.client.call('secrets_list_items'), a.client.call('secrets_list_items'), a.client.call('secrets_list_keys', { item: INFRA_ITEM }),
      b.client.call('secrets_list_items'), b.client.call('secrets_list_items'),
    ]);
    for (const result of results) expect(result.isError, JSON.stringify(result)).toBeFalsy();
    expect(w.vault.state().unlocks).toBe(1);
    expect(credCalls(w.credDir).filter(call => call.op === 'read')).toHaveLength(1);
    expect(w.vault.overlaps()).toBe('');
    await a.close();
    await b.close();
  }, 30_000);

  it('a failure answers a fixed SESSION_LOCKED message, and backs off for 30 s', async () => {
    const w = world('libsecret');
    seedStored(w.credDir, 'the-old-master-password');
    writeConfig(w, { auto_unlock: true });
    const clock = { now: Date.now() };
    const m = await mcp(w, { clock });
    const first = await m.client.call('secrets_list_items');
    expect(errorOf(first)).toEqual(expect.objectContaining({ code: 'SESSION_LOCKED', message: AUTO_UNLOCK_FAILED_MESSAGE }));
    expect(m.logs).toContain('dumont-secrets-mcp auto_unlock outcome=failed reason=unlock_failed');
    const reads = () => credCalls(w.credDir).filter(call => call.op === 'read').length;
    expect(reads()).toBe(1);
    // Within the back-off: no new attempt, same answer.
    clock.now += 10_000;
    const second = await m.client.call('secrets_list_items');
    expect(errorOf(second)?.message).toBe(AUTO_UNLOCK_FAILED_MESSAGE);
    expect(reads()).toBe(1);
    expect(m.logs).toContain('dumont-secrets-mcp auto_unlock outcome=failed reason=backoff');
    // After it, a new attempt; with the right password stored, it works.
    seedStored(w.credDir, SENTINEL_PW);
    clock.now += 25_000;
    const third = await m.client.call('secrets_list_items');
    expect(third.isError, JSON.stringify(third)).toBeFalsy();
    expect(reads()).toBe(2);
    await m.close();
  }, 30_000);

  it('logged out: logs in with the recorded email; with 2FA it answers the fixed "run bw login" message', async () => {
    const w = world('libsecret', state => { state.loggedIn = false; });
    seedStored(w.credDir, SENTINEL_PW);
    writeConfig(w, { auto_unlock: true, account_email: 'person@example.test' });
    const m = await mcp(w);
    const listed = await m.client.call('secrets_list_items');
    expect(listed.isError, JSON.stringify(listed)).toBeFalsy();
    expect(w.vault.state().logins).toBe(1);
    expectNoPasswordAnywhere(w, [...m.logs, JSON.stringify(listed)]);
    await m.close();

    const tfa = world('libsecret', state => { state.loggedIn = false; state.twoFactor = true; });
    seedStored(tfa.credDir, SENTINEL_PW);
    writeConfig(tfa, { auto_unlock: true, account_email: 'person@example.test' });
    const t = await mcp(tfa);
    const refused = await t.client.call('secrets_list_items');
    expect(errorOf(refused)).toEqual(expect.objectContaining({ code: 'SESSION_LOCKED', message: AUTO_LOGIN_FAILED_MESSAGE }));
    expect(t.logs).toContain('dumont-secrets-mcp auto_unlock outcome=failed reason=login_failed');
    await t.close();

    // Logged out and no email recorded: the same fixed message, no login attempt.
    const noEmail = world('libsecret', state => { state.loggedIn = false; });
    seedStored(noEmail.credDir, SENTINEL_PW);
    writeConfig(noEmail, { auto_unlock: true });
    const n = await mcp(noEmail);
    expect(errorOf(await n.client.call('secrets_list_items'))?.message).toBe(AUTO_LOGIN_FAILED_MESSAGE);
    expect(noEmail.vault.state().calls.some(call => call.args[0] === 'login')).toBe(false);
    await n.close();
  }, 30_000);

  it('the server check still applies: bw on another server is VAULT_SERVER_MISMATCH, never an unlock', async () => {
    const w = world('libsecret');
    seedStored(w.credDir, SENTINEL_PW);
    writeConfig(w, { auto_unlock: true });
    const m = await mcp(w);
    w.vault.update(state => { state.serverUrl = 'https://vault.bitwarden.com'; });
    const result = await m.client.call('secrets_list_items');
    expect(errorOf(result)?.code).toBe('VAULT_SERVER_MISMATCH');
    expect(w.vault.state().unlocks).toBe(0);
    await m.close();
  });
});

describe('the retry and the single flight, unit level', () => {
  it('a SESSION_LOCKED after a write was sent is never retried', async () => {
    const vault = makeVaultDir();
    let session: string | null = vault.unlock();
    let recovered = 0;
    const runner = inProcessRunner(undefined, args => {
      // The session dies right as the create is sent.
      if (args[0] === 'create') vault.update(state => { state.sessions = []; });
    });
    const bw = new BwVault(testBwConfig(), {
      runner,
      session: () => { if (!session) throw new SecretsError('SESSION_LOCKED', SESSION_LOCKED_MESSAGE, true); return session; },
      log: () => undefined,
      baseEnv: { PATH: process.env.PATH, BITWARDENCLI_APPDATA_DIR: vault.dir },
      recover: async () => { recovered += 1; session = vault.unlock(); return null; },
    });
    const error = await bw.withLock(ops => ops.createItem({ name: 'x' })).catch(caught => caught as SecretsError);
    expect((error as SecretsError).code).toBe('SESSION_LOCKED');
    expect(recovered).toBe(0);
    // A read that finds the vault locked is retried once after recover.
    session = null;
    const items = await bw.withLock(ops => ops.listItems());
    expect(recovered).toBe(1);
    expect(items.length).toBeGreaterThan(0);
  });

  it('AutoUnlocker: concurrent callers share one attempt; failures back off; off means no attempt', async () => {
    let now = 1_000_000;
    let performs = 0;
    let answer: AutoUnlockResult = { ok: false, reason: 'backend_failed' };
    let enabled = true;
    const logs: string[] = [];
    const unlocker = new AutoUnlocker({
      settings: () => ({ enabled, accountEmail: null }),
      perform: async () => { performs += 1; await new Promise(resolve => setTimeout(resolve, 20)); return answer; },
      log: line => { logs.push(line); },
      now: () => now,
    });
    const results = await Promise.all([unlocker.unlock(), unlocker.unlock(), unlocker.unlock()]);
    expect(performs).toBe(1);
    expect(results.every(result => !result.ok && result.reason === 'backend_failed')).toBe(true);
    now += 29_000;
    expect(await unlocker.unlock()).toEqual({ ok: false, reason: 'backoff', cause: 'backend_failed' });
    expect(performs).toBe(1);
    now += 2_000;
    answer = { ok: true, expiresAt: new Date(now + 1000), mode: 'unlock' };
    expect((await unlocker.unlock()).ok).toBe(true);
    expect(performs).toBe(2);
    expect(logs).toEqual([
      'dumont-secrets-mcp auto_unlock outcome=failed reason=backend_failed',
      'dumont-secrets-mcp auto_unlock outcome=failed reason=backoff',
      'dumont-secrets-mcp auto_unlock outcome=ok',
    ]);
    enabled = false;
    expect(await unlocker.unlock()).toEqual({ ok: false, reason: 'not_enabled' });
    expect(performs).toBe(2);
  });

  it('performAutoUnlock without a credential store fails closed', async () => {
    const w = world('libsecret');
    const result = await performAutoUnlock({
      paths: w.paths, serverUrl: SERVER_URL, sessionFile: w.sessionPath, lockFile: join(w.vault.home, 'session', 'bw.lock'), bin: FAKE_BW,
      lock: { run: fn => fn() }, backend: null, runBw: runFake, accountEmail: null, ttlMs: 3_600_000, startWatchdog: () => undefined,
    });
    expect(result).toEqual({ ok: false, reason: 'backend_unavailable' });
  });
});
