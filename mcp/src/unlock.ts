#!/usr/bin/env node
import { execFile, spawn } from 'node:child_process';
import { lstatSync } from 'node:fs';
import {
  AUTO_UNLOCK_LOCK_STALE_MS, bwStatus as readBwStatus, DEFAULT_TTL_MS, parseDuration, performAutoUnlock, readLoginRecord,
  type AutoUnlockFailure, type BwResult,
} from './autounlock.js';
import { bwEnvironment, normalizedServer, type CrossProcessLock } from './bw.js';
import { loadLocalConfig, parseBwBin, parseServerUrl, SecretsConfigError, updateLocalConfig } from './config.js';
import {
  CredStoreError, promptHiddenLine, selectBackend, type CredentialBackend, type ToolRunner,
} from './credstore.js';
import { FileLock } from './lock.js';
import { configFile, currentPathEnvironment, lockFile, sessionFile, type PathEnvironment } from './paths.js';
import { isMainModule } from './runtime.js';
import {
  deleteSessionFile, expireSessionFile, readSessionFile, SESSION_KEY_PATTERN, sessionFingerprint, writeSessionFile, type SessionState,
} from './session.js';
import { startDetachedWatchdog, type WatchdogStart } from './watchdog.js';

export { DEFAULT_TTL_MS, parseDuration, startDetachedWatchdog };
export type { BwResult, WatchdogStart };

// dumont-secrets-unlock: runs in YOUR terminal. It asks your own `bw` to unlock
// (`bw unlock --raw`, with this terminal handed straight to bw, so you type the
// master password into bw itself: this program never reads it, and it is never
// in argv, the environment or shell history). bw prints the session key on
// stdout; that one line is captured and written to the 0600 session file the
// MCP reads, with an expiry, and starts a detached watchdog that locks bw at that
// expiry. It never prints the key.
//
// Opt-in auto-unlock (--setup-auto, --auto, --disable-auto) is the one exception
// to "never reads the password": see autounlock.ts and credstore.ts.

/** Tests only: lets the helper run with a pipe instead of a terminal. */
export const ALLOW_NON_TTY_ENV = 'DUMONT_SECRETS_UNLOCK_ALLOW_NON_TTY';
const STATUS_TIMEOUT_MS = 30_000;
const UNLOCK_TIMEOUT_MS = 60_000;
const MAX_SESSION_OUTPUT = 4096;

export const USAGE = `Usage: dumont-secrets-unlock [--ttl <duration>] [--force]
       dumont-secrets-unlock --status
       dumont-secrets-unlock --lock
       dumont-secrets-unlock --setup-auto | --disable-auto | --auto   (opt-in auto-unlock)

Unlocks your own Bitwarden vault for the Dumont Secrets MCP. Run it in a real
terminal window: bw asks for your master password there, and this program never
reads it. It stores only the session key bw prints, in a file only you can read,
until it expires (default 2h, --ttl 5m..12h, or DUMONT_SECRETS_SESSION_TTL); a
background watchdog runs bw lock at that time.

  --status   say whether the MCP can use the vault, and until when (never the key),
             and whether auto-unlock is on
  --lock     delete the session file and run bw lock
  --force    unlock again even when a valid session exists
  --ttl      how long the session is valid, e.g. 1h, 90m

Auto-unlock (OFF unless you turn it on, per machine):
  --setup-auto    store your master password in the OS credential store (Windows
                  DPAPI under WSL, macOS Keychain, Linux Secret Service), check it
                  unlocks bw, and let the MCP unlock by itself whenever it needs to
  --disable-auto  delete the stored password and turn auto-unlock off
  --auto          unlock now with the stored password, without a prompt
  RISK: with auto-unlock on, ANY program running as you (an AI agent's shell
  included) can unlock your WHOLE vault, personal items included, at any time.

While unlocked, any program running as you (the agent's shell included) can use
your whole vault through bw, personal items included; the MCP tools themselves
never show personal items. Unlocking replaces the session of any earlier
bw unlock (an exported BW_SESSION stops working); --lock and expiry also lock the
bw you use interactively.

Before the first unlock: bw config server https://secret.getdumont.ai, then
bw login <your email> (email + master password; 2FA asked by bw), or
bw login --sso (Dumont SSO; not yet tested with this vault).`;

const RISK_NOTICE = [
  'AUTO-UNLOCK: read this before you type your password.',
  '  Your Bitwarden master password will be kept in this machine\'s credential store.',
  '  That store protects it from OTHER users and from someone who takes the disk.',
  '  It does NOT protect it from programs running as YOU: any of them, an AI agent\'s',
  '  shell included, can read it and unlock your WHOLE vault, personal items included,',
  '  at any time, without asking you. Do not use this on a shared machine.',
  '  Turn it off at any time with: dumont-secrets-unlock --disable-auto',
];

export interface UnlockDependencies {
  readonly paths: PathEnvironment;
  /** Shared bw lock file (the MCP's). Defaults to a FileLock on the per-user lock path. */
  readonly lock?: CrossProcessLock;
  /** Starts the detached expiry watchdog. */
  readonly startWatchdog?: (start: WatchdogStart) => void;
  /** Non-interactive bw call (status, lock, and the auto-unlock's unlock/login). */
  readonly runBw: (args: readonly string[], env: Record<string, string>, timeoutMs?: number) => Promise<BwResult>;
  /** `bw unlock --raw` with the terminal's stdin/stderr handed to bw; only stdout is captured. */
  readonly interactiveUnlock: (env: Record<string, string>) => Promise<BwResult>;
  /** Credential store for auto-unlock. Default: the platform's (credstore.ts). null: none on this platform. */
  readonly backend?: CredentialBackend | null;
  /** Runs the credential tools (tests pass fakes). */
  readonly toolRunner?: ToolRunner;
  /** Asks for a password with echo off (DPAPI setup only). */
  readonly promptHidden?: (prompt: string) => Promise<Buffer | null>;
  readonly stdinIsTty: boolean;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  readonly now?: () => number;
}

type Mode = 'unlock' | 'status' | 'lock' | 'help' | 'setup-auto' | 'disable-auto' | 'auto';

interface Options {
  readonly mode: Mode;
  readonly force: boolean;
  readonly ttlMs: number;
}

const MODE_FLAGS: Record<string, Mode> = {
  '--status': 'status', '--lock': 'lock', '--help': 'help', '-h': 'help',
  '--setup-auto': 'setup-auto', '--disable-auto': 'disable-auto', '--auto': 'auto',
};

function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv): Options | string {
  let mode: Mode = 'unlock';
  let force = false;
  let ttlRaw = env.DUMONT_SECRETS_SESSION_TTL?.trim() || '';
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    const flagMode = MODE_FLAGS[arg];
    if (flagMode) {
      if (mode !== 'unlock' && mode !== flagMode && flagMode !== 'help') return `Only one of --status, --lock, --setup-auto, --disable-auto, --auto`;
      mode = flagMode === 'help' ? 'help' : flagMode;
    } else if (arg === '--force') force = true;
    else if (arg === '--ttl') ttlRaw = argv[++index] ?? '';
    else if (arg.startsWith('--ttl=')) ttlRaw = arg.slice('--ttl='.length);
    else return `Unknown argument: ${arg.slice(0, 40)}`;
  }
  const ttlMs = ttlRaw ? parseDuration(ttlRaw) : DEFAULT_TTL_MS;
  if (ttlMs === null) return 'The session TTL must be between 5m and 12h (e.g. 2h, 90m)';
  return { mode, force, ttlMs };
}

type LockedRun = (args: readonly string[], env: Record<string, string>) => Promise<BwResult>;

function describe(state: SessionState, now: number): string {
  if (state.state === 'unlocked') {
    const minutes = Math.max(0, Math.round((state.expiresAt.getTime() - now) / 60_000));
    return `unlocked until ${state.expiresAt.toISOString()} (${Math.floor(minutes / 60)}h${String(minutes % 60).padStart(2, '0')}m left)`;
  }
  switch (state.reason) {
    case 'missing': return 'locked (no session file)';
    case 'expired': return `locked (session expired at ${state.expiresAt?.toISOString() ?? 'an earlier time'})`;
    case 'insecure_permissions': return 'locked (session file or directory is readable by others; it is ignored)';
    case 'wrong_owner': return 'locked (session file is owned by another user; it is ignored)';
    case 'not_a_file': return 'locked (session path is not a regular file; it is ignored)';
    default: return 'locked (session file unreadable)';
  }
}

const SERVER_HINT = (url: string) => [
  `Your bw CLI is not configured for ${url}. In this terminal run:`,
  '  bw logout            (only if you are logged in to another server)',
  `  bw config server ${url}`,
  '  bw login <your email>   (or: bw login --sso, Dumont SSO, not yet tested)',
  '  dumont-secrets-unlock',
];

const LOGIN_HINT = [
  'You are not logged in to bw. In this terminal run one of:',
  '  bw login <your email>       (email + master password; 2FA is asked by bw)',
  '  bw login --sso              (Dumont SSO; not yet tested with this vault)',
  'then run dumont-secrets-unlock again. Login is once per machine; unlock is per session.',
];

/** A fixed sentence per auto-unlock failure class; never bw output, never a value. */
export function autoUnlockFailureText(reason: AutoUnlockFailure): string {
  switch (reason) {
    case 'not_enabled': return 'Auto-unlock is off on this machine (dumont-secrets-unlock --setup-auto turns it on).';
    case 'backend_unavailable': return 'No supported credential store on this machine (Windows DPAPI under WSL, macOS Keychain, Linux Secret Service).';
    case 'backend_failed': return 'The credential store did not return the password (locked keyring, access denied, or the tool failed).';
    case 'no_password': return 'No password is stored; run dumont-secrets-unlock --setup-auto again.';
    case 'status_unreadable': return 'Could not run `bw status` (is the Bitwarden CLI installed and on PATH?).';
    case 'server_mismatch': return 'bw is configured for another server (see dumont-secrets-unlock --status).';
    case 'account_mismatch': return 'bw is logged in as a different account than the one auto-unlock was set up for; nothing was unlocked. Run bw logout, then bw login <your email>, or --setup-auto again.';
    case 'login_blocked': return 'An earlier automatic login failed; the MCP will not try again until you run bw login <your email> (or dumont-secrets-unlock --auto) yourself.';
    case 'login_backoff': return 'An automatic login was attempted less than 15 minutes ago; the MCP waits before trying again. Run bw login <your email> yourself.';
    case 'unauthenticated': return 'bw is logged out and no account email is recorded: run bw login <your email> once in this terminal.';
    case 'login_failed': return 'bw is logged out and automatic login failed (two-step login needs you): run bw login <your email> once in this terminal.';
    case 'unlock_failed': return 'bw did not accept the stored password (changed master password?): run dumont-secrets-unlock --setup-auto again.';
    case 'session_write_failed': return 'bw unlocked, but the session file could not be written.';
    case 'lock_busy': return 'Another Dumont Secrets process is using bw; retry shortly.';
    case 'unexpected': return 'Auto-unlock failed unexpectedly (an internal error, not the password).';
    default: return 'Auto-unlock failed unexpectedly.';
  }
}

export async function runUnlock(argv: readonly string[], deps: UnlockDependencies): Promise<number> {
  const now = deps.now ?? Date.now;
  const options = parseArgs(argv, deps.paths.env);
  if (typeof options === 'string') {
    deps.err(options);
    deps.err(USAGE);
    return 64;
  }
  if (options.mode === 'help') {
    deps.out(USAGE);
    return 0;
  }
  let serverUrl: string;
  try {
    parseBwBin(deps.paths.env);
    serverUrl = normalizedServer(parseServerUrl(deps.paths.env).href);
  } catch (error) {
    deps.err(error instanceof SecretsConfigError ? error.message : 'Invalid configuration');
    return 64;
  }
  const path = sessionFile(deps.paths);
  const bin = parseBwBin(deps.paths.env);
  // staleMs: the same floor as the MCP's (an auto-unlock may hold the lock up to its
  // budget); waitMs: long enough to wait out another process's whole auto-unlock.
  const lock: CrossProcessLock = deps.lock ?? new FileLock({
    path: lockFile(deps.paths), waitMs: AUTO_UNLOCK_LOCK_STALE_MS + 5_000, staleMs: AUTO_UNLOCK_LOCK_STALE_MS,
  });
  // Every non-interactive bw call takes the shared lock file, like the MCP's.
  const run: LockedRun = (args, env) => lock.run(() => deps.runBw(args, env));
  const lockEnv = bwEnvironment(deps.paths.env, null);
  const config = configFile(deps.paths);
  const startWatchdog = deps.startWatchdog ?? startDetachedWatchdog;
  const backend = (): CredentialBackend | null => {
    if (deps.backend !== undefined) return deps.backend;
    return selectBackend(deps.paths.env, deps.paths.platform, deps.toolRunner);
  };

  // An expired session is cleaned up whoever sees it first: file removed, bw locked.
  let current = readSessionFile(path, { uid: deps.paths.uid, now });
  if (current.state === 'locked' && current.reason === 'expired') {
    const expired = await lock.run(async () => {
      if (!expireSessionFile(path, { uid: deps.paths.uid, now })) return false;
      await deps.runBw(['lock'], lockEnv).catch(() => null);
      return true;
    }).catch(() => false);
    if (expired) deps.err('The previous session had expired: its file was removed and bw was locked.');
    current = readSessionFile(path, { uid: deps.paths.uid, now });
  }

  if (options.mode === 'lock') {
    // File and bw together, under the lock; a running watchdog sees the file gone and exits.
    const removed = await lock.run(async () => {
      const gone = deleteSessionFile(path);
      const status = await readBwStatus(deps.runBw, deps.paths.env, null);
      if (status && status.status !== 'unauthenticated') await deps.runBw(['lock'], lockEnv).catch(() => null);
      return gone;
    });
    deps.out(removed ? `Locked: session file removed (${path}); bw locked.` : 'Locked: there was no session file; bw locked.');
    let autoOn = false;
    try { autoOn = loadLocalConfig(config).autoUnlock; } catch { autoOn = false; }
    if (autoOn) {
      deps.out('Auto-unlock is ON: the MCP will unlock again by itself on its next call. To stop that: dumont-secrets-unlock --disable-auto');
    }
    return 0;
  }

  if (options.mode === 'disable-auto') {
    return disableAuto(deps, config, backend);
  }

  // Everything below reads the auto-unlock settings.
  let local;
  try {
    local = loadLocalConfig(config);
  } catch (error) {
    if (options.mode === 'setup-auto' || options.mode === 'auto') {
      deps.err(`${config}: ${error instanceof SecretsConfigError ? error.message : 'unreadable'}. Fix it first.`);
      return 64;
    }
    local = null;
  }

  if (options.mode === 'status') {
    deps.out(`Session file: ${path}`);
    deps.out(`Session: ${describe(current, now())}`);
    // The flag says whether the MCP TRIES; the stored password is what makes it possible.
    let chosen: CredentialBackend | null = null;
    let where = 'no supported credential store on this platform';
    try {
      chosen = backend();
      where = chosen?.description ?? where;
    } catch (error) {
      where = error instanceof CredStoreError ? error.message : where;
    }
    const stored = chosen ? await chosen.exists().catch(() => 'unknown' as const) : 'unknown';
    const flag = !local ? `unknown (${config} is invalid)` : local.autoUnlock ? 'ON (mcp.json)' : 'off (mcp.json)';
    deps.out(`Auto-unlock: ${flag} — stored password: ${stored} (${where})`);
    if (local?.autoUnlock && local.accountEmail) deps.out(`  Automatic login as ${local.accountEmail} when bw is logged out.`);
    const login = readLoginRecord(path);
    if (local?.autoUnlock && login.failedAt !== null) {
      deps.out(`  An automatic login failed at ${new Date(login.failedAt).toISOString()} (${login.reason}); the MCP will not log in again until you run bw login yourself (or dumont-secrets-unlock --auto).`);
    }
    if (stored === 'present') {
      deps.out('  Any program running as you can read that password and unlock your whole vault. Remove it: dumont-secrets-unlock --disable-auto');
    } else if (local?.autoUnlock && stored === 'absent') {
      deps.out('  auto_unlock is on but no password is stored: the MCP cannot unlock. Run --setup-auto again, or --disable-auto.');
    } else if (!local?.autoUnlock) {
      deps.out('  Manual unlock (the default). Opt in with dumont-secrets-unlock --setup-auto (read the risk first).');
    }
    const status = await readBwStatus(run, deps.paths.env, current.state === 'unlocked' ? current.session : null);
    if (!status) {
      deps.out('bw: status could not be read (is the Bitwarden CLI installed? npm i -g @bitwarden/cli)');
      return 1;
    }
    deps.out(`bw: ${status.status || 'unknown'}, server ${status.serverUrl || '(not configured)'}`);
    if (status.serverUrl !== serverUrl) {
      for (const line of SERVER_HINT(serverUrl)) deps.out(line);
      return 1;
    }
    if (current.state === 'unlocked' && status.status === 'unlocked') return 0;
    if (status.status === 'unauthenticated') for (const line of LOGIN_HINT) deps.out(line);
    else if (local?.autoUnlock) deps.out('The MCP unlocks by itself on its next call (auto-unlock is on).');
    else deps.out('Run dumont-secrets-unlock (in a terminal window) to unlock.');
    return 1;
  }

  if (options.mode === 'auto') {
    if (!local?.autoUnlock) {
      deps.err('Auto-unlock is off on this machine. Turn it on with: dumont-secrets-unlock --setup-auto (read the risk first).');
      return 6;
    }
    let chosen: CredentialBackend | null;
    try {
      chosen = backend();
    } catch (error) {
      deps.err(error instanceof CredStoreError ? error.message : 'The credential store could not be chosen.');
      return 5;
    }
    const result = await performAutoUnlock({
      paths: deps.paths, serverUrl, sessionFile: path, lockFile: lockFile(deps.paths), bin, lock, backend: chosen,
      runBw: deps.runBw, accountEmail: local.accountEmail, ttlMs: options.ttlMs, startWatchdog, now,
    }, { force: options.force, byPerson: true });
    if (result.ok) {
      deps.out(result.mode === 'reused'
        ? `Already unlocked until ${result.expiresAt.toISOString()}.`
        : `Unlocked until ${result.expiresAt.toISOString()} (auto-unlock${result.mode === 'login' ? ', after logging in again' : ''}).`);
      return 0;
    }
    deps.err(autoUnlockFailureText(result.reason));
    if (result.reason === 'server_mismatch') return 2;
    if (['unauthenticated', 'login_failed', 'login_blocked', 'login_backoff', 'account_mismatch'].includes(result.reason)) return 3;
    if (result.reason === 'backend_unavailable') return 5;
    return 1;
  }

  // Unlock (manual) and --setup-auto both need bw logged in to the right server.
  const before = await readBwStatus(run, deps.paths.env, current.state === 'unlocked' ? current.session : null);
  if (!before) {
    deps.err('Could not run `bw status`. Install the Bitwarden CLI (npm i -g @bitwarden/cli) and make sure `bw` is on PATH.');
    return 1;
  }
  if (before.serverUrl !== serverUrl) {
    for (const line of SERVER_HINT(serverUrl)) deps.err(line);
    return 2;
  }
  if (before.status === 'unauthenticated') {
    for (const line of LOGIN_HINT) deps.err(line);
    return 3;
  }
  if (options.mode === 'setup-auto') {
    return setupAuto(deps, {
      serverUrl, path, bin, lock, config, startWatchdog, now, ttlMs: options.ttlMs, email: before.userEmail, backend,
      wasOn: local?.autoUnlock === true,
    });
  }
  if (current.state === 'unlocked' && before.status === 'unlocked' && !options.force) {
    deps.out(`Already ${describe(current, now())}. Use --force to unlock again, --lock to lock.`);
    return 0;
  }
  if (!deps.stdinIsTty && deps.paths.env[ALLOW_NON_TTY_ENV] !== '1') {
    deps.err('dumont-secrets-unlock needs an interactive terminal: bw asks for your master password there.');
    deps.err('Open a separate terminal window and run: dumont-secrets-unlock');
    return 4;
  }
  if (current.state === 'locked' && current.reason !== 'missing' && current.reason !== 'expired') {
    // Too open, someone else's, or corrupt: never reuse it; replace it.
    try { deleteSessionFile(path); } catch { /* the write below reports the problem */ }
  }

  deps.err(`Unlocking your vault on ${serverUrl}: bw will ask for your master password.`);
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(deps.paths.env)) {
    if (typeof value === 'string' && name !== 'BW_SESSION' && name !== 'BW_NOINTERACTION' && name !== ALLOW_NON_TTY_ENV) env[name] = value;
  }
  let unlocked: BwResult;
  try {
    // Not under the lock file: it waits on a person typing.
    unlocked = await deps.interactiveUnlock(env);
  } catch {
    deps.err('Could not start bw.');
    return 1;
  }
  const key = unlocked.stdout.trim();
  if (unlocked.code !== 0 || !SESSION_KEY_PATTERN.test(key)) {
    // bw's own message went to this terminal (stderr); stdout is not echoed: it could be anything.
    deps.err('Unlock failed; nothing was stored.');
    return 1;
  }
  const after = await readBwStatus(run, deps.paths.env, key);
  if (!after || after.status !== 'unlocked' || after.serverUrl !== serverUrl) {
    deps.err('bw printed a session key but does not accept it as unlocked; nothing was stored.');
    return 1;
  }
  let expiresAt: Date;
  try {
    expiresAt = writeSessionFile(path, key, options.ttlMs, { uid: deps.paths.uid, now });
  } catch {
    deps.err(`Could not write the session file at ${path}; nothing was stored.`);
    return 1;
  }
  let watchdog = true;
  try {
    const watchdogEnv = { ...lockEnv };
    const poll = deps.paths.env.DUMONT_SECRETS_WATCHDOG_POLL_MS;
    if (poll) watchdogEnv.DUMONT_SECRETS_WATCHDOG_POLL_MS = poll;
    startWatchdog({
      sessionFile: path, fingerprint: sessionFingerprint(key), lockFile: lockFile(deps.paths), bin, env: watchdogEnv,
    });
  } catch {
    watchdog = false;
  }
  deps.out(`Unlocked until ${expiresAt.toISOString()}. The Dumont Secrets MCP can now use your vault.`);
  deps.out(watchdog
    ? 'A background watchdog runs bw lock at that time. Lock early with: dumont-secrets-unlock --lock'
    : 'WARNING: the expiry watchdog could not start; run dumont-secrets-unlock --lock when you are done.');
  deps.out('While unlocked, any program running as you (the agent\'s shell included) can use your whole vault through bw.');
  return 0;
}

interface SetupContext {
  readonly serverUrl: string;
  readonly path: string;
  readonly bin: string;
  readonly lock: CrossProcessLock;
  readonly config: string;
  readonly startWatchdog: (start: WatchdogStart) => void;
  readonly now: () => number;
  readonly ttlMs: number;
  readonly email: string | null;
  readonly backend: () => CredentialBackend | null;
  /** auto_unlock was already true before this setup. */
  readonly wasOn: boolean;
}

/** Remove the stored password; on failure say it is STILL stored and how to remove it by hand. */
async function removeOrExplain(deps: UnlockDependencies, backend: CredentialBackend): Promise<'removed' | 'none' | 'failed'> {
  try {
    return (await backend.remove()) ? 'removed' : 'none';
  } catch (error) {
    deps.err(`Could not remove the stored password: ${error instanceof CredStoreError ? error.message : 'the tool failed'}.`);
    deps.err(`The password is STILL STORED in ${backend.description}.`);
    deps.err(`Remove it by hand: ${backend.manualRemoval}`);
    return 'failed';
  }
}

/** After a failed setup: if auto_unlock was already on, it must not stay on without a working password. */
function turnFlagOff(deps: UnlockDependencies, context: SetupContext): void {
  if (!context.wasOn) return;
  try {
    updateLocalConfig(context.config, record => { record.auto_unlock = false; });
    deps.err(`auto_unlock was on; it is now set to false in ${context.config}.`);
  } catch {
    deps.err(`auto_unlock is still true in ${context.config} but no working password is stored; set it to false there.`);
  }
}

async function setupAuto(deps: UnlockDependencies, context: SetupContext): Promise<number> {
  if (!deps.stdinIsTty && deps.paths.env[ALLOW_NON_TTY_ENV] !== '1') {
    deps.err('dumont-secrets-unlock --setup-auto needs an interactive terminal: you type your master password there.');
    deps.err('Open a separate terminal window and run: dumont-secrets-unlock --setup-auto');
    return 4;
  }
  if (!context.email) {
    deps.err('bw status does not say which account is logged in; nothing was stored.');
    return 1;
  }
  let backend: CredentialBackend | null;
  try {
    backend = context.backend();
  } catch (error) {
    deps.err(error instanceof CredStoreError ? error.message : 'The credential store could not be chosen.');
    return 5;
  }
  if (!backend) {
    deps.err('Auto-unlock is not supported on this platform (Windows DPAPI under WSL, macOS Keychain, Linux Secret Service only).');
    deps.err('Nothing was stored; auto-unlock stays off. There is no plaintext-file fallback.');
    return 5;
  }
  const missing = await backend.unavailable();
  if (missing) {
    deps.err(missing);
    deps.err('Nothing was stored; auto-unlock stays off. There is no plaintext-file fallback.');
    return 5;
  }
  for (const line of RISK_NOTICE) deps.err(line);
  deps.err(`Password store: ${backend.description}. Account: ${context.email}.`);
  let stored: boolean;
  try {
    stored = await backend.store({
      promptHidden: deps.promptHidden ?? (prompt => promptHiddenLine(prompt)),
      err: deps.err,
    });
  } catch {
    stored = false;
  }
  if (!stored) {
    deps.err('The password was not stored; auto-unlock stays off.');
    return 1;
  }
  deps.err('Stored. Checking that it unlocks bw...');
  const result = await performAutoUnlock({
    paths: deps.paths, serverUrl: context.serverUrl, sessionFile: context.path, lockFile: lockFile(deps.paths), bin: context.bin,
    lock: context.lock, backend, runBw: deps.runBw, accountEmail: context.email, ttlMs: context.ttlMs,
    startWatchdog: context.startWatchdog, now: context.now,
  }, { force: true, byPerson: true });
  if (!result.ok) {
    deps.err(`The stored password did not unlock bw: ${autoUnlockFailureText(result.reason)}`);
    const removed = await removeOrExplain(deps, backend);
    if (removed !== 'failed') deps.err('It was removed again.');
    turnFlagOff(deps, context);
    deps.err(context.wasOn ? 'Auto-unlock is now off.' : 'Auto-unlock stays off.');
    return 1;
  }
  try {
    updateLocalConfig(context.config, record => {
      record.auto_unlock = true;
      record.account_email = context.email;
    });
  } catch (error) {
    deps.err(`Could not update ${context.config}: ${error instanceof SecretsConfigError ? error.message : 'write failed'}.`);
    const removed = await removeOrExplain(deps, backend);
    if (removed !== 'failed') deps.err('The stored password was removed again.');
    deps.err('Auto-unlock was not turned on.');
    return 1;
  }
  deps.out(`Auto-unlock is ON for ${context.email} on this machine (${context.config}).`);
  deps.out(`Unlocked until ${result.expiresAt.toISOString()}. When a session expires or is locked, the MCP unlocks again by itself.`);
  deps.out('Any program running as you can now unlock your whole vault. Turn it off with: dumont-secrets-unlock --disable-auto');
  return 0;
}

async function disableAuto(deps: UnlockDependencies, config: string, backend: () => CredentialBackend | null): Promise<number> {
  let code = 0;
  let chosen: CredentialBackend | null = null;
  try {
    chosen = backend();
  } catch (error) {
    deps.err(error instanceof CredStoreError ? error.message : 'The credential store could not be chosen.');
    code = 1;
  }
  let stillStored = code !== 0;
  if (chosen) {
    const removed = await removeOrExplain(deps, chosen);
    if (removed === 'failed') {
      stillStored = true;
      code = 1;
    } else {
      deps.out(removed === 'removed' ? `Stored password removed from ${chosen.description}.` : `No stored password in ${chosen.description}.`);
    }
  }
  try {
    // No config file means auto-unlock was never on: nothing to write.
    if (pathExists(config)) {
      updateLocalConfig(config, record => {
        record.auto_unlock = false;
        delete record.account_email;
      });
    }
    if (stillStored) {
      deps.err('auto_unlock is set to false, so the MCP will not use the password; but the password itself is still');
      deps.err('stored, and any program running as you can still read it. Auto-unlock is NOT fully off until it is removed.');
    } else {
      deps.out('Auto-unlock is OFF. The current session (if any) stays until it expires; end it now with dumont-secrets-unlock --lock.');
    }
  } catch (error) {
    deps.err(`Could not update ${config}: ${error instanceof SecretsConfigError ? error.message : 'write failed'}. Set "auto_unlock": false there by hand.`);
    code = 1;
  }
  return code;
}

function pathExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

function defaultRunBw(bin: string) {
  return (args: readonly string[], env: Record<string, string>, timeoutMs?: number) => new Promise<BwResult>((resolve, reject) => {
    const timeout = timeoutMs ?? (args[0] === 'unlock' || args[0] === 'login' ? UNLOCK_TIMEOUT_MS : STATUS_TIMEOUT_MS);
    const child = execFile(bin, [...args], { env, timeout, killSignal: 'SIGKILL', shell: false, encoding: 'utf8', maxBuffer: 1024 * 1024 },
      (error, stdout) => {
        const failure = error as (NodeJS.ErrnoException & { code?: unknown }) | null;
        if (failure && typeof failure.code === 'string') { reject(failure); return; }
        resolve({ code: failure ? (typeof failure.code === 'number' ? failure.code : 1) : 0, stdout: typeof stdout === 'string' ? stdout : '' });
      });
    child.stdin?.on('error', () => undefined);
    child.stdin?.end();
  });
}

function defaultInteractiveUnlock(bin: string) {
  return (env: Record<string, string>) => new Promise<BwResult>((resolve, reject) => {
    // stdin and stderr are this terminal: bw prompts on stderr and reads the
    // password itself. Only stdout (the --raw session key) comes back here.
    const child = spawn(bin, ['unlock', '--raw'], { env, stdio: ['inherit', 'pipe', 'inherit'], shell: false });
    const chunks: Buffer[] = [];
    let size = 0;
    child.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_SESSION_OUTPUT) chunks.push(chunk);
    });
    child.on('error', reject);
    child.on('close', code => {
      resolve({ code: size > MAX_SESSION_OUTPUT ? 1 : code, stdout: Buffer.concat(chunks).toString('utf8') });
    });
  });
}

if (isMainModule(import.meta.url)) {
  const paths = currentPathEnvironment();
  let bin = 'bw';
  try {
    bin = parseBwBin(paths.env);
  } catch {
    // runUnlock reports the configuration error.
  }
  runUnlock(process.argv.slice(2), {
    paths,
    runBw: defaultRunBw(bin),
    interactiveUnlock: defaultInteractiveUnlock(bin),
    stdinIsTty: Boolean(process.stdin.isTTY),
    out: line => { process.stdout.write(`${line}\n`); },
    err: line => { process.stderr.write(`${line}\n`); },
  }).then(code => { process.exitCode = code; }, () => {
    process.stderr.write('dumont-secrets-unlock failed unexpectedly; nothing was stored.\n');
    process.exitCode = 1;
  });
}
