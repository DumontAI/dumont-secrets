#!/usr/bin/env node
import { execFile, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { bwEnvironment, normalizedServer, type CrossProcessLock } from './bw.js';
import { parseBwBin, parseServerUrl, SecretsConfigError } from './config.js';
import { FileLock } from './lock.js';
import { currentPathEnvironment, lockFile, sessionFile, type PathEnvironment } from './paths.js';
import { isMainModule } from './runtime.js';
import {
  deleteSessionFile, expireSessionFile, readSessionFile, SESSION_KEY_PATTERN, sessionFingerprint, writeSessionFile, type SessionState,
} from './session.js';

// dumont-secrets-unlock: runs in YOUR terminal. It asks your own `bw` to unlock
// (`bw unlock --raw`, with this terminal handed straight to bw, so you type the
// master password into bw itself: this program never reads it, and it is never
// in argv, the environment or shell history). bw prints the session key on
// stdout; that one line is captured and written to the 0600 session file the
// MCP reads, with an expiry, and starts a detached watchdog that locks bw at that
// expiry. It never prints the key.

export const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000;
const MIN_TTL_MS = 5 * 60 * 1000;
const MAX_TTL_MS = 12 * 60 * 60 * 1000;
/** Tests only: lets the helper run with a pipe instead of a terminal. */
export const ALLOW_NON_TTY_ENV = 'DUMONT_SECRETS_UNLOCK_ALLOW_NON_TTY';
const STATUS_TIMEOUT_MS = 30_000;
const MAX_SESSION_OUTPUT = 4096;

export const USAGE = `Usage: dumont-secrets-unlock [--ttl <duration>] [--force]
       dumont-secrets-unlock --status
       dumont-secrets-unlock --lock

Unlocks your own Bitwarden vault for the Dumont Secrets MCP. Run it in a real
terminal window: bw asks for your master password there, and this program never
reads it. It stores only the session key bw prints, in a file only you can read,
until it expires (default 2h, --ttl 5m..12h, or DUMONT_SECRETS_SESSION_TTL); a
background watchdog runs bw lock at that time.

  --status   say whether the MCP can use the vault, and until when (never the key)
  --lock     delete the session file and run bw lock
  --force    unlock again even when a valid session exists
  --ttl      how long the session is valid, e.g. 1h, 90m

While unlocked, any program running as you (the agent's shell included) can use
your whole vault through bw, personal items included; the MCP tools themselves
never show personal items. Unlocking replaces the session of any earlier
bw unlock (an exported BW_SESSION stops working); --lock and expiry also lock the
bw you use interactively.

Before the first unlock: bw config server https://secret.getdumont.ai, then
bw login <your email> (email + master password; 2FA asked by bw), or
bw login --sso (Dumont SSO; not yet tested with this vault).`;

export interface BwResult {
  readonly code: number | null;
  readonly stdout: string;
}

export interface WatchdogStart {
  readonly sessionFile: string;
  readonly fingerprint: string;
  readonly lockFile: string;
  readonly bin: string;
  readonly env: Record<string, string>;
}

export interface UnlockDependencies {
  readonly paths: PathEnvironment;
  /** Shared bw lock file (the MCP's). Defaults to a FileLock on the per-user lock path. */
  readonly lock?: CrossProcessLock;
  /** Starts the detached expiry watchdog. */
  readonly startWatchdog?: (start: WatchdogStart) => void;
  /** Non-interactive bw call (status, lock). */
  readonly runBw: (args: readonly string[], env: Record<string, string>) => Promise<BwResult>;
  /** `bw unlock --raw` with the terminal's stdin/stderr handed to bw; only stdout is captured. */
  readonly interactiveUnlock: (env: Record<string, string>) => Promise<BwResult>;
  readonly stdinIsTty: boolean;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  readonly now?: () => number;
}

export function parseDuration(raw: string): number | null {
  const match = /^(\d{1,4})\s*(m|min|h)?$/i.exec(raw.trim());
  if (!match) return null;
  const amount = Number(match[1]);
  const unit = (match[2] ?? 'h').toLowerCase();
  const ms = unit === 'h' ? amount * 3_600_000 : amount * 60_000;
  return ms >= MIN_TTL_MS && ms <= MAX_TTL_MS ? ms : null;
}

interface Options {
  readonly mode: 'unlock' | 'status' | 'lock' | 'help';
  readonly force: boolean;
  readonly ttlMs: number;
}

function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv): Options | string {
  let mode: Options['mode'] = 'unlock';
  let force = false;
  let ttlRaw = env.DUMONT_SECRETS_SESSION_TTL?.trim() || '';
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === '--status') mode = 'status';
    else if (arg === '--lock') mode = 'lock';
    else if (arg === '--help' || arg === '-h') mode = 'help';
    else if (arg === '--force') force = true;
    else if (arg === '--ttl') ttlRaw = argv[++index] ?? '';
    else if (arg.startsWith('--ttl=')) ttlRaw = arg.slice('--ttl='.length);
    else return `Unknown argument: ${arg.slice(0, 40)}`;
  }
  const ttlMs = ttlRaw ? parseDuration(ttlRaw) : DEFAULT_TTL_MS;
  if (ttlMs === null) return 'The session TTL must be between 5m and 12h (e.g. 2h, 90m)';
  return { mode, force, ttlMs };
}

interface BwStatus {
  readonly status: string;
  readonly serverUrl: string;
}

type LockedRun = (args: readonly string[], env: Record<string, string>) => Promise<BwResult>;

async function bwStatus(run: LockedRun, env: NodeJS.ProcessEnv, session: string | null): Promise<BwStatus | null> {
  let result: BwResult;
  try {
    result = await run(['status'], bwEnvironment(env, session));
  } catch {
    return null;
  }
  const text = result.stdout.trim();
  if (result.code !== 0 || !text.startsWith('{')) return null;
  try {
    const record = JSON.parse(text) as Record<string, unknown>;
    return {
      status: typeof record.status === 'string' ? record.status : '',
      serverUrl: normalizedServer(record.serverUrl),
    };
  } catch {
    return null;
  }
}

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
  const lock: CrossProcessLock = deps.lock ?? new FileLock({ path: lockFile(deps.paths), waitMs: 35_000, staleMs: 65_000 });
  // Every non-interactive bw call takes the shared lock file, like the MCP's.
  const run: LockedRun = (args, env) => lock.run(() => deps.runBw(args, env));
  const lockEnv = bwEnvironment(deps.paths.env, null);

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
      const status = await bwStatusWith(deps.runBw, deps.paths.env, null);
      if (status && status.status !== 'unauthenticated') await deps.runBw(['lock'], lockEnv).catch(() => null);
      return gone;
    });
    deps.out(removed ? `Locked: session file removed (${path}); bw locked.` : 'Locked: there was no session file; bw locked.');
    return 0;
  }

  if (options.mode === 'status') {
    deps.out(`Session file: ${path}`);
    deps.out(`Session: ${describe(current, now())}`);
    const status = await bwStatus(run, deps.paths.env, current.state === 'unlocked' ? current.session : null);
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
    else deps.out('Run dumont-secrets-unlock (in a terminal window) to unlock.');
    return 1;
  }

  // Unlock.
  const before = await bwStatus(run, deps.paths.env, current.state === 'unlocked' ? current.session : null);
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
  const after = await bwStatus(run, deps.paths.env, key);
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
    (deps.startWatchdog ?? startDetachedWatchdog)({
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

async function bwStatusWith(runBw: UnlockDependencies['runBw'], env: NodeJS.ProcessEnv, session: string | null) {
  return bwStatus(runBw, env, session);
}

/** A detached node process, its own session/process group (no setsid binary needed), unref'd. */
export function startDetachedWatchdog(start: WatchdogStart): void {
  const script = fileURLToPath(new URL('./watchdog.js', import.meta.url));
  const child = spawn(process.execPath, [script, start.sessionFile, start.fingerprint, start.lockFile, start.bin], {
    detached: true,
    stdio: 'ignore',
    env: start.env,
    shell: false,
  });
  child.on('error', () => undefined);
  child.unref();
}

function defaultRunBw(bin: string) {
  return (args: readonly string[], env: Record<string, string>) => new Promise<BwResult>((resolve, reject) => {
    const child = execFile(bin, [...args], { env, timeout: STATUS_TIMEOUT_MS, killSignal: 'SIGKILL', shell: false, encoding: 'utf8', maxBuffer: 1024 * 1024 },
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
