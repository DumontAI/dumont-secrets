#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { fileAuditSink, RateLimiter } from './audit.js';
import { AutoUnlocker, performAutoUnlock, sessionTtl, type AutoUnlockAttempt, type BwCall } from './autounlock.js';
import { BwVault, execFileRunner, normalizedServer, serverMismatch, type BwRunner } from './bw.js';
import { loadLocalConfig, loadSecretsConfig } from './config.js';
import { selectBackend, type CredentialBackend, type ToolRunner } from './credstore.js';
import { FileLock } from './lock.js';
import { currentPathEnvironment, type PathEnvironment } from './paths.js';
import { isMainModule } from './runtime.js';
import { SecretsService } from './secrets.js';
import { expireSessionFile, readSessionFile } from './session.js';
import { createSecretsServer, SERVER_VERSION } from './tools.js';
import { autoLoginFailed, autoUnlockFailed, SecretsError, SessionExpired, sessionLocked, type SecretsConfig } from './types.js';
import { startDetachedWatchdog, type WatchdogStart } from './watchdog.js';

// Local stdio MCP: started by Claude Code / Dumont Code as the user, speaks MCP
// on stdin/stdout, writes only fixed operational lines to stderr (the client's
// MCP log). stdout carries protocol messages only.

function log(line: string): void {
  process.stderr.write(`${line}\n`);
}

/** Read the session file for every operation; log why it is locked (never the key). */
export function sessionSourceFor(config: SecretsConfig, logLine: (line: string) => void = log): () => string {
  let lastReason: string | null = null;
  return () => {
    const state = readSessionFile(config.sessionFile);
    if (state.state === 'unlocked') {
      lastReason = null;
      return state.session;
    }
    if (state.reason !== lastReason) {
      lastReason = state.reason;
      logLine(`dumont-secrets-mcp session outcome=locked reason=${state.reason}`);
    }
    throw state.reason === 'expired' ? new SessionExpired() : sessionLocked();
  };
}

/** What an auto-unlock that did not work answers instead of the plain SESSION_LOCKED. */
export function autoUnlockError(attempt: AutoUnlockAttempt, locked: SecretsError, config: SecretsConfig): SecretsError | null {
  if (attempt.ok) return null;
  if (attempt.reason === 'not_enabled') return locked;
  const cause = attempt.reason === 'backoff' ? attempt.cause : attempt.reason;
  if (cause === 'server_mismatch') return serverMismatch(config.bw.serverUrl);
  if (cause === 'login_failed' || cause === 'unauthenticated') return autoLoginFailed();
  return autoUnlockFailed();
}

export interface LocalServerOverrides {
  /** bw runner (tests: the fake bw in-process). */
  readonly runner?: BwRunner;
  /** Credential store (tests: fake tools); default: the platform's, chosen on first use. */
  readonly backend?: CredentialBackend | null;
  readonly toolRunner?: ToolRunner;
  readonly startWatchdog?: (start: WatchdogStart) => void;
  readonly paths?: PathEnvironment;
  readonly log?: (line: string) => void;
  readonly now?: () => number;
}

export function createLocalServer(config: SecretsConfig, baseEnv: NodeJS.ProcessEnv = process.env, overrides: LocalServerOverrides = {}) {
  const logLine = overrides.log ?? log;
  const lock = new FileLock({ path: config.lockFile, waitMs: config.bw.timeoutMs + 5000, staleMs: config.bw.timeoutMs * 2 + 5000 });
  const runner = overrides.runner ?? execFileRunner(config.bw.bin);
  const paths = overrides.paths ?? currentPathEnvironment(baseEnv);
  const runBw: BwCall = async (args, env) => {
    const result = await runner(args, { env, timeoutMs: config.bw.timeoutMs });
    return { code: result.timedOut ? null : result.code, stdout: result.stdout };
  };
  let backend: CredentialBackend | null | undefined = overrides.backend;
  const unlocker = new AutoUnlocker({
    // Re-read on every attempt: --setup-auto / --disable-auto need no client restart.
    settings: () => {
      const local = loadLocalConfig(config.configFile);
      return { enabled: local.autoUnlock, accountEmail: local.accountEmail };
    },
    perform: accountEmail => {
      if (backend === undefined) {
        try {
          backend = selectBackend(baseEnv, paths.platform, overrides.toolRunner);
        } catch {
          backend = null;
        }
      }
      return performAutoUnlock({
        paths,
        serverUrl: normalizedServer(config.bw.serverUrl.href),
        sessionFile: config.sessionFile,
        lockFile: config.lockFile,
        bin: config.bw.bin,
        lock,
        backend,
        runBw,
        accountEmail,
        ttlMs: sessionTtl(baseEnv),
        startWatchdog: overrides.startWatchdog ?? startDetachedWatchdog,
        ...(overrides.now ? { now: overrides.now } : {}),
      });
    },
    log: logLine,
    ...(overrides.now ? { now: overrides.now } : {}),
  });
  const vault = new BwVault(config.bw, {
    baseEnv,
    runner,
    session: sessionSourceFor(config, logLine),
    expire: () => expireSessionFile(config.sessionFile),
    lock,
    log: logLine,
    recover: async locked => autoUnlockError(await unlocker.unlock(), locked, config),
    ...(overrides.now ? { now: overrides.now } : {}),
  });
  const service = new SecretsService({ vault, scope: config.scope, log: logLine });
  return createSecretsServer({
    allowSet: config.allowSet,
    allowRotate: config.allowRotate,
    service,
    limiter: new RateLimiter(config.rateLimitPerMinute, config.writeRateLimitPerMinute),
    audit: fileAuditSink(config.auditFile, { log: logLine }),
  });
}

export async function startStdio(): Promise<void> {
  const config = loadSecretsConfig();
  const server = createLocalServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log(
    `dumont-secrets-mcp ready version=${SERVER_VERSION} server=${config.bw.serverUrl.origin} ` +
      `writes=${config.scope.writeCollection === null ? 'disabled' : 'enabled'} ` +
      `get=${config.scope.valueCollections === null ? 'disabled' : 'enabled'} ` +
      `rotate=${config.allowRotate ? 'enabled' : 'disabled'} set=${config.allowSet ? 'enabled' : 'disabled'} ` +
      `auto_unlock=${config.autoUnlock ? 'on' : 'off'}`,
  );
}

if (isMainModule(import.meta.url)) {
  // Never let an unexpected rejection print its object (it could hold bw output).
  process.on('unhandledRejection', () => {
    log('dumont-secrets-mcp outcome=unhandled_rejection');
    process.exit(1);
  });
  startStdio().catch(error => {
    // Config errors carry field names only (see config.ts); anything else gets a fixed line.
    const message = error instanceof Error && error.name === 'SecretsConfigError'
      ? `dumont-secrets-mcp config error: ${error.message}`
      : 'dumont-secrets-mcp failed to start';
    log(message);
    process.exitCode = 1;
  });
}
