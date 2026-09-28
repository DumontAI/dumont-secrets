#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { fileAuditSink, RateLimiter } from './audit.js';
import { BwVault } from './bw.js';
import { loadSecretsConfig } from './config.js';
import { FileLock } from './lock.js';
import { isMainModule } from './runtime.js';
import { SecretsService } from './secrets.js';
import { expireSessionFile, readSessionFile } from './session.js';
import { createSecretsServer, SERVER_VERSION } from './tools.js';
import { SessionExpired, sessionLocked, type SecretsConfig } from './types.js';

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

export function createLocalServer(config: SecretsConfig, baseEnv: NodeJS.ProcessEnv = process.env) {
  const vault = new BwVault(config.bw, {
    baseEnv,
    session: sessionSourceFor(config),
    expire: () => expireSessionFile(config.sessionFile),
    lock: new FileLock({ path: config.lockFile, waitMs: config.bw.timeoutMs + 5000, staleMs: config.bw.timeoutMs * 2 + 5000 }),
    log,
  });
  const service = new SecretsService({ vault, scope: config.scope, log });
  return createSecretsServer({
    allowSet: config.allowSet,
    allowRotate: config.allowRotate,
    service,
    limiter: new RateLimiter(config.rateLimitPerMinute, config.writeRateLimitPerMinute),
    audit: fileAuditSink(config.auditFile, { log }),
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
      `rotate=${config.allowRotate ? 'enabled' : 'disabled'} set=${config.allowSet ? 'enabled' : 'disabled'}`,
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
