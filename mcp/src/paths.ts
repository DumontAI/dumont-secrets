import { statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';

/**
 * Per-user locations. Linux (WSL included) and macOS only.
 *
 *   session  Linux: $XDG_RUNTIME_DIR/dumont-secrets, else /run/user/<uid>/dumont-secrets
 *                   (both tmpfs, gone at logout/reboot), else ~/.cache/dumont-secrets
 *            macOS: ~/Library/Caches/dumont-secrets
 *   config   $XDG_CONFIG_HOME/dumont-secrets/mcp.json, else ~/.config/dumont-secrets/mcp.json
 *   audit    Linux: $XDG_STATE_HOME/dumont-secrets/audit.log, else ~/.local/state/dumont-secrets/audit.log
 *            macOS: ~/Library/Logs/dumont-secrets/audit.log
 *
 * Every one of them can be overridden by an environment variable; the MCP and
 * the unlock helper resolve the session directory with this same function.
 */
export interface PathEnvironment {
  readonly env: NodeJS.ProcessEnv;
  readonly platform: NodeJS.Platform;
  readonly home: string;
  readonly uid: number;
  /** True when `path` is a directory owned by `uid`. */
  readonly ownedDir: (path: string, uid: number) => boolean;
}

function defaultOwnedDir(path: string, uid: number): boolean {
  try {
    const info = statSync(path);
    return info.isDirectory() && info.uid === uid;
  } catch {
    return false;
  }
}

export function currentPathEnvironment(env: NodeJS.ProcessEnv = process.env): PathEnvironment {
  return {
    env,
    platform: process.platform,
    home: env.HOME && isAbsolute(env.HOME) ? env.HOME : homedir(),
    uid: process.getuid?.() ?? -1,
    ownedDir: defaultOwnedDir,
  };
}

function absoluteEnv(env: NodeJS.ProcessEnv, name: string): string | null {
  const value = env[name]?.trim();
  return value && isAbsolute(value) ? value : null;
}

export function sessionDir(p: PathEnvironment): string {
  const override = absoluteEnv(p.env, 'DUMONT_SECRETS_SESSION_DIR');
  if (override) return override;
  if (p.platform === 'darwin') return join(p.home, 'Library', 'Caches', 'dumont-secrets');
  const runtime = absoluteEnv(p.env, 'XDG_RUNTIME_DIR');
  if (runtime && p.ownedDir(runtime, p.uid)) return join(runtime, 'dumont-secrets');
  const runUser = `/run/user/${p.uid}`;
  if (p.uid >= 0 && p.ownedDir(runUser, p.uid)) return join(runUser, 'dumont-secrets');
  return join(p.home, '.cache', 'dumont-secrets');
}

export function sessionFile(p: PathEnvironment): string {
  return join(sessionDir(p), 'session.json');
}

/** Cross-process lock around each `bw` run: two MCP processes (two sessions) must not run bw at once. */
export function lockFile(p: PathEnvironment): string {
  return join(sessionDir(p), 'bw.lock');
}

export function configFile(p: PathEnvironment): string {
  const override = absoluteEnv(p.env, 'DUMONT_SECRETS_MCP_CONFIG');
  if (override) return override;
  const base = absoluteEnv(p.env, 'XDG_CONFIG_HOME') ?? join(p.home, '.config');
  return join(base, 'dumont-secrets', 'mcp.json');
}

export function auditFile(p: PathEnvironment): string {
  const override = absoluteEnv(p.env, 'DUMONT_SECRETS_AUDIT_LOG');
  if (override) return override;
  if (p.platform === 'darwin') return join(p.home, 'Library', 'Logs', 'dumont-secrets', 'audit.log');
  const base = absoluteEnv(p.env, 'XDG_STATE_HOME') ?? join(p.home, '.local', 'state');
  return join(base, 'dumont-secrets', 'audit.log');
}
