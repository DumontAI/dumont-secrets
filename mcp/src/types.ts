/**
 * The Bitwarden CLI as this process drives it. Everything identity-related is
 * the user's own: their `bw` data directory (BITWARDENCLI_APPDATA_DIR, or the
 * CLI default under their HOME), their login, their unlock.
 */
export interface BwConfig {
  /** Path (or PATH-resolved name) of the Bitwarden CLI. Tests point it at a fake. */
  readonly bin: string;
  /** The server the user's `bw` must already be configured for (`bw config server`). */
  readonly serverUrl: URL;
  readonly timeoutMs: number;
  /** Floor between two read-side `bw sync` runs, in seconds. */
  readonly syncMaxAgeSeconds: number;
}

/**
 * The "what": which organizations and collections this MCP may see, from the
 * local config file. Personal-vault items are never in scope, whatever this says.
 */
export interface ScopeConfig {
  /** Organization names or ids; null means every organization the user belongs to. */
  readonly organizations: readonly string[] | null;
  /** Collection names or ids whose items are visible; null means every collection of the organizations in scope. */
  readonly readCollections: readonly string[] | null;
  /** The one collection writes go to (name or id); null disables writes. */
  readonly writeCollection: string | null;
  /**
   * Collections (names or ids) whose VALUES secrets_get_secret may return; null
   * disables secrets_get_secret. Listing names and keys is not affected.
   */
  readonly valueCollections: readonly string[] | null;
}

export interface SecretsConfig {
  readonly bw: BwConfig;
  readonly scope: ScopeConfig;
  /** Where the local scope config was read from (or would be), for messages only. */
  readonly configFile: string;
  readonly sessionFile: string;
  readonly auditFile: string;
  readonly lockFile: string;
  readonly allowSet: boolean;
  /** replace_existing (rotating an existing key) is refused unless this is true. */
  readonly allowRotate: boolean;
  /** auto_unlock from the local config when the MCP started (the MCP re-reads it before each attempt). */
  readonly autoUnlock: boolean;
  readonly accountEmail: string | null;
  readonly rateLimitPerMinute: number;
  readonly writeRateLimitPerMinute: number;
}

/**
 * Errors surfaced to MCP callers. `message` is always a fixed, locally authored
 * sentence: never bw output, never a value, never user input echoed back.
 */
export class SecretsError extends Error {
  constructor(
    public readonly code: SecretsErrorCode,
    message: string,
    public readonly retryable = false,
  ) {
    super(message);
    this.name = 'SecretsError';
  }
}

export type SecretsErrorCode =
  | 'SESSION_LOCKED'
  | 'VAULT_SERVER_MISMATCH'
  | 'FORBIDDEN'
  | 'WRITE_DISABLED'
  | 'GET_DISABLED'
  | 'ROTATE_DISABLED'
  | 'SET_DISABLED'
  | 'RATE_LIMITED'
  | 'INVALID_ARGUMENT'
  | 'ITEM_NOT_FOUND'
  | 'KEY_NOT_FOUND'
  | 'AMBIGUOUS_ITEM'
  | 'AMBIGUOUS_KEY'
  | 'KEY_CONFLICT'
  | 'KEY_EXISTS'
  | 'VAULT_CONFLICT'
  | 'COLLECTION_NOT_ALLOWED'
  | 'SCOPE_UNRESOLVED'
  | 'VAULT_UNAVAILABLE'
  | 'VAULT_ERROR'
  | 'OUTPUT_GUARD'
  | 'INTERNAL_ERROR';

/** The one message for every locked / missing / expired / unusable session. */
export const SESSION_LOCKED_MESSAGE =
  'Vault locked. Ask the user to run dumont-secrets-unlock in a separate terminal window ' +
  '(it needs an interactive terminal), then retry.';

export function sessionLocked(): SecretsError {
  return new SecretsError('SESSION_LOCKED', SESSION_LOCKED_MESSAGE, true);
}

/** Auto-unlock is on but did not work (password store, wrong stored password, bw): a person has to look. */
export const AUTO_UNLOCK_FAILED_MESSAGE =
  'Vault locked and automatic unlock failed. Ask the user to run dumont-secrets-unlock --status in a separate ' +
  'terminal window to see why (or dumont-secrets-unlock to unlock by hand), then retry. Do not run it yourself.';

/** Auto-unlock is on, bw is logged out, and logging in again needs a person (2FA) or failed. */
export const AUTO_LOGIN_FAILED_MESSAGE =
  'Vault locked: the Bitwarden CLI is logged out and automatic login did not complete (two-step login needs a ' +
  'person). Ask the user to run bw login <their email> once in a separate terminal window, then retry. Do not run it yourself.';

export function autoUnlockFailed(): SecretsError {
  return new SecretsError('SESSION_LOCKED', AUTO_UNLOCK_FAILED_MESSAGE, true);
}

export function autoLoginFailed(): SecretsError {
  return new SecretsError('SESSION_LOCKED', AUTO_LOGIN_FAILED_MESSAGE, true);
}

/** SESSION_LOCKED because the session file expired: the vault client also locks bw and removes the file. */
export class SessionExpired extends SecretsError {
  constructor() {
    super('SESSION_LOCKED', SESSION_LOCKED_MESSAGE, true);
    this.name = 'SessionExpired';
  }
}
