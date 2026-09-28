/** Logical roles. The ZITADEL role keys that map to them are configurable. */
export type LogicalRole = 'meta' | 'reader' | 'writer';

export const LOGICAL_ROLES: readonly LogicalRole[] = ['meta', 'reader', 'writer'];

export interface RoleNames {
  readonly meta: string;
  readonly reader: string;
  readonly writer: string;
}

/**
 * OIDC half of the configuration (from the Bugit MCP, narrowed): JWT access
 * tokens only (no introspection, no static bearer), issued for THIS server's
 * own ZITADEL project and client, never for a project shared with other MCPs.
 */
export interface OidcConfig {
  readonly httpPort: number;
  readonly httpHost: string;
  readonly allowedOrigins: readonly string[];
  readonly allowedHosts: readonly string[];
  readonly oidcIssuer: URL;
  readonly oidcJwksUrl: URL;
  /** The dedicated ZITADEL project id; roles are read only from its own claim. */
  readonly oidcAudience: string;
  /** Clients whose tokens are accepted (`client_id` / `azp`). */
  readonly oidcAllowedClientIds: readonly string[];
  readonly oidcAllowedOrgId: string;
  readonly oidcAllowedSubjects: readonly string[];
  readonly resourceUrl: URL;
  readonly roleNames: RoleNames;
}

export interface BwConfig {
  /** Path (or PATH-resolved name) of the Bitwarden CLI. Tests point it at a fake. */
  readonly bin: string;
  readonly serverUrl: URL;
  readonly email: string;
  /** Read by `bw` itself (--passwordfile); this process only stat()s it. */
  readonly passwordFile: string;
  /** BITWARDENCLI_APPDATA_DIR for the CLI; under the service's StateDirectory. */
  readonly appDataDir: string;
  readonly timeoutMs: number;
  /** Optional: only collections of this organization are considered. */
  readonly organizationId: string;
  readonly syncMaxAgeSeconds: number;
}

export interface SecretsConfig extends OidcConfig {
  readonly bw: BwConfig;
  readonly policyFile: string;
  readonly allowSet: boolean;
  readonly rateLimitPerMinute: number;
  readonly writeRateLimitPerMinute: number;
}

/** Who is calling, as established by the authorizer for this one HTTP request. */
export interface Principal {
  readonly sub: string;
  readonly email: string | null;
  /** The configured role keys this token holds (subset of the three). */
  readonly roles: ReadonlySet<LogicalRole>;
}

/**
 * Errors surfaced to MCP callers. `message` is always a fixed, server-authored
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
  | 'FORBIDDEN'
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
  | 'POLICY_UNRESOLVED'
  | 'VAULT_UNAVAILABLE'
  | 'VAULT_ERROR'
  | 'OUTPUT_GUARD'
  | 'INTERNAL_ERROR'
  | 'REQUEST_TOO_LARGE'
  | 'INVALID_REQUEST';
