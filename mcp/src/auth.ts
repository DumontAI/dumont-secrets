import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { IncomingMessage } from 'node:http';
import { LOGICAL_ROLES, type LogicalRole, type OidcConfig, type Principal } from './types.js';

// Adapted from the Bugit MCP (DumontAI/dumont-bugit mcp/src/auth.ts), narrowed
// against token replay between MCP servers:
//   - JWT (JWS) access tokens only, verified locally with the JWKS; no
//     introspection path, so opaque DCR tokens are always 401;
//   - `aud` must contain THIS server's dedicated ZITADEL project, and the
//     issuing client (`client_id` / `azp`) must be allowlisted;
//   - roles are read ONLY from `urn:zitadel:iam:org:project:<audience>:roles`,
//     never from the project-agnostic claim, a generic `roles` claim or
//     `my:zitadel:grants`, which can carry another project's roles;
//   - instead of ONE required role, at least one of three, carried with the
//     request as a Principal so each tool can check its own.

const MAX_BEARER_BYTES = 16 * 1024;
// Small allowance for clock skew between this host and the issuer on `nbf`.
const NOT_BEFORE_TOLERANCE_SECONDS = 30;
const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]*$/;

function canonicalUrl(url: URL): string {
  return `${url.origin}${url.pathname && url.pathname !== '/' ? url.pathname : ''}`;
}

export type AuthorizationFailure =
  | 'missing_credentials'
  | 'invalid_credentials'
  | 'insufficient_scope'
  | 'temporarily_unavailable'
  | 'request_origin_not_allowed'
  | 'request_host_not_allowed';

export interface AuthorizationResult {
  readonly failure: AuthorizationFailure | null;
  readonly subject: string | null;
  /** Present only when failure is null. */
  readonly principal: Principal | null;
}

function requestHost(req: IncomingMessage): string {
  const raw = req.headers.host?.trim().toLowerCase() ?? '';
  if (!raw) return '';
  if (raw.startsWith('[')) return raw.slice(1, raw.indexOf(']'));
  return raw.split(':', 1)[0] ?? raw;
}

function requestHostAllowed(req: IncomingMessage, config: OidcConfig): boolean {
  const host = requestHost(req);
  const configuredHosts = config.allowedHosts.length > 0
    ? config.allowedHosts
    : ['127.0.0.1', 'localhost', '::1'];
  return Boolean(host) && configuredHosts.some(allowed =>
    allowed === host || allowed === req.headers.host?.toLowerCase());
}

function requestOriginAllowed(req: IncomingMessage, config: OidcConfig): boolean {
  if (config.allowedOrigins.length === 0) return true;
  const origin = req.headers.origin;
  return !origin || config.allowedOrigins.includes(origin);
}

function bearerToken(req: IncomingMessage): string | null {
  const authorization = req.headers.authorization ?? '';
  const match = /^Bearer[ \t]+([^ \t]+)$/i.exec(authorization);
  const token = match?.[1] ?? '';
  if (!token || Buffer.byteLength(token, 'utf8') > MAX_BEARER_BYTES) return null;
  return token;
}

function containsString(value: unknown, wanted: string): boolean {
  if (value === wanted) return true;
  if (Array.isArray(value)) return value.some(item => containsString(item, wanted));
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([key, item]) => key === wanted || containsString(item, wanted));
  }
  return false;
}

function projectRolesClaim(config: OidcConfig): string {
  return `urn:zitadel:iam:org:project:${config.oidcAudience}:roles`;
}

/**
 * Role keys asserted FOR THIS PROJECT: ZITADEL writes
 * `urn:zitadel:iam:org:project:<projectId>:roles` as
 * `{ <role>: { <orgId>: <domain> } }`. Nothing else is read.
 */
function assertedRoleKeys(payload: JWTPayload, config: OidcConfig): Set<string> {
  const claim = payload[projectRolesClaim(config)];
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) return new Set();
  return new Set(Object.keys(claim));
}

/**
 * The issuing client. ZITADEL JWT access tokens carry `client_id`; `azp` is
 * checked too when present. At least one must be there, and every one present
 * must be allowlisted.
 */
function clientAllowed(payload: JWTPayload, config: OidcConfig): boolean {
  const present = (['client_id', 'azp'] as const)
    .map(name => payload[name])
    .filter(value => value !== undefined);
  return present.length > 0 &&
    present.every(value => typeof value === 'string' && config.oidcAllowedClientIds.includes(value));
}

export function heldRoles(payload: JWTPayload, config: OidcConfig): Set<LogicalRole> {
  const asserted = assertedRoleKeys(payload, config);
  return new Set(LOGICAL_ROLES.filter(role => asserted.has(config.roleNames[role])));
}

/** The OAuth scopes that ask ZITADEL to assert each role (it may assert only the ones requested). */
export function roleScopes(config: OidcConfig): string[] {
  return LOGICAL_ROLES.map(role => `urn:zitadel:iam:org:project:role:${config.roleNames[role]}`);
}

function hasAllowedOrganization(payload: JWTPayload, organizationId: string, config: OidcConfig): boolean {
  return containsString(payload['urn:zitadel:iam:user:resourceowner'], organizationId) ||
    payload['urn:zitadel:iam:user:resourceowner:id'] === organizationId ||
    containsString(payload['urn:zitadel:iam:org:id'], organizationId) ||
    containsString(payload.org_id, organizationId) ||
    containsString(payload[projectRolesClaim(config)], organizationId);
}

function invalidCredentials(): AuthorizationResult {
  return { failure: 'invalid_credentials', subject: null, principal: null };
}

function emailOf(payload: JWTPayload): string | null {
  const email = payload.email;
  return typeof email === 'string' && email.length > 0 && email.length <= 254 && !/[\s"\\]/.test(email)
    ? email
    : null;
}

/**
 * The authorization policy for verified access-token claims. Binding failures
 * (issuer, audience, client, lifetime, subject) are 401; a valid token without
 * any of the three roles, or outside the org/subject allowlist, is 403.
 */
export function evaluateAccessClaims(
  claims: JWTPayload,
  config: OidcConfig,
  nowSeconds: number,
): AuthorizationResult {
  if (claims.iss !== canonicalUrl(config.oidcIssuer)) return invalidCredentials();
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
  if (!config.oidcAudience || !audiences.includes(config.oidcAudience)) return invalidCredentials();
  if (!clientAllowed(claims, config)) return invalidCredentials();
  if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds) return invalidCredentials();
  if (claims.nbf !== undefined &&
      (typeof claims.nbf !== 'number' || claims.nbf > nowSeconds + NOT_BEFORE_TOLERANCE_SECONDS)) {
    return invalidCredentials();
  }
  if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 255) return invalidCredentials();
  const subject = claims.sub;
  const roles = heldRoles(claims, config);
  const forbidden: AuthorizationResult = { failure: 'insufficient_scope', subject, principal: null };
  if (roles.size === 0) return forbidden;
  if (config.oidcAllowedOrgId && !hasAllowedOrganization(claims, config.oidcAllowedOrgId, config)) return forbidden;
  if (config.oidcAllowedSubjects.length > 0 && !config.oidcAllowedSubjects.includes(subject)) return forbidden;
  return { failure: null, subject, principal: { sub: subject, email: emailOf(claims), roles } };
}

function protectedHeader(segment: string): Record<string, unknown> | null {
  if (!segment) return null;
  try {
    const header: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    return header && typeof header === 'object' && !Array.isArray(header)
      ? header as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/** Only a compact JWS is ever verified; opaque (JWE) and anything else are 401 without a network call. */
function isCompactJws(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every(part => BASE64URL_SEGMENT.test(part))) return false;
  const header = protectedHeader(parts[0] ?? '');
  return Boolean(header) && typeof header!.alg === 'string' && header!.enc === undefined;
}

export interface AuthorizerDependencies {
  readonly now?: () => number;
}

function createOidcVerifier(config: OidcConfig, dependencies: AuthorizerDependencies) {
  const issuer = canonicalUrl(config.oidcIssuer);
  const jwks = createRemoteJWKSet(config.oidcJwksUrl);
  const now = dependencies.now ?? Date.now;

  async function verifyJws(token: string): Promise<AuthorizationResult> {
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience: config.oidcAudience,
        algorithms: ['RS256'],
        currentDate: new Date(now()),
      });
      // `nonce`/`at_hash` only appear in ID tokens; never accept one as an access token.
      if (payload.nonce !== undefined || payload.at_hash !== undefined) return invalidCredentials();
      return evaluateAccessClaims(payload, config, Math.floor(now() / 1000));
    } catch {
      return invalidCredentials();
    }
  }

  return async (token: string): Promise<AuthorizationResult> =>
    isCompactJws(token) ? verifyJws(token) : invalidCredentials();
}

export function metadataUrl(config: OidcConfig): URL {
  return new URL('/.well-known/oauth-protected-resource', config.resourceUrl.origin);
}

export function protectedResourceMetadata(config: OidcConfig): Record<string, unknown> {
  return {
    resource: canonicalUrl(config.resourceUrl),
    authorization_servers: [canonicalUrl(config.oidcIssuer)],
    // All three: ZITADEL asserts only the roles whose scope the client asked
    // for, so a client that requested one role would never see the others.
    scopes_supported: roleScopes(config),
    bearer_methods_supported: ['header'],
  };
}

export function protectedResourceMetadataPaths(config: OidcConfig): string[] {
  const paths = new Set(['/.well-known/oauth-protected-resource']);
  if (config.resourceUrl.pathname && config.resourceUrl.pathname !== '/') {
    paths.add(`/.well-known/oauth-protected-resource${config.resourceUrl.pathname}`);
  }
  return [...paths];
}

export function authorizationChallenge(
  config: OidcConfig,
  failure: AuthorizationFailure,
): string | null {
  if (failure === 'temporarily_unavailable') return null;
  const quote = (value: string) => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
  const scope = quote(roleScopes(config).join(' '));
  const resourceMetadata = quote(metadataUrl(config).href);
  if (failure === 'insufficient_scope') {
    return `Bearer error="insufficient_scope", scope=${scope}, resource_metadata=${resourceMetadata}`;
  }
  return `Bearer resource_metadata=${resourceMetadata}, scope=${scope}`;
}

export function createAuthorizer(
  config: OidcConfig,
  dependencies: AuthorizerDependencies = {},
): (req: IncomingMessage) => Promise<AuthorizationResult> {
  const verifyOidc = createOidcVerifier(config, dependencies);
  return async (req) => {
    if (!requestOriginAllowed(req, config)) {
      return { failure: 'request_origin_not_allowed', subject: null, principal: null };
    }
    if (!requestHostAllowed(req, config)) {
      return { failure: 'request_host_not_allowed', subject: null, principal: null };
    }
    const token = bearerToken(req);
    if (!token) return { failure: 'missing_credentials', subject: null, principal: null };
    return verifyOidc(token);
  };
}
