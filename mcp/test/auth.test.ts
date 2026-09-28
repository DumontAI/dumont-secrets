import { createServer, type Server } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, describe, expect, it } from 'vitest';
import { authorizationChallenge, createAuthorizer, protectedResourceMetadata } from '../src/auth.js';
import { createSecretsHttpServer } from '../src/http.js';
import { createSecretsServer } from '../src/tools.js';
import { harness, INFRA_ITEM, SENTINELS, testConfig } from './fixtures.js';

// Adapted from the Bugit MCP auth tests (DumontAI/dumont-bugit mcp/test/auth.test.ts).

const openServers: Server[] = [];

afterEach(async () => {
  await Promise.all(openServers.splice(0).map(server => new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  })));
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('server did not bind');
  openServers.push(server);
  return address.port;
}

const PROJECT_ROLES = 'urn:zitadel:iam:org:project:secrets-mcp-project:roles';
const grantOf = (...roles: string[]) => Object.fromEntries(roles.map(role => [role, { 'dumont-org': 'dumont.example.test' }]));

const THREE_SCOPES = [
  'urn:zitadel:iam:org:project:role:secrets_meta',
  'urn:zitadel:iam:org:project:role:secrets_reader',
  'urn:zitadel:iam:org:project:role:secrets_writer',
];

async function setupOidc(overrides: Parameters<typeof testConfig>[0] = {}) {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const keyId = 'test-key';
  const jwksServer = createServer((req, res) => {
    if (req.url !== '/jwks') {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [{ ...jwk, kid: keyId, alg: 'RS256', use: 'sig' }] }));
  });
  const jwksPort = await listen(jwksServer);
  const issuer = new URL('https://issuer.example.test');
  const config = testConfig({
    oidcIssuer: issuer,
    oidcJwksUrl: new URL(`http://127.0.0.1:${jwksPort}/jwks`),
    oidcAudience: 'secrets-mcp-project',
    oidcAllowedOrgId: 'dumont-org',
    resourceUrl: new URL('https://secret.example.test/mcp'),
    ...overrides,
  });
  const token = (
    roles: string[] = ['secrets_reader'],
    overridesClaims: Record<string, unknown> = {},
    audience = 'secrets-mcp-project',
    tokenIssuer = issuer.origin,
    expiration = '5m',
  ) => new SignJWT({
    [PROJECT_ROLES]: Object.fromEntries(roles.map(role => [role, { 'dumont-org': 'dumont.example.test' }])),
    client_id: 'secrets-mcp-client',
    email: 'person@example.test',
    ...overridesClaims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: keyId })
    .setIssuer(tokenIssuer)
    .setAudience(audience)
    .setSubject('user-1')
    .setIssuedAt()
    .setExpirationTime(expiration)
    .sign(privateKey);
  return { config, token };
}

function request(token: string) {
  return { headers: { host: '127.0.0.1', authorization: `Bearer ${token}` } } as never;
}

describe('OIDC authorization', () => {
  it('publishes protected resource metadata that lists all three role scopes', async () => {
    const { config } = await setupOidc();
    expect(protectedResourceMetadata(config)).toEqual({
      resource: 'https://secret.example.test/mcp',
      authorization_servers: ['https://issuer.example.test'],
      scopes_supported: THREE_SCOPES,
      bearer_methods_supported: ['header'],
    });
    expect(authorizationChallenge(config, 'missing_credentials')).toBe(
      `Bearer resource_metadata="https://secret.example.test/.well-known/oauth-protected-resource", scope="${THREE_SCOPES.join(' ')}"`,
    );
    expect(authorizationChallenge(config, 'insufficient_scope')).toContain(`scope="${THREE_SCOPES.join(' ')}"`);
  });

  it('turns the asserted roles into a principal, and ignores roles it does not know', async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const result = await authorize(request(await token(['secrets_reader', 'secrets_writer', 'bugit_reader'])));
    expect(result.failure).toBeNull();
    expect(result.principal?.sub).toBe('user-1');
    expect(result.principal?.email).toBe('person@example.test');
    expect([...result.principal!.roles].sort()).toEqual(['reader', 'writer']);
  });

  it('honours renamed role keys', async () => {
    const { config, token } = await setupOidc({ roleNames: { meta: 'vault_meta', reader: 'vault_read', writer: 'vault_write' } });
    const result = await createAuthorizer(config)(request(await token(['vault_meta'])));
    expect([...result.principal!.roles]).toEqual(['meta']);
    expect((await createAuthorizer(config)(request(await token(['secrets_meta'])))).failure).toBe('insufficient_scope');
  });

  it('rejects wrong audience, wrong issuer, expired tokens and ID tokens with 401 semantics', async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    for (const bad of [
      await token(['secrets_reader'], {}, 'another-project'),
      await token(['secrets_reader'], {}, 'secrets-mcp-project', 'https://another-issuer.example.test'),
      await token(['secrets_reader'], {}, 'secrets-mcp-project', 'https://issuer.example.test', '0s'),
      await token(['secrets_reader'], { nonce: 'n-1' }),
      await token(['secrets_reader'], { at_hash: 'abc' }),
    ]) {
      expect((await authorize(request(bad))).failure).toBe('invalid_credentials');
    }
  });

  it('rejects tokens of another client, or with no client claim, with 401 semantics', async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    for (const claims of [
      { client_id: 'bugit-or-hangar-client' },
      { client_id: undefined },
      { client_id: undefined, azp: 'bugit-or-hangar-client' },
      { azp: 'bugit-or-hangar-client' },
      { client_id: ['secrets-mcp-client'] },
    ]) {
      expect((await authorize(request(await token(['secrets_reader'], claims)))).failure, JSON.stringify(claims)).toBe('invalid_credentials');
    }
    // azp alone is accepted when it is the allowlisted client.
    const azpOnly = await token(['secrets_reader'], { client_id: undefined, azp: 'secrets-mcp-client' });
    expect((await authorize(request(azpOnly))).failure).toBeNull();
  });

  it('reads roles ONLY from this project\'s claim: another project, the generic claims and grants are ignored', async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    for (const claims of [
      { 'urn:zitadel:iam:org:project:roles': grantOf('secrets_reader', 'secrets_writer') },
      { 'urn:zitadel:iam:org:project:another-project:roles': grantOf('secrets_reader') },
      { roles: ['secrets_reader'] },
      { 'my:zitadel:grants': ['secrets-mcp-project:secrets_reader', 'secrets_reader'] },
    ]) {
      const result = await authorize(request(await token([], claims)));
      expect(result.failure, JSON.stringify(claims)).toBe('insufficient_scope');
      expect(result.principal).toBeNull();
    }
    // Roles in the project claim, with extra roles elsewhere: only the project's count.
    const mixed = await authorize(request(await token(['secrets_meta'], {
      'urn:zitadel:iam:org:project:roles': grantOf('secrets_writer'),
      'urn:zitadel:iam:org:project:another-project:roles': grantOf('secrets_reader'),
    })));
    expect([...mixed.principal!.roles]).toEqual(['meta']);
  });

  it('never accepts an opaque (JWE-shaped) token: there is no introspection path', async () => {
    const { config } = await setupOidc();
    const b64 = (value: string) => Buffer.from(value).toString('base64url');
    const jwe = [b64(JSON.stringify({ alg: 'A256GCMKW', enc: 'A256GCM', kid: 'k1' })), 'A'.repeat(43), 'A'.repeat(16), 'AAAA', 'A'.repeat(22)].join('.');
    expect((await createAuthorizer(config)(request(jwe))).failure).toBe('invalid_credentials');
  });

  it('gates on at least one of the three roles, the organization and the subject allowlist (403)', async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    expect((await authorize(request(await token([])))).failure).toBe('insufficient_scope');
    expect((await authorize(request(await token(['bugit_reader'])))).failure).toBe('insufficient_scope');
    const otherOrg = await token([], { [PROJECT_ROLES]: { secrets_reader: { 'other-org': 'x' } } });
    expect((await authorize(request(otherOrg))).failure).toBe('insufficient_scope');
    const limited = createAuthorizer({ ...config, oidcAllowedSubjects: ['user-2'] });
    expect((await limited(request(await token()))).failure).toBe('insufficient_scope');
  });

  it('serves metadata, 401 with the challenge, 403 without a role, and tools with the caller\'s roles', async () => {
    const { config: oidcConfig, token } = await setupOidc();
    const h = harness();
    const config = { ...h.context.config, ...oidcConfig, bw: h.context.config.bw };
    const context = { ...h.context, config };
    const server = createSecretsHttpServer(config, principal => createSecretsServer(context, principal));
    const port = await listen(server);
    const baseUrl = `http://127.0.0.1:${port}`;

    const metadataResponse = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    expect(metadataResponse.status).toBe(200);
    expect(await metadataResponse.json()).toMatchObject({ scopes_supported: THREE_SCOPES });
    expect((await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`)).status).toBe(200);
    expect((await fetch(`${baseUrl}/`)).status).toBe(404);

    const unauthorized = await fetch(`${baseUrl}/mcp`, { method: 'POST', body: '{}' });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get('www-authenticate')).toContain('resource_metadata="https://secret.example.test/.well-known/oauth-protected-resource"');
    expect(unauthorized.headers.get('www-authenticate')).toContain(THREE_SCOPES.join(' '));

    const forbidden = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await token([])}`, 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(forbidden.status).toBe(403);
    expect(forbidden.headers.get('www-authenticate')).toContain('insufficient_scope');

    const post = async (bearer: string, body: Record<string, unknown>) => {
      const response = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${bearer}`,
          accept: 'application/json, text/event-stream',
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      return await response.json() as Record<string, unknown>;
    };
    const metaToken = await token(['secrets_meta']);
    const initialize = await post(metaToken, {
      jsonrpc: '2.0', id: 2, method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'oidc-test', version: '1' } },
    });
    expect(initialize.result).toMatchObject({ serverInfo: { name: 'dumont-secrets-mcp' } });
    const listed = await post(metaToken, { jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} });
    expect((listed.result as { tools: Array<{ name: string }> }).tools.map(tool => tool.name)).toEqual([
      'secrets_list_items', 'secrets_list_keys', 'secrets_get_secret', 'secrets_generate_secret', 'secrets_set_secret',
    ]);
    // A meta token asking for a value: a tool error (FORBIDDEN), not an HTTP 401/403.
    const denied = await post(metaToken, {
      jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: { name: 'secrets_get_secret', arguments: { item: INFRA_ITEM, key: 'OTHER_KEY' } },
    });
    expect(denied.result).toMatchObject({ isError: true, structuredContent: { error: { code: 'FORBIDDEN' } } });
    expect(SENTINELS.some(sentinel => JSON.stringify(denied).includes(sentinel))).toBe(false);
    const audited = JSON.parse(h.audit.at(-1)!) as Record<string, unknown>;
    expect(audited).toMatchObject({ sub: 'user-1', email: 'person@example.test', roles: ['secrets_meta'], outcome: 'denied' });
    expect(h.audit.join('\n')).not.toContain(metaToken);
  });
});
