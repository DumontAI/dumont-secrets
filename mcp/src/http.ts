import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { RateLimiter, stderrAuditSink } from './audit.js';
import {
  authorizationChallenge,
  createAuthorizer,
  type AuthorizerDependencies,
  protectedResourceMetadata,
  protectedResourceMetadataPaths,
} from './auth.js';
import { BwVault } from './bw.js';
import { checkPasswordFile, loadSecretsConfig } from './config.js';
import { loadPolicyWithHash } from './policy.js';
import { isMainModule } from './runtime.js';
import { SecretsService } from './secrets.js';
import { createSecretsServer, type ToolContext } from './tools.js';
import type { Principal, SecretsConfig } from './types.js';

// Plain node:http, stateless Streamable HTTP, one McpServer per request (as in
// the Bugit MCP). The request's Principal is bound into that per-request
// server, which is how every tool knows who is calling and with which roles.

const MAX_REQUEST_BYTES = 256 * 1024;

class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

function responseError(
  res: ServerResponse,
  status: number,
  message: string,
  headers: Record<string, string> = {},
): void {
  if (res.headersSent) return;
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
}

function requestPath(req: IncomingMessage): string {
  return (req.url ?? '').split('?', 1)[0] ?? '';
}

function responseMetadata(res: ServerResponse, metadata: Record<string, unknown>): void {
  res.writeHead(200, {
    'cache-control': 'public, max-age=300',
    'content-type': 'application/json; charset=utf-8',
  });
  res.end(JSON.stringify(metadata));
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const declaredLength = Number(req.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
    throw new HttpError(413, 'The MCP request exceeded the configured safety limit');
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_REQUEST_BYTES) throw new HttpError(413, 'The MCP request exceeded the configured safety limit');
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new HttpError(400, 'The MCP request body must be valid JSON');
  }
}

export type ServerFactory = (principal: Principal) => ReturnType<typeof createSecretsServer>;

export function createSecretsHttpServer(
  config: SecretsConfig,
  serverFactory: ServerFactory,
  authorizerDependencies: AuthorizerDependencies = {},
): Server {
  const authorize = createAuthorizer(config, authorizerDependencies);
  const metadata = protectedResourceMetadata(config);
  const metadataPaths = protectedResourceMetadataPaths(config);
  return createServer(async (req, res) => {
    const path = requestPath(req);
    if (metadataPaths.includes(path)) {
      if (req.method !== 'GET') {
        responseError(res, 405, 'Protected resource metadata only accepts GET');
        return;
      }
      responseMetadata(res, metadata);
      return;
    }
    if (path !== '/mcp') {
      responseError(res, 404, 'Not found');
      return;
    }
    const authorization = await authorize(req);
    if (authorization.failure === 'temporarily_unavailable') {
      responseError(res, 503, 'MCP authorization is temporarily unavailable', { 'retry-after': '1' });
      return;
    }
    if (authorization.failure || !authorization.principal) {
      const failure = authorization.failure ?? 'invalid_credentials';
      const status = failure === 'insufficient_scope' ? 403 : 401;
      const challenge = authorizationChallenge(config, failure);
      responseError(
        res,
        status,
        status === 403 ? 'MCP credentials do not hold any secrets role' : 'Missing or invalid MCP credentials or request origin/host',
        challenge ? { 'www-authenticate': challenge } : {},
      );
      return;
    }
    const origin = req.headers.origin;
    if (origin && config.allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
    if (req.method !== 'POST' && req.method !== 'GET' && req.method !== 'DELETE') {
      responseError(res, 405, 'MCP endpoint accepts POST, GET, or DELETE');
      return;
    }
    res.setHeader('cache-control', 'no-store');

    try {
      const body = req.method === 'POST' ? await readJsonBody(req) : undefined;
      const server = serverFactory(authorization.principal);
      const transport = new NodeStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      if (error instanceof HttpError) {
        responseError(res, error.status, error.message);
      } else {
        responseError(res, 500, 'MCP request could not be completed');
      }
    }
  });
}

export function createToolContext(config: SecretsConfig): { context: ToolContext; vault: BwVault; policySha256: string } {
  const { policy, sha256 } = loadPolicyWithHash(config.policyFile);
  const vault = new BwVault(config.bw);
  return {
    context: {
      config,
      policy,
      service: new SecretsService({ vault }),
      limiter: new RateLimiter(config.rateLimitPerMinute, config.writeRateLimitPerMinute),
      audit: stderrAuditSink,
    },
    vault,
    policySha256: sha256,
  };
}

export async function startHttp(): Promise<Server> {
  const config = loadSecretsConfig();
  checkPasswordFile(config);
  const { context, vault, policySha256 } = createToolContext(config);
  // Read by apply-on-vault-syd1.sh --show-release: which policy bytes this process loaded.
  process.stderr.write(`secrets-mcp policy sha256=${policySha256}\n`);
  const server = createSecretsHttpServer(config, principal => createSecretsServer(context, principal));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.httpPort, config.httpHost, () => {
      server.off('error', reject);
      resolve();
    });
  });
  process.stderr.write(`secrets-mcp listening host=${config.httpHost} port=${config.httpPort}\n`);
  // Startup self-test: logs `secrets-mcp vault outcome=unlocked|failed`, no
  // detail. The server keeps serving either way (tools answer VAULT_UNAVAILABLE
  // and retry after the back-off); the apply treats `failed` as a failed apply.
  void vault.selfTest();
  return server;
}

if (isMainModule(import.meta.url)) {
  // Never let an unexpected rejection print its object (it could hold bw output).
  // Then exit: state after an unexpected rejection is unknown; systemd restarts the unit.
  process.on('unhandledRejection', () => {
    process.stderr.write('secrets-mcp outcome=unhandled_rejection\n');
    process.exit(1);
  });
  startHttp().catch(error => {
    // Config errors carry variable NAMES only (see config.ts); anything else gets a fixed line.
    const message = error instanceof Error && error.name === 'SecretsConfigError'
      ? error.message
      : 'Dumont Secrets MCP HTTP server failed to start';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
