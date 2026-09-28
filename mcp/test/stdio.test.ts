import { PassThrough } from 'node:stream';
import { join } from 'node:path';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { describe, expect, it } from 'vitest';
import { loadSecretsConfig } from '../src/config.js';
import { writeSessionFile } from '../src/session.js';
import { createLocalServer } from '../src/stdio.js';
import { SECRETS_TOOL_NAMES } from '../src/tools.js';
import { FAKE_BW, INFRA_ITEM, makeVaultDir, PERSONAL_ITEM, SERVER_URL } from './fixtures.js';

/** A newline-delimited JSON-RPC client over the stdio transport's streams. */
function client() {
  const toServer = new PassThrough();
  const fromServer = new PassThrough();
  const pending = new Map<number, (message: Record<string, unknown>) => void>();
  let buffer = '';
  const raw: string[] = [];
  fromServer.on('data', chunk => {
    buffer += String(chunk);
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      raw.push(line);
      const message = JSON.parse(line) as Record<string, unknown>;
      if (typeof message.id === 'number') pending.get(message.id)?.(message);
    }
  });
  let id = 0;
  return {
    transport: new StdioServerTransport(toServer, fromServer),
    raw,
    request(method: string, params: Record<string, unknown>) {
      id += 1;
      const current = id;
      return new Promise<Record<string, unknown>>(resolve => {
        pending.set(current, resolve);
        toServer.write(`${JSON.stringify({ jsonrpc: '2.0', id: current, method, params })}\n`);
      });
    },
    notify(method: string) {
      toServer.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`);
    },
  };
}

describe('stdio protocol smoke', () => {
  it('initializes, lists the five tools, and calls secrets_list_items against the fake bw', async () => {
    const vault = makeVaultDir();
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      HOME: vault.home,
      BITWARDENCLI_APPDATA_DIR: vault.dir,
      DUMONT_SECRETS_BW_BIN: FAKE_BW,
      DUMONT_SECRETS_SERVER_URL: SERVER_URL,
      DUMONT_SECRETS_SESSION_DIR: join(vault.home, 'session'),
      DUMONT_SECRETS_AUDIT_LOG: join(vault.home, 'audit.log'),
      DUMONT_SECRETS_MCP_CONFIG: join(vault.home, 'mcp.json'),
    };
    const config = loadSecretsConfig({ env, platform: 'linux', home: vault.home, uid: process.getuid?.() ?? 0, ownedDir: () => false });
    const server = createLocalServer(config, env);
    const c = client();
    await server.connect(c.transport);
    const init = await c.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } });
    expect((init.result as { serverInfo: { name: string } }).serverInfo.name).toBe('dumont-secrets-mcp');
    c.notify('notifications/initialized');
    const tools = await c.request('tools/list', {});
    expect(((tools.result as { tools: Array<{ name: string }> }).tools).map(tool => tool.name).sort()).toEqual([...SECRETS_TOOL_NAMES].sort());

    const locked = await c.request('tools/call', { name: 'secrets_list_items', arguments: {} });
    expect(locked.result).toMatchObject({ isError: true, structuredContent: { error: { code: 'SESSION_LOCKED' } } });

    writeSessionFile(config.sessionFile, vault.unlock(), 60_000);
    const listed = await c.request('tools/call', { name: 'secrets_list_items', arguments: {} });
    const items = (listed.result as { structuredContent: { items: Array<{ name: string }> } }).structuredContent.items.map(item => item.name);
    expect(items).toContain(INFRA_ITEM);
    expect(items).not.toContain(PERSONAL_ITEM);
    // stdout carries JSON-RPC only.
    for (const line of c.raw) expect(JSON.parse(line)).toHaveProperty('jsonrpc', '2.0');
    await server.close();
  }, 30_000);
});
