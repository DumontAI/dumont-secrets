import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fileAuditSink } from '../src/audit.js';
import { createSecretsServer } from '../src/tools.js';
import { callTool, containsAnySentinel, harness, INFRA_ITEM, LOGIN_ITEM, PERSONAL_ITEM, SENTINEL_OTHER } from './fixtures.js';

describe('local audit file', () => {
  it('is created 0600 in a 0700 directory and tightens a file left open', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-audit-'));
    const path = join(dir, 'state', 'dumont-secrets', 'audit.log');
    const sink = fileAuditSink(path);
    sink('{"a":1}');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700);
    chmodSync(path, 0o644);
    sink('{"a":2}');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readFileSync(path, 'utf8')).toBe('{"a":1}\n{"a":2}\n');
  });

  it('rotates at the size limit and keeps three old files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-audit-'));
    const path = join(dir, 'audit.log');
    const sink = fileAuditSink(path, { rotateBytes: 100 });
    for (let i = 0; i < 30; i += 1) sink(JSON.stringify({ n: i, pad: 'x'.repeat(30) }));
    expect(existsSync(`${path}.1`)).toBe(true);
    expect(existsSync(`${path}.3`)).toBe(true);
    expect(existsSync(`${path}.4`)).toBe(false);
    expect(statSync(path).size).toBeLessThanOrEqual(100);
    expect(readFileSync(path, 'utf8')).toContain('"n":29');
  });

  it('a sink that cannot write reports once and never throws', () => {
    const logs: string[] = [];
    // A regular file where the directory should be: every write fails with ENOTDIR.
    const dir = mkdtempSync(join(tmpdir(), 'secrets-audit-'));
    writeFileSync(join(dir, 'blocker'), 'x');
    const sink = fileAuditSink(join(dir, 'blocker', 'sub', 'audit.log'), { log: line => { logs.push(line); } });
    expect(() => { sink('{}'); sink('{}'); }).not.toThrow();
    expect(logs).toEqual(['dumont-secrets-mcp audit outcome=write_failed']);
  });

  it('never holds a value, the notes, or the session key, whatever the calls do', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'secrets-audit-'));
    const path = join(dir, 'audit.log');
    const h = harness({ allowSet: true });
    const context = { ...h.context, audit: fileAuditSink(path) };
    const call = (tool: string, args: Record<string, unknown>) => callTool(createSecretsServer(context), tool, args);
    const get = await call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    expect(get.structured.value).toBe(SENTINEL_OTHER);
    await call('secrets_list_items', {});
    await call('secrets_list_keys', { item: LOGIN_ITEM });
    await call('secrets_get_secret', { item: PERSONAL_ITEM, key: 'PERSONAL_KEY' });
    await call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING', replace_existing: true });
    await call('secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: 'set-value-sentinel-12345' });
    const text = readFileSync(path, 'utf8');
    expect(text.trim().split('\n')).toHaveLength(6);
    expect(containsAnySentinel(text)).toBeUndefined();
    expect(text).not.toContain('set-value-sentinel-12345');
    expect(text).not.toContain(h.session!);
    const generated = /EXISTING=([A-Za-z0-9_-]{48})/.exec(h.vault.state().items.find(i => i.id === 'item-writable')!.notes as string)![1]!;
    expect(text).not.toContain(generated);
  });
});
