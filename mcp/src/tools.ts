import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { auditLine, type AuditSink, type RateLimiter } from './audit.js';
import { assertNoRawBwJson, assertSafeOutput, OutputGuardError } from './guard.js';
import { normalizeKey, READ_KEY_PATTERN, WRITE_KEY_PATTERN } from './notes.js';
import { accessFor, type Access, type SecretsPolicy } from './policy.js';
import { generateValue, Taint, type Alphabet, type SecretsService } from './secrets.js';
import { SecretsError, type LogicalRole, type Principal, type SecretsConfig } from './types.js';

export const SECRETS_TOOL_NAMES = [
  'secrets_list_items',
  'secrets_list_keys',
  'secrets_get_secret',
  'secrets_generate_secret',
  'secrets_set_secret',
] as const;

type ToolName = typeof SECRETS_TOOL_NAMES[number];

export const VALUE_IN_CONTEXT_WARNING =
  'WARNING: this secret value is now in the model context and in this conversation\'s transcript. ' +
  'Use it for the task at hand only; do not repeat it, write it to files, commit it, or paste it elsewhere.';

const MAX_VALUE_LENGTH = 8192;
const CONTROL = /[\u0000-\u001f\u007f]/;

export interface ToolContext {
  readonly config: SecretsConfig;
  readonly policy: SecretsPolicy;
  readonly service: SecretsService;
  readonly limiter: RateLimiter;
  readonly audit: AuditSink;
  readonly now?: () => number;
}

// Loose schemas on purpose: the SDK's validation errors are sent to the
// caller verbatim, so anything that could echo input (a value above all) is
// checked by hand below with fixed messages instead.
const itemSchema = z.string().max(512);
const keySchema = z.string().max(512);

function validItemName(item: string): string {
  if (item.length < 1 || item.length > 200 || CONTROL.test(item) || item.trim() !== item) {
    throw new SecretsError('INVALID_ARGUMENT', 'item must be 1-200 printable characters without leading or trailing spaces');
  }
  return item;
}

function validReadKey(key: string): string {
  // `_` or `-._` would normalize to nothing and match every punctuation-only key.
  if (!READ_KEY_PATTERN.test(key) || normalizeKey(key) === '') {
    throw new SecretsError('INVALID_ARGUMENT', 'key must be 1-128 characters of letters, digits, _ . -');
  }
  return key;
}

function validWriteKey(key: string): string {
  if (!WRITE_KEY_PATTERN.test(key)) {
    throw new SecretsError('INVALID_ARGUMENT', 'key must match ^[A-Z][A-Z0-9_]{0,127}$');
  }
  return key;
}

function validValue(value: string): string {
  if (value.length < 1 || value.length > MAX_VALUE_LENGTH) {
    throw new SecretsError('INVALID_ARGUMENT', `value must be 1-${MAX_VALUE_LENGTH} characters`);
  }
  if (/[\r\n\u0000]/.test(value)) {
    throw new SecretsError('INVALID_ARGUMENT', 'value must be a single line (no newline, carriage return or NUL)');
  }
  return value;
}

function success(value: Record<string, unknown>, text?: string) {
  return {
    structuredContent: value,
    content: [{ type: 'text' as const, text: text ?? JSON.stringify(value) }],
  };
}

function failure(code: string, message: string, retryable = false) {
  const value = { error: { code, message, retryable } };
  return {
    isError: true,
    structuredContent: value,
    content: [{ type: 'text' as const, text: JSON.stringify(value) }],
  };
}

/** Audit fields: filled only with values that passed validation. */
interface CallFields {
  item: string | null;
  key: string | null;
  collection: string | null;
}

/**
 * full:       scan for raw bw JSON and every value the call touched (get_secret: all but the one value)
 * structural: raw bw JSON only (listings built from names)
 * written:    the vault already changed; a guard hit must not turn the success into an error
 */
type ToolOutcome = {
  readonly result: ReturnType<typeof success>;
  readonly allowed: string | null;
  readonly guard: 'full' | 'structural' | 'written';
};

export function createSecretsServer(context: ToolContext, principal: Principal): McpServer {
  const { config, policy, service, limiter, audit } = context;
  const now = context.now ?? Date.now;
  const access: Access = accessFor(principal, policy);
  const roleNames = [...principal.roles].map(role => config.roleNames[role]).sort();

  const server = new McpServer(
    { name: 'dumont-secrets-mcp', version: '0.1.0' },
    {
      instructions:
        'Dumont Secrets vault, scoped by your ZITADEL roles and the server collection policy. ' +
        'Prefer secrets_list_keys to discover names and secrets_generate_secret to create or rotate a secret: ' +
        'neither puts a value in the conversation. secrets_get_secret returns ONE value into the model context; ' +
        'use it only when the task truly needs the value itself.',
    },
  );

  async function runTool(
    tool: ToolName,
    required: LogicalRole,
    isWrite: boolean,
    fields: CallFields,
    operation: (taint: Taint) => Promise<ToolOutcome>,
  ) {
    const started = now();
    const taint = new Taint();
    let outcome: 'ok' | 'denied' | 'error' = 'ok';
    let errorCode: string | null = null;
    let guardFired = false;
    try {
      if (!limiter.allow(principal.sub, isWrite)) {
        throw new SecretsError('RATE_LIMITED', 'Too many calls; wait a minute', true);
      }
      const permitted = required === 'meta' ? access.canMeta : required === 'reader' ? access.canRead : access.canWrite;
      if (!permitted) {
        throw new SecretsError('FORBIDDEN', `This tool requires the ${config.roleNames[required]} role`);
      }
      const done = await operation(taint);
      const serialized = [JSON.stringify(done.result.structuredContent), ...done.result.content.map(part => part.text)];
      if (done.guard === 'written') {
        // The vault ALREADY changed. The answer is built from fixed fields and
        // the caller's own validated item/key, so the guard should never fire;
        // if it does, the write must still read as a success (a retry would
        // rotate again), with a fixed text instead of the built answer.
        try {
          assertSafeOutput(serialized, taint.values, null);
          return done.result;
        } catch {
          guardFired = true;
          return success({ written: true }, 'Write completed; details withheld by the output guard.');
        }
      }
      if (done.guard === 'structural') {
        // Built only from item names, collection names, dates and key names:
        // the structural rule applies, the value scan would only misfire on a
        // value that happens to equal a name.
        assertNoRawBwJson(serialized);
      } else {
        assertSafeOutput(serialized, taint.values, done.allowed);
      }
      return done.result;
    } catch (error) {
      let answer;
      if (error instanceof SecretsError) {
        errorCode = error.code;
        answer = failure(error.code, error.message, error.retryable);
      } else if (error instanceof OutputGuardError) {
        errorCode = 'OUTPUT_GUARD';
        answer = failure('OUTPUT_GUARD', 'Response withheld by the output guard');
      } else {
        errorCode = 'INTERNAL_ERROR';
        answer = failure('INTERNAL_ERROR', 'The secrets operation could not be completed');
      }
      outcome = errorCode === 'FORBIDDEN' || errorCode === 'SET_DISABLED' || errorCode === 'RATE_LIMITED' ? 'denied' : 'error';
      try {
        // Errors pass the same guard; a failure here falls back to a fixed answer.
        assertSafeOutput([JSON.stringify(answer.structuredContent)], taint.values, null);
        return answer;
      } catch {
        errorCode = 'OUTPUT_GUARD';
        return failure('OUTPUT_GUARD', 'Response withheld by the output guard');
      }
    } finally {
      try {
        audit(auditLine({
          ts: new Date(started).toISOString(),
          event: 'secrets.mcp.tool',
          tool,
          sub: principal.sub,
          email: principal.email,
          roles: roleNames,
          item: fields.item,
          key: fields.key,
          collection: fields.collection,
          outcome,
          error_code: errorCode,
          latency_ms: Math.max(0, now() - started),
          ...(guardFired ? { guard: 'fired' as const } : {}),
        }));
      } catch {
        // Audit must never change the answer; a broken sink shows up in the journal as its own failure.
      }
    }
  }

  const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
  const writes = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false } as const;

  server.registerTool('secrets_list_items', {
    title: 'List secret items',
    description: 'List the names of vault items you may see (never values or notes), with their collection names and last revision date. ' +
      'Requires secrets_meta (or secrets_reader / secrets_writer).',
    inputSchema: z.object({
      collection: z.string().max(200).optional().describe('Only this collection (by name)'),
      search: z.string().max(200).optional().describe('Case-insensitive substring of the item name'),
    }),
    annotations: readOnly,
  }, async args => {
    const fields: CallFields = { item: null, key: null, collection: null };
    return runTool('secrets_list_items', 'meta', false, fields, async taint => {
      if (args.collection !== undefined && (args.collection.length === 0 || CONTROL.test(args.collection))) {
        throw new SecretsError('INVALID_ARGUMENT', 'collection must be printable text');
      }
      if (args.search !== undefined && CONTROL.test(args.search)) {
        throw new SecretsError('INVALID_ARGUMENT', 'search must be printable text');
      }
      fields.collection = args.collection ?? null;
      const listed = await service.listItems(access, {
        ...(args.collection !== undefined ? { collection: args.collection } : {}),
        ...(args.search ? { search: args.search } : {}),
      }, taint);
      return { result: success({ ...listed }), allowed: null, guard: 'structural' };
    });
  });

  server.registerTool('secrets_list_keys', {
    title: 'List keys of a secret item',
    description: 'List the key names inside one vault item (KEY=value note lines, custom fields, login username/password). ' +
      'Names only, never values. Requires secrets_meta (or secrets_reader / secrets_writer).',
    inputSchema: z.object({ item: itemSchema.describe('Item name (or id)') }),
    annotations: readOnly,
  }, async args => {
    const fields: CallFields = { item: null, key: null, collection: null };
    return runTool('secrets_list_keys', 'meta', false, fields, async taint => {
      const item = validItemName(args.item);
      fields.item = item;
      const listed = await service.listKeys(access, item, taint);
      fields.collection = listed.collections.join(',') || null;
      return { result: success({ ...listed }), allowed: null, guard: 'structural' };
    });
  });

  server.registerTool('secrets_get_secret', {
    title: 'Get one secret value',
    description: 'Return ONE value (item + key) into the model context. Prefer secrets_generate_secret or telling a human where the ' +
      'secret lives; use this only when the task needs the value itself. Requires secrets_reader.',
    inputSchema: z.object({
      item: itemSchema.describe('Item name (or id)'),
      key: keySchema.describe('Key name; matching ignores case and punctuation'),
    }),
    annotations: { ...readOnly, idempotentHint: true },
  }, async args => {
    const fields: CallFields = { item: null, key: null, collection: null };
    return runTool('secrets_get_secret', 'reader', false, fields, async taint => {
      const item = validItemName(args.item);
      fields.item = item;
      const key = validReadKey(args.key);
      fields.key = key;
      const found = await service.getSecret(access, item, key, taint);
      fields.collection = found.collections.join(',') || null;
      const value = { warning: VALUE_IN_CONTEXT_WARNING, item: found.item, key: found.key, value: found.value };
      return { result: success(value, `${VALUE_IN_CONTEXT_WARNING}\n${found.value}`), allowed: found.value, guard: 'full' };
    });
  });

  server.registerTool('secrets_generate_secret', {
    title: 'Generate and store a secret',
    description: 'Generate a random value on the server and store it as KEY=value in an item of the writable collection ' +
      '(creating the Secure Note if needed, or adding that one line and keeping every other line as it was). ' +
      'An existing key is replaced (rotated) only with replace_existing: true. ' +
      'The value is NEVER returned. Requires secrets_writer.',
    inputSchema: z.object({
      item: itemSchema.describe('Item name in the writable collection'),
      key: keySchema.describe('Key name, ^[A-Z][A-Z0-9_]{0,127}$'),
      length: z.number().int().min(16).max(128).default(48),
      alphabet: z.enum(['base64url', 'hex', 'alnum']).default('base64url'),
      replace_existing: z.boolean().default(false).describe('Rotate the key if it already exists'),
    }),
    annotations: writes,
  }, async args => {
    const fields: CallFields = { item: null, key: null, collection: access.writeCollection };
    return runTool('secrets_generate_secret', 'writer', true, fields, async taint => {
      const item = validItemName(args.item);
      fields.item = item;
      const key = validWriteKey(args.key);
      fields.key = key;
      const generated = generateValue(args.length, args.alphabet as Alphabet);
      const written = await service.writeKey(access, item, key, generated, taint, args.replace_existing);
      // Fixed fields and the caller's own validated item/key only.
      return {
        result: success({ item, key, action: written.action, item_created: written.item_created, length: args.length }),
        allowed: null,
        guard: 'written',
      };
    });
  });

  server.registerTool('secrets_set_secret', {
    title: 'Store a given secret value',
    description: 'Store a caller-supplied single-line value as KEY=value in an item of the writable collection. ' +
      'Disabled unless the server sets SECRETS_MCP_ALLOW_SET=true; prefer secrets_generate_secret, which keeps the value ' +
      'out of the conversation. Returns a confirmation only. Requires secrets_writer.',
    inputSchema: z.object({
      item: itemSchema.describe('Item name in the writable collection'),
      key: keySchema.describe('Key name, ^[A-Z][A-Z0-9_]{0,127}$'),
      value: z.string().describe('Single-line value'),
      replace_existing: z.boolean().default(false).describe('Replace the key if it already exists'),
    }),
    annotations: writes,
  }, async args => {
    const fields: CallFields = { item: null, key: null, collection: access.writeCollection };
    return runTool('secrets_set_secret', 'writer', true, fields, async taint => {
      taint.add(args.value);
      if (!config.allowSet) {
        throw new SecretsError('SET_DISABLED', 'secrets_set_secret is disabled on this server; use secrets_generate_secret');
      }
      const item = validItemName(args.item);
      fields.item = item;
      const key = validWriteKey(args.key);
      fields.key = key;
      const written = await service.writeKey(access, item, key, validValue(args.value), taint, args.replace_existing);
      return {
        result: success({ item, key, action: written.action, item_created: written.item_created }),
        allowed: null,
        guard: 'written',
      };
    });
  });

  return server;
}
