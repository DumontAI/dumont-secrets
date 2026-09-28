import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SecretsConfigError } from './config.js';
import type { Principal } from './types.js';

/**
 * The "what" of access, versioned in the repository as policy.example.json and
 * installed on the host as SECRETS_MCP_POLICY_FILE. ZITADEL says WHO holds a
 * role; this file says which Bitwarden collections each role reaches.
 * Collection NAMES here, resolved to ids at runtime with `bw list collections`.
 *
 *   meta.read_collections    names/keys visible to secrets_meta
 *   reader.read_collections  values readable by secrets_reader (names/keys too)
 *   writer.write_collection  the one collection secrets_writer may create or
 *                            change items in (names/keys there visible too)
 */
export interface SecretsPolicy {
  readonly metaCollections: readonly string[];
  readonly readerCollections: readonly string[];
  readonly writeCollection: string;
}

const MAX_POLICY_BYTES = 64 * 1024;

function collectionName(value: unknown, where: string): string {
  // Names are data from the operator; refuse control characters so they can
  // never smuggle a line into the audit log or a response.
  if (typeof value !== 'string' || value.length < 1 || value.length > 200 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new SecretsConfigError(`policy ${where} must be collection names of 1-200 printable characters`);
  }
  return value;
}

function nameList(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) {
    throw new SecretsConfigError(`policy ${where} must be a non-empty array of collection names`);
  }
  return [...new Set(value.map(item => collectionName(item, where)))];
}

function section(roles: Record<string, unknown>, name: string): Record<string, unknown> {
  const value = roles[name];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new SecretsConfigError(`policy roles.${name} is required`);
  }
  return value as Record<string, unknown>;
}

export function parsePolicy(raw: string): SecretsPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SecretsConfigError('SECRETS_MCP_POLICY_FILE must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SecretsConfigError('SECRETS_MCP_POLICY_FILE must be a JSON object');
  }
  const record = parsed as Record<string, unknown>;
  if (record.version !== 1) throw new SecretsConfigError('policy version must be 1');
  const roles = record.roles;
  if (!roles || typeof roles !== 'object' || Array.isArray(roles)) {
    throw new SecretsConfigError('policy roles is required');
  }
  const known = new Set(['meta', 'reader', 'writer']);
  const unknown = Object.keys(roles).find(name => !known.has(name));
  if (unknown !== undefined) throw new SecretsConfigError('policy roles may only contain meta, reader and writer');
  const rolesRecord = roles as Record<string, unknown>;
  const meta = section(rolesRecord, 'meta');
  const reader = section(rolesRecord, 'reader');
  const writer = section(rolesRecord, 'writer');
  if (Object.keys(meta).some(key => key !== 'read_collections') ||
      Object.keys(reader).some(key => key !== 'read_collections') ||
      Object.keys(writer).some(key => key !== 'write_collection')) {
    throw new SecretsConfigError('policy: meta/reader take only read_collections, writer takes only write_collection');
  }
  return {
    metaCollections: nameList(meta.read_collections, 'roles.meta.read_collections'),
    readerCollections: nameList(reader.read_collections, 'roles.reader.read_collections'),
    writeCollection: collectionName(writer.write_collection, 'roles.writer.write_collection'),
  };
}

/**
 * Read and parse the policy once, returning the sha256 of the exact bytes that
 * were parsed: the server logs it at start (`secrets-mcp policy sha256=<hex>`)
 * so --show-release can tell whether the running process loaded the file on disk.
 */
export function loadPolicyWithHash(
  path: string,
  read: (path: string) => Buffer = p => readFileSync(p),
): { policy: SecretsPolicy; sha256: string } {
  let raw: Buffer;
  try {
    raw = read(path);
  } catch {
    throw new SecretsConfigError('SECRETS_MCP_POLICY_FILE cannot be read');
  }
  if (raw.byteLength > MAX_POLICY_BYTES) {
    throw new SecretsConfigError('SECRETS_MCP_POLICY_FILE is larger than 64 KiB');
  }
  return { policy: parsePolicy(raw.toString('utf8')), sha256: createHash('sha256').update(raw).digest('hex') };
}

export function loadPolicy(path: string): SecretsPolicy {
  return loadPolicyWithHash(path).policy;
}

/**
 * Role hierarchy, in one place:
 *   reader => meta   (the meta collections, plus the collections it may read)
 *   writer => meta   (the meta collections, plus the write collection), and
 *             NOT reader: a writer never reads a value back, not even one it wrote.
 */
export interface Access {
  readonly canMeta: boolean;
  readonly canRead: boolean;
  readonly canWrite: boolean;
  /** Collection names whose item names and key names are visible. */
  readonly metaCollections: readonly string[];
  /** Collection names whose values may be returned. */
  readonly readCollections: readonly string[];
  /** The one collection writes go to, or null. */
  readonly writeCollection: string | null;
}

export function accessFor(principal: Principal, policy: SecretsPolicy): Access {
  const meta = principal.roles.has('meta');
  const reader = principal.roles.has('reader');
  const writer = principal.roles.has('writer');
  const metaCollections = new Set<string>();
  if (meta || reader || writer) policy.metaCollections.forEach(name => metaCollections.add(name));
  if (reader) policy.readerCollections.forEach(name => metaCollections.add(name));
  if (writer) metaCollections.add(policy.writeCollection);
  return {
    canMeta: meta || reader || writer,
    canRead: reader,
    canWrite: writer,
    metaCollections: [...metaCollections],
    readCollections: reader ? [...policy.readerCollections] : [],
    writeCollection: writer ? policy.writeCollection : null,
  };
}
