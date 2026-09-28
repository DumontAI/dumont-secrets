import { randomBytes } from 'node:crypto';
import type { BwCollection, BwVault, VaultOperations } from './bw.js';
import { findValue, itemEntries, itemSecretStrings, keyNames, normalizeKey, upsertNoteLine, type BwItem } from './notes.js';
import type { Access } from './policy.js';
import { SecretsError } from './types.js';

export type Alphabet = 'base64url' | 'hex' | 'alnum';

/** One refusal for every "not writable" case, so the answer reveals nothing about other collections. */
export const WRITE_REFUSED_MESSAGE = 'Cannot write an item with this name';

const ALNUM ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const MAX_LISTED_ITEMS = 500;

/** Collector for every secret string the operation touched, for the output guard. */
export class Taint {
  readonly values = new Set<string>();

  addItem(item: BwItem): void {
    for (const value of itemSecretStrings(item)) this.values.add(value);
  }

  add(value: string): void {
    this.values.add(value);
  }
}

export function generateValue(length: number, alphabet: Alphabet): string {
  if (!Number.isInteger(length) || length < 16 || length > 128) {
    throw new SecretsError('INVALID_ARGUMENT', 'length must be an integer from 16 to 128');
  }
  if (alphabet === 'hex') return randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
  if (alphabet === 'base64url') return randomBytes(Math.ceil((length * 3) / 4) + 3).toString('base64url').slice(0, length);
  // alnum: rejection sampling, so every character is equally likely (62 * 4 = 248).
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte >= 248) continue;
      out += ALNUM[byte % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

function collectionIdsOf(item: BwItem): string[] {
  return Array.isArray(item.collectionIds) ? item.collectionIds.filter((id): id is string => typeof id === 'string') : [];
}

function nameOf(item: BwItem): string {
  return typeof item.name === 'string' ? item.name : '';
}

function idOf(item: BwItem): string {
  return typeof item.id === 'string' ? item.id : '';
}

function revisionOf(item: BwItem): string | null {
  return typeof item.revisionDate === 'string' ? item.revisionDate : null;
}

/**
 * Resolve policy collection names to ids. Fail closed: a name that matches no
 * collection, or more than one, stops the call. The name goes to the
 * operator log (journal), not to the caller.
 */
export function resolveCollections(
  names: readonly string[],
  collections: readonly BwCollection[],
  log: (line: string) => void,
): Map<string, BwCollection> {
  const resolved = new Map<string, BwCollection>();
  for (const name of names) {
    const matches = collections.filter(collection => collection.name === name);
    if (matches.length !== 1) {
      log(`secrets-mcp policy outcome=${matches.length === 0 ? 'collection_not_found' : 'collection_ambiguous'} collection=${JSON.stringify(name)}`);
      throw new SecretsError('POLICY_UNRESOLVED', 'A collection named in the server policy is not available to the vault account');
    }
    resolved.set(matches[0]!.id, matches[0]!);
  }
  return resolved;
}

function visibleIn(items: readonly BwItem[], allowed: Map<string, BwCollection>): BwItem[] {
  return items.filter(item => collectionIdsOf(item).some(id => allowed.has(id)));
}

/** Exact id, then exact name, then case-insensitive name. Several matches is an error, not a guess. */
export function findItem(items: readonly BwItem[], reference: string): BwItem | null {
  const byId = items.filter(item => idOf(item) === reference);
  if (byId.length === 1) return byId[0]!;
  let matches = items.filter(item => nameOf(item) === reference);
  if (matches.length === 0) {
    const lower = reference.toLowerCase();
    matches = items.filter(item => nameOf(item).toLowerCase() === lower);
  }
  if (matches.length > 1) {
    throw new SecretsError('AMBIGUOUS_ITEM', 'More than one visible item has this name; rename one in the vault');
  }
  return matches[0] ?? null;
}

function collectionNames(item: BwItem, allowed: Map<string, BwCollection>): string[] {
  return collectionIdsOf(item)
    .map(id => allowed.get(id)?.name)
    .filter((name): name is string => typeof name === 'string')
    .sort();
}

export interface ServiceDependencies {
  readonly vault: BwVault;
  readonly log?: (line: string) => void;
}

export interface ListedItem {
  readonly name: string;
  readonly collections: string[];
  readonly revision_date: string | null;
}

export interface WriteResult {
  readonly item: string;
  readonly key: string;
  readonly action: 'created' | 'rotated';
  readonly item_created: boolean;
  readonly collection: string;
}

export class SecretsService {
  private readonly log: (line: string) => void;

  constructor(private readonly dependencies: ServiceDependencies) {
    this.log = dependencies.log ?? (line => { process.stderr.write(`${line}\n`); });
  }

  private async visibleItems(ops: VaultOperations, names: readonly string[]) {
    const allowed = resolveCollections(names, await ops.listCollections(), this.log);
    return { allowed, items: visibleIn(await ops.listItems(), allowed) };
  }

  /** Find a visible item, syncing once on a miss (the CLI reads a local copy). */
  private async locate(
    ops: VaultOperations,
    names: readonly string[],
    reference: string,
    accept: (item: BwItem) => boolean = () => true,
  ) {
    await ops.syncIfStale();
    let view = await this.visibleItems(ops, names);
    let item = findItem(view.items, reference);
    if (!item || !accept(item)) {
      await ops.sync();
      view = await this.visibleItems(ops, names);
      item = findItem(view.items, reference);
    }
    if (!item) throw new SecretsError('ITEM_NOT_FOUND', 'No visible item has this name');
    return { item, allowed: view.allowed };
  }

  async listItems(access: Access, filter: { collection?: string; search?: string }, taint: Taint) {
    if (filter.collection !== undefined && !access.metaCollections.includes(filter.collection)) {
      throw new SecretsError('COLLECTION_NOT_ALLOWED', 'That collection is not visible to you');
    }
    const names = filter.collection !== undefined ? [filter.collection] : access.metaCollections;
    return this.dependencies.vault.withLock(async ops => {
      await ops.sync();
      const { allowed, items } = await this.visibleItems(ops, names);
      const search = filter.search?.toLowerCase();
      const listed: ListedItem[] = items
        .filter(item => !search || nameOf(item).toLowerCase().includes(search))
        .map(item => {
          taint.addItem(item);
          return { name: nameOf(item), collections: collectionNames(item, allowed), revision_date: revisionOf(item) };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
      return { items: listed.slice(0, MAX_LISTED_ITEMS), truncated: listed.length > MAX_LISTED_ITEMS };
    });
  }

  async listKeys(access: Access, reference: string, taint: Taint) {
    return this.dependencies.vault.withLock(async ops => {
      const { item, allowed } = await this.locate(ops, access.metaCollections, reference);
      taint.addItem(item);
      return { item: nameOf(item), collections: collectionNames(item, allowed), keys: keyNames(item) };
    });
  }

  async getSecret(access: Access, reference: string, key: string, taint: Taint) {
    return this.dependencies.vault.withLock(async ops => {
      const hasKey = (item: BwItem) => itemEntries(item).some(entry => normalizeKey(entry.name) === normalizeKey(key));
      const { item, allowed } = await this.locate(ops, access.readCollections, reference, hasKey);
      taint.addItem(item);
      const value = findValue(item, key);
      return { item: nameOf(item), key, value, collections: collectionNames(item, allowed) };
    });
  }

  /**
   * Create-or-update `key` in an item of the write collection, keeping every
   * other byte of its notes. Only items whose VISIBLE collections are exactly
   * the write collection are writable: an item also shared into another
   * collection the machine account is a member of is refused, as is any name
   * that exists outside the write collection, with one fixed message that
   * says nothing about where or whether the other item exists. An existing key
   * is replaced only with `replaceExisting`.
   *
   * VAULT LIMITATION: `collectionIds` as the CLI sees them only lists the
   * collections the machine account can access. An item of the write
   * collection that someone also put into a collection the account is NOT a
   * member of looks write-only here and WILL be written. The owner rule
   * (bootstrap-owner-steps.md, step 3.5) is that items of the write
   * collection are MCP-owned and never added to any other collection; the
   * runbook has a read-only database check for it.
   */
  async writeKey(
    access: Access,
    reference: string,
    key: string,
    value: string,
    taint: Taint,
    replaceExisting = false,
  ): Promise<WriteResult> {
    const writeCollection = access.writeCollection;
    if (!writeCollection) throw new SecretsError('FORBIDDEN', 'Writing requires the writer role');
    taint.add(value);
    const refused = () => new SecretsError('FORBIDDEN', WRITE_REFUSED_MESSAGE);
    return this.dependencies.vault.withLock(async ops => {
      // Always a forced sync (reads are throttled, writes are not): the
      // read-modify-write starts from the vault's current copy. If the item
      // still changes before the edit lands, the vault refuses the edit as
      // out of date and the call ends in VAULT_CONFLICT (retryable).
      await ops.sync({ force: true });
      const collections = await ops.listCollections();
      const write = resolveCollections([writeCollection], collections, this.log);
      const [writeId, writeInfo] = [...write.entries()][0]!;
      const onlyInWrite = (item: BwItem) => {
        const ids = collectionIdsOf(item);
        return ids.length === 1 && ids[0] === writeId;
      };
      const all = await ops.listItems();
      const lower = reference.toLowerCase();
      const sameName = all.filter(item => idOf(item) === reference || nameOf(item).toLowerCase() === lower);
      if (sameName.some(item => !onlyInWrite(item))) throw refused();
      const target = findItem(sameName, reference);
      if (!target) {
        await ops.createItem({
          organizationId: writeInfo.organizationId,
          collectionIds: [writeId],
          folderId: null,
          type: 2,
          name: reference,
          notes: `${key}=${value}`,
          favorite: false,
          fields: [],
          login: null,
          secureNote: { type: 0 },
          card: null,
          identity: null,
          reprompt: 0,
        });
        return { item: reference, key, action: 'created', item_created: true, collection: writeInfo.name };
      }
      const fresh = await ops.getItem(idOf(target));
      taint.addItem(fresh);
      if (!onlyInWrite(fresh)) throw refused();
      const wanted = normalizeKey(key);
      const existing = itemEntries(fresh).filter(entry => normalizeKey(entry.name) === wanted);
      if (existing.some(entry => entry.source !== 'notes')) {
        throw new SecretsError('KEY_CONFLICT', 'The key exists as a custom field or login field; change it by hand');
      }
      if (existing.length > 0 && !replaceExisting) {
        throw new SecretsError('KEY_EXISTS', 'The key already exists in this item; pass replace_existing: true to rotate it');
      }
      const update = upsertNoteLine(typeof fresh.notes === 'string' ? fresh.notes : '', key, value);
      await ops.editItem(idOf(fresh), { ...fresh, notes: update.notes });
      return {
        item: reference,
        key,
        action: update.action === 'replaced' ? 'rotated' : 'created',
        item_created: false,
        collection: writeInfo.name,
      };
    });
  }
}
