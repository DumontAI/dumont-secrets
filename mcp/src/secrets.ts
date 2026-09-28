import { randomBytes } from 'node:crypto';
import type { BwCollection, BwOrganization, BwVault, VaultOperations } from './bw.js';
import { findValue, itemEntries, itemSecretStrings, keyNames, normalizeKey, upsertNoteLine, type BwItem } from './notes.js';
import { SecretsError, type ScopeConfig } from './types.js';

export type Alphabet = 'base64url' | 'hex' | 'alnum';

/** One refusal for every "not writable" case, so the answer reveals nothing about other collections. */
export const WRITE_REFUSED_MESSAGE = 'Cannot write an item with this name';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
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

function orgOf(item: BwItem): string {
  return typeof item.organizationId === 'string' ? item.organizationId : '';
}

function revisionOf(item: BwItem): string | null {
  return typeof item.revisionDate === 'string' ? item.revisionDate : null;
}

/** Match by exact id, else by exact name. Exactly one match, or the call fails closed. */
function resolveOne<T extends { id: string; name: string }>(
  reference: string,
  candidates: readonly T[],
  kind: 'organization' | 'collection',
  log: (line: string) => void,
): T {
  const byId = candidates.filter(candidate => candidate.id === reference);
  const matches = byId.length > 0 ? byId : candidates.filter(candidate => candidate.name === reference);
  if (matches.length !== 1) {
    // The name is the user's own config; it goes to stderr (the client's MCP log), not to the caller.
    log(`dumont-secrets-mcp scope outcome=${kind}_${matches.length === 0 ? 'not_found' : 'ambiguous'} ${kind}=${JSON.stringify(reference)}`);
    throw new SecretsError(
      'SCOPE_UNRESOLVED',
      `A ${kind} named in your local Dumont Secrets MCP config is not available to your vault account (or matches more than one); check the MCP log and the config file`,
    );
  }
  return matches[0]!;
}

/**
 * What one call may see, resolved against the user's own vault:
 *   organizations  the configured ones (by name or id), or every one the user belongs to
 *   collections    of those organizations: the configured read_collections plus the
 *                  write_collection, or all of them when read_collections is unset
 * Personal-vault items are never in scope (bw.ts drops them before this runs).
 */
export interface ResolvedScope {
  readonly organizationIds: ReadonlySet<string>;
  /** Collections whose names may be shown, by id. */
  readonly collections: ReadonlyMap<string, BwCollection>;
  /** When true, an item must be in one of `collections` to be visible. */
  readonly restricted: boolean;
}

export function resolveScope(
  scope: ScopeConfig,
  organizations: readonly BwOrganization[],
  collections: readonly BwCollection[],
  log: (line: string) => void,
): ResolvedScope {
  const organizationIds = new Set(
    scope.organizations === null
      ? organizations.map(org => org.id)
      : scope.organizations.map(reference => resolveOne(reference, organizations, 'organization', log).id),
  );
  const inOrgs = collections.filter(collection => organizationIds.has(collection.organizationId));
  if (scope.readCollections === null) {
    return { organizationIds, collections: new Map(inOrgs.map(c => [c.id, c])), restricted: false };
  }
  const allowed = new Map<string, BwCollection>();
  const references = scope.writeCollection === null ? scope.readCollections : [...scope.readCollections, scope.writeCollection];
  for (const reference of references) {
    const collection = resolveOne(reference, inOrgs, 'collection', log);
    allowed.set(collection.id, collection);
  }
  return { organizationIds, collections: allowed, restricted: true };
}

function visibleIn(items: readonly BwItem[], scope: ResolvedScope): BwItem[] {
  return items.filter(item => {
    if (!scope.organizationIds.has(orgOf(item))) return false;
    return !scope.restricted || collectionIdsOf(item).some(id => scope.collections.has(id));
  });
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

function collectionNames(item: BwItem, scope: ResolvedScope): string[] {
  return collectionIdsOf(item)
    .map(id => scope.collections.get(id)?.name)
    .filter((name): name is string => typeof name === 'string')
    .sort();
}

export interface ServiceDependencies {
  readonly vault: BwVault;
  readonly scope: ScopeConfig;
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
  readonly scope: ScopeConfig;

  constructor(private readonly dependencies: ServiceDependencies) {
    this.log = dependencies.log ?? (line => { process.stderr.write(`${line}\n`); });
    this.scope = dependencies.scope;
  }

  private async view(ops: VaultOperations) {
    const scope = resolveScope(this.scope, await ops.listOrganizations(), await ops.listCollections(), this.log);
    return { scope, items: visibleIn(await ops.listItems(), scope) };
  }

  /** Find a visible item, syncing once on a miss (the CLI reads a local copy). */
  private async locate(ops: VaultOperations, reference: string, accept: (item: BwItem) => boolean = () => true) {
    await ops.syncIfStale();
    let view = await this.view(ops);
    let item = findItem(view.items, reference);
    if (!item || !accept(item)) {
      await ops.sync();
      view = await this.view(ops);
      item = findItem(view.items, reference);
    }
    if (!item) throw new SecretsError('ITEM_NOT_FOUND', 'No visible item has this name');
    return { item, scope: view.scope };
  }

  async listItems(filter: { collection?: string; search?: string }, taint: Taint) {
    return this.dependencies.vault.withLock(async ops => {
      await ops.sync();
      const { scope, items } = await this.view(ops);
      let listed = items;
      if (filter.collection !== undefined) {
        const wanted = new Set([...scope.collections.values()].filter(c => c.name === filter.collection || c.id === filter.collection).map(c => c.id));
        if (wanted.size === 0) throw new SecretsError('COLLECTION_NOT_ALLOWED', 'That collection is not visible to this MCP');
        listed = listed.filter(item => collectionIdsOf(item).some(id => wanted.has(id)));
      }
      const search = filter.search?.toLowerCase();
      const answer: ListedItem[] = listed
        .filter(item => !search || nameOf(item).toLowerCase().includes(search))
        .map(item => {
          taint.addItem(item);
          return { name: nameOf(item), collections: collectionNames(item, scope), revision_date: revisionOf(item) };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
      return { items: answer.slice(0, MAX_LISTED_ITEMS), truncated: answer.length > MAX_LISTED_ITEMS };
    });
  }

  async listKeys(reference: string, taint: Taint) {
    return this.dependencies.vault.withLock(async ops => {
      const { item, scope } = await this.locate(ops, reference);
      taint.addItem(item);
      return { item: nameOf(item), collections: collectionNames(item, scope), keys: keyNames(item) };
    });
  }

  /**
   * One value, and only from an item in one of the configured value_collections:
   * the tool that puts a value into the model context is off until the user names
   * the collections it may read from (a prompt-injected agent can then only reach
   * those). Listing names and keys is not affected.
   */
  async getSecret(reference: string, key: string, taint: Taint) {
    const valueCollections = this.scope.valueCollections;
    if (valueCollections === null) {
      throw new SecretsError('GET_DISABLED', 'secrets_get_secret is disabled: set value_collections in your local Dumont Secrets MCP config');
    }
    return this.dependencies.vault.withLock(async ops => {
      const hasKey = (item: BwItem) => itemEntries(item).some(entry => normalizeKey(entry.name) === normalizeKey(key));
      const { item, scope } = await this.locate(ops, reference, hasKey);
      const inOrgs = (await ops.listCollections()).filter(collection => scope.organizationIds.has(collection.organizationId));
      const valueIds = new Set(valueCollections.map(ref => resolveOne(ref, inOrgs, 'collection', this.log).id));
      if (!collectionIdsOf(item).some(id => valueIds.has(id))) {
        throw new SecretsError('GET_DISABLED', 'This item is not in one of your value_collections; its values cannot be returned');
      }
      taint.addItem(item);
      const value = findValue(item, key);
      return { item: nameOf(item), key, value, collections: collectionNames(item, scope) };
    });
  }

  /**
   * Create-or-update `key` in an item of the write collection, keeping every
   * other byte of its notes. Only items whose VISIBLE collections are exactly
   * the write collection are writable: an item also shared into another
   * collection you can see is refused, as is any name that exists outside the
   * write collection, with one fixed message that says nothing about where or
   * whether the other item exists. An existing key is replaced only with
   * `replaceExisting`.
   *
   * VAULT LIMITATION: `collectionIds` as the CLI sees them only lists the
   * collections YOUR account can access. An item of the write collection that
   * someone also put into a collection you are NOT a member of looks
   * write-only here and WILL be written. Keep the write collection for items
   * that live nowhere else (README, "Limitations").
   */
  async writeKey(reference: string, key: string, value: string, taint: Taint, replaceExisting = false): Promise<WriteResult> {
    const writeCollection = this.scope.writeCollection;
    if (!writeCollection) {
      throw new SecretsError('WRITE_DISABLED', 'Writes are disabled: set write_collection in your local Dumont Secrets MCP config');
    }
    taint.add(value);
    const refused = () => new SecretsError('FORBIDDEN', WRITE_REFUSED_MESSAGE);
    return this.dependencies.vault.withLock(async ops => {
      // Always a forced sync (reads are throttled, writes are not): the
      // read-modify-write starts from the vault's current copy. If the item
      // still changes before the edit lands, the vault refuses the edit as
      // out of date and the call ends in VAULT_CONFLICT (retryable).
      await ops.sync({ force: true });
      const scope = resolveScope(
        { ...this.scope, readCollections: null },
        await ops.listOrganizations(),
        await ops.listCollections(),
        this.log,
      );
      const writeInfo = resolveOne(writeCollection, [...scope.collections.values()], 'collection', this.log);
      const writeId = writeInfo.id;
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
