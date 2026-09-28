import { describe, expect, it } from 'vitest';
import { WRITE_REFUSED_MESSAGE } from '../src/secrets.js';
import { VALUE_IN_CONTEXT_WARNING } from '../src/tools.js';
import { SESSION_LOCKED_MESSAGE } from '../src/types.js';
import {
  containsAnySentinel,
  errorCode,
  errorMessage,
  harness,
  HIDDEN_ITEM,
  INFRA_ITEM,
  LOGIN_ITEM,
  OTHER_ORG_ITEM,
  PERSONAL_ITEM,
  SENTINEL_FIELD,
  SENTINEL_HIDDEN,
  SENTINEL_INFRA,
  SENTINEL_LOGIN,
  SENTINEL_OTHER,
  SENTINEL_OTHER_ORG,
  SENTINEL_PERSONAL,
  SENTINEL_SHARED,
  SENTINEL_WRITABLE,
  SHARED_ITEM,
  WRITABLE_NOTES,
} from './fixtures.js';

const ALL_ORG_ITEMS = ['app: generated', HIDDEN_ITEM, INFRA_ITEM, LOGIN_ITEM, OTHER_ORG_ITEM, SHARED_ITEM].sort();

function names(answer: { structured: Record<string, unknown> }): string[] {
  return (answer.structured.items as Array<{ name: string }>).map(item => item.name).sort();
}

describe('default scope: every organization, never the personal vault', () => {
  it('lists the items of every organization the user belongs to, and no personal item', async () => {
    const h = harness();
    const items = await h.call('secrets_list_items', {});
    expect(items.isError).toBe(false);
    expect(names(items)).toEqual(ALL_ORG_ITEMS);
    expect(items.raw).not.toContain(PERSONAL_ITEM);
    const search = await h.call('secrets_list_items', { search: 'personal' });
    expect(search.structured.items).toEqual([]);
  });

  it('a personal item cannot be reached by name or by id', async () => {
    const h = harness();
    for (const item of [PERSONAL_ITEM, 'item-personal']) {
      const keys = await h.call('secrets_list_keys', { item });
      expect(errorCode(keys)).toBe('ITEM_NOT_FOUND');
      const get = await h.call('secrets_get_secret', { item, key: 'PERSONAL_KEY' });
      expect(errorCode(get)).toBe('ITEM_NOT_FOUND');
      expect(get.raw).not.toContain(SENTINEL_PERSONAL);
    }
    // Not even a write to a personal item's name touches it.
    const write = await h.call('secrets_generate_secret', { item: PERSONAL_ITEM, key: 'PERSONAL_KEY', replace_existing: true });
    expect(write.isError).toBe(false);
    const personal = h.vault.state().items.find(i => i.id === 'item-personal')!;
    expect(personal.notes).toBe(`PERSONAL_KEY=${SENTINEL_PERSONAL}`);
    expect(h.audit.join('\n')).not.toContain(SENTINEL_PERSONAL);
    expect(h.logs.join('\n')).not.toContain(SENTINEL_PERSONAL);
  });

  it('reads one value with the context warning, and exactly one', async () => {
    const h = harness();
    const get = await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'example-admin-token' });
    expect(get.isError).toBe(false);
    expect(get.structured).toMatchObject({ item: INFRA_ITEM, value: SENTINEL_INFRA, warning: VALUE_IN_CONTEXT_WARNING });
    expect(get.text.startsWith('WARNING: this secret value is now in the model context')).toBe(true);
    expect(containsAnySentinel(get.raw, [SENTINEL_INFRA])).toBeUndefined();
  });

  it('reads custom fields and login fields like the secret wrapper', async () => {
    const h = harness();
    const field = await h.call('secrets_get_secret', { item: LOGIN_ITEM, key: 'API_KEY' });
    expect(field.structured.value).toBe(SENTINEL_FIELD);
    const login = await h.call('secrets_get_secret', { item: LOGIN_ITEM, key: 'Password' });
    expect(login.structured.value).toBe(SENTINEL_LOGIN);
    const keys = await h.call('secrets_list_keys', { item: LOGIN_ITEM });
    expect(keys.structured.keys).toEqual(['api_key', 'username', 'password']);
    expect(containsAnySentinel(keys.raw)).toBeUndefined();
  });

  it('list_keys hides note "keys" that look like secret material or have no value', async () => {
    const blob = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w';
    const h = harness({
      state: state => {
        state.items[0]!.notes = [
          'GOOD_KEY=value-one',
          `${blob}==`,
          `${'A'.repeat(70)}=long-name-value`,
          'EMPTY_KEY=',
          'SPACES_ONLY=   ',
          'ANOTHER_GOOD=value-two',
        ].join('\n');
      },
    });
    const keys = await h.call('secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.structured.keys).toEqual(['GOOD_KEY', 'ANOTHER_GOOD']);
    expect(keys.raw).not.toContain(blob);
  });

  it('refuses a key that normalizes to nothing', async () => {
    const h = harness({ state: state => { state.items[0]!.notes += '_=punctuation-only-key-value\n'; } });
    for (const key of ['_', '_.-']) {
      const answer = await h.call('secrets_get_secret', { item: INFRA_ITEM, key });
      expect(errorCode(answer)).toBe('INVALID_ARGUMENT');
    }
    const keys = await h.call('secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.structured.keys).toEqual(['EXAMPLE_ADMIN_TOKEN', 'OTHER_KEY']);
  });
});

describe('local scope config', () => {
  it('organizations (by name or id) limit what is visible, not even names leak', async () => {
    for (const reference of ['Example Org', 'org-test']) {
      const h = harness({ scope: { organizations: [reference] } });
      const items = await h.call('secrets_list_items', {});
      expect(names(items)).toEqual(ALL_ORG_ITEMS.filter(name => name !== OTHER_ORG_ITEM));
      expect(items.raw).not.toContain('Partner/shared');
      const get = await h.call('secrets_get_secret', { item: OTHER_ORG_ITEM, key: 'PARTNER_KEY' });
      expect(errorCode(get)).toBe('ITEM_NOT_FOUND');
      expect(get.raw).not.toContain(SENTINEL_OTHER_ORG);
    }
  });

  it('read_collections limit items to those collections plus the write collection', async () => {
    const h = harness({ scope: { readCollections: ['Infra/example'] } });
    const items = await h.call('secrets_list_items', {});
    expect(names(items)).toEqual(['app: generated', INFRA_ITEM, LOGIN_ITEM, SHARED_ITEM].sort());
    expect(items.raw).not.toContain(HIDDEN_ITEM);
    expect(items.raw).not.toContain('Finance/private');
    // An item in an allowed and a hidden collection shows only the allowed name.
    const shared = await h.call('secrets_list_items', { search: 'shared' });
    expect(shared.structured.items).toEqual([{ name: SHARED_ITEM, collections: ['MCP/writable'], revision_date: '2026-09-05T00:00:00.000Z' }]);
    const hidden = await h.call('secrets_get_secret', { item: HIDDEN_ITEM, key: 'BANK_TOKEN' });
    expect(errorCode(hidden)).toBe('ITEM_NOT_FOUND');
    expect(hidden.raw).not.toContain(SENTINEL_HIDDEN);
    const byId = await h.call('secrets_get_secret', { item: 'item-hidden', key: 'BANK_TOKEN' });
    expect(errorCode(byId)).toBe('ITEM_NOT_FOUND');
    const byCollection = await h.call('secrets_list_items', { collection: 'Finance/private' });
    expect(errorCode(byCollection)).toBe('COLLECTION_NOT_ALLOWED');
    const onlyInfra = await h.call('secrets_list_items', { collection: 'Infra/example' });
    expect(names(onlyInfra)).toEqual([INFRA_ITEM, LOGIN_ITEM].sort());
  });

  it('a configured organization or collection the account cannot see fails closed', async () => {
    const org = harness({ scope: { organizations: ['No Such Org'] } });
    const a = await org.call('secrets_list_items', {});
    expect(errorCode(a)).toBe('SCOPE_UNRESOLVED');
    expect(org.logs.join('\n')).toContain('organization_not_found organization="No Such Org"');
    const collection = harness({ scope: { readCollections: ['Ops/restricted'] } });
    const b = await collection.call('secrets_list_items', {});
    expect(errorCode(b)).toBe('SCOPE_UNRESOLVED');
    // A collection of an organization outside the configured ones is not found either.
    const outside = harness({ scope: { organizations: ['Example Org'], readCollections: ['Partner/shared'] } });
    expect(errorCode(await outside.call('secrets_list_items', {}))).toBe('SCOPE_UNRESOLVED');
  });

  it('writes are disabled while write_collection is unset', async () => {
    const h = harness({ scope: { writeCollection: null }, allowSet: true });
    const generate = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(generate)).toBe('WRITE_DISABLED');
    const set = await h.call('secrets_set_secret', { item: 'app: generated', key: 'NEW_KEY', value: 'x'.repeat(20) });
    expect(errorCode(set)).toBe('WRITE_DISABLED');
    expect(h.vault.state().writes).toBe(0);
    // Reads still work.
    expect((await h.call('secrets_list_items', {})).isError).toBe(false);
  });
});

describe('value_collections and allow_rotate', () => {
  it('secrets_get_secret is disabled until value_collections is set, before any bw call', async () => {
    const h = harness({ scope: { valueCollections: null } });
    const get = await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    expect(errorCode(get)).toBe('GET_DISABLED');
    expect(h.runner.tracker.calls).toBe(0);
    // Names and keys are still listed.
    expect((await h.call('secrets_list_keys', { item: INFRA_ITEM })).isError).toBe(false);
    expect(JSON.parse(h.audit[0]!)).toMatchObject({ outcome: 'denied', error_code: 'GET_DISABLED' });
  });

  it('returns values only from items in a value collection', async () => {
    const h = harness({ scope: { valueCollections: ['Infra/example'] } });
    expect((await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' })).structured.value).toBe(SENTINEL_OTHER);
    for (const [item, key] of [[HIDDEN_ITEM, 'BANK_TOKEN'], [OTHER_ORG_ITEM, 'PARTNER_KEY'], ['app: generated', 'EXISTING']] as const) {
      const get = await h.call('secrets_get_secret', { item, key });
      expect(errorCode(get)).toBe('GET_DISABLED');
      expect(containsAnySentinel(get.raw)).toBeUndefined();
      expect((await h.call('secrets_list_keys', { item })).isError).toBe(false);
    }
    // An item shared into a value collection and another one is readable.
    const shared = harness({ scope: { valueCollections: ['Finance/private'] } });
    expect((await shared.call('secrets_get_secret', { item: SHARED_ITEM, key: 'SHARED_KEY' })).structured.value).toBe(SENTINEL_SHARED);
  });

  it('a value collection the account cannot see fails closed', async () => {
    const h = harness({ scope: { valueCollections: ['Ops/restricted'] } });
    expect(errorCode(await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }))).toBe('SCOPE_UNRESOLVED');
  });

  it('replace_existing is refused unless allow_rotate, for generate and set, before any bw call', async () => {
    const h = harness({ allowRotate: false, allowSet: true });
    const generate = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING', replace_existing: true });
    expect(errorCode(generate)).toBe('ROTATE_DISABLED');
    const set = await h.call('secrets_set_secret', { item: 'app: generated', key: 'EXISTING', value: 'another-value-123456', replace_existing: true });
    expect(errorCode(set)).toBe('ROTATE_DISABLED');
    expect(h.runner.tracker.calls).toBe(0);
    // Adding a new key still works; an existing one without the flag is KEY_EXISTS.
    expect((await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' })).isError).toBe(false);
    expect(errorCode(await h.call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING' }))).toBe('KEY_EXISTS');
    expect(h.vault.state().items.find(i => i.id === 'item-writable')!.notes).toContain(`EXISTING=${SENTINEL_WRITABLE}`);
  });
});

describe('session', () => {
  it('no session file: SESSION_LOCKED with the fixed message, and bw is never run', async () => {
    const h = harness();
    h.session = null;
    for (const [tool, args] of [
      ['secrets_list_items', {}],
      ['secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }],
      ['secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' }],
    ] as const) {
      const answer = await h.call(tool, args);
      expect(errorCode(answer)).toBe('SESSION_LOCKED');
      expect(errorMessage(answer)).toBe(SESSION_LOCKED_MESSAGE);
    }
    expect(h.runner.tracker.calls).toBe(0);
    expect(JSON.parse(h.audit.at(-1)!)).toMatchObject({ outcome: 'denied', error_code: 'SESSION_LOCKED' });
  });

  it('a session bw no longer accepts (bw lock, logout) is SESSION_LOCKED too', async () => {
    const h = harness();
    expect((await h.call('secrets_list_items', {})).isError).toBe(false);
    h.vault.update(state => { state.sessions = []; });
    const locked = await h.call('secrets_list_keys', { item: INFRA_ITEM });
    expect(errorCode(locked)).toBe('SESSION_LOCKED');
    expect(errorMessage(locked)).toBe(SESSION_LOCKED_MESSAGE);
    h.vault.update(state => { state.loggedIn = false; });
    h.advance(120_000);
    const loggedOut = await h.call('secrets_list_items', {});
    expect(errorCode(loggedOut)).toBe('SESSION_LOCKED');
    // After a new unlock the same MCP process works again, without a restart.
    h.vault.update(state => { state.loggedIn = true; });
    h.session = h.vault.unlock();
    expect((await h.call('secrets_list_keys', { item: INFRA_ITEM })).isError).toBe(false);
  });

  it('refuses a bw configured for another server, before listing anything', async () => {
    const h = harness({ state: state => { state.serverUrl = 'https://vault.bitwarden.com'; } });
    const answer = await h.call('secrets_list_items', {});
    expect(errorCode(answer)).toBe('VAULT_SERVER_MISMATCH');
    expect(errorMessage(answer)).toContain('bw config server https://vault.example.test');
    expect(h.vault.state().calls.map(call => call.args[0])).toEqual(['unlock', 'status']);
  });
});

describe('sync', () => {
  it('a missing key syncs at most once per 30 s', async () => {
    const h = harness();
    await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'EXAMPLE_ADMIN_TOKEN' });
    const first = h.vault.state().syncs;
    expect(first).toBe(1);
    for (let i = 0; i < 5; i += 1) {
      const miss = await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'NOPE' });
      expect(errorCode(miss)).toBe('KEY_NOT_FOUND');
      await h.call('secrets_list_items', {});
    }
    expect(h.vault.state().syncs).toBe(first);
    h.advance(30_001);
    await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'NOPE' });
    expect(h.vault.state().syncs).toBe(first + 1);
  });

  it('every write forces a sync, bypassing the read throttle', async () => {
    const h = harness();
    await h.call('secrets_list_items', {});
    const before = h.vault.state().syncs;
    await h.call('secrets_generate_secret', { item: 'app: generated', key: 'A_KEY' });
    await h.call('secrets_generate_secret', { item: 'app: generated', key: 'B_KEY' });
    expect(h.vault.state().syncs).toBe(before + 2);
    await h.call('secrets_list_items', {});
    expect(h.vault.state().syncs).toBe(before + 2);
  });

  it('an edit refused as out of date is VAULT_CONFLICT, retryable', async () => {
    let bumped = false;
    const h = harness({
      beforeBw: (args, vault) => {
        if (args[0] === 'edit' && !bumped) {
          bumped = true;
          vault.update(state => { state.items.find(i => i.id === 'item-writable')!.revisionDate = '2026-09-28T00:00:00.000Z'; });
        }
      },
    });
    const answer = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(answer)).toBe('VAULT_CONFLICT');
    expect((answer.structured.error as { retryable?: boolean }).retryable).toBe(true);
    expect(h.vault.state().writes).toBe(0);
    expect(h.logs).toContain('dumont-secrets-mcp bw outcome=out_of_date command=edit');
    const retry = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(retry.isError).toBe(false);
  });
});

describe('write scope', () => {
  it('writes only to items whose collections are exactly the write collection, with one refusal message', async () => {
    const h = harness();
    const shared = await h.call('secrets_generate_secret', { item: SHARED_ITEM, key: 'NEW_KEY' });
    const outside = await h.call('secrets_generate_secret', { item: INFRA_ITEM, key: 'NEW_KEY' });
    const otherOrg = await h.call('secrets_generate_secret', { item: OTHER_ORG_ITEM, key: 'NEW_KEY' });
    const hiddenById = await h.call('secrets_generate_secret', { item: 'item-hidden', key: 'NEW_KEY' });
    for (const answer of [shared, outside, otherOrg, hiddenById]) {
      expect(errorCode(answer)).toBe('FORBIDDEN');
      expect(errorMessage(answer)).toBe(WRITE_REFUSED_MESSAGE);
      expect(containsAnySentinel(answer.raw)).toBeUndefined();
    }
    expect(h.vault.state().writes).toBe(0);
    expect(h.vault.state().items.find(i => i.id === 'item-shared')!.notes).toBe(`SHARED_KEY=${SENTINEL_SHARED}`);
  });

  it('VAULT LIMITATION (documented): a collection you are not a member of is invisible, so the item is written', async () => {
    const h = harness({ state: state => { state.items[2]!.collectionIds = ['col-writable', 'col-nonmember']; } });
    const answer = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(answer.isError).toBe(false);
    const stored = h.vault.state().items.find(i => i.id === 'item-writable')!;
    expect(stored.collectionIds).toEqual(['col-writable', 'col-nonmember']);
    expect(stored.notes as string).toContain('NEW_KEY=');
    const items = await h.call('secrets_list_items', {});
    expect(items.raw).not.toContain('Ops/restricted');
  });

  it('re-checks the collections on the fresh copy it is about to edit', async () => {
    let shareBeforeGet = true;
    const h = harness({
      beforeBw: (args, vault) => {
        if (args[0] === 'get' && shareBeforeGet) {
          shareBeforeGet = false;
          vault.update(state => { state.items.find(i => i.id === 'item-writable')!.collectionIds = ['col-writable', 'col-hidden']; });
        }
      },
    });
    const answer = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(answer)).toBe('FORBIDDEN');
    expect(errorMessage(answer)).toBe(WRITE_REFUSED_MESSAGE);
    expect(h.vault.state().writes).toBe(0);
  });

  it('a write collection outside the configured organizations is not found', async () => {
    const h = harness({ scope: { organizations: ['Partner Org'], writeCollection: 'MCP/writable' } });
    const answer = await h.call('secrets_generate_secret', { item: 'svc: new', key: 'NEW_KEY' });
    expect(errorCode(answer)).toBe('SCOPE_UNRESOLVED');
    expect(h.vault.state().writes).toBe(0);
  });
});

describe('secrets_generate_secret', () => {
  it('refuses to replace an existing key unless replace_existing is true', async () => {
    const h = harness();
    const refused = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING' });
    expect(errorCode(refused)).toBe('KEY_EXISTS');
    expect(h.vault.state().writes).toBe(0);
    const rotated = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING', replace_existing: true });
    expect(rotated.structured).toMatchObject({ action: 'rotated' });
  });

  it('rotates one line, keeps every other byte of the notes, and never returns the value', async () => {
    const h = harness();
    const answer = await h.call('secrets_generate_secret', {
      item: 'app: generated', key: 'EXISTING', length: 32, alphabet: 'hex', replace_existing: true,
    });
    expect(answer.isError).toBe(false);
    expect(answer.structured).toEqual({ item: 'app: generated', key: 'EXISTING', action: 'rotated', item_created: false, length: 32 });
    const notes = h.vault.state().items.find(i => i.id === 'item-writable')!.notes as string;
    const match = /EXISTING=([0-9a-f]{32})\r\n/.exec(notes);
    expect(match).not.toBeNull();
    expect(notes).toBe(WRITABLE_NOTES.replace(`EXISTING=${SENTINEL_WRITABLE}`, `EXISTING=${match![1]}`));
    expect(answer.raw).not.toContain(match![1]);
    expect(h.audit.join('\n')).not.toContain(match![1]);
  });

  it('appends a new key with the item\'s own line ending and no other change', async () => {
    const h = harness();
    const answer = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY', length: 16, alphabet: 'alnum' });
    expect(answer.structured).toMatchObject({ action: 'created', item_created: false, length: 16 });
    const notes = h.vault.state().items.find(i => i.id === 'item-writable')!.notes as string;
    expect(notes.startsWith(`${WRITABLE_NOTES}\r\nNEW_KEY=`)).toBe(true);
    expect(/NEW_KEY=([A-Za-z0-9]{16})$/.test(notes)).toBe(true);
  });

  it('creates a Secure Note in the write collection when the item does not exist', async () => {
    const h = harness();
    const answer = await h.call('secrets_generate_secret', { item: 'svc: brand new', key: 'API_TOKEN' });
    expect(answer.structured).toEqual({ item: 'svc: brand new', key: 'API_TOKEN', action: 'created', item_created: true, length: 48 });
    const created = h.vault.state().items.find(i => i.name === 'svc: brand new')!;
    expect(created).toMatchObject({ type: 2, organizationId: 'org-test', collectionIds: ['col-writable'], secureNote: { type: 0 } });
    expect(/^API_TOKEN=[A-Za-z0-9_-]{48}$/.test(created.notes as string)).toBe(true);
    const createCall = h.vault.state().calls.find(call => call.args[0] === 'create')!;
    expect(createCall.args).toEqual(['create', 'item']);
    expect(createCall.stdin).toBe(true);
  });

  it('validates the key, the item name and the length, and audits only validated fields', async () => {
    const h = harness();
    for (const args of [
      { item: 'app: generated', key: 'lower_case' },
      { item: 'app: generated', key: '1STARTS_WITH_DIGIT' },
      { item: 'bad\nname', key: 'OK_KEY' },
      { item: ' padded', key: 'OK_KEY' },
      { item: 'x'.repeat(201), key: 'OK_KEY' },
    ]) {
      const answer = await h.call('secrets_generate_secret', args);
      expect(answer.isError).toBe(true);
    }
    const tooShort = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'OK_KEY', length: 8 });
    expect(tooShort.isError).toBe(true);
    expect(h.vault.state().writes).toBe(0);
    const audited = h.audit.map(line => JSON.parse(line) as Record<string, unknown>);
    expect(audited[2]).toMatchObject({ item: null, key: null, error_code: 'INVALID_ARGUMENT' });
    expect(audited[0]).toMatchObject({ item: 'app: generated', key: null });
  });

  it('refuses a key that lives in a custom field instead of shadowing it', async () => {
    const h = harness({
      state: state => { state.items[2]!.fields = [{ name: 'FIELD_KEY', value: 'field-value-12345678', type: 1 }]; },
    });
    const answer = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'FIELD_KEY', replace_existing: true });
    expect(errorCode(answer)).toBe('KEY_CONFLICT');
  });

  it('a guard hit after the vault changed still reads as success, and the audit says guard=fired', async () => {
    const h = harness({ state: state => { state.items[2]!.notes = 'NAME_COPY=app: generated\n'; } });
    const answer = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(answer.isError).toBe(false);
    expect(answer.structured).toEqual({ written: true });
    expect(answer.text).toBe('Write completed; details withheld by the output guard.');
    expect(h.vault.state().writes).toBe(1);
    expect(JSON.parse(h.audit.at(-1)!)).toMatchObject({ outcome: 'ok', error_code: null, guard: 'fired' });
  });
});

describe('secrets_set_secret', () => {
  const VALUE = 'SENTINEL-set-value-0007-abcdef';

  it('is disabled by default', async () => {
    const h = harness();
    const answer = await h.call('secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: VALUE });
    expect(errorCode(answer)).toBe('SET_DISABLED');
    expect(answer.raw).not.toContain(VALUE);
    expect(h.audit.join('\n')).not.toContain(VALUE);
    expect(h.vault.state().writes).toBe(0);
  });

  it('when enabled, writes only a single line and answers with a confirmation only', async () => {
    const h = harness({ allowSet: true });
    const multi = await h.call('secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: `${VALUE}\nINJECTED=1` });
    expect(errorCode(multi)).toBe('INVALID_ARGUMENT');
    expect(multi.raw).not.toContain(VALUE);
    const ok = await h.call('secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: VALUE });
    expect(ok.structured).toEqual({ item: 'app: generated', key: 'SET_KEY', action: 'created', item_created: false });
    expect(ok.raw).not.toContain(VALUE);
    expect(h.vault.state().items.find(i => i.id === 'item-writable')!.notes).toBe(`${WRITABLE_NOTES}\r\nSET_KEY=${VALUE}`);
    const again = await h.call('secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: `${VALUE}-2` });
    expect(errorCode(again)).toBe('KEY_EXISTS');
  });
});

describe('audit and output safety', () => {
  it('no sentinel value ever reaches an audit line, a log line, an error, or a non-get answer', async () => {
    const h = harness({ allowSet: true });
    const answers = [
      await h.call('secrets_list_items', {}),
      await h.call('secrets_list_items', { search: 'svc' }),
      await h.call('secrets_list_keys', { item: INFRA_ITEM }),
      await h.call('secrets_list_keys', { item: LOGIN_ITEM }),
      await h.call('secrets_list_keys', { item: SHARED_ITEM }),
      await h.call('secrets_list_keys', { item: PERSONAL_ITEM }),
      await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'MISSING' }),
      await h.call('secrets_get_secret', { item: PERSONAL_ITEM, key: 'PERSONAL_KEY' }),
      await h.call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING' }),
      await h.call('secrets_generate_secret', { item: 'app: generated', key: 'EXISTING', replace_existing: true }),
      await h.call('secrets_generate_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }),
      await h.call('secrets_generate_secret', { item: SHARED_ITEM, key: 'SHARED_KEY', replace_existing: true }),
      await h.call('secrets_set_secret', { item: 'app: generated', key: 'LAST', value: 'another-value-123456', replace_existing: true }),
    ];
    for (const answer of answers) expect(containsAnySentinel(answer.raw)).toBeUndefined();
    const get = await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    expect(get.structured.value).toBe(SENTINEL_OTHER);
    const audit = h.audit.join('\n');
    expect(containsAnySentinel(audit)).toBeUndefined();
    expect(audit).not.toContain('another-value-123456');
    expect(audit).not.toContain(h.session!);
    expect(containsAnySentinel(h.logs.join('\n'))).toBeUndefined();
    expect(h.logs.join('\n')).not.toContain(h.session!);
  });

  it('listings are checked structurally only: a value equal to a key name does not block them', async () => {
    const h = harness({ state: state => { state.items[0]!.notes = 'FIRST_KEY_NAME=SECOND_KEY_NAME\nSECOND_KEY_NAME=some-value-here\n'; } });
    const keys = await h.call('secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.isError).toBe(false);
    expect(keys.structured.keys).toEqual(['FIRST_KEY_NAME', 'SECOND_KEY_NAME']);
    expect(keys.raw).not.toContain('some-value-here');
  });

  it('writes one audit line per call with the documented fields', async () => {
    const h = harness();
    await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    h.session = null;
    await h.call('secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    expect(h.audit).toHaveLength(2);
    const [ok, locked] = h.audit.map(line => JSON.parse(line) as Record<string, unknown>);
    expect(Object.keys(ok!).sort()).toEqual(['collection', 'error_code', 'item', 'key', 'latency_ms', 'outcome', 'tool', 'ts']);
    expect(ok).toMatchObject({
      tool: 'secrets_get_secret', item: INFRA_ITEM, key: 'OTHER_KEY', collection: 'Infra/example', outcome: 'ok', error_code: null,
    });
    expect(locked).toMatchObject({ outcome: 'denied', error_code: 'SESSION_LOCKED', item: INFRA_ITEM, key: 'OTHER_KEY' });
  });

  it('never forwards raw bw JSON, even when the vault echoes items', async () => {
    const h = harness();
    const answers = [
      await h.call('secrets_generate_secret', { item: 'svc: another', key: 'TOKEN' }),
      await h.call('secrets_list_items', {}),
      await h.call('secrets_list_keys', { item: 'app: generated' }),
    ];
    for (const answer of answers) {
      expect(answer.raw).not.toMatch(/\\?"(object|organizationId|collectionIds|notes|login|fields)\\?"\s*:/);
    }
  });

  it('rate-limits the process: all tools, and writes separately', async () => {
    const h = harness({ rateLimitPerMinute: 4, writeRateLimitPerMinute: 1 });
    const results = [];
    for (let i = 0; i < 3; i += 1) results.push(await h.call('secrets_list_keys', { item: INFRA_ITEM }));
    const w1 = await h.call('secrets_generate_secret', { item: 'app: generated', key: 'A_KEY' });
    expect(results.every(answer => !answer.isError)).toBe(true);
    expect(w1.isError).toBe(false);
    const over = await h.call('secrets_list_keys', { item: INFRA_ITEM });
    expect(errorCode(over)).toBe('RATE_LIMITED');
    expect(JSON.parse(h.audit.at(-1)!)).toMatchObject({ outcome: 'denied', error_code: 'RATE_LIMITED' });
    const w = harness({ writeRateLimitPerMinute: 1 });
    expect((await w.call('secrets_generate_secret', { item: 'app: generated', key: 'A_KEY' })).isError).toBe(false);
    expect(errorCode(await w.call('secrets_generate_secret', { item: 'app: generated', key: 'B_KEY' }))).toBe('RATE_LIMITED');
    expect((await w.call('secrets_list_items', {})).isError).toBe(false);
  });
});
