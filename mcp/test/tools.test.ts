import { describe, expect, it } from 'vitest';
import { WRITE_REFUSED_MESSAGE } from '../src/secrets.js';
import { VALUE_IN_CONTEXT_WARNING } from '../src/tools.js';
import {
  harness,
  INFRA_ITEM,
  LOGIN_ITEM,
  SENTINEL_FIELD,
  SENTINEL_HIDDEN,
  SENTINEL_INFRA,
  SENTINEL_LOGIN,
  SENTINEL_OTHER,
  SENTINEL_SHARED,
  SENTINEL_WRITABLE,
  SENTINELS,
  SHARED_ITEM,
  WRITABLE_NOTES,
} from './fixtures.js';

const VISIBLE_ITEMS = ['app: generated', INFRA_ITEM, LOGIN_ITEM, SHARED_ITEM].sort();

function errorCode(answer: { structured: Record<string, unknown> }): unknown {
  return (answer.structured.error as { code?: unknown } | undefined)?.code;
}

function errorMessage(answer: { structured: Record<string, unknown> }): unknown {
  return (answer.structured.error as { message?: unknown } | undefined)?.message;
}

function names(answer: { structured: Record<string, unknown> }): string[] {
  return (answer.structured.items as Array<{ name: string }>).map(item => item.name).sort();
}

function containsAnySentinel(text: string, except: string[] = []): string | undefined {
  return SENTINELS.filter(sentinel => !except.includes(sentinel)).find(sentinel => text.includes(sentinel));
}

describe('role matrix', () => {
  it('meta lists items and keys but cannot read a value', async () => {
    const h = harness();
    const items = await h.call(['meta'], 'secrets_list_items', {});
    expect(items.isError).toBe(false);
    expect(names(items)).toEqual(VISIBLE_ITEMS);
    const keys = await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.structured).toMatchObject({ item: INFRA_ITEM, keys: ['EXAMPLE_ADMIN_TOKEN', 'OTHER_KEY'] });
    const get = await h.call(['meta'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'EXAMPLE_ADMIN_TOKEN' });
    expect(get.isError).toBe(true);
    expect(errorCode(get)).toBe('FORBIDDEN');
    expect(containsAnySentinel(get.raw)).toBeUndefined();
    const write = await h.call(['meta'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(write)).toBe('FORBIDDEN');
  });

  it('writer can list and generate but cannot read a value, not even one it wrote', async () => {
    const h = harness();
    const generated = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(generated.isError).toBe(false);
    const get = await h.call(['writer'], 'secrets_get_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(get)).toBe('FORBIDDEN');
    const infra = await h.call(['writer'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'EXAMPLE_ADMIN_TOKEN' });
    expect(errorCode(infra)).toBe('FORBIDDEN');
    // Writer implies meta (names only), never reader.
    const items = await h.call(['writer'], 'secrets_list_items', {});
    expect(names(items)).toEqual(VISIBLE_ITEMS);
    expect(containsAnySentinel(items.raw)).toBeUndefined();
  });

  it('reader reads one value with the context warning, and cannot write', async () => {
    const h = harness();
    const get = await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'example-admin-token' });
    expect(get.isError).toBe(false);
    expect(get.structured).toMatchObject({ item: INFRA_ITEM, value: SENTINEL_INFRA, warning: VALUE_IN_CONTEXT_WARNING });
    expect(get.text.startsWith('WARNING: this secret value is now in the model context')).toBe(true);
    // Exactly one value: never the other key of the same item.
    expect(containsAnySentinel(get.raw, [SENTINEL_INFRA])).toBeUndefined();
    const write = await h.call(['reader'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(write)).toBe('FORBIDDEN');
    const set = await h.call(['reader'], 'secrets_set_secret', { item: 'app: generated', key: 'NEW_KEY', value: 'x'.repeat(20) });
    expect(errorCode(set)).toBe('FORBIDDEN');
  });

  it('reads custom fields and login fields like the secret wrapper', async () => {
    const h = harness();
    const field = await h.call(['reader'], 'secrets_get_secret', { item: LOGIN_ITEM, key: 'API_KEY' });
    expect(field.structured.value).toBe(SENTINEL_FIELD);
    const login = await h.call(['reader'], 'secrets_get_secret', { item: LOGIN_ITEM, key: 'Password' });
    expect(login.structured.value).toBe(SENTINEL_LOGIN);
    const keys = await h.call(['meta'], 'secrets_list_keys', { item: LOGIN_ITEM });
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
    const keys = await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.structured.keys).toEqual(['GOOD_KEY', 'ANOTHER_GOOD']);
    expect(keys.raw).not.toContain(blob);
  });

  it('refuses a key that normalizes to nothing', async () => {
    const h = harness({ state: state => { state.items[0]!.notes += '_=punctuation-only-key-value\n'; } });
    for (const key of ['_', '_.-']) {
      const answer = await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key });
      expect(errorCode(answer)).toBe('INVALID_ARGUMENT');
    }
    const keys = await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.structured.keys).toEqual(['EXAMPLE_ADMIN_TOKEN', 'OTHER_KEY']);
  });
});

describe('sync', () => {
  it('a missing key syncs at most once per 30 s, globally', async () => {
    const h = harness();
    await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'EXAMPLE_ADMIN_TOKEN' });
    const first = h.vault.state().syncs;
    expect(first).toBe(1);
    for (let i = 0; i < 5; i += 1) {
      const miss = await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'NOPE' });
      expect(errorCode(miss)).toBe('KEY_NOT_FOUND');
      await h.call(['meta'], 'secrets_list_items', {});
    }
    expect(h.vault.state().syncs).toBe(first);
    h.advance(30_001);
    await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'NOPE' });
    expect(h.vault.state().syncs).toBe(first + 1);
  });

  it('every write forces a sync, bypassing the read throttle', async () => {
    const h = harness();
    await h.call(['meta'], 'secrets_list_items', {});
    const before = h.vault.state().syncs;
    await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'A_KEY' });
    await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'B_KEY' });
    expect(h.vault.state().syncs).toBe(before + 2);
    // Reads right after are still throttled.
    await h.call(['meta'], 'secrets_list_items', {});
    expect(h.vault.state().syncs).toBe(before + 2);
  });

  it('an edit refused as out of date is VAULT_CONFLICT, retryable, without a session recheck', async () => {
    let bumped = false;
    const h = harness({
      beforeBw: (args, vault) => {
        if (args[0] === 'edit' && !bumped) {
          bumped = true;
          // Someone else saved the item between our get and our edit.
          vault.update(state => { state.items.find(i => i.id === 'item-writable')!.revisionDate = '2026-09-28T00:00:00.000Z'; });
        }
      },
    });
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(answer)).toBe('VAULT_CONFLICT');
    expect((answer.structured.error as { retryable?: boolean }).retryable).toBe(true);
    expect(h.vault.state().writes).toBe(0);
    expect(h.logs.some(line => line.includes('session_recheck'))).toBe(false);
    expect(h.logs).toContain('secrets-mcp bw outcome=out_of_date command=edit');
    // A retry starts from a fresh copy and succeeds.
    const retry = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(retry.isError).toBe(false);
  });
});

describe('collection policy', () => {
  it('items outside the allowed collections are invisible, not even by name', async () => {
    const h = harness();
    for (const roles of [['meta'], ['reader'], ['writer'], ['meta', 'reader', 'writer']] as const) {
      const items = await h.call([...roles], 'secrets_list_items', {});
      expect(items.raw).not.toContain('finance: bank');
      expect(items.raw).not.toContain('Finance/private');
      const search = await h.call([...roles], 'secrets_list_items', { search: 'bank' });
      expect(search.structured.items).toEqual([]);
    }
    const keys = await h.call(['meta'], 'secrets_list_keys', { item: 'finance: bank' });
    expect(errorCode(keys)).toBe('ITEM_NOT_FOUND');
    const get = await h.call(['reader'], 'secrets_get_secret', { item: 'finance: bank', key: 'BANK_TOKEN' });
    expect(errorCode(get)).toBe('ITEM_NOT_FOUND');
    expect(get.raw).not.toContain(SENTINEL_HIDDEN);
    const byCollection = await h.call(['meta'], 'secrets_list_items', { collection: 'Finance/private' });
    expect(errorCode(byCollection)).toBe('COLLECTION_NOT_ALLOWED');
  });

  it('an item shared into a hidden collection shows only the allowed collection name', async () => {
    const h = harness();
    const items = await h.call(['meta'], 'secrets_list_items', { search: 'shared' });
    expect(items.structured.items).toEqual([{ name: SHARED_ITEM, collections: ['MCP/writable'], revision_date: '2026-09-05T00:00:00.000Z' }]);
  });

  it('an item id outside the allowed collections is refused too', async () => {
    const h = harness();
    const get = await h.call(['reader'], 'secrets_get_secret', { item: 'item-hidden', key: 'BANK_TOKEN' });
    expect(errorCode(get)).toBe('ITEM_NOT_FOUND');
  });

  it('a policy collection that the vault account cannot see fails closed', async () => {
    const h = harness({ state: state => { state.collections = state.collections.filter(c => c.name !== 'Infra/hel1'); } });
    const items = await h.call(['meta'], 'secrets_list_items', {});
    expect(errorCode(items)).toBe('POLICY_UNRESOLVED');
    expect(h.logs.join('\n')).toContain('collection_not_found collection="Infra/hel1"');
  });
});

describe('write scope', () => {
  it('writes only to items whose collections are exactly the write collection, with one refusal message', async () => {
    const h = harness();
    const shared = await h.call(['writer'], 'secrets_generate_secret', { item: SHARED_ITEM, key: 'NEW_KEY' });
    const outside = await h.call(['writer'], 'secrets_generate_secret', { item: INFRA_ITEM, key: 'NEW_KEY' });
    const hidden = await h.call(['writer'], 'secrets_generate_secret', { item: 'finance: bank', key: 'NEW_KEY' });
    const hiddenById = await h.call(['writer'], 'secrets_generate_secret', { item: 'item-hidden', key: 'NEW_KEY' });
    for (const answer of [shared, outside, hidden, hiddenById]) {
      expect(errorCode(answer)).toBe('FORBIDDEN');
      expect(errorMessage(answer)).toBe(WRITE_REFUSED_MESSAGE);
      expect(containsAnySentinel(answer.raw)).toBeUndefined();
    }
    // Indistinguishable: a hidden name and a visible-but-shared name read the same.
    expect(hidden.raw.replace(/"id":\d+/, '')).toBe(shared.raw.replace(/"id":\d+/, ''));
    expect(h.vault.state().writes).toBe(0);
    expect(h.vault.state().items.find(i => i.id === 'item-shared')!.notes).toBe(`SHARED_KEY=${SENTINEL_SHARED}`);
  });

  it('VAULT LIMITATION (documented, runbook step 3.5): a collection the account is not a member of is invisible, so the item is written', async () => {
    // The item is in the write collection AND in a collection the machine
    // account cannot see. The CLI strips the second one, so the item looks
    // write-only and the write goes through. This test pins that behaviour so
    // a change to it is deliberate; the owner rule is what prevents the case.
    const h = harness({ state: state => { state.items[2]!.collectionIds = ['col-writable', 'col-nonmember']; } });
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(answer.isError).toBe(false);
    const stored = h.vault.state().items.find(i => i.id === 'item-writable')!;
    expect(stored.collectionIds).toEqual(['col-writable', 'col-nonmember']);
    expect(stored.notes as string).toContain('NEW_KEY=');
    // And nothing about the non-member collection ever shows.
    const items = await h.call(['meta'], 'secrets_list_items', {});
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
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(errorCode(answer)).toBe('FORBIDDEN');
    expect(errorMessage(answer)).toBe(WRITE_REFUSED_MESSAGE);
    expect(h.vault.state().writes).toBe(0);
  });
});

describe('secrets_generate_secret', () => {
  it('refuses to replace an existing key unless replace_existing is true', async () => {
    const h = harness();
    const refused = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'EXISTING' });
    expect(errorCode(refused)).toBe('KEY_EXISTS');
    expect(h.vault.state().writes).toBe(0);
    const rotated = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'EXISTING', replace_existing: true });
    expect(rotated.structured).toMatchObject({ action: 'rotated' });
  });

  it('rotates one line, keeps every other byte of the notes, and never returns the value', async () => {
    const h = harness();
    const answer = await h.call(['writer'], 'secrets_generate_secret', {
      item: 'app: generated', key: 'EXISTING', length: 32, alphabet: 'hex', replace_existing: true,
    });
    expect(answer.isError).toBe(false);
    expect(answer.structured).toEqual({ item: 'app: generated', key: 'EXISTING', action: 'rotated', item_created: false, length: 32 });
    const item = h.vault.state().items.find(i => i.id === 'item-writable')!;
    const notes = item.notes as string;
    const match = /EXISTING=([0-9a-f]{32})\r\n/.exec(notes);
    expect(match).not.toBeNull();
    expect(notes).toBe(WRITABLE_NOTES.replace(`EXISTING=${SENTINEL_WRITABLE}`, `EXISTING=${match![1]}`));
    expect(answer.raw).not.toContain(match![1]);
    expect(h.audit.join('\n')).not.toContain(match![1]);
  });

  it('appends a new key with the item\'s own line ending and no other change', async () => {
    const h = harness();
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY', length: 16, alphabet: 'alnum' });
    expect(answer.structured).toMatchObject({ action: 'created', item_created: false, length: 16 });
    const notes = h.vault.state().items.find(i => i.id === 'item-writable')!.notes as string;
    expect(notes.startsWith(`${WRITABLE_NOTES}\r\nNEW_KEY=`)).toBe(true);
    expect(/NEW_KEY=([A-Za-z0-9]{16})$/.test(notes)).toBe(true);
  });

  it('creates a Secure Note in the write collection when the item does not exist', async () => {
    const h = harness();
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'svc: brand new', key: 'API_TOKEN' });
    expect(answer.structured).toEqual({ item: 'svc: brand new', key: 'API_TOKEN', action: 'created', item_created: true, length: 48 });
    const created = h.vault.state().items.find(i => i.name === 'svc: brand new')!;
    expect(created).toMatchObject({ type: 2, organizationId: 'org-test', collectionIds: ['col-writable'], secureNote: { type: 0 } });
    expect(/^API_TOKEN=[A-Za-z0-9_-]{48}$/.test(created.notes as string)).toBe(true);
    // Item JSON went through stdin, never argv.
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
      const answer = await h.call(['writer'], 'secrets_generate_secret', args);
      expect(answer.isError).toBe(true);
    }
    const tooShort = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'OK_KEY', length: 8 });
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
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'FIELD_KEY', replace_existing: true });
    expect(errorCode(answer)).toBe('KEY_CONFLICT');
  });

  it('a guard hit after the vault changed still reads as success, and the audit says guard=fired', async () => {
    // The item's own notes hold its name as a value, so the (correct) answer
    // echoing the item name looks like a value leak to the guard.
    const h = harness({ state: state => { state.items[2]!.notes = 'NAME_COPY=app: generated\n'; } });
    const answer = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'NEW_KEY' });
    expect(answer.isError).toBe(false);
    expect(answer.structured).toEqual({ written: true });
    expect(answer.text).toBe('Write completed; details withheld by the output guard.');
    expect(h.vault.state().writes).toBe(1);
    expect(JSON.parse(h.audit.at(-1)!)).toMatchObject({ outcome: 'ok', error_code: null, guard: 'fired' });
  });
});

describe('secrets_set_secret', () => {
  const VALUE = 'SENTINEL-set-value-0007-abcdef';

  it('is disabled by default, even for a writer', async () => {
    const h = harness();
    const answer = await h.call(['writer'], 'secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: VALUE });
    expect(errorCode(answer)).toBe('SET_DISABLED');
    expect(answer.raw).not.toContain(VALUE);
    expect(h.audit.join('\n')).not.toContain(VALUE);
    expect(h.vault.state().writes).toBe(0);
  });

  it('when enabled, writes only a single line and answers with a confirmation only', async () => {
    const h = harness({ config: { allowSet: true } });
    const multi = await h.call(['writer'], 'secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: `${VALUE}\nINJECTED=1` });
    expect(errorCode(multi)).toBe('INVALID_ARGUMENT');
    expect(multi.raw).not.toContain(VALUE);
    const ok = await h.call(['writer'], 'secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: VALUE });
    expect(ok.structured).toEqual({ item: 'app: generated', key: 'SET_KEY', action: 'created', item_created: false });
    expect(ok.raw).not.toContain(VALUE);
    expect(h.vault.state().items.find(i => i.id === 'item-writable')!.notes).toBe(`${WRITABLE_NOTES}\r\nSET_KEY=${VALUE}`);
    const again = await h.call(['writer'], 'secrets_set_secret', { item: 'app: generated', key: 'SET_KEY', value: `${VALUE}-2` });
    expect(errorCode(again)).toBe('KEY_EXISTS');
  });
});

describe('audit and output safety', () => {
  it('no sentinel value ever reaches an audit line, an error, or a non-get answer', async () => {
    const h = harness({ config: { allowSet: true } });
    const answers = [
      await h.call(['meta'], 'secrets_list_items', {}),
      await h.call(['meta'], 'secrets_list_items', { search: 'svc' }),
      await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM }),
      await h.call(['meta'], 'secrets_list_keys', { item: LOGIN_ITEM }),
      await h.call(['meta'], 'secrets_list_keys', { item: SHARED_ITEM }),
      await h.call(['meta'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }),
      await h.call(['writer'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }),
      await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'MISSING' }),
      await h.call(['reader'], 'secrets_get_secret', { item: 'finance: bank', key: 'BANK_TOKEN' }),
      await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'EXISTING' }),
      await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'EXISTING', replace_existing: true }),
      await h.call(['writer'], 'secrets_generate_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }),
      await h.call(['writer'], 'secrets_generate_secret', { item: SHARED_ITEM, key: 'SHARED_KEY', replace_existing: true }),
      await h.call(['writer'], 'secrets_set_secret', { item: 'app: generated', key: 'LAST', value: 'another-value-123456', replace_existing: true }),
    ];
    for (const answer of answers) expect(containsAnySentinel(answer.raw)).toBeUndefined();
    // The one allowed value path: reader get.
    const get = await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    expect(get.structured.value).toBe(SENTINEL_OTHER);
    const audit = h.audit.join('\n');
    expect(containsAnySentinel(audit)).toBeUndefined();
    expect(audit).not.toContain('another-value-123456');
    expect(containsAnySentinel(h.logs.join('\n'))).toBeUndefined();
  });

  it('listings are checked structurally only: a value equal to a key name does not block them', async () => {
    const h = harness({ state: state => { state.items[0]!.notes = 'FIRST_KEY_NAME=SECOND_KEY_NAME\nSECOND_KEY_NAME=some-value-here\n'; } });
    const keys = await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM });
    expect(keys.isError).toBe(false);
    expect(keys.structured.keys).toEqual(['FIRST_KEY_NAME', 'SECOND_KEY_NAME']);
    expect(keys.raw).not.toContain('some-value-here');
  });

  it('writes one audit line per call with the documented fields', async () => {
    const h = harness();
    await h.call(['reader'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' });
    await h.call(['meta'], 'secrets_get_secret', { item: INFRA_ITEM, key: 'OTHER_KEY' }, 'user-2');
    expect(h.audit).toHaveLength(2);
    const [ok, denied] = h.audit.map(line => JSON.parse(line) as Record<string, unknown>);
    expect(Object.keys(ok!).sort()).toEqual([
      'collection', 'email', 'error_code', 'event', 'item', 'key', 'latency_ms', 'outcome', 'roles', 'sub', 'tool', 'ts',
    ]);
    expect(ok).toMatchObject({
      event: 'secrets.mcp.tool', tool: 'secrets_get_secret', sub: 'user-1', email: 'person@example.test',
      roles: ['secrets_reader'], item: INFRA_ITEM, key: 'OTHER_KEY', collection: 'Infra/hel1', outcome: 'ok', error_code: null,
    });
    // Denied before validation ran: no input is recorded.
    expect(denied).toMatchObject({ sub: 'user-2', outcome: 'denied', error_code: 'FORBIDDEN', roles: ['secrets_meta'], item: null, key: null });
  });

  it('never forwards raw bw JSON, even when the vault echoes items', async () => {
    const h = harness();
    const answers = [
      await h.call(['writer'], 'secrets_generate_secret', { item: 'svc: another', key: 'TOKEN' }),
      await h.call(['meta'], 'secrets_list_items', {}),
      await h.call(['meta'], 'secrets_list_keys', { item: 'app: generated' }),
    ];
    for (const answer of answers) {
      expect(answer.raw).not.toMatch(/\\?"(object|organizationId|collectionIds|notes|login|fields)\\?"\s*:/);
    }
  });

  it('rate-limits per subject: all tools, and writes separately', async () => {
    const h = harness({ config: { rateLimitPerMinute: 3, writeRateLimitPerMinute: 1 } });
    const results = [];
    for (let i = 0; i < 4; i += 1) results.push(await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM }));
    expect(results.map(errorCode)).toEqual([undefined, undefined, undefined, 'RATE_LIMITED']);
    // Another subject has its own budget.
    expect((await h.call(['meta'], 'secrets_list_keys', { item: INFRA_ITEM }, 'user-2')).isError).toBe(false);
    const w1 = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'A_KEY' }, 'user-3');
    const w2 = await h.call(['writer'], 'secrets_generate_secret', { item: 'app: generated', key: 'B_KEY' }, 'user-3');
    expect(w1.isError).toBe(false);
    expect(errorCode(w2)).toBe('RATE_LIMITED');
    expect(JSON.parse(h.audit.at(-1)!)).toMatchObject({ outcome: 'denied', error_code: 'RATE_LIMITED' });
  });
});
