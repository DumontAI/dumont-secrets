import { SecretsError } from './types.js';

/**
 * Where a key lives inside a Bitwarden item, mirroring the host `secret`
 * wrapper: `KEY=value` lines in the notes (the Dumont convention, Secure
 * Notes), custom fields, and the login's username/password.
 */
export type KeySource = 'notes' | 'field' | 'login';

export interface KeyEntry {
  readonly name: string;
  readonly source: KeySource;
  readonly value: string;
}

/** A structural view of the bw item JSON; everything is optional and re-checked. */
export interface BwItem {
  readonly id?: unknown;
  readonly organizationId?: unknown;
  readonly collectionIds?: unknown;
  readonly type?: unknown;
  readonly name?: unknown;
  readonly notes?: unknown;
  readonly fields?: unknown;
  readonly login?: unknown;
  readonly revisionDate?: unknown;
  readonly [key: string]: unknown;
}

// Line key as the wrapper reads it: identifier-ish text before the first '='.
// Groups: 1 leading text up to the key, 2 key, 3 spaces before '=', 4 value.
const NOTE_LINE = /^([ \t]*(?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_.-]{0,127})([ \t]*)=(.*)$/;

/** Case- and punctuation-insensitive key identity, as in the `secret` wrapper. */
export function normalizeKey(key: string): string {
  return key.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export const WRITE_KEY_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/;
export const READ_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;

function stripCr(value: string): string {
  return value.endsWith('\r') ? value.slice(0, -1) : value;
}

export function noteEntries(notes: unknown): KeyEntry[] {
  if (typeof notes !== 'string' || notes.length === 0) return [];
  const entries: KeyEntry[] = [];
  for (const line of notes.split('\n')) {
    const match = NOTE_LINE.exec(stripCr(line));
    if (!match) continue;
    entries.push({ name: match[2]!, source: 'notes', value: match[4]! });
  }
  return entries;
}

export function itemEntries(item: BwItem): KeyEntry[] {
  const entries = noteEntries(item.notes);
  if (Array.isArray(item.fields)) {
    for (const field of item.fields) {
      if (!field || typeof field !== 'object') continue;
      const { name, value, type } = field as Record<string, unknown>;
      // type 3 is a "linked" field: it points at another property, no value of its own.
      if (typeof name !== 'string' || !name || type === 3) continue;
      entries.push({ name, source: 'field', value: typeof value === 'string' ? value : '' });
    }
  }
  if (item.login && typeof item.login === 'object') {
    const { username, password } = item.login as Record<string, unknown>;
    if (typeof username === 'string' && username) entries.push({ name: 'username', source: 'login', value: username });
    if (typeof password === 'string' && password) entries.push({ name: 'password', source: 'login', value: password });
  }
  return entries;
}

// A note "key" that is really secret material: a base64 blob (or a PEM/key
// line) that happens to match `name=...`, e.g. `QUJD...xyz==`.
const MAX_LISTED_NOTE_KEY = 64;
const SECRET_LOOKING = /^[A-Za-z0-9+/]{40,}={0,2}$/;

function listableNoteKey(entry: KeyEntry): boolean {
  if (entry.source !== 'notes') return true;
  return entry.value.trim() !== '' &&
    entry.name.length <= MAX_LISTED_NOTE_KEY &&
    !SECRET_LOOKING.test(entry.name);
}

/**
 * Distinct key names, in item order (first spelling wins). Never values.
 * Note lines whose "name" looks like secret material, or that have no value
 * after `=`, are not listed: a key name is shown to anyone with meta.
 */
export function keyNames(item: BwItem): string[] {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const entry of itemEntries(item)) {
    if (!listableNoteKey(entry)) continue;
    const normalized = normalizeKey(entry.name);
    // A punctuation-only name cannot be asked for (it normalizes to nothing).
    if (normalized === '' || seen.has(normalized)) continue;
    seen.add(normalized);
    names.push(entry.name);
  }
  return names;
}

/** Every value-bearing string in an item, for the output guard. */
export function itemSecretStrings(item: BwItem): string[] {
  const values = itemEntries(item).map(entry => entry.value);
  if (typeof item.notes === 'string' && item.notes) values.push(item.notes);
  if (item.login && typeof item.login === 'object') {
    const { totp } = item.login as Record<string, unknown>;
    if (typeof totp === 'string' && totp) values.push(totp);
  }
  return values;
}

export function findValue(item: BwItem, key: string): string {
  const wanted = normalizeKey(key);
  const matches = itemEntries(item).filter(entry => normalizeKey(entry.name) === wanted);
  if (matches.length === 0) throw new SecretsError('KEY_NOT_FOUND', 'The item has no such key');
  const distinct = new Set(matches.map(entry => entry.value));
  if (distinct.size > 1) {
    throw new SecretsError('AMBIGUOUS_KEY', 'The key appears more than once in the item with different values');
  }
  return matches[0]!.value;
}

export interface NotesUpdate {
  readonly notes: string;
  readonly action: 'added' | 'replaced';
}

/**
 * Put `KEY=value` into the notes, changing nothing else: every other byte of
 * the notes (other lines, comments, blank lines, CRLF endings, a missing final
 * newline) is kept as it was. The matching line keeps its own spelling of the
 * key and its own line ending.
 */
export function upsertNoteLine(notes: string, key: string, value: string): NotesUpdate {
  if (/[\r\n\u0000]/.test(value)) {
    throw new SecretsError('INVALID_ARGUMENT', 'Values must be a single line');
  }
  const wanted = normalizeKey(key);
  const lines = notes.split('\n');
  const matching: number[] = [];
  lines.forEach((line, index) => {
    const match = NOTE_LINE.exec(stripCr(line));
    if (match && normalizeKey(match[2]!) === wanted) matching.push(index);
  });
  if (matching.length > 1) {
    throw new SecretsError('AMBIGUOUS_KEY', 'The key appears on more than one line of the item; fix the item by hand first');
  }
  if (matching.length === 1) {
    const index = matching[0]!;
    const line = lines[index]!;
    const match = NOTE_LINE.exec(stripCr(line))!;
    const cr = line.endsWith('\r') ? '\r' : '';
    const prefix = `${match[1]!}${match[2]!}${match[3]!}`;
    lines[index] = `${prefix}=${value}${cr}`;
    return { notes: lines.join('\n'), action: 'replaced' };
  }
  const newLine = `${key}=${value}`;
  if (notes.length === 0) return { notes: newLine, action: 'added' };
  const eol = notes.includes('\r\n') ? '\r\n' : '\n';
  if (notes.endsWith('\n')) return { notes: `${notes}${newLine}${eol}`, action: 'added' };
  return { notes: `${notes}${eol}${newLine}`, action: 'added' };
}
