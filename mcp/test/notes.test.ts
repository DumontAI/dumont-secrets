import { describe, expect, it } from 'vitest';
import { findValue, keyNames, normalizeKey, upsertNoteLine } from '../src/notes.js';
import { generateValue } from '../src/secrets.js';
import { assertSafeOutput, OutputGuardError } from '../src/guard.js';

describe('KEY=value notes', () => {
  it('matches keys ignoring case and punctuation, like the secret wrapper', () => {
    expect(normalizeKey('example-admin_api.TOKEN')).toBe(normalizeKey('EXAMPLE_ADMIN_API_TOKEN'));
    expect(normalizeKey('_.-')).toBe('');
    const item = { notes: 'export Db_Password = hunter2-long-value\n# DB_PASSWORD=commented\n' };
    expect(findValue(item, 'DB_PASSWORD')).toBe(' hunter2-long-value');
    expect(keyNames(item)).toEqual(['Db_Password']);
  });

  it('replaces one line and keeps every other byte, CRLF and missing final newline included', () => {
    const notes = '# top\r\nA=1\r\n\r\n  b_key  =old\r\nZ=last';
    const updated = upsertNoteLine(notes, 'B_KEY', 'new');
    expect(updated).toEqual({ notes: '# top\r\nA=1\r\n\r\n  b_key  =new\r\nZ=last', action: 'replaced' });
  });

  it('appends with the notes\' own line ending, respecting a final newline or its absence', () => {
    expect(upsertNoteLine('', 'K', 'v').notes).toBe('K=v');
    expect(upsertNoteLine('A=1', 'K', 'v').notes).toBe('A=1\nK=v');
    expect(upsertNoteLine('A=1\n', 'K', 'v').notes).toBe('A=1\nK=v\n');
    expect(upsertNoteLine('A=1\r\nB=2', 'K', 'v').notes).toBe('A=1\r\nB=2\r\nK=v');
  });

  it('keeps "export" and the key spelling of the replaced line', () => {
    expect(upsertNoteLine('export ex=1\n', 'EX', 'two').notes).toBe('export ex=two\n');
  });

  it('does not list note "keys" that look like secret material or have no value', () => {
    const blob = 'A'.repeat(20) + 'b'.repeat(20) + '==';
    expect(keyNames({ notes: `OK=1\n${blob}\nNO_VALUE=\n${'K'.repeat(65)}=v\nLAST=2` })).toEqual(['OK', 'LAST']);
    // Custom fields and login entries are listed by their own names, as before.
    expect(keyNames({ notes: null, fields: [{ name: 'api_key', value: 'x', type: 1 }] })).toEqual(['api_key']);
  });

  it('refuses ambiguity and multi-line values instead of guessing', () => {
    expect(() => upsertNoteLine('A=1\na=2\n', 'A', 'v')).toThrow(/more than one line/);
    expect(() => upsertNoteLine('A=1', 'B', 'x\ny')).toThrow(/single line/);
    expect(() => findValue({ notes: 'A=1\nA=2' }, 'A')).toThrow(/more than once/);
  });
});

describe('generated values', () => {
  it('have the requested length and alphabet', () => {
    expect(generateValue(48, 'base64url')).toMatch(/^[A-Za-z0-9_-]{48}$/);
    expect(generateValue(17, 'hex')).toMatch(/^[0-9a-f]{17}$/);
    expect(generateValue(128, 'alnum')).toMatch(/^[A-Za-z0-9]{128}$/);
    expect(generateValue(16, 'alnum')).not.toBe(generateValue(16, 'alnum'));
    expect(() => generateValue(15, 'hex')).toThrow();
    expect(() => generateValue(129, 'hex')).toThrow();
  });
});

describe('output guard', () => {
  it('blocks raw bw JSON and tainted values, allows the one requested value', () => {
    expect(() => assertSafeOutput(['{"object":"item","id":"x"}'], [], null)).toThrow(OutputGuardError);
    expect(() => assertSafeOutput(['{"a":"has secret-value-123 inside"}'], ['secret-value-123'], null)).toThrow(OutputGuardError);
    expect(() => assertSafeOutput(['{"value":"quote\\"d-value-1"}'], ['quote"d-value-1'], null)).toThrow(OutputGuardError);
    expect(() => assertSafeOutput(['{"value":"secret-value-123"}'], ['secret-value-123'], 'secret-value-123')).not.toThrow();
    // Short values are not searched (documented limitation).
    expect(() => assertSafeOutput(['{"ok":true}'], ['true'], null)).not.toThrow();
  });
});
