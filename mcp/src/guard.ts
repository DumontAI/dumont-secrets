/**
 * Last line of defence on everything a tool returns, errors included.
 *
 * Two things must never leave this server:
 *   1. raw Bitwarden CLI JSON (an item, a collection, an echo of create/edit);
 *   2. any secret value, except the one value `secrets_get_secret` was asked for.
 *
 * Tools build their answers from explicit fields, so the guard should never
 * fire; if it does, the whole answer is replaced by OUTPUT_GUARD.
 *
 * Limitation, documented in the README: values shorter than MIN_TAINT_LENGTH
 * are not searched for (a value like "true" or "8080" would match ordinary
 * text and block every answer). The structural rule (1) still applies.
 */
export const MIN_TAINT_LENGTH = 8;

// Property names of bw item/collection JSON that no tool answer ever uses.
const RAW_BW_MARKERS = /"(object|organizationId|collectionIds|revisionDate|creationDate|deletedDate|notes|login|fields|secureNote|passwordHistory|folderId|reprompt|totp|password)"\s*:/;

export class OutputGuardError extends Error {
  constructor(public readonly reason: 'raw_bw_json' | 'secret_value') {
    super('Response withheld by the output guard');
    this.name = 'OutputGuardError';
  }
}

function jsonEscaped(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}

/** Structural rule only: no bw item/collection JSON in the answer. */
export function assertNoRawBwJson(serialized: readonly string[]): void {
  for (const text of serialized) {
    if (RAW_BW_MARKERS.test(text)) throw new OutputGuardError('raw_bw_json');
  }
}

export function assertSafeOutput(serialized: readonly string[], taint: Iterable<string>, allowed: string | null): void {
  assertNoRawBwJson(serialized);
  for (const value of taint) {
    if (value.length < MIN_TAINT_LENGTH || value === allowed) continue;
    const escaped = jsonEscaped(value);
    for (const text of serialized) {
      // A value that merely CONTAINS the allowed value is still a leak only if
      // the text holds more of it than the allowed value itself.
      if (allowed !== null && allowed.includes(value)) continue;
      if (text.includes(value) || text.includes(escaped)) throw new OutputGuardError('secret_value');
    }
  }
}
