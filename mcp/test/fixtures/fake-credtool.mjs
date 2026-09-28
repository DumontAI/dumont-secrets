// Fake credential-store tools for the tests: powershell.exe (Windows DPAPI),
// macOS `security`, and `secret-tool` (libsecret). Each keeps the "stored"
// password in $FAKE_CREDSTORE_DIR/stored, obfuscated (reversed + base64) so a
// sentinel password never shows up in plain text on disk, and appends one JSON
// line per call to $FAKE_CREDSTORE_DIR/calls.jsonl saying whether the password
// was in its argv or its environment (it must never be).
//
// The argument lists are checked exactly as the real module builds them; anything
// else exits 2. Knobs (environment):
//   FAKE_CREDSTORE_FAIL=read|store|remove   that operation fails
//   FAKE_CREDSTORE_DELAY_MS=<n>             sleep before answering
//   FAKE_SECRET_SERVICE=down                secret-tool finds no Secret Service
import { appendFileSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const SERVICE = 'dumont-secrets-bw-master';
const ATTRS = ['service', 'dumont-secrets', 'account', 'bw-master'];

function dir() {
  const value = process.env.FAKE_CREDSTORE_DIR;
  if (!value) {
    process.stderr.write('FAKE_CREDSTORE_DIR is not set\n');
    process.exit(70);
  }
  return value;
}

function storedPath() {
  return join(dir(), 'stored');
}

export function readStored(directory) {
  const path = join(directory, 'stored');
  if (!existsSync(path)) return null;
  return Buffer.from(readFileSync(path, 'utf8'), 'base64').reverse();
}

function stored() {
  return readStored(dir());
}

function save(bytes) {
  writeFileSync(storedPath(), Buffer.from(bytes).reverse().toString('base64'), { mode: 0o600 });
}

function record(kind, op, password) {
  const needle = password && password.length > 0 ? password.toString('utf8') : null;
  const line = {
    kind,
    op,
    passwordInArgv: needle !== null && process.argv.some(arg => arg.includes(needle)),
    passwordInEnv: needle !== null && Object.values(process.env).some(value => typeof value === 'string' && value.includes(needle)),
  };
  appendFileSync(join(dir(), 'calls.jsonl'), `${JSON.stringify(line)}\n`);
}

function sleep(ms) {
  if (ms > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

async function stdinLine() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString('utf8');
  return (text.split('\n')[0] ?? '').replace(/\r$/, '');
}

function refuse(message) {
  process.stderr.write(`fake: unexpected arguments: ${message}\n`);
  process.exit(2);
}

function failIf(op, code = 1) {
  // FAKE_CREDSTORE_FAIL_ONCE=<op>: only the first such call fails (WSL interop hiccup).
  if (process.env.FAKE_CREDSTORE_FAIL_ONCE === op) {
    const marker = join(dir(), `failed-once-${op}`);
    if (!existsSync(marker)) {
      writeFileSync(marker, '');
      process.stderr.write('<3>WSL (1 - ) ERROR: UtilAcceptVsock:271: accept4 failed 110\n');
      process.exit(1);
    }
  }
  if (process.env.FAKE_CREDSTORE_FAIL === op) {
    process.stderr.write(`fake: ${op} failed on purpose\n`);
    process.exit(code);
  }
}

function same(a, b) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export async function powershell(args) {
  sleep(Number(process.env.FAKE_CREDSTORE_DELAY_MS ?? 0));
  if (!same(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-EncodedCommand']) || args.length !== 4) refuse(args.join(' '));
  const script = Buffer.from(args[3], 'base64').toString('utf16le');
  const op = /^# dumont-secrets op=(store|read|remove|exists)\n/.exec(script)?.[1];
  if (!op) refuse('no op marker');
  if (!/\$f = /.test(script)) refuse('no file expression');
  if (!script.includes('trap { exit 5 }')) refuse('no trap');
  // An error inside a real script is caught by `trap { exit 5 }`.
  if (op === 'store') {
    failIf('store', 5);
    const line = await stdinLine();
    const password = Buffer.from(line, 'base64');
    if (password.length === 0) process.exit(4);
    record('dpapi', 'store', password);
    if (script.includes(password.toString('utf8'))) refuse('password in the script');
    save(password);
    process.exit(0);
  }
  const current = stored();
  record('dpapi', op, current);
  if (op === 'exists') {
    failIf('exists', 5);
    process.exit(current ? 0 : 3);
  }
  if (op === 'read') {
    failIf('read', 5);
    if (!current) process.exit(3);
    process.stdout.write(current);
    process.exit(0);
  }
  failIf('remove', 5);
  if (!current) process.exit(3);
  unlinkSync(storedPath());
  process.exit(0);
}

export async function security(args) {
  sleep(Number(process.env.FAKE_CREDSTORE_DELAY_MS ?? 0));
  const [command, ...rest] = args;
  const user = rest[1];
  const base = ['-a', user, '-s', SERVICE];
  if (!user || !same(rest.slice(0, 4), base)) refuse(args.join(' '));
  if (command === 'add-generic-password') {
    // -w must be the LAST argument, with no value: security then prompts itself.
    if (!same(rest.slice(4), ['-l', 'Dumont Secrets: Bitwarden master password (auto-unlock)', '-U', '-w'])) refuse(args.join(' '));
    failIf('store');
    const password = Buffer.from(await stdinLine(), 'utf8');
    if (password.length === 0) process.exit(1);
    record('keychain', 'store', password);
    save(password);
    process.exit(0);
  }
  const current = stored();
  if (command === 'find-generic-password' && rest.length === 4) {
    // Attributes only, never the password.
    record('keychain', 'exists', current);
    failIf('exists');
    if (!current) process.exit(44);
    process.stdout.write('keychain: "login.keychain-db"\nclass: "genp"\n');
    process.exit(0);
  }
  if (command === 'find-generic-password') {
    if (!same(rest.slice(4), ['-w'])) refuse(args.join(' '));
    record('keychain', 'read', current);
    failIf('read');
    if (!current) {
      process.stderr.write('security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n');
      process.exit(44);
    }
    process.stdout.write(Buffer.concat([current, Buffer.from('\n')]));
    process.exit(0);
  }
  if (command === 'delete-generic-password') {
    if (rest.length !== 4) refuse(args.join(' '));
    record('keychain', 'remove', current);
    failIf('remove');
    if (!current) process.exit(44);
    unlinkSync(storedPath());
    process.stdout.write('keychain: "login.keychain-db"\nclass: "genp"\n');
    process.exit(0);
  }
  refuse(args.join(' '));
}

export async function secretTool(args) {
  sleep(Number(process.env.FAKE_CREDSTORE_DELAY_MS ?? 0));
  if (process.env.FAKE_SECRET_SERVICE === 'down') {
    process.stderr.write('secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n');
    process.exit(1);
  }
  const [command, ...rest] = args;
  if (command === 'lookup' && same(rest, ['service', 'dumont-secrets-probe', 'account', 'probe'])) process.exit(1);
  if (command === 'store') {
    if (!same(rest, ['--label=Dumont Secrets: Bitwarden master password (auto-unlock)', ...ATTRS])) refuse(args.join(' '));
    failIf('store');
    const password = Buffer.from(await stdinLine(), 'utf8');
    if (password.length === 0) process.exit(1);
    record('libsecret', 'store', password);
    save(password);
    process.exit(0);
  }
  if (!same(rest, ATTRS)) refuse(args.join(' '));
  const current = stored();
  if (command === 'lookup') {
    record('libsecret', 'read', current);
    failIf('read');
    if (!current) process.exit(1);
    process.stdout.write(current);
    process.exit(0);
  }
  if (command === 'search') {
    // Like the real secret-tool: the matching item WITH its secret.
    record('libsecret', 'exists', current);
    failIf('exists');
    if (!current) process.exit(0);
    process.stdout.write(Buffer.concat([Buffer.from('[/org/freedesktop/secrets/collection/login/1]\nlabel = x\nsecret = '), current, Buffer.from('\n')]));
    process.exit(0);
  }
  if (command === 'clear') {
    record('libsecret', 'remove', current);
    failIf('remove');
    if (current) unlinkSync(storedPath());
    process.exit(0);
  }
  refuse(args.join(' '));
}

/** Tests: put a password in the fake store as if --setup-auto had stored it. */
export function seedStored(directory, password) {
  writeFileSync(join(directory, 'stored'), Buffer.from(password, 'utf8').reverse().toString('base64'), { mode: 0o600 });
}

/** Tests: the calls.jsonl lines. */
export function credCalls(directory) {
  const path = join(directory, 'calls.jsonl');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
}
