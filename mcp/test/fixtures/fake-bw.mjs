#!/usr/bin/env node
// A fake Bitwarden CLI for the tests. It keeps its whole "vault" in
// $BITWARDENCLI_APPDATA_DIR/fake-state.json and imitates the behaviours the
// MCP and the unlock helper have to survive:
//   - `status` prints JSON; list/get with a dead session print a plain
//     sentence and still EXIT 0 (as the real CLI does);
//   - `unlock --raw` prompts on STDERR and reads the master password from
//     STDIN (the terminal, in real life), or from --passwordfile / --passwordenv,
//     and prints only the session key on stdout;
//   - `login <email> --passwordenv X --raw` logs in, unless `twoFactor` is set
//     in the state (then it fails without a --code, as the real CLI does when it
//     cannot prompt);
//   - `list items`/`get item` return personal-vault items (organizationId null)
//     too, like the real CLI: the MCP must drop them;
//   - create/edit read the base64 JSON from STDIN and echo the whole item;
//   - two processes at once are recorded as an overlap (the real CLI logs out).
// It runs both as an executable (BW_BIN) and in-process (runFakeBw).
import { appendFileSync, closeSync, existsSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';

export function statePath(appDataDir) {
  return join(appDataDir, 'fake-state.json');
}

export function readState(appDataDir) {
  return JSON.parse(readFileSync(statePath(appDataDir), 'utf8'));
}

export function writeState(appDataDir, state) {
  writeFileSync(statePath(appDataDir), JSON.stringify(state, null, 2));
}

function sleepSync(ms) {
  if (ms > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function option(args, name) {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

export function runFakeBw(args, env, input = '') {
  const dir = env.BITWARDENCLI_APPDATA_DIR;
  if (!dir) return { code: 1, stdout: '' };
  const lock = `${statePath(dir)}.lock`;
  let fd;
  try {
    fd = openSync(lock, 'wx');
  } catch {
    appendFileSync(`${statePath(dir)}.overlap`, `${args[0]}\n`);
  }
  try {
    const state = readState(dir);
    sleepSync(state.delayMs ?? 0);
    const result = handle(state, args, env, input);
    state.calls.push({
      args: args.map(arg => (arg.includes(state.password) ? '<PASSWORD-IN-ARGV>' : arg)),
      hadSession: Boolean(env.BW_SESSION),
      stdin: input.length > 0,
      // Anything that must never reach bw from the MCP's environment.
      leakedEnv: ['BW_PASSWORD', 'BW_CLIENTSECRET', 'SENTINEL_ENV'].filter(name => env[name] !== undefined),
      passwordInEnv: Object.values(env).some(value => typeof value === 'string' && value.includes(state.password)),
      // Names of the variables that carried the password (auto-unlock: DUMONT_BW_PW only, unlock/login only).
      passwordEnvNames: Object.entries(env).filter(([, value]) => typeof value === 'string' && value.includes(state.password)).map(([name]) => name),
      noInteraction: env.BW_NOINTERACTION === 'true',
    });
    writeState(dir, state);
    return result;
  } finally {
    if (fd !== undefined) {
      closeSync(fd);
      unlinkSync(lock);
    }
  }
}

function unlocked(state, env) {
  return state.loggedIn && Boolean(env.BW_SESSION) && state.sessions.includes(env.BW_SESSION);
}

function newSession(state) {
  const session = Buffer.from(randomUUID() + randomUUID()).toString('base64');
  state.sessions = [session];
  return session;
}

function passwordOk(state, args, input, env) {
  const file = option(args, '--passwordfile');
  if (file) return existsSync(file) && readFileSync(file, 'utf8').trim() === state.password;
  const variable = option(args, '--passwordenv');
  if (variable) return env[variable] === state.password;
  // Interactive: the first line typed on stdin.
  return (input.split('\n')[0] ?? '').replace(/\r$/, '') === state.password;
}

// Collections with `member: false` exist in the vault but the machine account
// is not a member: the CLI never lists them and strips them from items.
function memberCollections(state) {
  return state.collections.filter(c => c.member !== false).map(({ member: _member, ...c }) => c);
}

function memberIds(state) {
  return new Set(memberCollections(state).map(c => c.id));
}

function visibleItems(state) {
  const ids = memberIds(state);
  return state.items
    .map(item => ({ ...item, collectionIds: (item.collectionIds ?? []).filter(cid => ids.has(cid)) }))
    // Personal items (no organization) are always yours; org items only through a collection you are in.
    .filter(item => item.organizationId === null || item.collectionIds.length > 0);
}

function decode(input) {
  return JSON.parse(Buffer.from(input.trim(), 'base64').toString('utf8'));
}

function handle(state, args, env, input) {
  const [command, object, id] = args;
  const locked = { code: 0, stdout: 'Vault is locked.' };
  const prompt = '? Master password: [input is hidden] ';
  switch (command) {
    case 'status':
      return {
        code: 0,
        stdout: JSON.stringify({
          serverUrl: state.serverUrl,
          lastSync: null,
          userEmail: state.loggedIn ? state.email : null,
          status: !state.loggedIn ? 'unauthenticated' : unlocked(state, env) ? 'unlocked' : 'locked',
        }),
      };
    case 'config':
      if (state.loggedIn) return { code: 1, stdout: 'Logout required before server config update.' };
      state.serverUrl = args[2];
      return { code: 0, stdout: 'Saved setting `config`.' };
    case 'login':
      if (state.loggedIn) return { code: 1, stdout: `You are already logged in as ${state.email}.` };
      if (object !== state.email || !passwordOk(state, args, input, env)) return { code: 1, stdout: 'Username or password is incorrect. Try again.' };
      // Two-step login: with BW_NOINTERACTION (or no --code) the real CLI cannot ask for the code and fails.
      if (state.twoFactor && !option(args, '--code')) return { code: 1, stdout: '', stderr: 'Login failed. No provider selected.' };
      state.loggedIn = true;
      state.logins += 1;
      return { code: 0, stdout: newSession(state) };
    case 'unlock':
      if (!state.loggedIn) return { code: 1, stdout: '', stderr: 'You are not logged in.' };
      if (!passwordOk(state, args, input, env)) return { code: 1, stdout: '', stderr: `${prompt}\nInvalid master password.` };
      state.unlocks += 1;
      return { code: 0, stdout: newSession(state), stderr: prompt };
    case 'lock':
      state.sessions = [];
      return { code: 0, stdout: 'Your vault is locked.' };
    case 'logout':
      state.loggedIn = false;
      state.sessions = [];
      return { code: 0, stdout: 'You have logged out.' };
    case 'sync':
      if (!unlocked(state, env)) return locked;
      state.syncs += 1;
      return { code: 0, stdout: 'Syncing complete.' };
    case 'list': {
      if (!unlocked(state, env)) return locked;
      const org = option(args, '--organizationid');
      if (object === 'organizations') return { code: 0, stdout: JSON.stringify(state.organizations) };
      if (object === 'collections') {
        return { code: 0, stdout: JSON.stringify(memberCollections(state).filter(c => !org || c.organizationId === org)) };
      }
      if (object === 'items') {
        return { code: 0, stdout: JSON.stringify(visibleItems(state).filter(i => !org || i.organizationId === org)) };
      }
      return { code: 1, stdout: 'Unknown object.' };
    }
    case 'get': {
      if (!unlocked(state, env)) return locked;
      const item = visibleItems(state).find(i => i.id === id);
      return item ? { code: 0, stdout: JSON.stringify(item) } : { code: 1, stdout: 'Not found.' };
    }
    case 'create': {
      if (!unlocked(state, env)) return locked;
      const item = { object: 'item', ...decode(input), id: randomUUID(), revisionDate: new Date().toISOString() };
      state.items.push(item);
      state.writes += 1;
      return { code: 0, stdout: JSON.stringify(item) };
    }
    case 'edit': {
      if (!unlocked(state, env)) return locked;
      const index = state.items.findIndex(i => i.id === id);
      if (index === -1) return { code: 1, stdout: 'Not found.' };
      const request = decode(input);
      const stored = state.items[index];
      // The vault's stale-copy check (src/api/core/ciphers.rs), printed on stderr, exit 1.
      if (request.revisionDate !== stored.revisionDate) {
        return { code: 1, stdout: '', stderr: 'The client copy of this cipher is out of date. Resync the client and try again.' };
      }
      // Memberships the account cannot see are kept by the server, not dropped.
      const hidden = (stored.collectionIds ?? []).filter(cid => !memberIds(state).has(cid));
      const item = { ...request, collectionIds: [...(request.collectionIds ?? []), ...hidden], id, revisionDate: new Date(Date.parse(stored.revisionDate) + 1000).toISOString() };
      state.items[index] = item;
      state.writes += 1;
      const ids = memberIds(state);
      return { code: 0, stdout: JSON.stringify({ ...item, collectionIds: item.collectionIds.filter(cid => ids.has(cid)) }) };
    }
    default:
      return { code: 1, stdout: 'Unknown command.' };
  }
}

function isMain() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1] ?? '');
  } catch {
    return false;
  }
}

if (isMain()) {
  const chunks = [];
  const finish = () => {
    const result = runFakeBw(process.argv.slice(2), process.env, Buffer.concat(chunks).toString('utf8'));
    process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(`${result.stderr}\n`);
    process.stderr.write('fake-bw: stderr noise that must never be forwarded\n');
    process.exitCode = result.code;
  };
  process.stdin.on('data', chunk => chunks.push(chunk));
  process.stdin.on('end', finish);
}
