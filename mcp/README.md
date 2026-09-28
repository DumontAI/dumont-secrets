# Dumont Secrets MCP (local)

A small MCP server that lets an AI coding agent (Claude Code, Dumont Code /
opencode) look up and create secrets in the Dumont Secrets vault
(`https://secret.getdumont.ai`, an OIDCWarden/Bitwarden-compatible server)
**on your own machine, as you**:

- it runs locally over **stdio**, started by your agent client; there is no
  server, no shared machine account and no extra login system;
- it drives **your own Bitwarden CLI (`bw`)**, logged in with **your** account,
  so it can reach at most what you can reach in the vault;
- its tools only ever show **organization items**: personal-vault items are
  dropped before any tool sees them;
- it never sees your master password: you type it into `bw` itself, through a
  small helper, `dumont-secrets-unlock`.

## Security model

| Question | Answer |
|---|---|
| Who is it? | You. The MCP process runs as your user and uses your `bw` login and data directory. Your vault permissions are its upper bound. |
| What can its tools see? | Item and key **names** of the organizations you belong to (optionally narrowed by the local config file). Personal-vault items (no organization) are dropped the moment `bw` answers: not listed, not found by name or id. |
| What can its tools return as a **value**? | Nothing, until you name `value_collections` in the local config. Then `secrets_get_secret` returns one value at a time, only from items in those collections, and that value is in the model context and the conversation transcript. |
| What can they write? | Nothing, until you name a `write_collection`. `secrets_generate_secret` then creates keys there without ever returning the value. Replacing an existing key needs `allow_rotate`; `secrets_set_secret` needs `allow_set`. |
| How is it unlocked? | `dumont-secrets-unlock`, in a terminal window, runs `bw unlock --raw` with the terminal handed straight to `bw`. You type the master password into `bw`; the helper never reads it, and it never appears in argv, the environment or shell history. The helper keeps only the session key `bw` prints, in a `0600` file in a per-user `0700` directory, with an expiry (**2 h** by default, 12 h at most). A detached watchdog runs `bw lock` and removes the file at that time; whoever sees an expired file first (MCP, helper, watchdog) does the same. |
| **What else can use the vault while it is unlocked?** | **Anything that runs as you**, including the agent's own shell: `bw` with that session key reaches your **whole** vault, personal items included, exactly as `export BW_SESSION=...` would. The MCP tools never expose personal items, but they are not the only way in. Guard rails make that harder, not impossible: Dumont Code's guard blocks the agent from reading the session file and from running local `bw list/get/export/...`; the Claude Code deny rules below do the same for its file tools. Neither is a sandbox. Unlock only for as long as you need, and `--lock` when done. |
| What is recorded? | One JSON line per tool call in a local audit file only you can read: `ts, tool, item, key, collection, outcome, error_code, latency_ms` (plus `guard` when the output guard fired). Never a value, the notes, `bw` output or the session key. |
| What limits a misbehaving or prompt-injected agent? | Value reads only from `value_collections`, writes only to `write_collection`, rotation and `set` off by default, your client's permission prompt on the value/write tools (see *Register it*), a per-process rate limit (60 calls/min, 10 writes/min) and an output guard. These limit what the **MCP tools** do. They do not stop an agent that has a shell from using an unlocked vault some other way (row above). |

When a tool answers `SESSION_LOCKED`, the agent is told to ask you to run
`dumont-secrets-unlock` in a separate terminal window; the MCP never unlocks or
logs in by itself and never asks for a password.

## Setup

Linux (WSL2 included) or macOS, Node.js 20 or newer.

1. **Install the Bitwarden CLI** (the installer checks for it, it does not install it):

   ```bash
   npm i -g @bitwarden/cli
   bw --version
   ```

2. **Point it at the Dumont vault and log in** (once per machine):

   ```bash
   bw config server https://secret.getdumont.ai
   bw login <your email>     # email + master password; bw asks for 2FA if you have it
   # or: bw login --sso      # Dumont SSO; not yet tested with this vault's CLI flow
   ```

   `bw config server` only works while logged out: run `bw logout` first if
   `bw` was used with another server.

3. **Install the MCP** (idempotent; re-run it to update):

   ```bash
   curl -fsSLo /tmp/dumont-secrets-install.sh \
     https://raw.githubusercontent.com/DumontAI/dumont-secrets/<sha>/mcp/scripts/install-local.sh
   bash /tmp/dumont-secrets-install.sh --ref <sha>     # a full commit sha on main, a tag, or main
   ```

   It resolves the ref (an annotated tag resolves to its commit), **refuses a
   commit that is not on `main`** (`git merge-base --is-ancestor` against a
   fresh fetch of `main`; `--allow-unmerged` or `DUMONT_SECRETS_ALLOW_UNMERGED=1`
   lifts that for testing a branch), fetches only `mcp/`, builds it (`npm ci`,
   `tsc`), prunes to production dependencies with `--ignore-scripts`, installs
   it to `~/.local/share/dumont-secrets-mcp/<sha>` (a `current` symlink, the
   `previous` one kept for rollback) and writes two launchers to
   `~/.local/bin`: `dumont-secrets-mcp` and `dumont-secrets-unlock`. It prints
   the registration commands and the Claude Code permission rules; it never
   edits your client settings.

4. **Unlock**, in a terminal window (once per session):

   ```bash
   dumont-secrets-unlock              # bw asks for your master password; 2h by default
   dumont-secrets-unlock --status     # locked/unlocked and until when (never the key)
   dumont-secrets-unlock --lock       # end it early (deletes the file, runs bw lock)
   dumont-secrets-unlock --ttl 1h     # 5m..12h; or DUMONT_SECRETS_SESSION_TTL
   ```

   It needs a real terminal: Claude Code's `!` bash mode does not give the
   command one, so run it in a separate terminal window. The MCP picks the
   session up on its next call.

   Shared state with your own `bw`: the helper uses the same `bw` data
   directory you use. A new unlock replaces the session of an earlier
   `bw unlock` (an exported `BW_SESSION` in another shell stops working), and
   `--lock`, the expiry watchdog and the expiry cleanup run `bw lock`, which
   also locks the `bw` you use interactively.

5. **Register it in your agent client:**

   Claude Code:

   ```bash
   claude mcp add -s user dumont-secrets -- ~/.local/bin/dumont-secrets-mcp
   ```

   and add these to `~/.claude/settings.json` yourself. `ask` makes every
   value-returning or writing call prompt even if the server is otherwise
   allowed (Claude Code checks deny, then ask, then allow); `deny` keeps its
   Read, Grep and Glob tools (and its best-effort checks of `cat`/`head`/`tail`)
   out of the session directory. Do **not** put the three tools in an allow
   list or answer "don't ask again" for them.

   ```json
   "permissions": {
     "ask": ["mcp__dumont-secrets__secrets_get_secret",
             "mcp__dumont-secrets__secrets_generate_secret",
             "mcp__dumont-secrets__secrets_set_secret"],
     "deny": ["Read(//run/user/*/dumont-secrets/**)",
              "Read(~/.cache/dumont-secrets/**)",
              "Read(~/Library/Caches/dumont-secrets/**)"]
   }
   ```

   opencode / Dumont Code (`opencode.jsonc`, under `"mcp"`; opencode expands
   `{env:HOME}` in its config). The engine names the tools
   `dumont-secrets_secrets_get_secret` etc.; set those three to `"ask"` under
   `"permission"` (Dumont Code's team config already does):

   ```jsonc
   "dumont-secrets": {
     "type": "local",
     "command": ["{env:HOME}/.local/bin/dumont-secrets-mcp"],
     "enabled": true
   }
   ```

   Restart the client, then ask the agent to list the Dumont secret items.

## Tools

| Tool | Input | Returns |
|---|---|---|
| `secrets_list_items` | `collection?`, `search?` | item names, their collection names (in scope), revision date. Never values or notes. |
| `secrets_list_keys` | `item` | key names in that item. Never values. |
| `secrets_get_secret` | `item`, `key` | **one** value, with a warning that it is now in the model context. `GET_DISABLED` unless the item is in one of your `value_collections`. |
| `secrets_generate_secret` | `item`, `key`, `length` (16-128, default 48), `alphabet` (`base64url` \| `hex` \| `alnum`), `replace_existing` (default `false`) | `{item, key, action: created\|rotated, item_created, length}`. **Never the value.** Needs `write_collection`; `replace_existing` needs `allow_rotate` (else `ROTATE_DISABLED`). |
| `secrets_set_secret` | `item`, `key`, `value` (one line), `replace_existing` | confirmation only. **Disabled** unless `DUMONT_SECRETS_ALLOW_SET=true` or `"allow_set": true`; the value has to pass through the model to get here. Same `write_collection` / `allow_rotate` rules. |

Keys live where the host `secret` wrapper finds them: `KEY=value` lines in the
notes (Secure Notes), custom fields, and the login username/password. Matching
ignores case and punctuation (`example-admin-token` finds
`EXAMPLE_ADMIN_TOKEN`); a key that normalizes to nothing is refused. An item
is named by id, exact name, then case-insensitive name; two visible items with
the same name are an error (`AMBIGUOUS_ITEM`), never a guess.
`secrets_list_keys` does not list note lines whose "name" looks like secret
material (longer than 64 characters, or a base64-looking run) or that have
nothing after `=`.

Writes:

- touch only items whose collections, **as your `bw` sees them**, are exactly
  the write collection (checked on the listing and again on the fresh copy
  about to be edited); anything else with that name, in any organization you
  see, gets the same `FORBIDDEN` "Cannot write an item with this name";
- create a Secure Note in the write collection when the item does not exist;
- add one `KEY=value` line, or replace it only with `replace_existing: true`
  and `allow_rotate` (otherwise `KEY_EXISTS` / `ROTATE_DISABLED`), keeping every
  other byte of the notes;
- validate keys as `^[A-Z][A-Z0-9_]{0,127}$`, item names as 1-200 printable
  characters, and refuse values with a newline, carriage return or NUL;
- refuse a key that exists as a custom or login field (`KEY_CONFLICT`) or on two
  lines (`AMBIGUOUS_KEY`);
- start from a forced `bw sync`; if the item still changes before the edit
  lands, the vault refuses it as out of date and the call answers
  `VAULT_CONFLICT` (retryable).

## Scope: the local config file

Optional. `~/.config/dumont-secrets/mcp.json` (or `$XDG_CONFIG_HOME/...`, or
the path in `DUMONT_SECRETS_MCP_CONFIG`). Read when the MCP starts: restart
your agent client after editing it. Every key is optional:

```json
{
  "version": 1,
  "organizations": ["Example Org"],
  "read_collections": ["Infra/example"],
  "value_collections": ["Infra/example"],
  "write_collection": "MCP/writable",
  "allow_rotate": false,
  "allow_set": false
}
```

| Key | Default | Meaning |
|---|---|---|
| `organizations` | every organization you belong to | names or ids; items of other organizations are invisible (names too) |
| `read_collections` | every collection of those organizations | names or ids; only items in these collections (plus `write_collection`) are visible |
| `value_collections` | unset: **`secrets_get_secret` disabled** | names or ids; the only collections whose values may be returned. Keep it to what agents genuinely need. |
| `write_collection` | unset: **writes disabled** | the one collection `generate`/`set` may create or change items in |
| `allow_rotate` | `false` | lets `replace_existing: true` replace an existing key |
| `allow_set` | `false` | enables `secrets_set_secret` |

A name that matches nothing you can see, or more than one collection, fails
the call closed (`SCOPE_UNRESOLVED`; the name goes to the MCP log, not to the
model).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DUMONT_SECRETS_SERVER_URL` | `https://secret.getdumont.ai` | the server your `bw` must be configured for; any other answer from `bw status` is refused (`VAULT_SERVER_MISMATCH`) |
| `DUMONT_SECRETS_BW_BIN` | `bw` | absolute path to the CLI, if `bw` is not on the client's PATH |
| `BITWARDENCLI_APPDATA_DIR` | the CLI default | honoured if you use a non-default `bw` data directory (set it for the MCP too) |
| `DUMONT_SECRETS_MCP_CONFIG` | see above | scope config file |
| `DUMONT_SECRETS_ALLOW_SET` | unset | `true`/`false`; overrides `allow_set` |
| `DUMONT_SECRETS_SESSION_DIR` | see below | where the session file lives (MCP and helper must agree) |
| `DUMONT_SECRETS_SESSION_TTL` | `2h` | helper default TTL (`5m`..`12h`) |
| `DUMONT_SECRETS_AUDIT_LOG` | see below | audit file path |
| `DUMONT_SECRETS_RATE_LIMIT` / `DUMONT_SECRETS_WRITE_RATE_LIMIT` | `60` / `10` | calls per minute per MCP process |
| `DUMONT_SECRETS_BW_TIMEOUT_MS` | `30000` | per `bw` call |
| `DUMONT_SECRETS_SYNC_MAX_AGE_SECONDS` | `60` | `bw sync` before a read when older |

Files:

| | Linux / WSL | macOS |
|---|---|---|
| session | `$XDG_RUNTIME_DIR/dumont-secrets/session.json`, else `/run/user/<uid>/...`, else `~/.cache/dumont-secrets/` | `~/Library/Caches/dumont-secrets/session.json` |
| audit | `~/.local/state/dumont-secrets/audit.log` (`$XDG_STATE_HOME`), rotated at 5 MB, 3 kept | `~/Library/Logs/dumont-secrets/audit.log` |
| lock | `bw.lock` next to the session file | same |

The session file must be `0600`, owned by you, a regular file, in a `0700`
directory owned by you; otherwise it is ignored (the vault reads as locked)
and `dumont-secrets-unlock` replaces it. Every non-interactive `bw` run (MCP,
helper, watchdog) takes the `bw.lock` file first, so they never run `bw` at the
same time; the interactive `bw unlock` does not (it waits on you).

## Troubleshooting

- **`SESSION_LOCKED`** ("Vault locked. Ask the user to run dumont-secrets-unlock
  in a separate terminal window..."): run `dumont-secrets-unlock` in a terminal
  window. The session expired, was locked (`bw lock`, `--lock`), or `bw` no
  longer accepts it (after `bw logout`, or a new `bw unlock` elsewhere). The MCP
  log line `dumont-secrets-mcp session outcome=locked reason=...` says which.
- **`! dumont-secrets-unlock` in Claude Code says it "needs an interactive
  terminal"**: expected, bash mode has no terminal to type into. Use a separate
  terminal window.
- **`GET_DISABLED`**: set `value_collections` (or add the item's collection to
  it) and restart the client. **`ROTATE_DISABLED`**: set `allow_rotate`.
  **`WRITE_DISABLED`**: set `write_collection`.
- **`VAULT_SERVER_MISMATCH`**: your `bw` points at another server
  (`bw status` shows it). `bw logout`, `bw config server https://secret.getdumont.ai`,
  `bw login <email>`, `dumont-secrets-unlock`.
- **Not logged in**: `dumont-secrets-unlock` tells you; run `bw login <email>`.
  Login is once per machine, unlock is per session.
- **SSO**: `bw login --sso` has not been tested with this vault yet. If you use
  it, unlocking afterwards still asks for your **master password** (SSO logs you
  in, it does not decrypt the vault).
- **2FA**: `bw login` asks for the code itself. Unlock does not need 2FA.
- **WSL**: run the agent client and the helper in the same WSL distribution and
  user. If `XDG_RUNTIME_DIR` is unset and `/run/user/<uid>` does not exist, the
  files go to `~/.cache/dumont-secrets`.
- **Desktop-launched clients** may start without your shell's PATH: the
  launchers pin the Node that the installer used; set `DUMONT_SECRETS_BW_BIN`
  (for example `claude mcp add -s user -e DUMONT_SECRETS_BW_BIN=/abs/bw ...`) if
  the MCP answers that `bw` could not be started.
- **Several agent sessions at once** are fine (see the lock file above).
  Running `bw` yourself at the same moment is not covered by that lock.

## Limitations

- **A value returned by `secrets_get_secret` is in the model context**: in the
  transcript, possibly in the client's logs and caches, and the model can
  repeat it. Keep `value_collections` small.
- **An unlocked vault is available to everything running as you**, not only to
  the MCP (see *Security model*). The guard rails are tripwires, not a sandbox.
- **Existence oracle**: the answers differ for a name that exists in a
  collection you can see but is not writable (`FORBIDDEN`, fixed message) and a
  free name (created); `ITEM_NOT_FOUND` vs `GET_DISABLED` also tells an item
  outside your read scope from one inside it. So the tools reveal whether an
  item **name** exists among the items your account can see, even outside the
  configured scope for writes. Never values.
- **Write check vs. collections you cannot see**: `bw` lists only the
  collections your account is a member of. An item of the write collection that
  someone also put into a collection you are **not** a member of looks
  write-only to you and **will** be written. With your own account this gap is
  smaller than with a machine account (you usually see the collections you work
  with), but it is not zero: keep the write collection for items that live
  nowhere else.
- **Output guard**: values shorter than 8 characters are not searched for in
  answers (they would match ordinary text); the structural rule (no raw `bw`
  JSON) still applies.
- **Sync delay**: reads sync at most every 30 s, so a change made elsewhere can
  take that long to show. Writes always sync first.
- **Watchdog**: a detached `node` process per unlock that polls the session
  file every 30 s and exits as soon as the file is gone or holds another
  session. If it is killed, the expiry still applies to the MCP (an expired
  file reads as locked and is cleaned up on the next call), but `bw` itself
  stays unlocked until something locks it.

## Development

```bash
cd mcp
npm ci
npm run typecheck
npm test
npm run build
```

The tests never touch a real vault: `test/fixtures/fake-bw.mjs` imitates the
CLI (dead-session exit 0, `unlock --raw` reading the password from stdin and
prompting on stderr, personal-vault items in its listings, stdin JSON for
create/edit, `lock`, a lock file that records overlapping processes) and runs
both in-process and as a real subprocess. For a scripted end-to-end run with
the fake, `DUMONT_SECRETS_UNLOCK_ALLOW_NON_TTY=1` lets the helper take the
password on a pipe (there is no command-line flag for it), and
`DUMONT_SECRETS_WATCHDOG_POLL_MS` shortens the watchdog's poll interval.
