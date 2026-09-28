# Dumont Secrets MCP

An MCP server (Streamable HTTP, stateless) that gives AI agents **scoped** access
to the Dumont Secrets vault (OIDCWarden at `https://secret.getdumont.ai`).

- **Who** may do what comes from ZITADEL: each person logs in with their own
  Dumont account (OAuth/OIDC with PKCE) against a **dedicated** ZITADEL project
  and client, and the access token carries one or more of three roles.
- **What** each role reaches comes from a versioned collection policy
  (`policy.example.json` here; the real one is kept in a private repository and
  installed as `/etc/dumont-secrets-mcp/policy.json`).
- **How** it reaches the vault: the Bitwarden CLI (`bw`), as one dedicated
  machine account, one call at a time, on the vault host itself
  (`vault-syd1`, loopback `127.0.0.1:3015`, behind Caddy).

Delivery and the owner-only bootstrap are in
[`deploy/vault-syd1-mcp/`](../deploy/vault-syd1-mcp/README.md).

## Tools

| Tool | Role | Input | Returns |
|---|---|---|---|
| `secrets_list_items` | meta | `collection?`, `search?` | item names, their (allowed) collection names, revision date. Never values or notes. |
| `secrets_list_keys` | meta | `item` | key names in that item. Never values. |
| `secrets_get_secret` | reader | `item`, `key` | **one** value, with a warning line that it is now in the model context. Never the whole item. |
| `secrets_generate_secret` | writer | `item`, `key`, `length` (16-128, default 48), `alphabet` (`base64url` \| `hex` \| `alnum`), `replace_existing` (default `false`) | `{item, key, action: created\|rotated, item_created, length}`. **Never the value.** |
| `secrets_set_secret` | writer + `SECRETS_MCP_ALLOW_SET=true` | `item`, `key`, `value` (one line), `replace_existing` (default `false`) | confirmation only. Disabled by default. |

Keys live where the host `secret` wrapper finds them: `KEY=value` lines in the
notes (the Dumont convention, Secure Notes), custom fields, and the login
username/password. Matching ignores case and punctuation
(`example-admin-token` finds `EXAMPLE_ADMIN_TOKEN`); a key that normalizes to
nothing (`_`, `-.`) is refused. An item is named by its exact name, then
case-insensitively, or by id; two visible items with the same name are an
error (`AMBIGUOUS_ITEM`), never a guess.

Writes:

- only touch items whose **visible** collections are exactly the write
  collection (checked on the listing and again on the fresh copy about to be
  edited). An item also shared into another collection the machine account is
  a member of, or a name that exists outside the write collection, gets the
  same `FORBIDDEN` "Cannot write an item with this name", which says nothing
  about where the other item lives;
- **vault limitation:** the CLI only sees the collections the machine account
  is a member of. An item of the write collection that is ALSO in a collection
  the account is not a member of looks write-only and **will be written**.
  The owner rule that prevents this (items in the write collection are
  MCP-owned and never added to any other collection) and a read-only database
  check for it are in `deploy/vault-syd1-mcp/bootstrap-owner-steps.md`, step 3.5;
- create a Secure Note in the write collection when the item does not exist;
- add one `KEY=value` line, or replace it only with `replace_existing: true`
  (otherwise `KEY_EXISTS`), keeping every other byte of the notes (comments,
  blank lines, CRLF, a missing final newline);
- validate keys as `^[A-Z][A-Z0-9_]{0,127}$`, item names as 1-200 printable
  characters, and refuse values with a newline, carriage return or NUL;
- refuse a key that already exists as a custom field or login field
  (`KEY_CONFLICT`), and a key on two lines (`AMBIGUOUS_KEY`);
- start from a forced `bw sync`; if the item still changes before the edit
  lands, the vault refuses the edit as out of date and the call answers
  `VAULT_CONFLICT` (retryable: a new call starts from a fresh copy).

`secrets_list_keys` does not list note lines whose "name" looks like secret
material (longer than 64 characters, or a base64-looking run of 40+
characters) or that have nothing after `=`: a key name is visible to anyone
with meta, so a pasted blob must not show up as one.

## Roles

| ZITADEL role (default key) | Grants | Implies |
|---|---|---|
| `secrets_meta` | list names and key names in `meta.read_collections` | - |
| `secrets_reader` | read one value at a time in `reader.read_collections` | meta (the meta collections plus its read collections) |
| `secrets_writer` | generate/rotate (and set, if enabled) in `writer.write_collection` | meta (the meta collections plus the write collection). **Not** reader: a writer never reads a value back, not even one it wrote. |

The token must hold at least one of the three roles to get past HTTP
(otherwise `403`). A tool whose role is missing answers with a tool error
`FORBIDDEN`, not an HTTP error. The role keys are configurable
(`SECRETS_MCP_ROLE_META/READER/WRITER`).

ZITADEL asserts only the roles whose scope the client asked for, so the
protected-resource metadata (`scopes_supported`) and the `401` challenge list
all three `urn:zitadel:iam:org:project:role:<role>` scopes.

### Why a dedicated ZITADEL project and client

The shared `ZITADEL DCR` project and its pre-registered client also serve
other MCP servers (Bugit, Hangar), with open Dynamic Client Registration and
role assertion on. A token sent to any of them would carry the same audience
and, if the person held them, the `secrets_*` roles: it could be replayed
here. So this server accepts a token only when:

- it is a JWT access token (JWS), verified locally with the issuer JWKS
  (RS256, `iss`, `exp`/`nbf`; ID tokens with `nonce`/`at_hash` are refused);
- `aud` contains `MCP_OIDC_AUDIENCE`, the id of the **dedicated** project;
- its `client_id` and/or `azp` is present and every one present is in
  `MCP_OIDC_ALLOWED_CLIENT_IDS` (that project's own native app);
- roles come **only** from `urn:zitadel:iam:org:project:<MCP_OIDC_AUDIENCE>:roles`.
  The project-agnostic `urn:zitadel:iam:org:project:roles`, a generic `roles`
  claim and `my:zitadel:grants` are ignored.

Token introspection (opaque tokens from DCR clients) is not supported at all:
an opaque token is `401` without a network call, and any
`MCP_OIDC_INTROSPECTION_*` setting stops the service at start.

## Collection policy

```json
{
  "version": 1,
  "roles": {
    "meta":   { "read_collections": ["Infra/hel1", "MCP/writable"] },
    "reader": { "read_collections": ["Infra/hel1", "MCP/writable"] },
    "writer": { "write_collection": "MCP/writable" }
  }
}
```

Collection **names**, resolved to ids at call time with `bw list collections`.
A name that matches no collection, or several, fails the call closed
(`POLICY_UNRESOLVED`; the name goes to the journal, not to the caller). Items
outside the allowed collections are invisible: not listed, not found, not even
their names; an item shared into an allowed and a hidden collection is listed
with the allowed collection's name only.

The policy is read once at start, and the process logs
`secrets-mcp policy sha256=<hex>` so the delivery can prove which bytes are
loaded. Change it through the delivery (`deploy/vault-syd1-mcp/README.md`,
"Changing the policy"), not by editing and restarting by hand.

The machine account should itself only have access to the collections the
policy names ("Can view" on read collections, "Can edit" on the write
collection): the policy is the second barrier, not the only one.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `MCP_HTTP_HOST` / `MCP_HTTP_PORT` | `127.0.0.1` / `3015` | listen address (loopback; Caddy is in front) |
| `MCP_ALLOWED_HOSTS` | loopback names | `Host` values accepted (add `secret.getdumont.ai`) |
| `MCP_ALLOWED_ORIGINS` | none | browser origins accepted, if any |
| `MCP_RESOURCE_URL` | required | `https://secret.getdumont.ai/mcp` |
| `MCP_OIDC_ISSUER` / `MCP_OIDC_JWKS_URL` | required | `https://auth.getdumont.ai`, `.../oauth/v2/keys` |
| `MCP_OIDC_AUDIENCE` | required | id of the dedicated "Dumont Secrets MCP" ZITADEL project |
| `MCP_OIDC_ALLOWED_CLIENT_IDS` | required | that project's client id(s), comma separated |
| `MCP_OIDC_ALLOWED_ORG_ID` | none | recommended: the Dumont org id |
| `MCP_OIDC_ALLOWED_SUBJECTS` | none | optional allowlist of `sub` |
| `SECRETS_MCP_ROLE_META/READER/WRITER` | `secrets_meta` / `secrets_reader` / `secrets_writer` | ZITADEL role keys |
| `SECRETS_MCP_POLICY_FILE` | required | the policy JSON |
| `SECRETS_MCP_ALLOW_SET` | `false` | enables `secrets_set_secret` |
| `SECRETS_MCP_RATE_LIMIT` / `SECRETS_MCP_WRITE_RATE_LIMIT` | `30` / `10` | calls per minute per `sub` (all tools / writes) |
| `SECRETS_MCP_SYNC_MAX_AGE_SECONDS` | `60` | `bw sync` before a read when the last sync is older |
| `BW_BIN` | `bw` | CLI path (absolute); tests point it at a fake |
| `BW_SERVER_URL` | `https://secret.getdumont.ai` | the vault as the CLI sees it. The vault's loopback port is accepted but untested with the CLI. |
| `BW_EMAIL` | required | the machine account's e-mail |
| `BW_PASSWORD_FILE` | required | 0600, owned by the service user; read by `bw`, never by this process |
| `BW_APPDATA_DIR` | required | `BITWARDENCLI_APPDATA_DIR`, under the service's StateDirectory |
| `BW_ORGANIZATION_ID` | none | only consider this organization's collections |
| `BW_TIMEOUT_MS` | `30000` | per `bw` call |

Static bearer mode does not exist here: every call carries a person's identity.

## Security notes

- **A value returned by `secrets_get_secret` is in the model context.** It is
  in the conversation transcript, may be cached or logged by the client, and a
  model can repeat it. That is why the tool returns one value at a time with a
  warning, why `secrets_reader` should be granted sparingly, and why the server
  instructions steer agents away from it.
- **Prefer `secrets_generate_secret`.** The value is made with
  `crypto.randomBytes` on the server, written straight into the vault and never
  returned: the agent can create or rotate a credential without ever seeing it.
  Deploy tooling then reads it from the vault the usual way. `secrets_set_secret`
  exists for values that come from elsewhere, and is off by default because the
  value has to pass through the model to reach it.
- **bw as a subprocess**, with the rules the host `secret` wrapper learned:
  `execFile`, never a shell; the password is read by `bw` from
  `--passwordfile`; item JSON goes in on stdin (argv is readable by other users
  in `/proc`); the session key is kept in memory and passed only in the child's
  environment; every `bw` call goes through one in-process mutex (concurrent
  `bw` processes have logged the CLI out); `bw` exits 0 on a dead session, so
  every answer is parsed as JSON and a non-JSON answer triggers one
  status/unlock/login and one retry; `create`/`edit` echo the whole item, which
  is parsed for its id and dropped; `bw` stderr is never read into anything.
  `bw serve` is never used.
- **Back-off and throttles.** After a failed login/unlock, no new attempt for
  30 s (a wrong password never turns every call into a login). Reads trigger at
  most one `bw sync` per 30 s (listing, or a miss), so a value changed in the
  vault can take up to that long to show. Writes always force a sync first,
  and a remaining race is caught by the vault's own out-of-date check
  (`VAULT_CONFLICT`); the vault's refusal text is matched inside the process
  and never forwarded.
- **Startup self-test.** After it starts listening, the process opens a vault
  session once and logs `secrets-mcp vault outcome=unlocked` or `=failed` (no
  detail). The delivery treats `failed` as a failed apply and rolls back.
- **Output guard.** Every answer and error is checked before it leaves:
  - `secrets_get_secret` and errors: no raw `bw` JSON and no value of any item
    the call touched, except the one requested value;
  - listings: structural check only (no raw `bw` JSON); they are built from
    names, collection names, dates and key names only;
  - writes: the answer is built from fixed fields and the caller's own
    validated item/key. If the guard still fires after the vault changed, the
    answer is a success with a fixed text (a retry would rotate again) and the
    audit line carries `guard: "fired"`.
  Values shorter than 8 characters are not searched for (they would match
  ordinary text); the structural rule still applies.
- **Audit.** One JSON line per call on stderr (the journal):
  `{ts, event: "secrets.mcp.tool", tool, sub, email, roles, item, key, collection, outcome, error_code, latency_ms}`
  (plus `guard` when it fired). `item`/`key` are recorded only once they passed
  validation, otherwise `null`. Never a value, the notes, `bw` output or the token.
- **Rate limits** per `sub`: 30 calls/min across tools, 10 writes/min.
- **Error codes** are fixed strings; messages are server-authored sentences
  that never contain `bw` output, a value, or input echoed back. Input
  validation that could echo a value is done by hand, not by the schema. An
  unhandled rejection prints one fixed line (never its object) and exits;
  systemd restarts the service.

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
```

The tests never touch a real vault: `test/fixtures/fake-bw.mjs` imitates the
CLI (including the dead-session exit 0, `--passwordfile`, stdin JSON, and a
lock file that records overlapping processes) and runs both in-process and as
a real subprocess through `execFile`.
