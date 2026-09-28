# Dumont Secrets MCP: owner-only bootstrap (vault-syd1)

Everything here touches production (vault-syd1 holds the vault and ZITADEL),
ZITADEL itself, or a secret, so it is run **by the owner**, one step at a time,
from the owner's machine (lines start with `!` so they can be pasted into a
Claude Code session as owner commands). Replace every `<PLACEHOLDER>`. This
repository is public: the real ids, names and addresses stay in the owner's
terminal and in the private config, never in a commit.

| Placeholder | What it is |
|---|---|
| `<MACHINE_ACCOUNT_EMAIL>` | mailbox of the vault machine account |
| `<PAT_ITEM>` / `<PAT_KEY>` | vault item and key holding an IAM owner PAT for ZITADEL |
| `<MACHINE_PW_ITEM>` / `<MACHINE_PW_KEY>` | vault item and key holding the machine account's password |
| `<DUMONT_ORG_ID>` | ZITADEL organization id of the Dumont org |
| `<SECRETS_MCP_PROJECT_ID>` | id of the new ZITADEL project (step 7) |
| `<SECRETS_MCP_CLIENT_ID>` | client id of that project's native app (step 7) |
| `<USER_ID>` | ZITADEL user id of a person getting a role |
| `<BW_CLI_VERSION>` | pinned Bitwarden CLI version (step 2) |
| `<VAULT_CONTAINER>` | the OIDCWarden container name on vault-syd1 |
| `<VAULT_DB_CONTAINER>` | the vault's postgres container name on vault-syd1 |
| `<WRITE_COLLECTION_UUID>` | uuid of the write collection (web vault address bar) |

Rules for every step:

- No value is ever printed, echoed or pasted. Secrets travel host -> host by
  ssh pipe (`ssh airbase-hel1 "secret get ..." | ssh vault-syd1 ...`) or by pipe
  into `curl -H @-`; only names, status codes, owners, modes and sizes are shown.
- vault-syd1 is reached as the `vault-syd1` ssh alias. Commands use `sudo`.
- After this bootstrap, deliveries are `deliver-to-vault-syd1.sh main [--apply]`.

Order: 1 -> 2 -> 3 (with 3.5) -> 4 -> 7 (its ids feed the env file) -> 5 -> 6
-> 9 (check, then apply) -> 10 -> 8 (Caddy, makes it public) -> 11 -> 12.

## 1. Unix user and config directory

```bash
! ssh vault-syd1 'sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin secrets-mcp && id secrets-mcp'
! ssh vault-syd1 'sudo install -d -o root -g secrets-mcp -m 0750 /etc/dumont-secrets-mcp && sudo stat -c "%U:%G %a %n" /etc/dumont-secrets-mcp'
```

`/var/lib/dumont-secrets-mcp` (bw CLI state) is created by systemd
(`StateDirectory=`), owned by `secrets-mcp`, 0700.

## 2. Node 22 and the Bitwarden CLI

What is there today:

```bash
! ssh vault-syd1 'node -v 2>/dev/null || echo "node: missing"; ls -l /usr/local/bin/bw 2>/dev/null || echo "bw: missing"'
```

Node 22 from the signed NodeSource apt repository (skip if `node -v` already
says v22):

```bash
! ssh vault-syd1 'set -e; sudo install -d -m 0755 /etc/apt/keyrings; curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null; sudo apt-get update -q; sudo apt-get install -y -q nodejs; node -v'
```

**CLI version.** `deploy/vault-syd1/COMPAT.md` tracks the browser extension
and the server image, not the CLI. Until it lists a CLI version, pin
`2026.6.0` (the version on the operator workstation when this was written) and
record the choice there when the vault image is next bumped.

Preferred: the standalone binary from the official release, checked against
the checksum published with it. Before running, open
`https://github.com/bitwarden/clients/releases/tag/cli-v<BW_CLI_VERSION>` and
confirm the two asset names used below exist (`bw-linux-<version>.zip` and
`bw-linux-sha256-<version>.txt`); adjust if the release names them otherwise.

```bash
! ssh vault-syd1 'set -euo pipefail; v=<BW_CLI_VERSION>; d=$(mktemp -d); cd "$d"; base=https://github.com/bitwarden/clients/releases/download/cli-v$v; curl -fsSLO "$base/bw-linux-$v.zip"; curl -fsSLO "$base/bw-linux-sha256-$v.txt"; want=$(grep -oiE "[0-9a-f]{64}" "bw-linux-sha256-$v.txt" | head -1); have=$(sha256sum "bw-linux-$v.zip" | cut -d" " -f1); [ "${want,,}" = "$have" ] || { echo "CHECKSUM MISMATCH"; exit 1; }; echo "checksum ok"; python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extract(\"bw\", \".\")" "bw-linux-$v.zip"; sudo install -o root -g root -m 0755 bw /usr/local/bin/bw; cd /; rm -rf "$d"; /usr/local/bin/bw --version'
```

Alternative (no download from GitHub on the host): the npm package, with its
install scripts disabled:

```bash
! ssh vault-syd1 'sudo npm install -g --ignore-scripts --prefix /usr/local @bitwarden/cli@<BW_CLI_VERSION> && /usr/local/bin/bw --version'
```

## 3. Machine account, collections and access (vault web UI)

1. Pick a mailbox the owner controls for the account (`<MACHINE_ACCOUNT_EMAIL>`;
   an alias is enough: it only receives the invitation and new-device notices).
2. As an organization owner at https://secret.getdumont.ai: **Members -> Invite**
   that address with role **User** (not Admin, not Owner, no "manage" rights).
3. Accept the invitation from that mailbox and set the master password to a
   long random value (the web generator, 40+ characters). Before leaving the
   page, store it as a vault item `<MACHINE_PW_ITEM>` with one note line
   `<MACHINE_PW_KEY>=<the password>`, in a collection that the machine account
   is **not a member of** (and that the MCP policy does not name): the account
   must never be able to read its own password, whatever the policy says.
4. Back as owner: **Members -> Confirm** the account.
5. Create the write collection (the policy's `write_collection`, e.g.
   `MCP/writable`) and decide which existing collections are readable. Give the
   machine account access **per collection**: read collections **Can view**
   (with "hide passwords" OFF), the write collection **Can edit**. Nothing else.
6. The service logs in non-interactively with the master password, so check
   both levels of SSO enforcement and the account's two-step setting:
   - organization: **Policies -> Require single sign-on authentication** must
     not apply to this member;
   - server: `SSO_ONLY` must not be `true` on the vault, neither in the
     container environment nor as an admin-panel override in
     `/data/config.json` (which wins over the environment). The command stops
     loudly if `<VAULT_CONTAINER>` is not a container, and prints only the
     `SSO_ONLY` line, the `sso_only` fragment of config.json, or "no override":

     ```bash
     ! ssh vault-syd1 'set -e; c=<VAULT_CONTAINER>; sudo docker inspect --type container "$c" >/dev/null 2>&1 || { echo "ERROR: no container named $c. List them with: sudo docker ps --format {{.Names}}"; exit 1; }; sudo docker inspect --type container --format "{{range .Config.Env}}{{println .}}{{end}}" "$c" | grep -E "^SSO_ONLY=" || echo "env: SSO_ONLY unset (default false)"; sudo docker exec "$c" sh -c "if [ -f /data/config.json ]; then grep -oE \"\\\"sso_only\\\" *: *[a-z]+\" /data/config.json || echo \"config.json: no sso_only override\"; else echo \"no /data/config.json (no admin overrides)\"; fi"'
     ```
   - account: no two-step login method configured on the machine account.

   If any of these is on, stop here and decide; the apply will fail with
   `secrets-mcp vault outcome=failed` otherwise.

## 3.5. Owner rule for the write collection (and a check for it)

The server refuses to write an item that is also in another collection, but it
can only see collections the machine account is a member of. An item of the
write collection that someone also adds to a collection the account is NOT a
member of looks write-only to the server and **will be written** (a test pins
this). So, as a standing rule:

- Items in the write collection are **MCP-owned**: never add one to any other
  collection, never move an existing item into it.
- Nobody but the owner has **Manage** or **Can edit** on the write collection,
  besides the machine account itself.
- To hand a value to people, read it where it is or copy it, never share the
  write-collection item into their collection.

Read-only check, any time: items of the write collection that belong to more
than one collection. Collection names are encrypted in the database, so it
takes the collection's **uuid** (open the collection in the web vault: the
`collectionId=` in the address bar), and it prints only cipher ids and counts,
never any data. `<VAULT_DB_CONTAINER>` is the vault's postgres container
(`sudo docker ps --format '{{.Names}}'`; the compose service is `postgres`).

```bash
! ssh vault-syd1 'set -e; c=<VAULT_DB_CONTAINER>; w=<WRITE_COLLECTION_UUID>; [[ "$w" =~ ^[0-9a-f-]{36}$ ]] || { echo "ERROR: not a uuid"; exit 1; }; sudo docker inspect --type container "$c" >/dev/null 2>&1 || { echo "ERROR: no container named $c"; exit 1; }; sudo docker exec "$c" psql -U dumont_secrets -d dumont_secrets -At -F " " -c "SELECT cc.cipher_uuid, count(*) FROM ciphers_collections cc JOIN ciphers ci ON ci.uuid = cc.cipher_uuid WHERE ci.deleted_at IS NULL AND cc.cipher_uuid IN (SELECT cipher_uuid FROM ciphers_collections WHERE collection_uuid = '"'"'$w'"'"') GROUP BY cc.cipher_uuid HAVING count(*) > 1;" | sed "s/^/shared item: /"; echo "items in the write collection: $(sudo docker exec "$c" psql -U dumont_secrets -d dumont_secrets -At -c "SELECT count(*) FROM ciphers_collections WHERE collection_uuid = '"'"'$w'"'"';")"'
```

Expected: no `shared item:` line. Any line is an item to take out of the
other collection (or out of the write collection) before the MCP writes to it.

## 4. Password file (by ssh pipe, never printed)

```bash
! ssh airbase-hel1 "secret get '<MACHINE_PW_ITEM>' <MACHINE_PW_KEY>" | ssh vault-syd1 "sudo sh -c 'umask 077; f=/etc/dumont-secrets-mcp/bw-password; cat > \$f.tmp && chown secrets-mcp:secrets-mcp \$f.tmp && chmod 0600 \$f.tmp && mv -f \$f.tmp \$f'"
! ssh vault-syd1 'sudo stat -c "%U:%G %a %s bytes %n" /etc/dumont-secrets-mcp/bw-password'
```

Expected: `secrets-mcp:secrets-mcp 600`, a size a little above the password
length (bw reads the first line). The apply refuses a file under 20 bytes
(an empty or failed pipe). A wrong password shows up at the apply as
`secrets-mcp vault outcome=failed`, with a message that says it is a
credentials problem.

## 5. Environment file

Fill the ids from step 7 (they are not secrets, but stay out of this
repository) and send it:

```bash
! sed -e 's/<SECRETS_MCP_PROJECT_ID>/<the project id>/' -e 's/<SECRETS_MCP_CLIENT_ID>/<the client id>/' -e 's/<DUMONT_ZITADEL_ORG_ID>/<the org id>/' -e 's/<MACHINE_ACCOUNT_EMAIL>/<the machine account e-mail>/' deploy/vault-syd1-mcp/dumont-secrets-mcp.env.example | ssh vault-syd1 "sudo sh -c 'umask 077; f=/etc/dumont-secrets-mcp.env; cat > \$f.tmp && chown root:root \$f.tmp && chmod 0600 \$f.tmp && mv -f \$f.tmp \$f'"
! ssh vault-syd1 'sudo stat -c "%U:%G %a %n" /etc/dumont-secrets-mcp.env; sudo grep -v "^#" /etc/dumont-secrets-mcp.env | grep -c "<" || true'
```

(The last number is how many `<placeholders>` are left outside comments:
expect `0`.) Run step 7 before this one: its two ids fill this file.

## 6. Collection policy (from the private repository)

The real policy is versioned in a private repository, not here (suggested:
`DumontAI/platform-infra`, e.g. `hosts/vault-syd1/dumont-secrets-mcp/policy.json`),
shaped like `mcp/policy.example.json`, with the collection names as they
appear in the vault. Install it:

```bash
! ssh vault-syd1 "sudo sh -c 'umask 027; f=/etc/dumont-secrets-mcp/policy.json; cat > \$f.tmp && chown root:secrets-mcp \$f.tmp && chmod 0640 \$f.tmp && mv -f \$f.tmp \$f'" < <PATH_TO_POLICY_IN_PRIVATE_REPO>
! ssh vault-syd1 'sudo stat -c "%U:%G %a %n" /etc/dumont-secrets-mcp/policy.json; sudo sha256sum /etc/dumont-secrets-mcp/policy.json'
```

Later changes: `README.md`, "Changing the policy".

## 7. ZITADEL: dedicated project, roles, app, grants

**Why not the shared DCR project:** the `ZITADEL DCR` project and its
pre-registered client also serve the Bugit and Hangar MCPs, with open Dynamic
Client Registration and role assertion on. A token minted for any of them
would carry that project's audience and, if the person held them, the
`secrets_*` roles, and could be replayed here. This server therefore only
accepts tokens whose `aud` is its own project and whose `client_id`/`azp` is
its own app, and reads roles only from that project's claim. Never add the
`secrets_*` roles to the DCR project, and never enable DCR for this project.

The PAT goes from the vault on hel1 straight into `curl -H @-` (the header is
read from stdin): it is never printed, never in argv, never in a variable.
Endpoints are ZITADEL Management API v1 (`AddProject`, `BulkAddProjectRoles`,
`AddOIDCApp`, `AddUserGrant`, `UpdateUserGrant`); check them against the API
reference of the running ZITADEL version before the first call (v1 is
deprecated in newer releases in favour of v2, but still served). All calls
act in the Dumont organization (`x-zitadel-orgid`). Each command is complete
on its own line (every `!` runs in a fresh shell).

**7a. Project** (role assertion on; `projectRoleCheck` refuses login to
anyone without a role in this project). The answer's `id` is
`<SECRETS_MCP_PROJECT_ID>`; only that id is printed:

```bash
! ssh airbase-hel1 "secret get '<PAT_ITEM>' <PAT_KEY>" | sed 's/^/Authorization: Bearer /' | curl -sS -H @- -H 'Content-Type: application/json' -H 'x-zitadel-orgid: <DUMONT_ORG_ID>' -X POST 'https://auth.getdumont.ai/management/v1/projects' -d '{"name":"Dumont Secrets MCP","projectRoleAssertion":true,"projectRoleCheck":true,"hasProjectCheck":false}' | jq -r '.id // .message'
```

**7b. Roles:**

```bash
! ssh airbase-hel1 "secret get '<PAT_ITEM>' <PAT_KEY>" | sed 's/^/Authorization: Bearer /' | curl -sS -o /dev/null -w '%{http_code}\n' -H @- -H 'Content-Type: application/json' -H 'x-zitadel-orgid: <DUMONT_ORG_ID>' -X POST 'https://auth.getdumont.ai/management/v1/projects/<SECRETS_MCP_PROJECT_ID>/roles/_bulk' -d '{"roles":[{"key":"secrets_meta","displayName":"Secrets MCP: item and key names","group":"secrets-mcp"},{"key":"secrets_reader","displayName":"Secrets MCP: read one value","group":"secrets-mcp"},{"key":"secrets_writer","displayName":"Secrets MCP: generate and rotate","group":"secrets-mcp"}]}'
```

Expected `200`.

**7c. Native app** (public client, PKCE, no secret, JWT access tokens with the
roles asserted; redirects for Claude Code and Dumont Code/opencode). The
answer's `clientId` is `<SECRETS_MCP_CLIENT_ID>`:

```bash
! ssh airbase-hel1 "secret get '<PAT_ITEM>' <PAT_KEY>" | sed 's/^/Authorization: Bearer /' | curl -sS -H @- -H 'Content-Type: application/json' -H 'x-zitadel-orgid: <DUMONT_ORG_ID>' -X POST 'https://auth.getdumont.ai/management/v1/projects/<SECRETS_MCP_PROJECT_ID>/apps/oidc' -d '{"name":"Dumont Secrets MCP CLI","redirectUris":["http://localhost:19877/callback","http://127.0.0.1:19876/mcp/oauth/callback"],"responseTypes":["OIDC_RESPONSE_TYPE_CODE"],"grantTypes":["OIDC_GRANT_TYPE_AUTHORIZATION_CODE","OIDC_GRANT_TYPE_REFRESH_TOKEN"],"appType":"OIDC_APP_TYPE_NATIVE","authMethodType":"OIDC_AUTH_METHOD_TYPE_NONE","accessTokenType":"OIDC_TOKEN_TYPE_JWT","accessTokenRoleAssertion":true,"idTokenRoleAssertion":false}' | jq -r '.clientId // .message'
```

Put both ids into the env file (step 5). They go nowhere else public.

**7d. Grants.** Start narrow: `secrets_meta` for people who use agents;
`secrets_reader` and `secrets_writer` only where needed. The person's user id
is on their user page in the console:

```bash
! ssh airbase-hel1 "secret get '<PAT_ITEM>' <PAT_KEY>" | sed 's/^/Authorization: Bearer /' | curl -sS -o /dev/null -w '%{http_code}\n' -H @- -H 'Content-Type: application/json' -H 'x-zitadel-orgid: <DUMONT_ORG_ID>' -X POST 'https://auth.getdumont.ai/management/v1/users/<USER_ID>/grants' -d '{"projectId":"<SECRETS_MCP_PROJECT_ID>","roleKeys":["secrets_meta"]}'
```

Expected `200`. To change a person's roles later, update the grant with the
FULL list (grant id from the console: Users -> the user -> Authorizations):

```bash
! ssh airbase-hel1 "secret get '<PAT_ITEM>' <PAT_KEY>" | sed 's/^/Authorization: Bearer /' | curl -sS -o /dev/null -w '%{http_code}\n' -H @- -H 'Content-Type: application/json' -H 'x-zitadel-orgid: <DUMONT_ORG_ID>' -X PUT 'https://auth.getdumont.ai/management/v1/users/<USER_ID>/grants/<GRANT_ID>' -d '{"roleKeys":["secrets_meta","secrets_writer"]}'
```

**7e. Check a token's claim names once** (after step 11, with the owner's own
login): decode the access token in the client's credential store locally and
confirm it has `aud` containing the project id, `client_id` (and/or `azp`)
equal to the client id, and `urn:zitadel:iam:org:project:<SECRETS_MCP_PROJECT_ID>:roles`.
The server refuses a token missing any of them (`401`/`403`).

## 8. Caddy route (makes the MCP public)

**8a. Discovery first** (read-only): how Caddy runs, which file it reads, and
what else it serves.

```bash
! ssh vault-syd1 'systemctl is-active caddy 2>/dev/null; systemctl cat caddy 2>/dev/null | grep -E "^ExecStart"; sudo docker ps --format "{{.Names}} {{.Image}} {{.Ports}}" 2>/dev/null | grep -i caddy; ls -l /etc/caddy/ 2>/dev/null; true'
! ssh vault-syd1 'sudo grep -nE "^[^#[:space:]].*\{\s*$" /etc/caddy/Caddyfile 2>/dev/null'
```

The second command lists the site blocks (adjust the path if Caddy runs in a
container or from another file). Note every site: all of them must still
answer the same after the change.

**8b. Back up, edit, validate, reload.** Merge `Caddyfile.snippet` into the
`secret.getdumont.ai` block by hand, in an ssh session: the MCP `handle` first,
the existing upstream wrapped unchanged in `handle { }`.

```bash
! ssh vault-syd1 'sudo cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date -u +%Y%m%dT%H%M%SZ) && ls -l /etc/caddy/'
! ssh vault-syd1 'sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy && systemctl is-active caddy'
```

(If Caddy runs in a container, run `caddy validate` and `caddy reload` inside
it instead.)

**8c. Smoke, from outside** (each line prints a status or a verdict only):

```bash
! curl -s -o /dev/null -w 'vault UI            %{http_code} (want 200)\n' https://secret.getdumont.ai/
! curl -s -w '\n' https://secret.getdumont.ai/api/config | jq -e '.version' >/dev/null && echo 'api/config          JSON (want JSON)' || echo 'api/config          NOT JSON'
! curl -s -o /dev/null -w 'identity token POST %{http_code} (want 400, not 404)\n' -X POST https://secret.getdumont.ai/identity/connect/token
! curl -s https://secret.getdumont.ai/notifications/hub | grep -q jsonrpc && echo 'notifications/hub   WRONG: answered by the MCP' || echo 'notifications/hub   not the MCP (ok)'
! curl -s -o /dev/null -w 'ZITADEL discovery   %{http_code} (want 200)\n' https://auth.getdumont.ai/.well-known/openid-configuration
! curl -s https://secret.getdumont.ai/.well-known/oauth-protected-resource | jq -e '.scopes_supported | length == 3' >/dev/null && echo 'MCP metadata        ok' || echo 'MCP metadata        WRONG'
! curl -s -o /dev/null -w 'MCP POST /mcp       %{http_code} (want 401)\n' -X POST https://secret.getdumont.ai/mcp
```

Also open the vault in a browser and log in with SSO once: the vault itself
must behave exactly as before.

**8d. Rollback:** restore the newest `/etc/caddy/Caddyfile.bak-*`, validate,
reload; the MCP keeps running on loopback, unreachable from outside.

```bash
! ssh vault-syd1 'set -e; b=$(ls -1t /etc/caddy/Caddyfile.bak-* | head -1); sudo cp -a "$b" /etc/caddy/Caddyfile; sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy && echo "restored $b"'
```

## 9. First delivery

```bash
! bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main
! bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main --apply
! bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh --show-release
```

The check must end in `OK: checks passed`; the apply in `OK: ... applied and
running` after `vault: the machine account opened a session`; `--show-release`
in `in-sync` + `runtime-in-sync`. If the apply stops on
`vault self-test failed`, it is the credentials (steps 3, 4): the service was
rolled back, fix and re-run the apply.

## 10. Smoke (loopback, before Caddy)

```bash
! ssh vault-syd1 'curl -s http://127.0.0.1:3015/.well-known/oauth-protected-resource; echo; curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:3015/mcp'
! ssh vault-syd1 'sudo journalctl -u dumont-secrets-mcp -o cat -n 20 | grep -E "^secrets-mcp (listening|policy|vault)"'
```

Expected: metadata JSON listing three `urn:zitadel:iam:org:project:role:secrets_*`
scopes, then `401`; the journal shows `listening`, `policy sha256=...` and
`vault outcome=unlocked`.

## 11. Clients

Claude Code (the callback port must match the app's redirect URI):

```bash
! claude mcp add --transport http --client-id <SECRETS_MCP_CLIENT_ID> --callback-port 19877 -s user dumont-secrets https://secret.getdumont.ai/mcp
```

Restart the Claude Code session, then `/mcp` -> dumont-secrets -> Authenticate.

Dumont Code / opencode (redirect `http://127.0.0.1:19876/mcp/oauth/callback`):

```jsonc
"mcp": {
  "dumont-secrets": {
    "type": "remote",
    "url": "https://secret.getdumont.ai/mcp",
    "enabled": true,
    "oauth": { "clientId": "<SECRETS_MCP_CLIENT_ID>" }
  }
}
```

A client that registers itself (DCR) instead of using the pinned client id
gets a token for the wrong project and is refused (`401`); that is intended.

## 12. First real use

1. With `secrets_meta`: `secrets_list_items` shows only the policy's
   collections; `secrets_list_keys` on one item shows names only.
2. With `secrets_writer`: `secrets_generate_secret` on a test item in the write
   collection answers `action: created` and no value; the item appears in the
   vault UI with one `KEY=...` line. A second call on the same key answers
   `KEY_EXISTS` until `replace_existing: true` is passed.
3. The audit trail has one line per call and no value:

```bash
! ssh vault-syd1 'sudo journalctl -u dumont-secrets-mcp -o cat --since "-10 min" | grep secrets.mcp.tool'
```
