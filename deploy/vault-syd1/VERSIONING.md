# Dumont Secrets — version pin (vault-syd1)

## Live pin (do not drift)

| Field | Value |
|---|---|
| Git tag | `v2026.8.0-1-dumont.1` (local alias of Timshel `v2026.8.0-1`) |
| Upstream commit | `Timshel/OIDCWarden@1bed3a18` |
| Image tag | `dumont-secrets-oidcwarden:v2026.8.0-1-dumont.1` |
| Image digest | `sha256:f48b1eca8111…` (see `IMAGE_DIGEST.txt`) |
| Web vault | `2026.8.0-1` (host binds refreshed 2026-09-02) |
| Host | `vault-syd1:/opt/secrets` |
| Public URL | https://secret.getdumont.ai |

This is the stack that fixed:

1. Bitwarden extension **2026.4+** login (`POST /identity/accounts/prelogin/password`)
2. Bitwarden clients **≥ 2026.7** vault spinner (`userDecryption` / VW **1.37** sync API)
3. Bitwarden clients **≥ 2026.8** empty vault / `revisionDate` (VW **1.37.2**) — applied **2026-09-02** on vault-syd1

Rollback pack: `/opt/secrets/backups/pre-upgrade-20260902T133701Z/`  
R2: `s3://dumont-vault-backups/vault-syd1/dumont_secrets_20260902T133701Z.sql.gz.age`  
Counts after apply: users=10 ciphers=958 orgs=1 (unchanged).

## Client / server compatibility (hard rules)

| Bitwarden client | Minimum Dumont Secrets (OIDCWarden / VW) |
|---|---|
| ≤ 2026.3 | `v2026.3.1-3` (old; do not stay here) |
| 2026.4 – 2026.6 | ≥ `v2026.4.2-1` (has `prelogin/password`) |
| **≥ 2026.7** | **≥ this pin** (`9c2af26b` / VW 1.37 API) |
| **≥ 2026.8** | **this pin** (`v2026.8.0-1` / `1bed3a18`, VW 1.37.2 `revisionDate`) |

Staff use the official Bitwarden browser extension against Self-hosted `https://secret.getdumont.ai`. Chrome auto-updates the extension — **the server must stay ahead of clients**, not the other way around.

## Compat watch (do not rely on memory)

Machine-readable pin: [`PIN.json`](./PIN.json). Relógio: [`compat-watch.py`](./compat-watch.py).

| Where | What |
|---|---|
| GitHub Action `Compat watch` | Daily compare only (fails if client/OIDCWarden > pin) |
| hel1 timer | Same compare + aviso no Hangar projeto **SEC** e no Chat `#alerts-dumont-secrets` |
| Notify rule | Só quando a versão **muda** (não spam diário do mesmo atraso) |

**CI/CD:** o relógio e o *build* da imagem (tag `v*-dumont.*` → GHCR) são automáticos. O *apply* no vault-syd1 **não** é — o relógio não faz `docker pull`.

## Rebuild the image (another machine)

Preferred (after GHCR publish from tag push / `dumont-release` workflow):

```bash
# Package is private to DumontAI — login once (PAT with read:packages, or gh)
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
# or: gh auth token | docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin

docker pull ghcr.io/dumontai/dumont-secrets-oidcwarden:v2026.7.1-1-dumont.1
docker tag ghcr.io/dumontai/dumont-secrets-oidcwarden:v2026.7.1-1-dumont.1 \
  dumont-secrets-oidcwarden:v2026.7.1-1-dumont.1
```

From source (offline / GHCR empty):

```bash
git clone git@github.com:DumontAI/dumont-secrets.git
cd dumont-secrets
git checkout v2026.7.1-1-dumont.1
./deploy/vault-syd1/build-image.sh
# or: docker build -t dumont-secrets-oidcwarden:v2026.7.1-1-dumont.1 -f Dockerfile .
```

Transfer to vault host if built elsewhere:

```bash
docker save dumont-secrets-oidcwarden:v2026.7.1-1-dumont.1 | gzip -1 \
  | ssh vault-syd1 'gunzip -c | docker load'
```

## Deploy / refresh host web-vault binds

Host bind-mounts `./web-vault_*` **override** the image. After every image upgrade, refresh them from the new image:

```bash
cd /opt/secrets
CID=$(docker create dumont-secrets-oidcwarden:v2026.7.1-1-dumont.1)
rm -rf web-vault_override web-vault_button
docker cp "$CID:/web-vault_override" ./web-vault_override
docker cp "$CID:/web-vault_button" ./web-vault_button
docker rm "$CID"
# keep compose image: line in sync with deploy/vault-syd1/docker-compose.yml
docker compose up -d --no-deps --force-recreate oidcwarden
```

## Upgrade policy (avoid repeating 2026-08-06)

1. **Never** run `docker pull` / untagged `:latest` on the live vault without a planned window.
2. Before upgrading server: note staff Bitwarden extension versions (`chrome://extensions`).
3. Prefer tagged OIDCWarden / Dumont releases over floating `main`.
4. If Timshel has no tag yet but VW **1.37+** is required, pin an exact upstream SHA in this repo (as we did with `9c2af26b`), build, tag `vYYYY.M.P-N-dumont.X`, update this file.
5. Acceptance before calling upgrade done:

```bash
# login path (2026.4+)
curl -sS -o /dev/null -w "%{http_code}\n" -X POST \
  https://secret.getdumont.ai/identity/accounts/prelogin/password \
  -H 'Content-Type: application/json' -d '{"email":"you@shipeezi.com"}'
# expect 200

curl -fsS https://secret.getdumont.ai/api/config \
  | jq '{version, gitHash, sso:.settings.ssoEnabled, reg:.settings.disableUserRegistration}'
# expect sso=true, reg=true, version >= 2026.6.0 for 2026.7 clients

docker exec dumont-secrets-oidcwarden-1 ./oidcwarden --help | head -1
```

6. After upgrade: staff must **Log out** (not only lock) once; clear extension storage if the vault spinner persists.

## Related docs

- Ops tooling / history: `shipeezi/devops/dumont/secrets-vault/` (esp. `VAULT_SYD1.md`)
- SSO scopes / refresh tokens: `deploy/vault-syd1/README.md`
