# Dumont Secrets deploy: vault-syd1

The live vault runs on **vault-syd1 (134.199.171.116)** at `/opt/secrets`, behind
Cloudflare on https://secret.getdumont.ai. It moved there from airbase-hel1 on
2026-07-16; hel1's copy was decommissioned 2026-07-17.

`docker-compose.yml` here is the deployed file. It is tracked so a droplet rebuild
cannot silently lose config. Secrets are NOT in it - every sensitive value is a
`${VAR}` read from `/opt/secrets/.env` on the host, which is not tracked.

## Why SSO_SCOPES matters

`SSO_SCOPES: "email profile offline_access"` is load-bearing and easy to lose.
Without `offline_access`, oidcwarden defaults to `"email profile"`, never asks the
IdP for a refresh token, and every SSO session dies after a few hours with
"Unable to refresh login credentials: Invalid refresh token" - mid-action, while
you are typing. This bit us on 2026-07-17.

It only works if BOTH sides agree. The ZITADEL app (project "Dumont Enterprise",
app id 369665485047857156) must also carry `OIDC_GRANT_TYPE_REFRESH_TOKEN`, or it
will not issue a refresh token no matter what scope is requested.

## Verifying after any change

1. The authorize redirect must request the scope:

       curl -si -G https://secret.getdumont.ai/identity/connect/authorize \
         --data-urlencode 'client_id=web' \
         --data-urlencode 'redirect_uri=https://secret.getdumont.ai/sso-connector.html' \
         --data-urlencode 'state=probe_probeidentifier' \
         --data-urlencode 'code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' \
         --data-urlencode 'code_challenge_method=S256' | grep -o 'scope=[^&]*'

   Expected: `scope=openid+email+profile+offline_access`

2. After a real login, this guard (oidcwarden src/sso.rs) must never fire:

       docker logs dumont-secrets-oidcwarden-1 2>&1 | grep -c 'contain no refresh_token'

   Expected: 0. Non-zero means the IdP returned no refresh token.

Existing broken sessions do not self-heal - sign out and back in once.
