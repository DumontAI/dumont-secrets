#!/usr/bin/env bash
# Deliver the Dumont Secrets MCP to vault-syd1 - FROM MAIN ONLY (SEC-14).
# Modeled on DumontAI/moveezi deploy/gatus-syd/deliver-to-vault-syd1.sh.
#
# Run on the OPERATOR'S machine, from a checkout of DumontAI/dumont-secrets:
#   bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main              # --check (default)
#   bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main --apply
#   bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh <sha40> [--apply]
#   bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh --show-release    # read-only
#
# vault-syd1 is PRODUCTION: it holds the vault and ZITADEL. Order of events:
#   1. git fetch origin main; the commit must be on origin/main, or this exits 2
#      before a single connection to the host is opened;
#   2. the release is BUILT HERE from `git archive <sha> mcp` (never from the
#      working tree): npm ci, typecheck, test, build, then a production-only
#      node_modules; packed as release.tar.gz + its sha256;
#   3. the bundle (tarball + deploy/vault-syd1-mcp from the same commit) goes to
#      ~/dumont-secrets-mcp-bundles/<sha> on the host, replaced wholesale;
#   4. apply-on-vault-syd1.sh runs there with sudo: --check by default (it
#      prints what would change and changes nothing in the service; the bundle
#      itself is still copied to the ssh user's home), the real apply only with
#      --apply, detached with `setsid --wait` so a dropped ssh session cannot
#      kill it half-way.
#
# Emergency only: --allow-non-main --reason "<why this cannot wait for main>".
# It is recorded on the host (source_ref=non-main + override_reason) and
# --show-release keeps warning until a delivery from main replaces it.
#
# Nothing here reads, prints or copies a secret: the bundle is repository files
# and a build of them; the env file and the password file on the host are only
# checked for owner and mode, by the apply.
set -euo pipefail

HOST="${DELIVER_HOST:-vault-syd1}"
SSH_OPTS=(-T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)
# The tilde is expanded by the REMOTE shell (the ssh user's home), on purpose.
# shellcheck disable=SC2088
REMOTE_BUNDLES='~/dumont-secrets-mcp-bundles'
REMOTE_APPLY_INSTALLED='/opt/dumont-secrets-mcp/apply-on-vault-syd1.sh'

usage() {
  echo "usage: $0 <sha40|main> [--check|--apply] [--allow-non-main --reason <text>] [--host <ssh-alias>]"
  echo "       $0 --show-release [--host <ssh-alias>]"
}

TARGET=""
APPLY=0
ALLOW_NON_MAIN=0
REASON=""
SHOW_RELEASE=0

while (($#)); do
  case "$1" in
    --apply) APPLY=1 ;;
    --check) APPLY=0 ;;
    --show-release) SHOW_RELEASE=1 ;;
    --allow-non-main) ALLOW_NON_MAIN=1 ;;
    --reason) (($# >= 2)) || { echo "ERROR: --reason needs a value" >&2; exit 2; }; REASON="$2"; shift ;;
    --reason=*) REASON="${1#*=}" ;;
    --host) (($# >= 2)) || { echo "ERROR: --host needs a value" >&2; exit 2; }; HOST="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    *)
      [[ -z "$TARGET" ]] || { echo "ERROR: one commit at a time (got $TARGET and $1)" >&2; exit 2; }
      TARGET="$1"
      ;;
  esac
  shift
done

refuse() {
  echo "REFUSED: $1" >&2
  echo "Nothing was sent to $HOST." >&2
  exit 2
}

[[ "$HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || refuse "--host must be an ssh alias"

if ((SHOW_RELEASE)); then
  [[ -z "$TARGET" ]] || refuse "--show-release takes no commit"
  exec ssh "${SSH_OPTS[@]}" "$HOST" "sudo -n bash $REMOTE_APPLY_INSTALLED --show-release" </dev/null
fi

[[ -n "$TARGET" ]] || { usage >&2; exit 2; }
if [[ -n "$REASON" ]] && ((!ALLOW_NON_MAIN)); then
  refuse "--reason is only for --allow-non-main"
fi
if ((ALLOW_NON_MAIN)); then
  [[ -n "$REASON" ]] || refuse "--allow-non-main needs --reason \"<why this cannot wait for main>\""
  [[ "$REASON" =~ ^[A-Za-z0-9\ ._,:\;()/#+@-]{10,200}$ ]] \
    || refuse "--reason must be 10-200 characters of letters, digits, spaces and ._,:;()/#+@-"
fi

REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)" \
  || refuse "not inside a git checkout of the repository"
git() { command git -C "$REPO_ROOT" "$@"; }

echo "==> git fetch origin main"
git fetch --quiet origin +refs/heads/main:refs/remotes/origin/main \
  || refuse "could not fetch main from origin; without it nothing proves the commit is on main"
MAIN_SHA="$(git rev-parse --verify --quiet 'refs/remotes/origin/main^{commit}')" \
  || refuse "origin/main does not resolve after the fetch"

if [[ "$TARGET" == main ]]; then
  SHA="$MAIN_SHA"
elif [[ "$TARGET" =~ ^[0-9a-f]{40}$ ]]; then
  SHA="$TARGET"
  git cat-file -e "$SHA^{commit}" 2>/dev/null || refuse "$SHA is not a commit in this clone"
else
  refuse "the commit must be 'main' or a full 40-character lowercase sha (got: $TARGET)"
fi

SOURCE_REF=main
if git merge-base --is-ancestor "$SHA" "$MAIN_SHA"; then
  echo "==> $SHA is on origin/main ($MAIN_SHA)"
  ((!ALLOW_NON_MAIN)) || refuse "$SHA is already on main; drop --allow-non-main and --reason"
else
  if ((!ALLOW_NON_MAIN)); then
    echo "REFUSED: $SHA is not on origin/main ($MAIN_SHA)." >&2
    echo "vault-syd1 is production and only receives commits already on main." >&2
    echo "Nothing was sent to $HOST." >&2
    exit 2
  fi
  SOURCE_REF=non-main
  echo "WARN: EMERGENCY OVERRIDE: delivering $SHA (NOT on origin/main) to production ($HOST). Reason: $REASON" >&2
fi

# --- Build locally, from the commit ------------------------------------------

command -v node >/dev/null 2>&1 || refuse "node is not installed here"
[[ "$(node -p 'process.versions.node.split(".")[0]')" == 22 ]] || refuse "build with Node 22 (the host runs Node 22)"
command -v npm >/dev/null 2>&1 || refuse "npm is not installed here"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/secrets-mcp-deliver.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
git archive --format=tar "$SHA" -- mcp deploy/vault-syd1-mcp | tar -xf - -C "$WORK" \
  || refuse "git archive failed for $SHA (mcp/ or deploy/vault-syd1-mcp/ missing at that commit)"

echo "==> building the release from $SHA (npm ci, typecheck, test, build)"
(
  cd "$WORK/mcp"
  npm ci --no-audit --no-fund >/dev/null
  npm run --silent typecheck
  npm test --silent >/dev/null
  npm run --silent build
) || refuse "the build of $SHA failed; nothing was sent"

RELEASE_DIR="$WORK/release"
mkdir -p "$RELEASE_DIR"
cp -R "$WORK/mcp/dist" "$WORK/mcp/package.json" "$WORK/mcp/package-lock.json" "$RELEASE_DIR/"
(cd "$RELEASE_DIR" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund >/dev/null) \
  || refuse "installing production dependencies failed"
echo "$SHA" >"$RELEASE_DIR/SOURCE_COMMIT"

BUNDLE_DIR="$WORK/bundle"
mkdir -p "$BUNDLE_DIR/deploy"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf "$BUNDLE_DIR/release.tar.gz" -C "$RELEASE_DIR" .
(cd "$BUNDLE_DIR" && sha256sum release.tar.gz >release.tar.gz.sha256)
cp -R "$WORK/deploy/vault-syd1-mcp" "$BUNDLE_DIR/deploy/"
echo "==> release.tar.gz sha256 $(cut -d' ' -f1 "$BUNDLE_DIR/release.tar.gz.sha256")"

# --- Ship and run the apply -------------------------------------------------

REMOTE_DIR="$REMOTE_BUNDLES/$SHA"
echo "==> sending the bundle for $SHA to $HOST:$REMOTE_DIR"
# Client-side expansion is intended below: $SHA is 40 hex characters (checked
# above) and REASON is limited to a quote-free character set.
# shellcheck disable=SC2029
# The newest 5 bundles are kept (by mtime; only sha-named directories).
tar -C "$BUNDLE_DIR" -cf - . | ssh "${SSH_OPTS[@]}" "$HOST" \
  "set -e; rm -rf $REMOTE_DIR; mkdir -p $REMOTE_DIR; tar -xf - -C $REMOTE_DIR; touch $REMOTE_DIR;
   cd $REMOTE_BUNDLES && ls -1t | grep -E '^[0-9a-f]{40}\$' | tail -n +6 | xargs -r rm -rf --"

REMOTE_APPLY="$REMOTE_DIR/deploy/vault-syd1-mcp/apply-on-vault-syd1.sh"
ARGS="--source-commit $SHA --source-ref $SOURCE_REF"
[[ "$SOURCE_REF" == non-main ]] && ARGS+=" --reason '$REASON'"
if ((APPLY)); then
  CMD="sudo -n setsid --wait bash $REMOTE_APPLY $ARGS"
  echo "==> APPLY on $HOST (source_ref=$SOURCE_REF), detached from this session"
else
  CMD="sudo -n bash $REMOTE_APPLY $ARGS --check"
  echo "==> check only on $HOST (source_ref=$SOURCE_REF); re-run with --apply to apply"
fi

set +e
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$HOST" "$CMD" </dev/null
status=$?
set -e
if ((APPLY)) && ((status == 255)); then
  echo "WARN: the connection to $HOST dropped while the apply ran. It is detached: it finishes or rolls itself back." >&2
  echo "WARN: read the outcome with: ssh $HOST 'sudo ls -t /opt/dumont-secrets-mcp/logs | head -1' and then" >&2
  echo "WARN:   bash $0 --show-release" >&2
fi
if ((APPLY)) && ((status == 0)); then
  echo "==> read it back: bash $0 --show-release"
fi
exit "$status"
