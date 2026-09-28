#!/usr/bin/env bash
# Install / switch the Dumont Secrets MCP release on vault-syd1 (SEC-14).
#
# Run ON vault-syd1, as root, from the bundle deliver-to-vault-syd1.sh unpacked
# into ~/dumont-secrets-mcp-bundles/<sha>/. Do not call this by hand for an
# apply: the deliver script proves the commit is on origin/main, builds the
# release from that commit and runs this with the right flags:
#   sudo bash <bundle>/deploy/vault-syd1-mcp/apply-on-vault-syd1.sh --source-commit <sha> --source-ref main --check
#   sudo setsid --wait bash <bundle>/deploy/vault-syd1-mcp/apply-on-vault-syd1.sh --source-commit <sha> --source-ref main
#   sudo bash /opt/dumont-secrets-mcp/apply-on-vault-syd1.sh --show-release     # read-only
#
# Layout it owns:
#   /opt/dumont-secrets-mcp/releases/<sha>/   immutable release (dist, node_modules, package*.json)
#   /opt/dumont-secrets-mcp/current           symlink -> releases/<sha>
#   /opt/dumont-secrets-mcp/RELEASE           what is installed (source_commit, source_ref, ...)
#   /opt/dumont-secrets-mcp/logs/             one 0600 log per apply
#   /etc/systemd/system/dumont-secrets-mcp.service
#
# What it NEVER does: read, print, copy or back up a secret. The machine-account
# password file (/etc/dumont-secrets-mcp/bw-password) is only stat()ed for
# owner, mode and size. The env file (no secret in it by design) is stat()ed
# and hashed (sha256 into RELEASE, never its content). The policy is hashed
# and parsed.
# Creating them is an owner step (bootstrap-owner-steps.md). The Caddy route
# is an owner step too.
#
# Fail-closed: every check runs before anything changes. After the first
# change, any exit that did not reach APPLY_DONE=1 (error, signal, dropped
# session) restores the previous symlink, unit and RELEASE and restarts the
# previous release, or stops the service if there was none.
set -euo pipefail
trap '' PIPE HUP
trap 'exit 130' INT TERM
APPLY_DONE=0

APP_ROOT="/opt/dumont-secrets-mcp"
RELEASES="$APP_ROOT/releases"
CURRENT="$APP_ROOT/current"
RELEASE_FILE="$APP_ROOT/RELEASE"
LOG_DIR="$APP_ROOT/logs"
LOG_KEEP=20
KEEP_RELEASES=5
KEEP_BACKUPS=5
MIN_PASSWORD_BYTES=20
UNIT_NAME="dumont-secrets-mcp.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"
SERVICE_USER="secrets-mcp"
ENV_FILE="/etc/dumont-secrets-mcp.env"
SECRETS_DIR="/etc/dumont-secrets-mcp"
PASSWORD_FILE="$SECRETS_DIR/bw-password"
POLICY_FILE="$SECRETS_DIR/policy.json"
BW_BIN="/usr/local/bin/bw"
PORT=3015
SOURCE_REPO="DumontAI/dumont-secrets"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"
HEALTH_SETTLE="${HEALTH_SETTLE:-5}"
# bw login + first sync can take a while on a cold CLI data dir.
VAULT_TIMEOUT="${VAULT_TIMEOUT:-90}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARBALL="$BUNDLE_ROOT/release.tar.gz"
TARBALL_SUM_FILE="$BUNDLE_ROOT/release.tar.gz.sha256"
UNIT_TEMPLATE="$SCRIPT_DIR/$UNIT_NAME"

CHECK_ONLY=0
SHOW_RELEASE=0
SOURCE_COMMIT=""
SOURCE_REF=""
OVERRIDE_REASON=""
APPLIED_BY=""
APPLY_LOG=""

usage() {
  echo "usage: $0 --source-commit <sha40> --source-ref main|non-main [--reason <text>] [--check]"
  echo "       $0 --show-release"
}

while (($#)); do
  case "$1" in
    --check) CHECK_ONLY=1 ;;
    --show-release) SHOW_RELEASE=1 ;;
    --source-commit) (($# >= 2)) || { echo "ERROR: --source-commit needs a value"; exit 2; }; SOURCE_COMMIT="$2"; shift ;;
    --source-ref) (($# >= 2)) || { echo "ERROR: --source-ref needs a value"; exit 2; }; SOURCE_REF="$2"; shift ;;
    --reason) (($# >= 2)) || { echo "ERROR: --reason needs a value"; exit 2; }; OVERRIDE_REASON="$2"; shift ;;
    --applied-by) (($# >= 2)) || { echo "ERROR: --applied-by needs a value"; exit 2; }; APPLIED_BY="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1"; usage; exit 2 ;;
  esac
  shift
done

fail() {
  echo "ERROR: $1"
  exit 1
}

sha256_of() {
  if [[ -f "$1" ]]; then sha256sum "$1" | cut -d' ' -f1; fi
}

release_value() {
  [[ -f "$RELEASE_FILE" ]] || return 0
  grep -m1 "^${1}=" "$RELEASE_FILE" | cut -d= -f2- || true
}

node_bin() {
  command -v node 2>/dev/null || true
}

render_unit() {
  local node="$1"
  sed -e "s#@NODE_BIN@#$node#g" -e "s#@NODE_DIR@#$(dirname "$node")#g" "$UNIT_TEMPLATE"
}

main_pid() {
  local pid
  pid="$(systemctl show -p MainPID --value "$UNIT_NAME" 2>/dev/null || true)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] && echo "$pid"
  return 0
}

# The release the RUNNING process started in: systemd resolved `current` at
# start, so the process cwd is the real releases/<sha> directory.
runtime_release_dir() {
  local pid
  pid="$(main_pid)"
  [[ -n "$pid" ]] || return 0
  readlink -e "/proc/$pid/cwd" 2>/dev/null || true
}

# Where `current` points, only if it IS a symlink to something that exists.
# A plain directory or a dangling link is not a release to go back to.
current_target() {
  if [[ -L "$CURRENT" ]]; then
    readlink -e "$CURRENT" 2>/dev/null || true
  fi
}

# Lines the running process wrote to the journal since it started (fixed
# lines only: `secrets-mcp policy sha256=...`, `secrets-mcp vault outcome=...`).
journal_of_pid() {
  local pid="$1"
  journalctl -q -o cat --no-pager -u "$UNIT_NAME" "_PID=$pid" 2>/dev/null || true
}

runtime_policy_sha() {
  local pid
  pid="$(main_pid)"
  [[ -n "$pid" ]] || return 0
  journal_of_pid "$pid" | grep -oE '^secrets-mcp policy sha256=[0-9a-f]{64}$' | tail -n1 | cut -d= -f2
}

# --- Read-only report --------------------------------------------------------

show_release() {
  if [[ ! -f "$RELEASE_FILE" ]]; then
    echo "no-release: $RELEASE_FILE does not exist (never applied, or applied by something else)"
    return 4
  fi
  echo "==> $RELEASE_FILE"
  cat "$RELEASE_FILE"
  local source_ref commit drift=0 want_dir actual_dir runtime_dir
  source_ref="$(release_value source_ref)"
  if [[ "$source_ref" != main ]]; then
    echo "WARN: source-ref-not-main: production runs a commit not proven to be on main (source_ref=${source_ref:-unrecorded})"
    echo "WARN:   override_reason: $(release_value override_reason)"
  fi
  commit="$(release_value source_commit)"
  want_dir="$RELEASES/$commit"
  actual_dir="$(current_target)"
  if [[ "$actual_dir" != "$want_dir" ]]; then
    echo "drift: $CURRENT is ${actual_dir:-not a symlink to an existing release}, RELEASE says $want_dir"
    drift=1
  fi
  # Hashes only; the env file's values are never printed.
  if [[ "$(sha256_of "$POLICY_FILE")" != "$(release_value policy_sha256)" ]]; then
    echo "drift: $POLICY_FILE changed since the apply (policy_sha256); re-apply to record and load it"
    drift=1
  fi
  if [[ "$(sha256_of "$ENV_FILE")" != "$(release_value env_sha256)" ]]; then
    echo "drift: $ENV_FILE changed since the apply (env_sha256); re-apply to record and load it"
    drift=1
  fi
  if [[ "$(cat "$want_dir/.tarball_sha256" 2>/dev/null || true)" != "$(release_value tarball_sha256)" ]]; then
    echo "drift: $want_dir was not installed from the recorded tarball_sha256"
    drift=1
  fi
  if [[ "$(sha256_of "$UNIT_PATH")" != "$(release_value unit_sha256)" ]]; then
    echo "drift: $UNIT_PATH no longer matches unit_sha256"
    drift=1
  fi
  local runtime_status=0 runtime_policy policy_matches=0
  runtime_dir="$(runtime_release_dir)"
  runtime_policy="$(runtime_policy_sha)"
  # The process, the file on disk and the RELEASE must all name the same policy.
  if [[ -n "$runtime_policy" && "$runtime_policy" == "$(sha256_of "$POLICY_FILE")" ]] \
     && [[ "$runtime_policy" == "$(release_value policy_sha256)" ]]; then
    policy_matches=1
  fi
  if [[ -z "$runtime_dir" ]]; then
    echo "runtime-unknown: $UNIT_NAME has no running process whose cwd can be read (not root, or not running)"
    runtime_status=6
  elif [[ "$runtime_dir" != "$want_dir" ]]; then
    echo "runtime-drifted: the running process started in $runtime_dir, RELEASE says $want_dir"
    runtime_status=5
  elif [[ "$(systemctl is-active "$UNIT_NAME" 2>/dev/null || true)" != active ]]; then
    echo "runtime-drifted: $UNIT_NAME is not active"
    runtime_status=5
  elif [[ -z "$runtime_policy" ]]; then
    echo "runtime-unknown: the running process's 'secrets-mcp policy sha256=' line is not in the journal (rotated away?)"
    runtime_status=6
  elif ((!policy_matches)); then
    echo "runtime-drifted: the running process loaded policy sha256 $runtime_policy; file and RELEASE may differ (restart via a re-apply)"
    runtime_status=5
  else
    echo "runtime-in-sync: $UNIT_NAME is active, running $want_dir, with the recorded policy loaded"
  fi
  if ((drift)); then
    echo "drifted: this host is NOT running what the RELEASE describes"
    return 3
  fi
  echo "in-sync: current, release tarball, unit, policy and env file match the RELEASE"
  return "$runtime_status"
}

if ((SHOW_RELEASE)); then
  ((CHECK_ONLY == 0)) || { echo "ERROR: --show-release reports, --check validates; run one or the other"; exit 2; }
  status=0
  show_release || status=$?
  exit "$status"
fi

# --- Arguments that name what is being applied --------------------------------

[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "ERROR: --source-commit must be a full 40-character lowercase sha; nothing was changed"; exit 2; }
case "$SOURCE_REF" in
  main) [[ -z "$OVERRIDE_REASON" ]] || { echo "ERROR: --reason is only for --source-ref non-main"; exit 2; } ;;
  non-main) [[ -n "$OVERRIDE_REASON" ]] || { echo "ERROR: --source-ref non-main needs --reason"; exit 2; } ;;
  *) echo "ERROR: --source-ref must be main or non-main; nothing was changed"; exit 2 ;;
esac
if [[ -n "$OVERRIDE_REASON" && ! "$OVERRIDE_REASON" =~ ^[A-Za-z0-9\ ._,:\;()/#+@-]{10,200}$ ]]; then
  echo "ERROR: --reason must be 10-200 characters of letters, digits, spaces and ._,:;()/#+@-"
  exit 2
fi
APPLIED_BY="${APPLIED_BY:-${SUDO_USER:-${USER:-unknown}}}"
[[ "$APPLIED_BY" =~ ^[A-Za-z0-9._@+-]{1,64}$ ]] || { echo "ERROR: --applied-by must be 1-64 characters of [A-Za-z0-9._@+-]"; exit 2; }

# --- Checks. Nothing above or in this block changes anything. ---------------

((EUID == 0)) || fail "run as root (sudo): the checks read file owners and the apply installs a unit"
for tool in sha256sum systemctl journalctl curl tar readlink stat ss; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not available"
done

[[ -f "$TARBALL" && -f "$TARBALL_SUM_FILE" ]] || fail "the bundle has no release.tar.gz (+ .sha256); deliver it with deliver-to-vault-syd1.sh"
TARBALL_SHA="$(sha256_of "$TARBALL")"
[[ "$TARBALL_SHA" == "$(cut -d' ' -f1 "$TARBALL_SUM_FILE")" ]] || fail "release.tar.gz does not match its .sha256: the transfer is incomplete"
[[ -f "$UNIT_TEMPLATE" ]] || fail "missing $UNIT_TEMPLATE in the bundle"

id -u "$SERVICE_USER" >/dev/null 2>&1 || fail "unix user $SERVICE_USER does not exist (bootstrap-owner-steps.md, step 1)"
[[ "$(id -u "$SERVICE_USER")" != 0 ]] || fail "$SERVICE_USER must not be uid 0"

NODE="$(node_bin)"
[[ -n "$NODE" ]] || fail "node is not installed (bootstrap-owner-steps.md, step 2)"
NODE="$(readlink -e "$NODE")"
node_major="$("$NODE" -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)"
[[ "$node_major" == 22 ]] || fail "node at $NODE is major ${node_major:-unknown}; the MCP needs Node 22"
[[ -x "$BW_BIN" ]] || fail "$BW_BIN is missing or not executable (bootstrap-owner-steps.md, step 2)"

# owner:group mode of a path, never its content.
stat_of() { stat -c '%U:%G %a %F' "$1" 2>/dev/null || true; }

env_stat="$(stat_of "$ENV_FILE")"
[[ -n "$env_stat" ]] || fail "$ENV_FILE does not exist (bootstrap-owner-steps.md, step 5)"
[[ "$env_stat" == "root:root 600 regular file" ]] || fail "$ENV_FILE must be root:root 0600, regular file (is: $env_stat)"

pw_stat="$(stat_of "$PASSWORD_FILE")"
[[ -n "$pw_stat" ]] || fail "$PASSWORD_FILE does not exist (bootstrap-owner-steps.md, step 4)"
[[ "$pw_stat" == "$SERVICE_USER:$SERVICE_USER 600 regular file" ]] \
  || fail "$PASSWORD_FILE must be $SERVICE_USER:$SERVICE_USER 0600, regular file (is: $pw_stat)"
# Size from stat, never the content: an empty or truncated pipe is caught here.
pw_size="$(stat -c '%s' "$PASSWORD_FILE")"
((pw_size >= MIN_PASSWORD_BYTES)) \
  || fail "$PASSWORD_FILE is $pw_size bytes; the machine-account password must be at least $MIN_PASSWORD_BYTES (re-run bootstrap step 4)"
dir_stat="$(stat_of "$SECRETS_DIR")"
[[ "$dir_stat" == "root:$SERVICE_USER 750 directory" ]] || fail "$SECRETS_DIR must be root:$SERVICE_USER 0750 (is: ${dir_stat:-missing})"

policy_stat="$(stat_of "$POLICY_FILE")"
[[ "$policy_stat" == "root:$SERVICE_USER 640 regular file" ]] || fail "$POLICY_FILE must be root:$SERVICE_USER 0640 (is: ${policy_stat:-missing})"

# Unpack the release into a scratch dir to validate it before anything moves.
# The policy is not a secret; it is parsed with the release's own parser so the
# check and the service can never disagree.
SCRATCH="$(mktemp -d /tmp/secrets-mcp-check.XXXXXX)"
cleanup_scratch() { rm -rf "$SCRATCH"; }
# Until the rollback trap replaces it (after the last use of SCRATCH).
trap cleanup_scratch EXIT
tar -xzf "$TARBALL" -C "$SCRATCH"
[[ -f "$SCRATCH/dist/http.js" && -d "$SCRATCH/node_modules" && -f "$SCRATCH/package.json" ]] \
  || { cleanup_scratch; fail "the release tarball is not a built release (dist/http.js, node_modules, package.json)"; }
if ! policy_check="$("$NODE" --input-type=module -e "
  const { loadPolicy } = await import('$SCRATCH/dist/policy.js');
  const policy = loadPolicy('$POLICY_FILE');
  console.log('policy ok: ' + policy.metaCollections.length + ' meta, ' + policy.readerCollections.length + ' reader collections, 1 write collection');
" 2>&1)"; then
  cleanup_scratch
  fail "the policy file does not parse: $(tail -n1 <<<"$policy_check" | cut -c1-200)"
fi
cleanup_scratch
echo "==> $policy_check"

# The port is ours or free.
listener="$(ss -Hltnp "sport = :$PORT" 2>/dev/null || true)"
if [[ -n "$listener" ]] && ! grep -q "pid=$(main_pid)," <<<"$listener"; then
  fail "127.0.0.1:$PORT is held by another process: $listener"
fi

PREVIOUS_DIR="$(current_target)"
if [[ -e "$CURRENT" && ! -L "$CURRENT" ]]; then
  fail "$CURRENT exists but is not a symlink; move it aside by hand after checking what it is"
fi
TARGET_DIR="$RELEASES/$SOURCE_COMMIT"
if [[ -d "$TARGET_DIR" && "$(cat "$TARGET_DIR/.tarball_sha256" 2>/dev/null || true)" != "$TARBALL_SHA" ]]; then
  fail "$TARGET_DIR exists but was installed from a different tarball; releases are immutable. Remove it by hand after checking why."
fi
RENDERED_UNIT="$(render_unit "$NODE")"

echo "==> plan (source_commit=$SOURCE_COMMIT, source_ref=$SOURCE_REF):"
echo "    current release:  ${PREVIOUS_DIR:-<none>}"
echo "    target release:   $TARGET_DIR $([[ -d "$TARGET_DIR" ]] && echo '(already installed, reused)' || echo '(new)')"
echo "    tarball sha256:   $TARBALL_SHA"
echo "    node:             $NODE (major $node_major)"
if [[ -f "$UNIT_PATH" ]] && diff -q <(printf '%s\n' "$RENDERED_UNIT") "$UNIT_PATH" >/dev/null; then
  echo "    unit:             unchanged"
else
  echo "    unit:             will be installed/updated; diff:"
  unit_before="$UNIT_PATH"
  [[ -f "$unit_before" ]] || unit_before=/dev/null
  diff -u "$unit_before" <(printf '%s\n' "$RENDERED_UNIT") 2>/dev/null | sed 's/^/      /' || true
fi
echo "    service:          $(systemctl is-active "$UNIT_NAME" 2>/dev/null || true) -> restarted on $TARGET_DIR"
echo "    policy sha256:    $(sha256_of "$POLICY_FILE") (recorded: $(release_value policy_sha256))"
echo "    env sha256:       $(sha256_of "$ENV_FILE") (recorded: $(release_value env_sha256))"
echo "    NOT touched:      $ENV_FILE, $PASSWORD_FILE, $POLICY_FILE, Caddy"

if ((CHECK_ONLY)); then
  echo "OK: checks passed; nothing was changed (re-run with --apply to apply)"
  exit 0
fi

# --- Apply --------------------------------------------------------------------

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0755 "$APP_ROOT" "$RELEASES"
install -d -m 0700 "$LOG_DIR"
APPLY_LOG="$LOG_DIR/apply-$STAMP-$$.log"
( umask 077 && : >>"$APPLY_LOG" )
exec > >(tee -a --output-error=warn-nopipe "$APPLY_LOG") 2>&1
echo "==> apply log: $APPLY_LOG (source_commit=$SOURCE_COMMIT, source_ref=$SOURCE_REF, applied_by=$APPLIED_BY)"
mapfile -t old_logs < <(find "$LOG_DIR" -maxdepth 1 -type f -name 'apply-*.log' -printf '%f\n' | LC_ALL=C sort)
if ((${#old_logs[@]} > LOG_KEEP)); then
  for old in "${old_logs[@]:0:${#old_logs[@]}-LOG_KEEP}"; do rm -f "${LOG_DIR:?}/$old"; done
fi

BACKUP_DIR="$APP_ROOT/backups/$STAMP-$$"
install -d -m 0700 "$APP_ROOT/backups"
mkdir -m 0700 "$BACKUP_DIR"
[[ -f "$UNIT_PATH" ]] && cp -a "$UNIT_PATH" "$BACKUP_DIR/unit"
[[ -f "$RELEASE_FILE" ]] && cp -a "$RELEASE_FILE" "$BACKUP_DIR/RELEASE"
OLD_PID="$(main_pid)"
ROLLBACK_ARMED=0
NEW_RELEASE_CREATED=0

# shellcheck disable=SC2329  # invoked by the EXIT trap below
rollback() {
  local status=$?
  trap - EXIT
  trap '' INT TERM
  set +e
  if ((APPLY_DONE)) || ((!ROLLBACK_ARMED)); then
    exit "$status"
  fi
  ((status)) || status=1
  echo "ERROR: the apply failed (exit $status); restoring the previous state"
  # Stop the (new) process BEFORE touching its unit file, so systemd never
  # holds a running service whose unit changed underneath it.
  systemctl stop "$UNIT_NAME" 2>/dev/null
  if [[ -f "$BACKUP_DIR/unit" ]]; then
    cp -a "$BACKUP_DIR/unit" "$UNIT_PATH"
  else
    systemctl disable "$UNIT_NAME" 2>/dev/null
    rm -f "$UNIT_PATH"
  fi
  systemctl daemon-reload
  if [[ -n "$PREVIOUS_DIR" && -d "$PREVIOUS_DIR" && -f "$BACKUP_DIR/unit" ]]; then
    ln -sfn "$PREVIOUS_DIR" "$CURRENT.rollback" && mv -Tf "$CURRENT.rollback" "$CURRENT"
    if [[ -f "$BACKUP_DIR/RELEASE" ]]; then cp -a "$BACKUP_DIR/RELEASE" "$RELEASE_FILE"; else rm -f "$RELEASE_FILE"; fi
    if systemctl start "$UNIT_NAME" && sleep "$HEALTH_SETTLE" && [[ "$(systemctl is-active "$UNIT_NAME")" == active ]]; then
      echo "ERROR: rolled back. $UNIT_NAME runs the previous release $PREVIOUS_DIR again."
      echo "ERROR: (the rollback checked only that it is active: its vault session and policy were NOT re-checked;"
      echo "ERROR:  read: journalctl -u $UNIT_NAME -o cat -n 20 | grep -E '^secrets-mcp (policy|vault)')"
    else
      echo "ERROR: rollback INCOMPLETE: the previous release did not come back. A human is needed now:"
      echo "ERROR:   systemctl status $UNIT_NAME; journalctl -u $UNIT_NAME -n 100"
    fi
  else
    systemctl disable "$UNIT_NAME" 2>/dev/null
    rm -f "$CURRENT" "$RELEASE_FILE"
    echo "ERROR: not rolled back: there was no previous release. $UNIT_NAME is stopped and disabled."
  fi
  if ((NEW_RELEASE_CREATED)); then
    rm -rf "${TARGET_DIR:?}"
    echo "==> removed the half-installed $TARGET_DIR"
  fi
  echo "==> the full output of this apply: $APPLY_LOG"
  exit "$status"
}
trap rollback EXIT
ROLLBACK_ARMED=1

# 1. The release directory: unpacked once, root-owned, read-only for the service.
if [[ ! -d "$TARGET_DIR" ]]; then
  STAGING="$RELEASES/.$SOURCE_COMMIT.tmp"
  rm -rf "$STAGING"
  mkdir -m 0755 "$STAGING"
  tar -xzf "$TARBALL" -C "$STAGING" --no-same-owner
  chown -R root:root "$STAGING"
  chmod -R go-w,a+rX "$STAGING"
  echo "$TARBALL_SHA" >"$STAGING/.tarball_sha256"
  mv -T "$STAGING" "$TARGET_DIR"
  NEW_RELEASE_CREATED=1
  echo "==> installed $TARGET_DIR"
fi

# 2. The unit.
printf '%s\n' "$RENDERED_UNIT" >"$UNIT_PATH.tmp"
chmod 0644 "$UNIT_PATH.tmp"
mv -f "$UNIT_PATH.tmp" "$UNIT_PATH"
systemctl daemon-reload
systemctl enable "$UNIT_NAME" >/dev/null 2>&1

# 3. Switch `current` atomically, then restart.
ln -sfn "$TARGET_DIR" "$CURRENT.new"
mv -Tf "$CURRENT.new" "$CURRENT"
echo "==> $CURRENT -> $TARGET_DIR"
systemctl restart "$UNIT_NAME"

# 4. Prove it: a NEW process, started in the target release, active on two
# readings HEALTH_SETTLE seconds apart, answering 401 + challenge on /mcp and
# the metadata JSON with the three role scopes.
deadline=$((SECONDS + HEALTH_TIMEOUT))
proven=0
while ((SECONDS < deadline)); do
  pid="$(main_pid)"
  if [[ -n "$pid" && "$pid" != "$OLD_PID" && "$(runtime_release_dir)" == "$TARGET_DIR" ]] \
     && [[ "$(systemctl is-active "$UNIT_NAME")" == active ]]; then
    headers="$(curl -sS -o /dev/null -D - --max-time 5 -X POST -H 'content-type: application/json' --data '{}' "http://127.0.0.1:$PORT/mcp" 2>/dev/null || true)"
    metadata="$(curl -fsS --max-time 5 "http://127.0.0.1:$PORT/.well-known/oauth-protected-resource" 2>/dev/null || true)"
    if grep -qE '^HTTP/[0-9.]+ 401' <<<"$headers" && grep -qi '^www-authenticate: Bearer resource_metadata=' <<<"$headers" \
       && "$NODE" -e '
         const m = JSON.parse(process.argv[1]);
         const ok = typeof m.resource === "string" && Array.isArray(m.scopes_supported) && m.scopes_supported.length === 3
           && m.scopes_supported.every(s => s.startsWith("urn:zitadel:iam:org:project:role:"));
         process.exit(ok ? 0 : 1);' "$metadata" 2>/dev/null; then
      sleep "$HEALTH_SETTLE"
      if [[ "$(main_pid)" == "$pid" && "$(systemctl is-active "$UNIT_NAME")" == active ]]; then
        proven=1
        break
      fi
    fi
  fi
  sleep 2
done
((proven)) || fail "$UNIT_NAME did not prove itself within ${HEALTH_TIMEOUT}s (new pid in $TARGET_DIR, active, 401 + challenge, metadata with three role scopes). journalctl -u $UNIT_NAME -n 50"
echo "==> runtime: pid $pid runs $TARGET_DIR; /mcp answers 401 with the OAuth challenge; metadata lists three role scopes"

# 4b. The process loaded the policy on disk, and the machine account opened a
# vault session (startup self-test; fixed lines, no detail).
POLICY_SHA="$(sha256_of "$POLICY_FILE")"
vault_deadline=$((SECONDS + VAULT_TIMEOUT))
vault_outcome=""
while ((SECONDS < vault_deadline)); do
  vault_outcome="$(journal_of_pid "$pid" | grep -oE '^secrets-mcp vault outcome=(unlocked|failed)$' | tail -n1 | cut -d= -f2 || true)"
  [[ -n "$vault_outcome" ]] && break
  sleep 2
done
case "$vault_outcome" in
  unlocked) echo "==> vault: the machine account opened a session (secrets-mcp vault outcome=unlocked)" ;;
  failed)
    echo "ERROR: ================================================================"
    echo "ERROR: the service is up, but the vault MACHINE ACCOUNT could not log in or unlock."
    echo "ERROR: This is a CREDENTIALS problem, not a code problem. Check, in order:"
    echo "ERROR:   - $PASSWORD_FILE holds the current master password (bootstrap step 4; never print it)"
    echo "ERROR:   - BW_EMAIL in $ENV_FILE is the machine account, and it is confirmed in the organization"
    echo "ERROR:   - no SSO requirement (org policy or SSO_ONLY) and no two-step login apply to it (bootstrap step 3)"
    echo "ERROR:   - journalctl -u $UNIT_NAME -o cat | grep 'secrets-mcp bw outcome=' (outcome names only)"
    echo "ERROR: ================================================================"
    fail "vault self-test failed (secrets-mcp vault outcome=failed)"
    ;;
  *) fail "no 'secrets-mcp vault outcome=' line from pid $pid within ${VAULT_TIMEOUT}s; is the vault reachable at BW_SERVER_URL?" ;;
esac
running_policy="$(journal_of_pid "$pid" | grep -oE '^secrets-mcp policy sha256=[0-9a-f]{64}$' | tail -n1 | cut -d= -f2 || true)"
[[ "$running_policy" == "$POLICY_SHA" ]] \
  || fail "pid $pid loaded policy sha256 ${running_policy:-<not logged>}, the file on disk is $POLICY_SHA"
echo "==> policy: pid $pid loaded $POLICY_FILE (sha256 $POLICY_SHA)"

# 5. Record what is installed, atomically (hashes only for policy and env).
{
  echo "source_repo=$SOURCE_REPO"
  echo "source_commit=$SOURCE_COMMIT"
  echo "source_ref=$SOURCE_REF"
  [[ -n "$OVERRIDE_REASON" ]] && echo "override_reason=$OVERRIDE_REASON"
  echo "applied_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "applied_by=$APPLIED_BY"
  echo "tarball_sha256=$TARBALL_SHA"
  echo "unit_sha256=$(sha256_of "$UNIT_PATH")"
  echo "policy_sha256=$POLICY_SHA"
  echo "env_sha256=$(sha256_of "$ENV_FILE")"
  echo "node=$NODE"
} >"$RELEASE_FILE.tmp"
chmod 0644 "$RELEASE_FILE.tmp"
mv -f "$RELEASE_FILE.tmp" "$RELEASE_FILE"
install -m 0755 "$SCRIPT_DIR/apply-on-vault-syd1.sh" "$APP_ROOT/apply-on-vault-syd1.sh"

# 6. Keep the newest releases (never the current or the previous one).
mapfile -t releases < <(find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9a-f]{40}' -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)
count=0
for dir in "${releases[@]}"; do
  count=$((count + 1))
  if ((count > KEEP_RELEASES)) && [[ "$dir" != "$TARGET_DIR" && "$dir" != "$PREVIOUS_DIR" ]]; then
    rm -rf "${dir:?}"
    echo "==> pruned $dir"
  fi
done
mapfile -t backups < <(find "$APP_ROOT/backups" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort)
if ((${#backups[@]} > KEEP_BACKUPS)); then
  for old in "${backups[@]:0:${#backups[@]}-KEEP_BACKUPS}"; do rm -rf "${APP_ROOT:?}/backups/${old:?}"; done
fi

APPLY_DONE=1
echo "==> recorded $RELEASE_FILE; read it back with: sudo bash $APP_ROOT/apply-on-vault-syd1.sh --show-release"
[[ "$SOURCE_REF" == main ]] || echo "WARN: production now runs a commit not proven to be on main (source_ref=$SOURCE_REF)"
echo "OK: dumont-secrets-mcp $SOURCE_COMMIT applied and running on 127.0.0.1:$PORT"
exit 0
