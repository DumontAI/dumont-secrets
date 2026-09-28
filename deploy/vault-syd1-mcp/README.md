# Dumont Secrets MCP on vault-syd1

The MCP server in [`mcp/`](../../mcp/README.md) runs on **vault-syd1**, next to the
vault it fronts:

```text
MCP client ── OAuth + PKCE (dedicated project + client) ──> auth.getdumont.ai (ZITADEL)
    │
    └── HTTPS secret.getdumont.ai/mcp ── Caddy ──> 127.0.0.1:3015  dumont-secrets-mcp.service (user secrets-mcp)
                         everything else ── Caddy ──> existing upstream  OIDCWarden (unchanged)
                                                         ▲
             bw CLI (machine account, via https://secret.getdumont.ai) ┘
```

| Piece | Where |
|---|---|
| Unit | `/etc/systemd/system/dumont-secrets-mcp.service` (from `dumont-secrets-mcp.service`, rendered by the apply) |
| Releases | `/opt/dumont-secrets-mcp/releases/<sha>/`, immutable; `current` -> the running one |
| Release record | `/opt/dumont-secrets-mcp/RELEASE` (`source_commit`, `source_ref`, `tarball_sha256`, `unit_sha256`, `policy_sha256`, `env_sha256`, ...) |
| Apply logs | `/opt/dumont-secrets-mcp/logs/apply-*.log` (0600, newest 20) |
| Environment | `/etc/dumont-secrets-mcp.env`, root:root 0600 (owner step; template `dumont-secrets-mcp.env.example`) |
| Machine-account password | `/etc/dumont-secrets-mcp/bw-password`, secrets-mcp 0600 (owner step) |
| Collection policy | `/etc/dumont-secrets-mcp/policy.json`, root:secrets-mcp 0640 (owner step; shape in `mcp/policy.example.json`) |
| bw CLI state | `/var/lib/dumont-secrets-mcp/bw` (systemd StateDirectory, 0700) |
| Caddy route | `Caddyfile.snippet` (owner step) |

The first install needs the owner-only steps in
[`bootstrap-owner-steps.md`](./bootstrap-owner-steps.md) (unix user, Node 22 +
bw, machine account and collections, password file, env and policy, the
dedicated ZITADEL project/app/roles/grants, Caddy).

## Delivering (production comes from `main` only)

From a checkout of this repository, on the operator's machine:

```bash
bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main            # --check: prints the plan; the service is not touched
bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main --apply    # the real apply
bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh --show-release  # what is running, read-only
```

`--check` changes nothing in the service, its files or its unit. It does copy
the bundle to `~/dumont-secrets-mcp-bundles/<sha>` in the ssh user's home on
the host (the newest 5 bundles are kept), because the checks run there.

1. `git fetch origin main`; a commit not on `origin/main` is refused **before
   any ssh** (`--allow-non-main --reason "..."` is the recorded emergency path).
2. The release is built locally from `git archive <sha> mcp` with Node 22:
   `npm ci`, typecheck, tests, build, then production-only `node_modules`,
   packed as `release.tar.gz` + sha256. The working tree never ships.
3. The bundle goes to `~/dumont-secrets-mcp-bundles/<sha>` on the host
   (replaced wholesale) and `apply-on-vault-syd1.sh` runs with `sudo`:
   - `--check` (default): checks the unix user, Node 22, `/usr/local/bin/bw`,
     `journalctl`/`ss`, owner and mode of the env file, owner, mode and size
     (at least 20 bytes) of the password file (stat only, never read), owner
     and mode of the policy, parses the policy with the release's own parser,
     checks port 3015 and that `current` is a symlink (or absent), and prints
     the plan: current -> target release, unit diff, policy and env hashes
     against the recorded ones.
   - `--apply` (run under `setsid --wait`, so a dropped ssh session cannot kill
     it): unpacks the release once into `releases/<sha>` (root-owned; a
     different tarball for an existing sha is refused), installs the unit,
     switches `current` atomically, restarts, and proves it:
     - a **new** PID whose cwd is `releases/<sha>`, `active` on two readings;
     - `POST /mcp` answers `401` with the OAuth challenge, and the metadata
       lists the three role scopes;
     - that PID logged `secrets-mcp vault outcome=unlocked` (the machine
       account opened a vault session) within 90 s. `outcome=failed` stops the
       apply with a message that says it is a **credentials** problem
       (password file, account, SSO or two-step policy), then rolls back;
     - that PID logged `secrets-mcp policy sha256=` equal to the policy file.
     Only then it writes `RELEASE` (with `policy_sha256` and `env_sha256`) and
     keeps the newest 5 releases and backups. Any failure after the first
     change rolls back: the service is stopped first, then the previous unit,
     symlink and `RELEASE` come back and the previous release is started (or,
     with no previous release, the service stays stopped and disabled).
4. `--show-release` separates the files (`in-sync` / `drifted`: symlink,
   release tarball hash, unit hash, policy hash, env hash) from the runtime
   (`runtime-in-sync` / `runtime-drifted` / `runtime-unknown`: the running
   PID's cwd, and the policy hash that PID logged at start compared with the
   file and the `RELEASE`).

## The write collection is MCP-owned

The server cannot see collections the machine account is not a member of, so
it cannot tell that an item of the write collection was also shared into one
of those, and would write it. Items of the write collection are never added
to any other collection; `bootstrap-owner-steps.md`, step 3.5, has the rule and
a read-only database check to run after any change to collection access.

## Changing the policy

The real policy lives in a private repository (suggested:
`DumontAI/platform-infra`, next to the vault-syd1 host config, e.g.
`hosts/vault-syd1/dumont-secrets-mcp/policy.json`). To change it:

1. Change and review it there.
2. Install it on the host with the pipe in `bootstrap-owner-steps.md`, step 6
   (root:secrets-mcp 0640).
3. Re-apply the current main: `bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh main --apply`.
   The release is reused, the service restarts, the apply proves the new PID
   loaded the new policy hash, and `RELEASE` records it.
4. `bash deploy/vault-syd1-mcp/deliver-to-vault-syd1.sh --show-release` must say
   `in-sync` and `runtime-in-sync`.

Between steps 2 and 3 `--show-release` reports `drift` (file != RELEASE) and
`runtime-drifted` (the process still runs the old policy): that is expected,
and exactly what those lines are for. The same applies to the env file.

A rollback on purpose is a delivery of the previous `main` commit. To take the
MCP out of service: remove the Caddy route first, then
`sudo systemctl disable --now dumont-secrets-mcp`.

The scripts never read, print or copy a secret: the env file and the password
file are only `stat`ed. They are created by the owner, by ssh pipe.

## Reading the audit trail

```bash
ssh vault-syd1 'sudo journalctl -u dumont-secrets-mcp -o cat --since today | grep secrets.mcp.tool'
```

One JSON line per tool call: `ts, tool, sub, email, roles, item, key,
collection, outcome (ok|denied|error), error_code, latency_ms`. Never a value.
Operational lines (`secrets-mcp bw outcome=...`, `secrets-mcp policy ...`) say
when the CLI had to unlock or log in again, or a policy collection is missing.
