import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// The delivery script must refuse anything not on origin/main BEFORE any ssh.
// A fake `ssh` on PATH records whether it was ever called.

const SCRIPT = join(import.meta.dirname, '..', '..', 'deploy', 'vault-syd1-mcp', 'deliver-to-vault-syd1.sh');
const GIT_ENV = {
  GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@example.test',
  GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@example.test',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, env: { ...process.env, ...GIT_ENV }, encoding: 'utf8' }).trim();
}

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'secrets-mcp-deliver-'));
  const origin = join(root, 'origin.git');
  const clone = join(root, 'clone');
  const bin = join(root, 'bin');
  const marker = join(root, 'ssh-called');
  git(root, 'init', '-q', '--bare', '-b', 'main', origin);
  git(root, 'clone', '-q', origin, clone);
  git(clone, 'checkout', '-q', '-b', 'main');
  mkdirSync(join(clone, 'deploy', 'vault-syd1-mcp'), { recursive: true });
  copyFileSync(SCRIPT, join(clone, 'deploy', 'vault-syd1-mcp', 'deliver-to-vault-syd1.sh'));
  git(clone, 'add', '.');
  git(clone, 'commit', '-q', '-m', 'on main');
  git(clone, 'push', '-q', 'origin', 'main');
  const onMain = git(clone, 'rev-parse', 'HEAD');
  writeFileSync(join(clone, 'extra.txt'), 'not promoted\n');
  git(clone, 'add', '.');
  git(clone, 'commit', '-q', '-m', 'not on main');
  const notOnMain = git(clone, 'rev-parse', 'HEAD');
  mkdirSync(bin);
  writeFileSync(join(bin, 'ssh'), `#!/bin/sh\necho called >> '${marker}'\nexit 0\n`);
  chmodSync(join(bin, 'ssh'), 0o755);
  const run = (...args: string[]) => spawnSync('bash', [join(clone, 'deploy', 'vault-syd1-mcp', 'deliver-to-vault-syd1.sh'), ...args], {
    env: { ...process.env, ...GIT_ENV, PATH: `${bin}:${process.env.PATH}` },
    encoding: 'utf8',
  });
  return { run, onMain, notOnMain, sshCalled: () => existsSync(marker) };
}

describe('deliver-to-vault-syd1.sh', () => {
  it('refuses a commit that is not on origin/main without touching ssh', () => {
    const t = setup();
    const result = t.run(t.notOnMain, '--apply');
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('is not on origin/main');
    expect(t.sshCalled()).toBe(false);
  });

  it('refuses malformed arguments and a bare override without ssh', () => {
    const t = setup();
    for (const args of [
      ['abc123'],
      [t.notOnMain, '--allow-non-main'],
      [t.notOnMain, '--allow-non-main', '--reason', 'short'],
      [t.notOnMain, '--allow-non-main', '--reason', "quote ' breaks out of the shell"],
      [t.onMain, '--reason', 'a reason that is long enough'],
      [t.onMain, '--allow-non-main', '--reason', 'already promoted to main'],
      [t.onMain, '--host', 'bad host; rm -rf /'],
    ]) {
      const result = t.run(...args);
      expect(result.status, args.join(' ')).toBe(2);
    }
    expect(t.sshCalled()).toBe(false);
  });

  it('lets a commit on main past the ancestry check (it then stops at the build, still before ssh)', () => {
    const t = setup();
    const result = t.run('main');
    expect(result.stdout).toContain(`${t.onMain} is on origin/main`);
    expect(result.status).toBe(2);
    expect(t.sshCalled()).toBe(false);
  });
});
