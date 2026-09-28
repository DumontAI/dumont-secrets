import { spawn } from 'node:child_process';
import { accessSync, constants, readFileSync, statSync } from 'node:fs';
import { userInfo } from 'node:os';
import { delimiter, isAbsolute, join } from 'node:path';

// Where auto-unlock keeps the Bitwarden master password: the operating system's
// own per-user credential store, never a file of ours.
//
//   WSL       Windows DPAPI (CurrentUser), through powershell.exe; the encrypted
//             blob lives in %LOCALAPPDATA%\DumontSecrets\bw-master.dpapi
//   macOS     the login Keychain, through /usr/bin/security
//   Linux     the Secret Service (gnome-keyring, KeePassXC, ...), through secret-tool
//
// There is NO plaintext-file fallback: without one of these, setup is refused.
//
// Rules, the same as for bw:
//   - execFile/spawn, never a shell; the password is never in argv (ours or the
//     tool's) and never in an environment variable of ours;
//   - reads capture stdout into Buffers that are zeroed once used; stderr is only
//     tested for "was anything said", never logged or returned;
//   - storing is interactive: macOS `security` and `secret-tool` prompt on the
//     terminal themselves. powershell.exe started from WSL has no Windows console
//     (Read-Host -AsSecureString cannot read a key there), so for DPAPI this
//     process asks for the password with echo off and hands it to PowerShell on
//     stdin (base64), where it goes straight into a SecureString.
//
// These stores protect the password against OTHER users and against someone who
// takes the disk. They do NOT protect it against programs running as you: any of
// them can ask the same tool for it, exactly as this module does.

export type BackendName = 'dpapi' | 'keychain' | 'libsecret';
export const BACKEND_NAMES: readonly BackendName[] = ['dpapi', 'keychain', 'libsecret'];

export const KEYCHAIN_SERVICE = 'dumont-secrets-bw-master';
export const LIBSECRET_ATTRIBUTES = ['service', 'dumont-secrets', 'account', 'bw-master'] as const;
export const DPAPI_DEFAULT_LOCATION = '%LOCALAPPDATA%\\DumontSecrets\\bw-master.dpapi';
const LABEL = 'Dumont Secrets: Bitwarden master password (auto-unlock)';
const MAX_PASSWORD_BYTES = 1024;
const READ_TIMEOUT_MS = 30_000;
const DEFAULT_POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';

export class CredStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredStoreError';
  }
}

export interface CaptureResult {
  readonly code: number | null;
  /** The tool's stdout. The caller zeroes it. */
  readonly stdout: Buffer;
  /** Only whether the tool wrote anything to stderr; its text is dropped. */
  readonly saidSomething: boolean;
  readonly timedOut: boolean;
}

export interface ToolRunner {
  /** Non-interactive run: `input` on stdin (or nothing), stdout captured as bytes. */
  capture(bin: string, args: readonly string[], options: { env: Record<string, string>; input?: Buffer; timeoutMs: number }): Promise<CaptureResult>;
  /** Interactive run with this terminal handed to the tool (it prompts by itself). Resolves to the exit code. */
  interactive(bin: string, args: readonly string[], env: Record<string, string>): Promise<number | null>;
}

export interface StoreIo {
  /** Ask the person for the password with echo off; null when they cancelled. */
  readonly promptHidden: (prompt: string) => Promise<Buffer | null>;
  readonly err: (line: string) => void;
}

export interface CredentialBackend {
  readonly name: BackendName;
  /** Human description, e.g. for --status: which store and where. */
  readonly description: string;
  /** null when it can be used; otherwise a fixed sentence saying why not. */
  unavailable(): Promise<string | null>;
  /** Interactive: asks the person and stores the password. True when stored. */
  store(io: StoreIo): Promise<boolean>;
  /** The stored password (the caller zeroes it), or null when none is stored. Throws CredStoreError. */
  read(): Promise<Buffer | null>;
  /** True when something was removed, false when nothing was stored. Throws CredStoreError. */
  remove(): Promise<boolean>;
}

/** The environment the credential tools get: yours, minus anything Bitwarden. */
export function toolEnvironment(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== 'string') continue;
    if (name.startsWith('BW_') || name === 'DUMONT_BW_PW') continue;
    out[name] = value;
  }
  return out;
}

export function findOnPath(name: string, env: NodeJS.ProcessEnv): string | null {
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (!dir || !isAbsolute(dir)) continue;
    const candidate = join(dir, name);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

function isExecutable(path: string): boolean {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function binOverride(env: NodeJS.ProcessEnv, name: string): string | null {
  const value = env[name]?.trim();
  if (!value) return null;
  if (!isAbsolute(value)) throw new CredStoreError(`${name} must be an absolute path`);
  return value;
}

/** True under WSL: WSL_DISTRO_NAME is set, or the kernel says "microsoft"/"WSL". */
export function isWsl(env: NodeJS.ProcessEnv, procVersion: () => string = () => readFileSync('/proc/version', 'utf8')): boolean {
  if (env.WSL_DISTRO_NAME?.trim()) return true;
  try {
    return /microsoft|wsl/i.test(procVersion());
  } catch {
    return false;
  }
}

/**
 * Which store this machine uses: DUMONT_SECRETS_CREDSTORE (dpapi | keychain |
 * libsecret) when set, else macOS -> keychain, WSL -> dpapi, other Linux ->
 * libsecret. null on anything else.
 */
export function detectBackend(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  procVersion?: () => string,
): BackendName | null {
  const override = env.DUMONT_SECRETS_CREDSTORE?.trim();
  if (override) {
    if (!(BACKEND_NAMES as readonly string[]).includes(override)) {
      throw new CredStoreError('DUMONT_SECRETS_CREDSTORE must be dpapi, keychain or libsecret');
    }
    return override as BackendName;
  }
  if (platform === 'darwin') return 'keychain';
  if (platform === 'linux') return isWsl(env, procVersion) ? 'dpapi' : 'libsecret';
  return null;
}

export function createBackend(name: BackendName, options: { env: NodeJS.ProcessEnv; runner?: ToolRunner }): CredentialBackend {
  const runner = options.runner ?? defaultToolRunner();
  switch (name) {
    case 'dpapi': return new DpapiBackend(options.env, runner);
    case 'keychain': return new KeychainBackend(options.env, runner);
    case 'libsecret': return new LibsecretBackend(options.env, runner);
  }
}

/** detectBackend + createBackend; null when this platform has no supported store. */
export function selectBackend(env: NodeJS.ProcessEnv, platform: NodeJS.Platform, runner?: ToolRunner): CredentialBackend | null {
  const name = detectBackend(env, platform);
  return name ? createBackend(name, { env, ...(runner ? { runner } : {}) }) : null;
}

function trimTrailingNewline(buffer: Buffer): Buffer {
  let end = buffer.length;
  if (end > 0 && buffer[end - 1] === 0x0a) end -= 1;
  if (end > 0 && buffer[end - 1] === 0x0d) end -= 1;
  if (end === buffer.length) return buffer;
  const out = Buffer.from(buffer.subarray(0, end));
  buffer.fill(0);
  return out;
}

function passwordFrom(result: CaptureResult): Buffer {
  const password = trimTrailingNewline(result.stdout);
  if (password.length === 0 || password.length > MAX_PASSWORD_BYTES) {
    password.fill(0);
    throw new CredStoreError('the credential store returned an unusable answer');
  }
  return password;
}

// ---------------------------------------------------------------------------
// Windows DPAPI through powershell.exe (WSL)

// Only a plain drive path is accepted as an override: it is put into the script
// between single quotes.
const WINDOWS_PATH = /^[A-Za-z]:\\[A-Za-z0-9 _.\\-]{1,200}$/;

class DpapiBackend implements CredentialBackend {
  readonly name = 'dpapi' as const;
  readonly description: string;
  private readonly fileExpression: string;

  constructor(private readonly env: NodeJS.ProcessEnv, private readonly runner: ToolRunner) {
    const override = env.DUMONT_SECRETS_DPAPI_FILE?.trim();
    if (override && !WINDOWS_PATH.test(override)) {
      throw new CredStoreError('DUMONT_SECRETS_DPAPI_FILE must be a plain Windows path like C:\\Users\\me\\x.dpapi');
    }
    this.fileExpression = override
      ? `'${override}'`
      : "(Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'DumontSecrets\\bw-master.dpapi')";
    this.description = `Windows DPAPI (CurrentUser) via powershell.exe, file ${override ?? DPAPI_DEFAULT_LOCATION}`;
  }

  private bin(): string | null {
    const override = binOverride(this.env, 'DUMONT_SECRETS_POWERSHELL_BIN');
    if (override) return isExecutable(override) ? override : null;
    return findOnPath('powershell.exe', this.env) ?? (isExecutable(DEFAULT_POWERSHELL) ? DEFAULT_POWERSHELL : null);
  }

  /** The script, UTF-16LE base64 for -EncodedCommand: no quoting through WSL interop, no value in it. */
  private encoded(op: 'store' | 'read' | 'remove', body: string): string {
    const script = [
      `# dumont-secrets op=${op}`,
      "$ErrorActionPreference = 'Stop'",
      "$ProgressPreference = 'SilentlyContinue'",
      `$f = ${this.fileExpression}`,
      body,
    ].join('\n');
    return Buffer.from(script, 'utf16le').toString('base64');
  }

  private args(op: 'store' | 'read' | 'remove', body: string): string[] {
    return ['-NoProfile', '-NonInteractive', '-EncodedCommand', this.encoded(op, body)];
  }

  async unavailable(): Promise<string | null> {
    try {
      if (this.bin()) return null;
    } catch (error) {
      return error instanceof CredStoreError ? error.message : 'powershell.exe could not be located';
    }
    return 'powershell.exe was not found (WSL interop with Windows must be enabled); auto-unlock needs it for Windows DPAPI.';
  }

  async store(io: StoreIo): Promise<boolean> {
    const bin = this.bin();
    if (!bin) return false;
    const password = await io.promptHidden('Bitwarden master password (to store with Windows DPAPI): ');
    if (!password || password.length === 0) {
      password?.fill(0);
      io.err('No password entered; nothing was stored.');
      return false;
    }
    if (password.length > MAX_PASSWORD_BYTES) {
      password.fill(0);
      io.err('That password is too long; nothing was stored.');
      return false;
    }
    // base64 of the UTF-8 bytes, one line on stdin: no console encoding in the way.
    const input = Buffer.concat([Buffer.from(password.toString('base64'), 'ascii'), Buffer.from('\n')]);
    password.fill(0);
    const body = [
      '$line = [Console]::In.ReadLine()',
      'if (-not $line) { exit 4 }',
      '$bytes = [Convert]::FromBase64String($line)',
      '$chars = [Text.Encoding]::UTF8.GetChars($bytes)',
      '[Array]::Clear($bytes, 0, $bytes.Length)',
      '$ss = New-Object Security.SecureString',
      'foreach ($c in $chars) { $ss.AppendChar($c) }',
      '[Array]::Clear($chars, 0, $chars.Length)',
      '$ss.MakeReadOnly()',
      'New-Item -ItemType Directory -Force -Path (Split-Path -Parent $f) | Out-Null',
      "$t = $f + '.tmp'",
      // ConvertFrom-SecureString without -Key: DPAPI, bound to this Windows user.
      'Set-Content -LiteralPath $t -Value (ConvertFrom-SecureString -SecureString $ss) -Encoding ASCII -NoNewline',
      'Move-Item -LiteralPath $t -Destination $f -Force',
      'exit 0',
    ].join('\n');
    try {
      const result = await this.runner.capture(bin, this.args('store', body), { env: toolEnvironment(this.env), input, timeoutMs: READ_TIMEOUT_MS });
      result.stdout.fill(0);
      return result.code === 0;
    } finally {
      input.fill(0);
    }
  }

  async read(): Promise<Buffer | null> {
    const bin = this.bin();
    if (!bin) throw new CredStoreError('powershell.exe was not found');
    const body = [
      'if (-not (Test-Path -LiteralPath $f)) { exit 3 }',
      '$s = ConvertTo-SecureString -String ((Get-Content -LiteralPath $f -Raw).Trim())',
      '$p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)',
      'try {',
      '  $b = [Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($p))',
      '  $o = [Console]::OpenStandardOutput()',
      '  $o.Write($b, 0, $b.Length)',
      '  $o.Flush()',
      '  [Array]::Clear($b, 0, $b.Length)',
      '} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }',
      'exit 0',
    ].join('\n');
    const run = () => this.runner.capture(bin, this.args('read', body), { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    let result = await run();
    if (result.code !== 0 && result.code !== 3 && !result.timedOut) {
      // WSL interop sometimes fails to start a Windows process at all
      // ("UtilAcceptVsock ... accept4 failed"); a read is safe to repeat once.
      result.stdout.fill(0);
      result = await run();
    }
    if (result.code === 3) {
      result.stdout.fill(0);
      return null;
    }
    if (result.code !== 0) {
      result.stdout.fill(0);
      throw new CredStoreError(result.timedOut ? 'powershell.exe did not answer in time' : 'Windows DPAPI could not decrypt the stored password');
    }
    return passwordFrom(result);
  }

  async remove(): Promise<boolean> {
    const bin = this.bin();
    if (!bin) throw new CredStoreError('powershell.exe was not found');
    const body = [
      'if (-not (Test-Path -LiteralPath $f)) { exit 3 }',
      'Remove-Item -LiteralPath $f -Force',
      'exit 0',
    ].join('\n');
    const result = await this.runner.capture(bin, this.args('remove', body), { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    result.stdout.fill(0);
    if (result.code === 3) return false;
    if (result.code !== 0) throw new CredStoreError('the DPAPI file could not be removed');
    return true;
  }
}

// ---------------------------------------------------------------------------
// macOS Keychain through /usr/bin/security

function keychainAccount(env: NodeJS.ProcessEnv): string {
  let name = '';
  try {
    name = userInfo().username;
  } catch {
    name = env.USER ?? '';
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(name) || name.startsWith('-')) throw new CredStoreError('could not determine your user name');
  return name;
}

class KeychainBackend implements CredentialBackend {
  readonly name = 'keychain' as const;
  readonly description = `macOS login Keychain (generic password, service ${KEYCHAIN_SERVICE})`;

  constructor(private readonly env: NodeJS.ProcessEnv, private readonly runner: ToolRunner) {}

  private bin(): string | null {
    const override = binOverride(this.env, 'DUMONT_SECRETS_SECURITY_BIN');
    const bin = override ?? '/usr/bin/security';
    return isExecutable(bin) ? bin : null;
  }

  private base(): string[] {
    return ['-a', keychainAccount(this.env), '-s', KEYCHAIN_SERVICE];
  }

  async unavailable(): Promise<string | null> {
    try {
      if (!this.bin()) return '/usr/bin/security was not found.';
      keychainAccount(this.env);
      return null;
    } catch (error) {
      return error instanceof CredStoreError ? error.message : 'the Keychain cannot be used';
    }
  }

  async store(io: StoreIo): Promise<boolean> {
    const bin = this.bin();
    if (!bin) return false;
    io.err('macOS `security` now asks for the password (twice) in this terminal.');
    // `-w` as the LAST argument, without a value: security prompts on the terminal
    // itself. `-w <password>` would put the password in argv.
    const code = await this.runner.interactive(bin, ['add-generic-password', ...this.base(), '-l', LABEL, '-U', '-w'], toolEnvironment(this.env));
    return code === 0;
  }

  async read(): Promise<Buffer | null> {
    const bin = this.bin();
    if (!bin) throw new CredStoreError('/usr/bin/security was not found');
    const result = await this.runner.capture(bin, ['find-generic-password', ...this.base(), '-w'], { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    if (result.code === 44) {
      result.stdout.fill(0);
      return null;
    }
    if (result.code !== 0) {
      result.stdout.fill(0);
      throw new CredStoreError(result.timedOut ? 'the Keychain did not answer in time' : 'the Keychain refused to return the password (locked, or access denied)');
    }
    return passwordFrom(result);
  }

  async remove(): Promise<boolean> {
    const bin = this.bin();
    if (!bin) throw new CredStoreError('/usr/bin/security was not found');
    // Prints the item's attributes (never the password) on stdout: dropped.
    const result = await this.runner.capture(bin, ['delete-generic-password', ...this.base()], { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    result.stdout.fill(0);
    if (result.code === 44) return false;
    if (result.code !== 0) throw new CredStoreError('the Keychain item could not be removed');
    return true;
  }
}

// ---------------------------------------------------------------------------
// Linux Secret Service through secret-tool (libsecret)

class LibsecretBackend implements CredentialBackend {
  readonly name = 'libsecret' as const;
  readonly description = `Secret Service via secret-tool (attributes ${LIBSECRET_ATTRIBUTES.join(' ')})`;

  constructor(private readonly env: NodeJS.ProcessEnv, private readonly runner: ToolRunner) {}

  private bin(): string | null {
    const override = binOverride(this.env, 'DUMONT_SECRETS_SECRET_TOOL_BIN');
    if (override) return isExecutable(override) ? override : null;
    return findOnPath('secret-tool', this.env);
  }

  async unavailable(): Promise<string | null> {
    let bin: string | null;
    try {
      bin = this.bin();
    } catch (error) {
      return error instanceof CredStoreError ? error.message : 'secret-tool could not be located';
    }
    if (!bin) return 'secret-tool was not found (install libsecret-tools, and run a Secret Service such as gnome-keyring or KeePassXC).';
    // A lookup of an item that does not exist: exit 1 and silence when a Secret
    // Service answered; an error message when there is none (no D-Bus, no daemon).
    const probe = await this.runner.capture(bin, ['lookup', 'service', 'dumont-secrets-probe', 'account', 'probe'], { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    probe.stdout.fill(0);
    if ((probe.code === 0 || probe.code === 1) && !probe.saidSomething && !probe.timedOut) return null;
    return 'No Secret Service answered (secret-tool could not reach gnome-keyring, KeePassXC or similar over D-Bus).';
  }

  async store(io: StoreIo): Promise<boolean> {
    const bin = this.bin();
    if (!bin) return false;
    io.err('secret-tool now asks for the password in this terminal.');
    // secret-tool reads the password from its own prompt (echo off) on the terminal.
    const code = await this.runner.interactive(bin, ['store', `--label=${LABEL}`, ...LIBSECRET_ATTRIBUTES], toolEnvironment(this.env));
    return code === 0;
  }

  async read(): Promise<Buffer | null> {
    const bin = this.bin();
    if (!bin) throw new CredStoreError('secret-tool was not found');
    const result = await this.runner.capture(bin, ['lookup', ...LIBSECRET_ATTRIBUTES], { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    if (result.code === 1 && !result.saidSomething && result.stdout.length === 0) {
      result.stdout.fill(0);
      return null;
    }
    if (result.code !== 0) {
      result.stdout.fill(0);
      throw new CredStoreError(result.timedOut ? 'the Secret Service did not answer in time' : 'the Secret Service refused to return the password (locked keyring?)');
    }
    return passwordFrom(result);
  }

  async remove(): Promise<boolean> {
    const bin = this.bin();
    if (!bin) throw new CredStoreError('secret-tool was not found');
    const result = await this.runner.capture(bin, ['clear', ...LIBSECRET_ATTRIBUTES], { env: toolEnvironment(this.env), timeoutMs: READ_TIMEOUT_MS });
    result.stdout.fill(0);
    if (result.code !== 0) throw new CredStoreError('the Secret Service item could not be removed');
    return true;
  }
}

// ---------------------------------------------------------------------------
// Processes and the terminal

const MAX_CAPTURE_BYTES = 64 * 1024;

export function defaultToolRunner(): ToolRunner {
  return {
    capture: (bin, args, options) => new Promise((resolve, reject) => {
      // cwd: a Windows program started from WSL warns about a Linux working
      // directory; any existing directory is fine for the others.
      const child = spawn(bin, [...args], {
        env: options.env, stdio: ['pipe', 'pipe', 'pipe'], shell: false, windowsHide: true, cwd: pickCwd(bin),
      });
      const chunks: Buffer[] = [];
      let size = 0;
      let said = false;
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, options.timeoutMs);
      child.stdout.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size <= MAX_CAPTURE_BYTES) chunks.push(chunk);
        else chunk.fill(0);
      });
      child.stderr.on('data', (chunk: Buffer) => { if (chunk.length > 0) said = true; });
      child.on('error', error => { clearTimeout(timer); for (const c of chunks) c.fill(0); reject(error); });
      child.on('close', code => {
        clearTimeout(timer);
        const stdout = Buffer.concat(chunks);
        for (const c of chunks) c.fill(0);
        if (size > MAX_CAPTURE_BYTES) {
          stdout.fill(0);
          resolve({ code: 1, stdout: Buffer.alloc(0), saidSomething: said, timedOut });
          return;
        }
        resolve({ code: timedOut ? null : code, stdout, saidSomething: said, timedOut });
      });
      child.stdin.on('error', () => undefined);
      child.stdin.end(options.input ?? Buffer.alloc(0));
    }),
    interactive: (bin, args, env) => new Promise((resolve, reject) => {
      const child = spawn(bin, [...args], { env, stdio: 'inherit', shell: false, cwd: pickCwd(bin) });
      child.on('error', reject);
      child.on('close', code => resolve(code));
    }),
  };
}

function pickCwd(bin: string): string | undefined {
  if (!/\.exe$/i.test(bin)) return undefined;
  try {
    return statSync('/mnt/c').isDirectory() ? '/mnt/c' : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Read one line from the terminal with echo off (raw mode), into a Buffer.
 * Enter ends it, Ctrl-C / Ctrl-D (on an empty line) cancel, Backspace works.
 * Without a terminal (tests, DUMONT_SECRETS_UNLOCK_ALLOW_NON_TTY) it reads the
 * first line of stdin instead.
 */
export function promptHiddenLine(
  prompt: string,
  input: NodeJS.ReadStream = process.stdin,
  output: NodeJS.WritableStream = process.stderr,
): Promise<Buffer | null> {
  return new Promise(resolve => {
    output.write(prompt);
    const tty = Boolean(input.isTTY) && typeof input.setRawMode === 'function';
    let bytes = Buffer.alloc(MAX_PASSWORD_BYTES + 4);
    let length = 0;
    let done = false;
    const finish = (result: Buffer | null) => {
      if (done) return;
      done = true;
      input.removeListener('data', onData);
      input.removeListener('end', onEnd);
      if (tty) input.setRawMode(false);
      input.pause();
      output.write('\n');
      bytes.fill(0);
      resolve(result);
    };
    const onEnd = () => {
      finish(tty || length === 0 ? null : Buffer.from(bytes.subarray(0, length)));
    };
    const onData = (chunk: Buffer | string) => {
      const data = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      for (const byte of data) {
        if (byte === 0x0d || byte === 0x0a) {
          const out = Buffer.from(bytes.subarray(0, length));
          data.fill(0);
          finish(out);
          return;
        }
        if (tty && byte === 0x03) { data.fill(0); finish(null); return; }
        if (tty && byte === 0x04 && length === 0) { data.fill(0); finish(null); return; }
        if (tty && (byte === 0x7f || byte === 0x08)) {
          // Drop one UTF-8 character: its continuation bytes, then its lead byte.
          while (length > 0 && ((bytes[length - 1] ?? 0) & 0xc0) === 0x80) bytes[--length] = 0;
          if (length > 0) bytes[--length] = 0;
          continue;
        }
        if (length >= bytes.length) {
          const bigger = Buffer.alloc(bytes.length * 2);
          bytes.copy(bigger);
          bytes.fill(0);
          bytes = bigger;
        }
        bytes[length++] = byte;
      }
      data.fill(0);
    };
    if (tty) input.setRawMode(true);
    input.on('data', onData);
    input.on('end', onEnd);
    input.resume();
  });
}
