export interface FakeCredCall {
  kind: 'dpapi' | 'keychain' | 'libsecret';
  op: 'store' | 'read' | 'remove' | 'exists';
  passwordInArgv: boolean;
  passwordInEnv: boolean;
}
export function readStored(directory: string): Buffer | null;
export function seedStored(directory: string, password: string): void;
export function credCalls(directory: string): FakeCredCall[];
export function powershell(args: string[]): Promise<void>;
export function security(args: string[]): Promise<void>;
export function secretTool(args: string[]): Promise<void>;
