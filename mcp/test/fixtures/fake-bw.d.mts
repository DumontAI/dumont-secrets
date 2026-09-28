export function statePath(appDataDir: string): string;
export function readState(appDataDir: string): unknown;
export function writeState(appDataDir: string, state: unknown): void;
export function runFakeBw(args: string[], env: Record<string, string | undefined>, input?: string): { code: number; stdout: string; stderr?: string };
