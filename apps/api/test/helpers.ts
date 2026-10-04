import { openDatabase, type Db } from '../src/db/database';

export function memoryDb(): Db {
  return openDatabase(':memory:');
}

export async function waitFor(predicate: () => boolean, timeoutMs = 3_000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor: timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}
