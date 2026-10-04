import { openDatabase, type Db } from '../src/db/database';

export function memoryDb(): Db {
  return openDatabase(':memory:');
}
