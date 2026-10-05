import { Pool } from 'pg';

const FALLBACK_DATABASE_URL = 'postgres://admin:Sup3rS3cretPw!@db.internal:5432/app';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || FALLBACK_DATABASE_URL,
});

export function query(sql: string, params?: unknown[]) {
  return pool.query(sql, params);
}
