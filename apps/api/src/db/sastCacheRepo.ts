import type { CachedSastIssue, SastResultCache } from '../analyzers/code/sast';
import type { Db } from './database';

type CacheRow = { json: string };

/**
 * Persistent SAST result cache (migration 009), implementing the analyzer's SastResultCache. No TTL: a
 * key already binds the per-file prompt hash, the SAST prompt version and the model id. Values hold
 * verified issue locations + the model's prose only — never repository code (see sast.ts).
 */
export class SastCacheRepo implements SastResultCache {
  constructor(private readonly db: Db, private readonly now: () => Date = () => new Date()) {}

  get(key: string): CachedSastIssue[] | undefined {
    const row = this.db.prepare(`SELECT json FROM sast_cache WHERE cache_key = ?`).get(key) as CacheRow | undefined;
    return row ? (JSON.parse(row.json) as CachedSastIssue[]) : undefined;
  }

  set(key: string, issues: CachedSastIssue[]): void {
    this.db
      .prepare(
        `INSERT INTO sast_cache (cache_key, json, created_at) VALUES (?, ?, ?)
         ON CONFLICT (cache_key) DO UPDATE SET json = excluded.json, created_at = excluded.created_at`,
      )
      .run(key, JSON.stringify(issues), this.now().toISOString());
  }
}
