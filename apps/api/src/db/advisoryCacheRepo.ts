import type { Db } from './database';

export type AdvisoryCacheKind = 'pkg' | 'vuln';

export const ADVISORY_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

type CacheRow = { json: string; fetched_at: string };

/** (kind, cache_key) -> JSON blob with a fetch timestamp. Freshness is TTL-aware, as of a
 *  caller-supplied `now` (never read from the system clock here), so callers fully control
 *  cache aging in tests. `kind` is 'pkg' for a (ecosystem, name, version) -> vuln id list, or
 *  'vuln' for a vuln id -> raw OSV JSON record. */
export class AdvisoryCacheRepo {
  constructor(private readonly db: Db) {}

  get<T = unknown>(kind: AdvisoryCacheKind, key: string): { value: T; fetchedAt: Date } | undefined {
    const row = this.db.prepare(`SELECT json, fetched_at FROM advisory_cache WHERE kind = ? AND cache_key = ?`).get(kind, key) as
      | CacheRow
      | undefined;
    if (!row) return undefined;
    return { value: JSON.parse(row.json) as T, fetchedAt: new Date(row.fetched_at) };
  }

  /** Undefined when missing, or when older than `ttlMs` (default 24h) as of `now`. */
  getFresh<T = unknown>(kind: AdvisoryCacheKind, key: string, now: Date, ttlMs: number = ADVISORY_CACHE_TTL_MS): T | undefined {
    const entry = this.get<T>(kind, key);
    if (!entry) return undefined;
    if (now.getTime() - entry.fetchedAt.getTime() > ttlMs) return undefined;
    return entry.value;
  }

  set(kind: AdvisoryCacheKind, key: string, value: unknown, fetchedAt: Date): void {
    this.db
      .prepare(
        `INSERT INTO advisory_cache (kind, cache_key, json, fetched_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (kind, cache_key) DO UPDATE SET json = excluded.json, fetched_at = excluded.fetched_at`,
      )
      .run(kind, key, JSON.stringify(value), fetchedAt.toISOString());
  }

  /** Deletes rows older than `ttlMs` as of `now` (they can never be served again); returns the count. */
  purgeExpired(now: Date, ttlMs: number = ADVISORY_CACHE_TTL_MS): number {
    const cutoff = new Date(now.getTime() - ttlMs).toISOString(); // ISO-8601 UTC strings sort chronologically
    return this.db.prepare(`DELETE FROM advisory_cache WHERE fetched_at < ?`).run(cutoff).changes;
  }
}
