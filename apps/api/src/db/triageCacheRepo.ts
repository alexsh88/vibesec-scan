import type { FileTriage } from '../analyzers/code/types';
import type { Db } from './database';

/** The triaged verdict minus `path`: the cache key already binds to one file's content (via its
 *  sha256), never to a path, so two files with byte-identical content and the same cache key share
 *  one row; the caller re-attaches whichever path it looked the key up for. */
export type CachedTriage = Omit<FileTriage, 'path'>;

type CacheRow = { json: string };

/**
 * cache_key -> FileTriage (minus path) JSON blob, no TTL (a given cache_key is permanently valid:
 * it already encodes the file's content hash, the triage prompt version and the model id, so any
 * change to any of those three simply produces a different key rather than invalidating this row).
 */
export class TriageCacheRepo {
  constructor(private readonly db: Db, private readonly now: () => Date = () => new Date()) {}

  get(key: string): CachedTriage | undefined {
    const row = this.db.prepare(`SELECT json FROM triage_cache WHERE cache_key = ?`).get(key) as CacheRow | undefined;
    return row ? (JSON.parse(row.json) as CachedTriage) : undefined;
  }

  set(key: string, value: CachedTriage): void {
    this.db
      .prepare(
        `INSERT INTO triage_cache (cache_key, json, created_at) VALUES (?, ?, ?)
         ON CONFLICT (cache_key) DO UPDATE SET json = excluded.json, created_at = excluded.created_at`,
      )
      .run(key, JSON.stringify(value), this.now().toISOString());
  }
}
