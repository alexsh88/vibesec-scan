import { describe, expect, it } from 'vitest';
import type { CachedTriage } from '../src/db/triageCacheRepo';
import { TriageCacheRepo } from '../src/db/triageCacheRepo';
import { memoryDb } from './helpers';

function triage(over: Partial<CachedTriage> = {}): CachedTriage {
  return { relevance: 2, sources: ['req.query.id (line 3)'], sinks: [], securityTopics: ['auth'], credentialRisk: false, ...over };
}

describe('TriageCacheRepo', () => {
  it('returns undefined for a missing key', () => {
    const repo = new TriageCacheRepo(memoryDb());
    expect(repo.get('missing')).toBeUndefined();
  });

  it('round-trips a stored value', () => {
    const repo = new TriageCacheRepo(memoryDb());
    const value = triage({ relevance: 3, sinks: ['db.query with string concat (line 10)'], credentialRisk: true });
    repo.set('k1', value);
    expect(repo.get('k1')).toEqual(value);
  });

  it('overwrites an existing key on a second set (ON CONFLICT upsert)', () => {
    const repo = new TriageCacheRepo(memoryDb());
    repo.set('k1', triage({ relevance: 1 }));
    repo.set('k1', triage({ relevance: 3, credentialRisk: true }));
    expect(repo.get('k1')).toEqual(triage({ relevance: 3, credentialRisk: true }));
  });

  it('keeps distinct keys independent', () => {
    const repo = new TriageCacheRepo(memoryDb());
    repo.set('a', triage({ relevance: 0 }));
    repo.set('b', triage({ relevance: 3 }));
    expect(repo.get('a')?.relevance).toBe(0);
    expect(repo.get('b')?.relevance).toBe(3);
  });

  it('stamps created_at from the injected clock', () => {
    const db = memoryDb();
    const now = new Date('2026-01-01T00:00:00.000Z');
    const repo = new TriageCacheRepo(db, () => now);
    repo.set('k1', triage());
    const row = db.prepare(`SELECT created_at FROM triage_cache WHERE cache_key = ?`).get('k1') as { created_at: string };
    expect(row.created_at).toBe(now.toISOString());
  });
});
