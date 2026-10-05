import { describe, expect, it } from 'vitest';
import { ADVISORY_CACHE_TTL_MS, AdvisoryCacheRepo } from '../src/db/advisoryCacheRepo';
import { memoryDb } from './helpers';

function repo() {
  return new AdvisoryCacheRepo(memoryDb());
}

describe('AdvisoryCacheRepo', () => {
  it('round-trips a value through get/set', () => {
    const cache = repo();
    const at = new Date('2024-01-01T00:00:00Z');
    cache.set('pkg', 'npm:lodash@4.17.19', ['GHSA-aaaa'], at);
    expect(cache.get<string[]>('pkg', 'npm:lodash@4.17.19')).toEqual({ value: ['GHSA-aaaa'], fetchedAt: at });
  });

  it('returns undefined for a missing key', () => {
    const cache = repo();
    expect(cache.get('pkg', 'missing')).toBeUndefined();
    expect(cache.getFresh('pkg', 'missing', new Date())).toBeUndefined();
  });

  it('keeps "pkg" and "vuln" kinds separate even with the same cache_key', () => {
    const cache = repo();
    const at = new Date('2024-01-01T00:00:00Z');
    cache.set('pkg', 'GHSA-aaaa', ['one'], at);
    cache.set('vuln', 'GHSA-aaaa', { id: 'GHSA-aaaa' }, at);
    expect(cache.get('pkg', 'GHSA-aaaa')?.value).toEqual(['one']);
    expect(cache.get('vuln', 'GHSA-aaaa')?.value).toEqual({ id: 'GHSA-aaaa' });
  });

  it('getFresh is fresh within the TTL and stale just past it', () => {
    const cache = repo();
    const fetchedAt = new Date('2024-01-01T00:00:00Z');
    cache.set('pkg', 'k', ['v'], fetchedAt);
    const justUnder = new Date(fetchedAt.getTime() + ADVISORY_CACHE_TTL_MS - 1);
    const justOver = new Date(fetchedAt.getTime() + ADVISORY_CACHE_TTL_MS + 1);
    expect(cache.getFresh('pkg', 'k', justUnder)).toEqual(['v']);
    expect(cache.getFresh('pkg', 'k', justOver)).toBeUndefined();
  });

  it('honors a custom ttlMs override', () => {
    const cache = repo();
    const fetchedAt = new Date('2024-01-01T00:00:00Z');
    cache.set('pkg', 'k', ['v'], fetchedAt);
    expect(cache.getFresh('pkg', 'k', new Date(fetchedAt.getTime() + 5_000), 1_000)).toBeUndefined();
    expect(cache.getFresh('pkg', 'k', new Date(fetchedAt.getTime() + 500), 1_000)).toEqual(['v']);
  });

  it('set overwrites an existing row (expired or not) in place', () => {
    const cache = repo();
    const first = new Date('2024-01-01T00:00:00Z');
    const second = new Date('2024-06-01T00:00:00Z');
    cache.set('pkg', 'k', ['old'], first);
    cache.set('pkg', 'k', ['new'], second);
    const entry = cache.get<string[]>('pkg', 'k');
    expect(entry?.value).toEqual(['new']);
    expect(entry?.fetchedAt).toEqual(second);
  });
});
