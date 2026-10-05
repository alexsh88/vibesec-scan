import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { AdvisoryCacheRepo } from '../src/db/advisoryCacheRepo';
import type { Ecosystem } from '../src/analyzers/dependencies/types';
import { normalizeOsv } from '../src/analyzers/dependencies/osv/normalize';
import { OsvClient } from '../src/analyzers/dependencies/osv/osvClient';
import { memoryDb } from './helpers';

function fixture(name: string): unknown {
  const path = fileURLToPath(new URL(`./fixtures/osv/${name}.json`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8'));
}

describe('normalizeOsv (fixtures)', () => {
  it('GHSA for lodash: computes CVSS v3 severity (overriding database_specific.severity), affected-range + symbols', () => {
    const record = fixture('ghsa-lodash');
    const advisory = normalizeOsv(record, { ecosystem: 'npm', name: 'lodash', version: '4.17.0' });
    expect(advisory).toMatchObject({
      id: 'GHSA-p6mc-m468-83gw',
      aliases: ['CVE-2020-8203'],
      severity: 'critical',
      cvss: 9.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      fixedVersions: ['4.17.19'],
      affectedSymbols: ['defaultsDeep', 'merge', 'mergeWith'],
      cwes: ['CWE-1321'],
      url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw',
      malicious: false,
    });
  });

  it('GHSA for lodash: a version past the fix is not affected -> null', () => {
    const record = fixture('ghsa-lodash');
    expect(normalizeOsv(record, { ecosystem: 'npm', name: 'lodash', version: '4.17.21' })).toBeNull();
  });

  it('PYSEC for PyYAML: matches via PEP 503 name normalization and ECOSYSTEM ranges', () => {
    const record = fixture('pysec-pyyaml');
    const advisory = normalizeOsv(record, { ecosystem: 'PyPI', name: 'pyyaml', version: '5.3' });
    expect(advisory).toMatchObject({ id: 'PYSEC-2021-142', severity: 'critical', cvss: 9.8, fixedVersions: ['5.4'], cwes: ['CWE-20', 'CWE-502'] });
  });

  it('PYSEC for PyYAML: a version at the fix is not affected -> null', () => {
    const record = fixture('pysec-pyyaml');
    expect(normalizeOsv(record, { ecosystem: 'PyPI', name: 'pyyaml', version: '5.4' })).toBeNull();
  });

  it('MAL record: malicious flag set, severity from database_specific, affected by explicit versions list', () => {
    const record = fixture('mal-malicious');
    const advisory = normalizeOsv(record, { ecosystem: 'npm', name: 'event-stream-fake', version: '1.0.1' });
    expect(advisory).toMatchObject({ malicious: true, severity: 'critical', cvss: null, cvssVector: null });
  });

  it('MAL record: a version absent from the explicit versions list is not affected -> null', () => {
    const record = fixture('mal-malicious');
    expect(normalizeOsv(record, { ecosystem: 'npm', name: 'event-stream-fake', version: '2.0.0' })).toBeNull();
  });

  it('CVSS v4 record: computes an approximate score and a plausible severity bucket', () => {
    const record = fixture('cvss-v4');
    const advisory = normalizeOsv(record, { ecosystem: 'npm', name: 'example-pkg', version: '1.0.0' });
    expect(advisory?.cvssVector).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(advisory?.cvss).not.toBeNull();
    expect(advisory?.severity).toBe('critical');
    expect(advisory?.fixedVersions).toEqual(['2.0.0']);
  });

  it('both CVSS v3 and v4 published: prefers the EXACT v3 score over the approximate v4 one', () => {
    const record = fixture('cvss-v4') as Record<string, unknown>;
    const v3 = 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N'; // exact 3.7 (low)
    const both = { ...record, severity: [...(record.severity as unknown[]), { type: 'CVSS_V3', score: v3 }] };
    const advisory = normalizeOsv(both, { ecosystem: 'npm', name: 'example-pkg', version: '1.0.0' });
    expect(advisory).toMatchObject({ cvss: 3.7, cvssVector: v3, severity: 'low' });
    // v4-first ordering in the input must not matter
    const reversed = { ...record, severity: [{ type: 'CVSS_V3', score: v3 }, ...(record.severity as unknown[])] };
    expect(normalizeOsv(reversed, { ecosystem: 'npm', name: 'example-pkg', version: '1.0.0' })?.cvss).toBe(3.7);
  });

  it('database_specific.severity only: no CVSS vectors published -> maps MODERATE to medium', () => {
    const record = fixture('db-severity-only');
    const advisory = normalizeOsv(record, { ecosystem: 'npm', name: 'sample-pkg', version: '1.0.0' });
    expect(advisory).toMatchObject({ severity: 'medium', cvss: null, cvssVector: null, fixedVersions: ['1.2.0'] });
  });

  it('returns null for a record with no affected entry for the given package', () => {
    const record = fixture('ghsa-lodash');
    expect(normalizeOsv(record, { ecosystem: 'npm', name: 'unrelated-pkg', version: '1.0.0' })).toBeNull();
  });

  it('returns null for malformed input (missing id)', () => {
    expect(normalizeOsv({ summary: 'no id' }, { ecosystem: 'npm', name: 'x', version: '1.0.0' })).toBeNull();
    expect(normalizeOsv('not an object', { ecosystem: 'npm', name: 'x', version: '1.0.0' })).toBeNull();
  });
});

type Pkg = { key: string; ecosystem: Ecosystem; name: string; version: string };

function minimalAffectedRecord(id: string, name: string, eco: Ecosystem): unknown {
  return {
    id,
    summary: 's',
    details: 'd',
    affected: [{ package: { ecosystem: eco, name }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
  };
}

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

describe('OsvClient', () => {
  it('queries uncached packages in querybatch chunks of <=1000', async () => {
    const pkgs: Pkg[] = Array.from({ length: 1001 }, (_, i) => ({ key: `npm:p${i}@1.0.0`, ecosystem: 'npm', name: `p${i}`, version: '1.0.0' }));
    const chunkSizes: number[] = [];
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
      chunkSizes.push(body.queries.length);
      return jsonResponse(200, { results: body.queries.map(() => ({ vulns: [] })) });
    });
    const cache = new AdvisoryCacheRepo(memoryDb());
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache });
    const { byKey, errors } = await client.advisoriesFor(pkgs, new AbortController().signal);
    expect(chunkSizes).toEqual([1000, 1]);
    expect(errors).toEqual([]);
    expect(byKey.size).toBe(1001);
  });

  it('follows next_page_token until exhausted, resending only the queries still paging, and merges vulns', async () => {
    const pkg: Pkg = { key: 'npm:foo@1.0.0', ecosystem: 'npm', name: 'foo', version: '1.0.0' };
    let postCalls = 0;
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'POST') {
        postCalls++;
        const body = JSON.parse(String(init?.body)) as { queries: Array<{ page_token?: string }> };
        expect(body.queries).toHaveLength(1);
        if (postCalls === 1) {
          expect(body.queries[0]?.page_token).toBeUndefined();
          return jsonResponse(200, { results: [{ vulns: [{ id: 'GHSA-aaa' }], next_page_token: 'tok1' }] });
        }
        expect(body.queries[0]?.page_token).toBe('tok1');
        return jsonResponse(200, { results: [{ vulns: [{ id: 'GHSA-bbb' }] }] });
      }
      const id = decodeURIComponent(String(url).split('/').pop() ?? '');
      return jsonResponse(200, minimalAffectedRecord(id, 'foo', 'npm'));
    });
    const cache = new AdvisoryCacheRepo(memoryDb());
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache });
    const { byKey, errors } = await client.advisoriesFor([pkg], new AbortController().signal);
    expect(postCalls).toBe(2);
    expect(errors).toEqual([]);
    expect(byKey.get(pkg.key)?.map((a) => a.id).sort()).toEqual(['GHSA-aaa', 'GHSA-bbb']);
  });

  it('a cache hit for both the id list and the vuln detail makes no network request', async () => {
    const pkg: Pkg = { key: 'npm:foo@1.0.0', ecosystem: 'npm', name: 'foo', version: '1.0.0' };
    const cache = new AdvisoryCacheRepo(memoryDb());
    const now = new Date('2024-06-01T00:00:00Z');
    cache.set('pkg', pkg.key, ['GHSA-aaa'], now);
    cache.set('vuln', 'GHSA-aaa', minimalAffectedRecord('GHSA-aaa', 'foo', 'npm'), now);
    const fetchMock = vi.fn();
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache, now: () => now });
    const { byKey, errors } = await client.advisoriesFor([pkg], new AbortController().signal);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(errors).toEqual([]);
    expect(byKey.get(pkg.key)?.map((a) => a.id)).toEqual(['GHSA-aaa']);
  });

  it('re-fetches once the 24h cache TTL has expired', async () => {
    const pkg: Pkg = { key: 'npm:foo@1.0.0', ecosystem: 'npm', name: 'foo', version: '1.0.0' };
    const cache = new AdvisoryCacheRepo(memoryDb());
    const fetchedAt = new Date('2024-06-01T00:00:00Z');
    cache.set('pkg', pkg.key, ['GHSA-aaa'], fetchedAt);
    cache.set('vuln', 'GHSA-aaa', minimalAffectedRecord('GHSA-aaa', 'foo', 'npm'), fetchedAt);
    const now = new Date(fetchedAt.getTime() + 25 * 60 * 60 * 1000); // +25h, past the 24h TTL
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'POST') return jsonResponse(200, { results: [{ vulns: [{ id: 'GHSA-aaa' }] }] });
      return jsonResponse(200, minimalAffectedRecord('GHSA-aaa', 'foo', 'npm'));
    });
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache, now: () => now });
    await client.advisoriesFor([pkg], new AbortController().signal);
    expect(fetchMock).toHaveBeenCalled();
  });

  it('retries a 429 on querybatch honoring Retry-After, then succeeds', async () => {
    const pkg: Pkg = { key: 'npm:foo@1.0.0', ecosystem: 'npm', name: 'foo', version: '1.0.0' };
    const responses = [jsonResponse(429, {}, { 'retry-after': '2' }), jsonResponse(200, { results: [{ vulns: [] }] })];
    const fetchMock = vi.fn(async () => responses.shift() ?? jsonResponse(500, {}));
    const sleeps: number[] = [];
    const cache = new AdvisoryCacheRepo(memoryDb());
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache, retryDeps: { sleep: async (ms) => { sleeps.push(ms); } } });
    const { errors } = await client.advisoriesFor([pkg], new AbortController().signal);
    expect(sleeps).toEqual([2_000]);
    expect(errors).toEqual([]);
  });

  it('partial failure: one advisory detail fails after retries are exhausted; the rest still resolve', async () => {
    const pkgs: Pkg[] = [
      { key: 'npm:foo@1.0.0', ecosystem: 'npm', name: 'foo', version: '1.0.0' },
    ];
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'POST') return jsonResponse(200, { results: [{ vulns: [{ id: 'GHSA-ok' }, { id: 'GHSA-bad' }] }] });
      const id = decodeURIComponent(String(_url).split('/').pop() ?? '');
      if (id === 'GHSA-bad') return jsonResponse(500, {});
      return jsonResponse(200, minimalAffectedRecord(id, 'foo', 'npm'));
    });
    const cache = new AdvisoryCacheRepo(memoryDb());
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache, retryDeps: { sleep: async () => {} } });
    const { byKey, errors } = await client.advisoriesFor(pkgs, new AbortController().signal);
    expect(byKey.get(pkgs[0]!.key)?.map((a) => a.id)).toEqual(['GHSA-ok']);
    expect(errors.some((e) => e.includes('GHSA-bad'))).toBe(true);
  });

  it('rejects with CANCELLED and makes no request when the signal is already aborted', async () => {
    const pkg: Pkg = { key: 'npm:foo@1.0.0', ecosystem: 'npm', name: 'foo', version: '1.0.0' };
    const fetchMock = vi.fn();
    const cache = new AdvisoryCacheRepo(memoryDb());
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache });
    const ac = new AbortController();
    ac.abort();
    await expect(client.advisoriesFor([pkg], ac.signal)).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('skips a manifest-only (non-concrete) version, recording an error and never querying it', async () => {
    const pkg: Pkg = { key: 'npm:foo@^1.0.0', ecosystem: 'npm', name: 'foo', version: '^1.0.0' };
    const fetchMock = vi.fn();
    const cache = new AdvisoryCacheRepo(memoryDb());
    const client = new OsvClient({ fetch: fetchMock as unknown as typeof fetch, cache });
    const { byKey, errors } = await client.advisoriesFor([pkg], new AbortController().signal);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(byKey.size).toBe(0);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain(pkg.key);
  });
});
