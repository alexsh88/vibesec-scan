/**
 * OSV (https://osv.dev) advisory client. Resolves advisories for concrete (ecosystem, name,
 * version) packages via the batch query API (id lists only) plus the per-id detail API, with a
 * 24h on-disk cache for both. Modeled on `../../github/GitHubClient`'s timeout/retry/error-mapping
 * style.
 */
import { AppError, toAppError } from '../../../errors/AppError';
import { CircuitBreaker } from '../../../resilience/circuitBreaker';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../../../resilience/retry';
import type { AdvisoryCacheRepo } from '../../../db/advisoryCacheRepo';
import type { Ecosystem, OsvAdvisory } from '../types';
import { isValidVersion } from '../versions';
import { normalizeOsv } from './normalize';

export type OsvPackageInput = { key: string; ecosystem: Ecosystem; name: string; version: string };
export type OsvAdvisoriesResult = {
  /** Advisories per package key; absent for packages whose query failed (see failedKeys). */
  byKey: Map<string, OsvAdvisory[]>;
  /** Package keys whose querybatch failed: their vulnerability status is UNKNOWN (not clean). */
  failedKeys: string[];
  /** Vuln ids that were listed for some package but whose details could not be fetched (each
   *  still appears in byKey as a placeholder advisory with detailsUnavailable). */
  failedIds: string[];
  errors: string[];
};

/** Placeholder for a vuln id OSV listed for a package but whose record could not be fetched. */
export function unavailableAdvisory(id: string): OsvAdvisory {
  return {
    id, aliases: [], summary: 'Advisory details unavailable (OSV record could not be fetched)', details: '',
    severity: 'medium', cvss: null, cvssVector: null, fixedVersions: [], affectedRanges: [], affectedSymbols: [], cwes: [],
    url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`, published: null, malicious: id.startsWith('MAL-'), detailsUnavailable: true,
  };
}

export type OsvClientDeps = {
  fetch?: typeof fetch;
  cache: AdvisoryCacheRepo;
  now?: () => Date;
  baseUrl?: string;
  breaker?: CircuitBreaker;
  /** Testing hook, mirrors GitHubClient's `retryDeps`: overrides withRetry's sleep/jitter. */
  retryDeps?: RetryDeps;
};

const QUERYBATCH_CHUNK = 1000;
const DETAIL_CONCURRENCY = 8;
const QUERYBATCH_TIMEOUT_MS = 15_000;
const DETAIL_TIMEOUT_MS = 10_000;

type BatchQuery = { package: { name: string; ecosystem: string }; version: string; page_token?: string };
type BatchResult = { vulns?: Array<{ id: string }>; next_page_token?: string };
type BatchResponse = { results?: BatchResult[] };

function retryAfterMsFromHeaders(headers: Headers): number | undefined {
  const retryAfter = Number(headers.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return retryAfter * 1000;
  return undefined;
}

export class OsvClient {
  private readonly fetchImpl: typeof fetch;
  private readonly cache: AdvisoryCacheRepo;
  private readonly now: () => Date;
  private readonly baseUrl: string;
  private readonly breaker: CircuitBreaker;
  private readonly retryDeps: RetryDeps | undefined;

  constructor(deps: OsvClientDeps) {
    this.fetchImpl = deps.fetch ?? fetch;
    this.cache = deps.cache;
    this.now = deps.now ?? (() => new Date());
    this.baseUrl = deps.baseUrl ?? 'https://api.osv.dev';
    this.breaker = deps.breaker ?? new CircuitBreaker('OSV API', { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'OSV_UNAVAILABLE' });
    this.retryDeps = deps.retryDeps;
  }

  async advisoriesFor(pkgs: readonly OsvPackageInput[], signal: AbortSignal): Promise<OsvAdvisoriesResult> {
    const errors: string[] = [];
    const byKey = new Map<string, OsvAdvisory[]>();
    const failedKeys: string[] = [];

    const candidates = new Map<string, OsvPackageInput>();
    for (const p of pkgs) {
      if (candidates.has(p.key)) continue;
      if (!isValidVersion(p.ecosystem, p.version)) {
        errors.push(`Skipped ${p.key}: "${p.version}" is not a concrete version`);
        continue;
      }
      candidates.set(p.key, p);
    }

    const idsByKey = new Map<string, string[]>();
    const uncached: OsvPackageInput[] = [];
    for (const p of candidates.values()) {
      const cached = this.cache.getFresh<string[]>('pkg', p.key, this.now());
      if (cached !== undefined) idsByKey.set(p.key, cached);
      else uncached.push(p);
    }

    for (let i = 0; i < uncached.length; i += QUERYBATCH_CHUNK) {
      if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
      const chunk = uncached.slice(i, i + QUERYBATCH_CHUNK);
      try {
        const results = await this.queryBatchChunk(chunk, signal);
        for (const [key, ids] of results) {
          idsByKey.set(key, ids);
          this.cache.set('pkg', key, ids, this.now());
        }
      } catch (err) {
        const appErr = toAppError(err);
        if (appErr.kind === 'cancelled') throw appErr;
        for (const p of chunk) {
          failedKeys.push(p.key);
          errors.push(`OSV querybatch failed for ${p.key}: ${appErr.userMessage}`);
        }
      }
    }

    const neededIds = new Set<string>();
    for (const ids of idsByKey.values()) for (const id of ids) neededIds.add(id);

    const vulnById = new Map<string, unknown>();
    const idsToFetch: string[] = [];
    for (const id of neededIds) {
      const cached = this.cache.getFresh<unknown>('vuln', id, this.now());
      if (cached !== undefined) vulnById.set(id, cached);
      else idsToFetch.push(id);
    }
    await this.fetchVulnDetails(idsToFetch, vulnById, errors, signal);
    const failedIds = idsToFetch.filter((id) => !vulnById.has(id));

    for (const p of candidates.values()) {
      const ids = idsByKey.get(p.key);
      if (ids === undefined) continue; // query failed: unknown, reported via failedKeys
      const advisories: OsvAdvisory[] = [];
      for (const id of ids) {
        const raw = vulnById.get(id);
        if (raw === undefined) {
          // Known vulnerable per OSV, details missing: never drop it silently.
          advisories.push(unavailableAdvisory(id));
          continue;
        }
        const normalized = normalizeOsv(raw, { ecosystem: p.ecosystem, name: p.name, version: p.version });
        if (normalized) advisories.push(normalized);
      }
      byKey.set(p.key, advisories);
    }

    return { byKey, failedKeys, failedIds, errors };
  }

  private async queryBatchChunk(chunk: readonly OsvPackageInput[], signal: AbortSignal): Promise<Map<string, string[]>> {
    const idsByKey = new Map<string, string[]>();
    for (const p of chunk) idsByKey.set(p.key, []);

    let active: Array<{ key: string; query: BatchQuery }> = chunk.map((p) => ({
      key: p.key,
      query: { package: { name: p.name, ecosystem: p.ecosystem }, version: p.version },
    }));

    while (active.length > 0) {
      if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
      const body = { queries: active.map((a) => a.query) };
      const json = await this.breaker.run(() =>
        withRetry(() => this.postQueryBatch(body, signal), RETRY_POLICIES.osv, signal, this.retryDeps),
      );
      const response = json as BatchResponse;
      const results = response.results ?? [];
      const next: Array<{ key: string; query: BatchQuery }> = [];
      for (let i = 0; i < active.length; i++) {
        const a = active[i];
        const res = results[i];
        if (!a) continue;
        const existing = idsByKey.get(a.key) ?? [];
        for (const v of res?.vulns ?? []) existing.push(v.id);
        idsByKey.set(a.key, existing);
        if (res?.next_page_token) next.push({ key: a.key, query: { ...a.query, page_token: res.next_page_token } });
      }
      active = next;
    }

    for (const [key, ids] of idsByKey) idsByKey.set(key, [...new Set(ids)]);
    return idsByKey;
  }

  private async fetchVulnDetails(ids: readonly string[], vulnById: Map<string, unknown>, errors: string[], signal: AbortSignal): Promise<void> {
    const queue = [...ids];
    const workerCount = Math.min(DETAIL_CONCURRENCY, queue.length);
    const workers = Array.from({ length: workerCount }, () => this.detailWorker(queue, vulnById, errors, signal));
    await Promise.all(workers);
  }

  private async detailWorker(queue: string[], vulnById: Map<string, unknown>, errors: string[], signal: AbortSignal): Promise<void> {
    for (;;) {
      const id = queue.shift();
      if (id === undefined) return;
      try {
        const json = await this.breaker.run(() => withRetry(() => this.getVuln(id, signal), RETRY_POLICIES.osv, signal, this.retryDeps));
        vulnById.set(id, json);
        this.cache.set('vuln', id, json, this.now());
      } catch (err) {
        const appErr = toAppError(err);
        if (appErr.kind === 'cancelled') throw appErr;
        errors.push(`Failed to fetch OSV advisory ${id}: ${appErr.userMessage}`);
      }
    }
  }

  private async postQueryBatch(body: unknown, signal: AbortSignal): Promise<unknown> {
    return this.request(`${this.baseUrl}/v1/querybatch`, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }, QUERYBATCH_TIMEOUT_MS, signal);
  }

  private async getVuln(id: string, signal: AbortSignal): Promise<unknown> {
    return this.request(`${this.baseUrl}/v1/vulns/${encodeURIComponent(id)}`, { method: 'GET' }, DETAIL_TIMEOUT_MS, signal);
  }

  private async request(url: string, init: RequestInit, timeoutMs: number, signal: AbortSignal): Promise<unknown> {
    if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    const timeout = AbortSignal.timeout(timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(url, { ...init, signal: AbortSignal.any([signal, timeout]) });
    } catch (err) {
      if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled', { cause: err });
      const e = toAppError(err);
      throw e.kind === 'permanent' ? new AppError('OSV_UNAVAILABLE', 'transient', 'Network error while talking to OSV', { cause: err }) : e;
    }

    if (res.ok) {
      try {
        return await res.json();
      } catch (err) {
        throw new AppError('OSV_UNAVAILABLE', 'transient', 'OSV returned an unparseable response', { cause: err });
      }
    }

    if (res.status === 429 || res.status >= 500) {
      throw new AppError('OSV_UNAVAILABLE', 'transient', 'OSV API is temporarily unavailable', { retryAfterMs: retryAfterMsFromHeaders(res.headers) });
    }
    if (res.status === 404) throw new AppError('NOT_FOUND', 'permanent', 'OSV record not found');
    throw new AppError('INTERNAL', 'permanent', `Unexpected OSV API response (${res.status})`);
  }
}
