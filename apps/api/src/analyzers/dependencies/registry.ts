/**
 * Registry metadata client: published versions and per-version dependency ranges, for npm
 * (registry.npmjs.org, abbreviated metadata) and PyPI (pypi.org JSON API). Modeled on
 * `../../github/GitHubClient`'s timeout/retry/error-mapping style. Only these two fixed hosts are
 * ever contacted; package names are validated before any URL is built, so no path injection is
 * possible even from a malicious lockfile.
 */
import { z } from 'zod';
import { AppError, toAppError } from '../../errors/AppError';
import { CircuitBreaker } from '../../resilience/circuitBreaker';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../../resilience/retry';
import type { Ecosystem } from './types';

export type RegistryClientOptions = {
  fetch?: typeof fetch;
  now?: () => Date;
  timeoutMs?: number;
  /** Testing hook, mirrors GitHubClient's `retryDeps`: overrides withRetry's sleep/jitter. */
  retryDeps?: RetryDeps;
  breaker?: CircuitBreaker;
  npmBaseUrl?: string;
  pypiBaseUrl?: string;
  /** Response bodies larger than this are refused while streaming (default 20 MiB). */
  maxResponseBytes?: number;
  /** Cached packages (projections only, never whole documents; default 300). */
  cacheCapacity?: number;
};

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CAPACITY = 300;
const DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
const CACHE_TTL_MS = 60 * 60 * 1000;

/** Bounded LRU with a per-entry TTL. */
class Lru<V> {
  private readonly map = new Map<string, { at: number; value: V }>();
  constructor(private readonly capacity: number, private readonly ttlMs: number, private readonly now: () => Date) {}

  get(key: string): V | undefined {
    const e = this.map.get(key);
    if (e === undefined) return undefined;
    this.map.delete(key);
    if (this.now().getTime() - e.at >= this.ttlMs) return undefined;
    this.map.set(key, e);
    return e.value;
  }

  set(key: string, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    while (this.map.size >= this.capacity) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
    this.map.set(key, { at: this.now().getTime(), value });
  }
}

/** What is kept per npm package: the version list and, per version, only its dependency ranges. */
type NpmProjection = { versions: string[]; deps: Map<string, Map<string, string>> };

// npm: <=214 chars, no leading '.'/'_', optional "@scope/name". Uppercase is allowed: legacy packages
// (e.g. JSONStream) still have it, and the character set alone rules out path injection.
const NPM_UNSCOPED_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// PEP 508 "Name" production.
const PEP508_NAME_RE = /^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$/;

function isValidNpmName(name: string): boolean {
  if (name.length === 0 || name.length > 214) return false;
  if (name.startsWith('@')) {
    const rest = name.slice(1);
    const slash = rest.indexOf('/');
    if (slash <= 0 || rest.indexOf('/', slash + 1) !== -1) return false;
    const scope = rest.slice(0, slash);
    const pkg = rest.slice(slash + 1);
    return NPM_UNSCOPED_RE.test(scope) && NPM_UNSCOPED_RE.test(pkg);
  }
  return NPM_UNSCOPED_RE.test(name);
}

function isValidPackageName(eco: Ecosystem, name: string): boolean {
  return eco === 'npm' ? isValidNpmName(name) : PEP508_NAME_RE.test(name) && name.length <= 214;
}

function assertValidName(eco: Ecosystem, name: string): void {
  if (!isValidPackageName(eco, name)) throw new AppError('VALIDATION', 'permanent', `Invalid ${eco} package name: ${name}`);
}

function encodeNpmName(name: string): string {
  const slash = name.indexOf('/');
  return slash === -1 ? name : `${name.slice(0, slash)}%2f${name.slice(slash + 1)}`;
}

function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

function retryAfterMsFromHeaders(headers: Headers): number | undefined {
  const retryAfter = Number(headers.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return retryAfter * 1000;
  return undefined;
}

const NpmAbbrevDocSchema = z
  .object({
    versions: z.record(z.string(), z.object({ dependencies: z.record(z.string(), z.string()).optional() }).passthrough()).optional(),
  })
  .passthrough();
type NpmAbbrevDoc = z.infer<typeof NpmAbbrevDocSchema>;

const PypiProjectDocSchema = z
  .object({
    releases: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();
type PypiProjectDoc = z.infer<typeof PypiProjectDocSchema>;

const PypiVersionDocSchema = z
  .object({
    info: z
      .object({
        requires_dist: z.array(z.string()).nullable().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

/** Parses one PEP 508 `requires_dist` entry into { name, range }. Best-effort: handles the common
 *  "name (>=1,<2)", "name>=1,<2" and "name[extra]>=1" shapes and strips a trailing "; marker". */
function parseRequiresDistEntry(entry: string): { name: string; range: string | null } | null {
  const withoutMarker = (entry.split(';')[0] ?? '').trim();
  const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:\(([^)]*)\)|(.*))?$/.exec(withoutMarker);
  if (!match) return null;
  const name = match[1];
  if (!name) return null;
  const range = (match[2] ?? match[3] ?? '').trim();
  return { name, range: range.length > 0 ? range : null };
}

export class RegistryClient {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly retryDeps: RetryDeps | undefined;
  private readonly breaker: CircuitBreaker;
  private readonly npmBaseUrl: string;
  private readonly pypiBaseUrl: string;
  private readonly maxResponseBytes: number;
  private readonly npmCache: Lru<NpmProjection>;
  private readonly pypiVersionsCache: Lru<string[]>;
  private readonly pypiRequiresCache: Lru<string[]>;

  constructor(opts: RegistryClientOptions = {}) {
    const now = opts.now ?? (() => new Date());
    const capacity = opts.cacheCapacity ?? DEFAULT_CAPACITY;
    this.npmCache = new Lru(capacity, CACHE_TTL_MS, now);
    this.pypiVersionsCache = new Lru(capacity, CACHE_TTL_MS, now);
    this.pypiRequiresCache = new Lru(capacity * 10, CACHE_TTL_MS, now);
    this.maxResponseBytes = opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.fetchImpl = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retryDeps = opts.retryDeps;
    this.breaker = opts.breaker ?? new CircuitBreaker('Registry', { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'INTERNAL' });
    this.npmBaseUrl = opts.npmBaseUrl ?? 'https://registry.npmjs.org';
    this.pypiBaseUrl = opts.pypiBaseUrl ?? 'https://pypi.org';
  }

  async versions(eco: Ecosystem, name: string, signal: AbortSignal): Promise<string[]> {
    assertValidName(eco, name);
    if (eco === 'npm') return [...(await this.npmProjection(name, signal)).versions];
    return [...(await this.pypiVersions(name, signal))];
  }

  async dependencyRange(eco: Ecosystem, name: string, version: string, child: string, signal: AbortSignal): Promise<string | null> {
    assertValidName(eco, name);
    assertValidName(eco, child);
    if (eco === 'npm') return (await this.npmProjection(name, signal)).deps.get(version)?.get(child) ?? null;
    const requiresDist = await this.pypiRequiresDist(name, version, signal);
    const target = normalizePypiName(child);
    for (const entry of requiresDist) {
      const parsed = parseRequiresDistEntry(entry);
      if (parsed && normalizePypiName(parsed.name) === target) return parsed.range ?? '';
    }
    return null;
  }

  /** npm abbreviated doc → projection (version list + per-version dependency ranges); the doc itself is dropped. */
  private async npmProjection(name: string, signal: AbortSignal): Promise<NpmProjection> {
    const cached = this.npmCache.get(name);
    if (cached) return cached;
    const url = `${this.npmBaseUrl}/${encodeNpmName(name)}`;
    const json = await this.request(url, { accept: 'application/vnd.npm.install-v1+json' }, signal);
    const parsed = NpmAbbrevDocSchema.safeParse(json);
    if (!parsed.success) throw new AppError('INTERNAL', 'transient', 'npm registry returned an unexpected response', { cause: parsed.error });
    const doc: NpmAbbrevDoc = parsed.data;
    const deps = new Map<string, Map<string, string>>();
    for (const [version, info] of Object.entries(doc.versions ?? {})) {
      const d = info.dependencies;
      if (d && Object.keys(d).length > 0) deps.set(version, new Map(Object.entries(d)));
    }
    const projection: NpmProjection = { versions: Object.keys(doc.versions ?? {}), deps };
    this.npmCache.set(name, projection);
    return projection;
  }

  private async pypiVersions(name: string, signal: AbortSignal): Promise<string[]> {
    const cached = this.pypiVersionsCache.get(name);
    if (cached) return cached;
    const url = `${this.pypiBaseUrl}/pypi/${encodeURIComponent(name)}/json`;
    const json = await this.request(url, {}, signal);
    const parsed = PypiProjectDocSchema.safeParse(json);
    if (!parsed.success) throw new AppError('INTERNAL', 'transient', 'PyPI returned an unexpected response', { cause: parsed.error });
    const doc: PypiProjectDoc = parsed.data;
    const versions = Object.keys(doc.releases ?? {});
    this.pypiVersionsCache.set(name, versions);
    return versions;
  }

  private async pypiRequiresDist(name: string, version: string, signal: AbortSignal): Promise<string[]> {
    const key = `${name}@${version}`;
    const cached = this.pypiRequiresCache.get(key);
    if (cached) return cached;
    const url = `${this.pypiBaseUrl}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;
    let list: string[];
    try {
      const json = await this.request(url, {}, signal);
      const parsed = PypiVersionDocSchema.safeParse(json);
      list = parsed.success ? parsed.data.info?.requires_dist ?? [] : [];
    } catch (err) {
      const appErr = toAppError(err);
      if (appErr.code === 'NOT_FOUND') list = [];
      else throw appErr;
    }
    this.pypiRequiresCache.set(key, list);
    return list;
  }

  /** Reads the body as a stream and aborts as soon as it exceeds maxResponseBytes (a full npm document of a
   *  popular package is tens of MB; a hostile mirror could send far more). */
  private async readCapped(res: Response): Promise<string> {
    const tooBig = () => new AppError('INTERNAL', 'permanent', `Registry response exceeds ${Math.round(this.maxResponseBytes / 1048576)} MB`);
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > this.maxResponseBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw tooBig();
    }
    if (!res.body) return '';
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > this.maxResponseBytes) {
        await reader.cancel().catch(() => undefined);
        throw tooBig();
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  private async request(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<unknown> {
    return this.breaker.run(() => withRetry(() => this.doFetch(url, headers, signal), RETRY_POLICIES.registry, signal, this.retryDeps));
  }

  private async doFetch(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<unknown> {
    if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    const timeout = AbortSignal.timeout(this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(url, { headers: { 'user-agent': 'vibesec-scan', ...headers }, signal: AbortSignal.any([signal, timeout]) });
    } catch (err) {
      if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled', { cause: err });
      const e = toAppError(err);
      throw e.kind === 'permanent' ? new AppError('INTERNAL', 'transient', 'Network error while talking to the registry', { cause: err }) : e;
    }

    if (res.status === 404) throw new AppError('NOT_FOUND', 'permanent', 'Package not found in registry');
    if (res.ok) {
      const text = await this.readCapped(res);
      try {
        return JSON.parse(text) as unknown;
      } catch (err) {
        throw new AppError('INTERNAL', 'transient', 'Registry returned an unparseable response', { cause: err });
      }
    }
    if (res.status === 429 || res.status >= 500) {
      throw new AppError('INTERNAL', 'transient', 'Registry is temporarily unavailable', { retryAfterMs: retryAfterMsFromHeaders(res.headers) });
    }
    throw new AppError('INTERNAL', 'permanent', `Unexpected registry response (${res.status})`);
  }
}
