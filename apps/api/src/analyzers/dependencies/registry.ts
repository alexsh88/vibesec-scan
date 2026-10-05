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
};

const DEFAULT_TIMEOUT_MS = 10_000;
const LRU_CAPACITY = 2000;

class Lru<V> {
  private readonly map = new Map<string, V>();
  constructor(private readonly capacity: number) {}

  get(key: string): V | undefined {
    const v = this.map.get(key);
    if (v === undefined) return undefined;
    this.map.delete(key);
    this.map.set(key, v);
    return v;
  }

  set(key: string, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    else if (this.map.size >= this.capacity) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    this.map.set(key, value);
  }
}

// npm: lowercase, <=214 chars, no leading '.'/'_', optional "@scope/name".
const NPM_UNSCOPED_RE = /^[a-z0-9][a-z0-9._-]*$/;
// PEP 508 "Name" production.
const PEP508_NAME_RE = /^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$/;

function isValidNpmName(name: string): boolean {
  if (name.length === 0 || name.length > 214) return false;
  if (name !== name.toLowerCase()) return false;
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
  private readonly cache = new Lru<unknown>(LRU_CAPACITY);

  constructor(opts: RegistryClientOptions = {}) {
    this.fetchImpl = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retryDeps = opts.retryDeps;
    this.breaker = opts.breaker ?? new CircuitBreaker('Registry', { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'INTERNAL' });
    this.npmBaseUrl = opts.npmBaseUrl ?? 'https://registry.npmjs.org';
    this.pypiBaseUrl = opts.pypiBaseUrl ?? 'https://pypi.org';
  }

  async versions(eco: Ecosystem, name: string, signal: AbortSignal): Promise<string[]> {
    assertValidName(eco, name);
    if (eco === 'npm') {
      const doc = await this.npmDoc(name, signal);
      return Object.keys(doc.versions ?? {});
    }
    const doc = await this.pypiProject(name, signal);
    return Object.keys(doc.releases ?? {});
  }

  async dependencyRange(eco: Ecosystem, name: string, version: string, child: string, signal: AbortSignal): Promise<string | null> {
    assertValidName(eco, name);
    assertValidName(eco, child);
    if (eco === 'npm') {
      const doc = await this.npmDoc(name, signal);
      const verInfo = doc.versions?.[version];
      return verInfo?.dependencies?.[child] ?? null;
    }
    const requiresDist = await this.pypiRequiresDist(name, version, signal);
    const target = normalizePypiName(child);
    for (const entry of requiresDist) {
      const parsed = parseRequiresDistEntry(entry);
      if (parsed && normalizePypiName(parsed.name) === target) return parsed.range ?? '';
    }
    return null;
  }

  private async npmDoc(name: string, signal: AbortSignal): Promise<NpmAbbrevDoc> {
    const key = `npm:doc:${name}`;
    const cached = this.cache.get(key) as NpmAbbrevDoc | undefined;
    if (cached) return cached;
    const url = `${this.npmBaseUrl}/${encodeNpmName(name)}`;
    const json = await this.request(url, { accept: 'application/vnd.npm.install-v1+json' }, signal);
    const parsed = NpmAbbrevDocSchema.safeParse(json);
    if (!parsed.success) throw new AppError('INTERNAL', 'transient', 'npm registry returned an unexpected response', { cause: parsed.error });
    this.cache.set(key, parsed.data);
    return parsed.data;
  }

  private async pypiProject(name: string, signal: AbortSignal): Promise<PypiProjectDoc> {
    const key = `pypi:project:${name}`;
    const cached = this.cache.get(key) as PypiProjectDoc | undefined;
    if (cached) return cached;
    const url = `${this.pypiBaseUrl}/pypi/${encodeURIComponent(name)}/json`;
    const json = await this.request(url, {}, signal);
    const parsed = PypiProjectDocSchema.safeParse(json);
    if (!parsed.success) throw new AppError('INTERNAL', 'transient', 'PyPI returned an unexpected response', { cause: parsed.error });
    this.cache.set(key, parsed.data);
    return parsed.data;
  }

  private async pypiRequiresDist(name: string, version: string, signal: AbortSignal): Promise<string[]> {
    const key = `pypi:version:${name}@${version}`;
    const cached = this.cache.get(key) as string[] | undefined;
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
    this.cache.set(key, list);
    return list;
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
      try {
        return await res.json();
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
