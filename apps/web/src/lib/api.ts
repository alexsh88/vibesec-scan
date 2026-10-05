/**
 * Typed client for the VibeSec API (apps/api). Every call goes through `request()`, which maps the
 * API's error envelope `{ error: { code, message, requestId, issues? } }` (apps/api/src/http/errorHandler.ts)
 * to an `ApiError` whose `userMessage` is safe to show verbatim.
 *
 * Shapes come from @vibesec/shared where the API exposes a shared schema; the rest mirror the API's
 * repository types (see the comments on each type for the source file).
 */
import {
  FindingSchema,
  FixPlanSchema,
  ScanDtoSchema,
  ScanSummarySchema,
  type Category,
  type CreateScanRequest,
  type ErrorCode,
  type Finding,
  type FixPlan,
  type ScanDto,
  type ScanState,
  type ScanSummary,
  type ScanWarningSchema,
  type Severity,
  type TriageStatus,
} from '@vibesec/shared';
import type { z } from 'zod';

const BASE = '/api';

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/** Client-only codes on top of the API's ErrorCode list. */
export type ClientErrorCode = ErrorCode | 'NETWORK' | 'BAD_RESPONSE';

export class ApiError extends Error {
  readonly code: ClientErrorCode;
  readonly status: number;
  /** Human-readable, safe to render (comes from the API's AppError.userMessage). */
  readonly userMessage: string;
  readonly requestId: string | undefined;
  readonly issues: Array<{ path: string; message: string }>;
  readonly retryAfterSec: number | undefined;

  constructor(init: {
    code: ClientErrorCode; status: number; userMessage: string; requestId?: string;
    issues?: Array<{ path: string; message: string }>; retryAfterSec?: number;
  }) {
    super(init.userMessage);
    this.name = 'ApiError';
    this.code = init.code;
    this.status = init.status;
    this.userMessage = init.userMessage;
    this.requestId = init.requestId;
    this.issues = init.issues ?? [];
    this.retryAfterSec = init.retryAfterSec;
  }

  /** Worth retrying automatically (network blips, 5xx, rate limits, full queue). */
  get transient(): boolean {
    return this.code === 'NETWORK' || this.status >= 500 || this.code === 'RATE_LIMITED' || this.code === 'QUEUE_FULL';
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** Normalises anything thrown into an ApiError (for components that render errors). */
export function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  return new ApiError({ code: 'INTERNAL', status: 0, userMessage: e instanceof Error ? e.message : 'Something went wrong' });
}

type ErrorEnvelope = { error?: { code?: string; message?: string; requestId?: string; issues?: Array<{ path: string; message: string }> } };

async function toError(res: Response): Promise<ApiError> {
  let body: ErrorEnvelope | null = null;
  try {
    body = (await res.json()) as ErrorEnvelope;
  } catch {
    /* non-JSON error body (proxy error page etc.) */
  }
  const retryAfter = Number(res.headers.get('retry-after'));
  const fallback = res.status === 502 || res.status === 504
    ? 'The VibeSec API is not reachable. Is it running on port 4000?'
    : `Request failed (HTTP ${res.status})`;
  return new ApiError({
    code: (body?.error?.code as ClientErrorCode | undefined) ?? (res.status >= 500 ? 'INTERNAL' : 'VALIDATION'),
    status: res.status,
    userMessage: body?.error?.message ?? fallback,
    requestId: body?.error?.requestId ?? res.headers.get('x-request-id') ?? undefined,
    issues: body?.error?.issues,
    retryAfterSec: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
  });
}

// ---------------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------------

type RequestOptions = {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
  /** Dev-only response validation: logs a warning when the API drifts from the shared schema. */
  schema?: z.ZodType;
};

function buildUrl(path: string, query?: RequestOptions['query']): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
  }
  const s = qs.toString();
  return `${BASE}${path}${s ? `?${s}` : ''}`;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json', ...opts.headers };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError({ code: 'NETWORK', status: 0, userMessage: 'Can’t reach the VibeSec API. Check that it is running and try again.' });
  }
  if (!res.ok) throw await toError(res);
  let data: unknown;
  try {
    data = await res.json();
  } catch {
    throw new ApiError({ code: 'BAD_RESPONSE', status: res.status, userMessage: 'The API returned an unreadable response.' });
  }
  if (import.meta.env.DEV && opts.schema) {
    const parsed = opts.schema.safeParse(data);
    if (!parsed.success) console.warn(`[api] ${path} response does not match the shared schema`, parsed.error.issues);
  }
  return data as T;
}

// ---------------------------------------------------------------------------------------------
// Response types not covered by @vibesec/shared
// ---------------------------------------------------------------------------------------------

export type ScanWarning = z.infer<typeof ScanWarningSchema>;

/** POST /api/scans — 202 new scan, 200 when deduplicated onto an existing/idempotent scan. */
export type CreateScanResponse = {
  scanId: string;
  status: ScanState;
  cacheHit: ScanDto['cacheHit'];
  deduplicated: boolean;
  scan: ScanDto;
};

/** apps/api/src/db/scanRepo.ts RepoRecord */
export type Repo = { id: string; owner: string; name: string; isPrivate: boolean; defaultBranch: string | null };

/** apps/api/src/db/findingRepo.ts FindingCounts — current findings (fixed excluded) + new/existing/fixed split. */
export type FindingCounts = {
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  byCategory: Partial<Record<Category, number>>;
  byScanStatus: Record<Finding['scanStatus'], number>;
  /** Same breakdowns scoped to the request's filters, except severity (left open on purpose). */
  filtered: { total: number; bySeverity: Partial<Record<Severity, number>>; byCategory: Partial<Record<Category, number>> };
};

export type FindingFilters = {
  category?: Category;
  severity?: Severity;
  file?: string;
  q?: string;
  /** API default 'all'. */
  triage?: 'open' | 'suppressed' | 'all';
  /** Omitted = current findings (new + existing); 'fixed' = gone since the previous scan. */
  scanStatus?: Finding['scanStatus'];
  /** 1..200 */
  limit?: number;
};

export type FindingsPage = { items: Finding[]; nextCursor: string | null; counts: FindingCounts };

export type TriageInput = { status: TriageStatus; reason: string; expiresAt?: string };

export type CoverageStatus = 'reviewed' | 'reviewed-fast' | 'cached' | 'not-relevant' | 'budget-skipped' | 'failed';

/** apps/api/src/index/types.ts SkipReason */
export type SkipReason = 'vendor' | 'binary' | 'too_large' | 'minified' | 'generated' | 'symlink' | 'submodule' | 'file_limit';

/** apps/api/src/index/types.ts IndexStats */
export type IndexStats = {
  totalFiles: number;
  indexedFiles: number;
  skipped: Partial<Record<SkipReason, number>>;
  byLanguage: Partial<Record<string, number>>;
  imports: number;
  entrypoints: number;
  /** true when MAX_FILES was reached and the rest were marked file_limit */
  truncated?: boolean;
};

export type LlmTotals = {
  calls: number; failedCalls: number; inputTokens: number; outputTokens: number;
  cacheReadTokens: number; cacheWriteTokens: number; costUsd: number;
};

/** GET /api/scans/:id/diagnostics (apps/api/src/http/routes/diagnostics.ts) */
export type Diagnostics = {
  scanId: string;
  state: ScanState;
  durationMs: number | null;
  warnings: ScanWarning[];
  index: IndexStats | null;
  cacheHit: ScanDto['cacheHit'];
  reuse: ScanDto['reuse'] | null;
  coverage: {
    totals: Record<CoverageStatus, number>;
    byAnalyzer: Record<string, Record<CoverageStatus, number>>;
    budgetSkipped: Array<{ analyzer: string; path: string }>;
  };
  llm: {
    mode: LlmMode;
    budgetUsd: number;
    totals: LlmTotals;
    byAnalyzer: Array<LlmTotals & { analyzer: string }>;
    reservedUsd: number;
    breakerTrips: number;
    /** 0..1 share of prompt tokens served from the prompt cache. */
    cacheHitRatio: number;
  };
};

/** GET /api/scans/:id/index */
export type ScanIndex = {
  stats: IndexStats | null;
  entrypoints: Array<{ path: string; kind: string; line: number | null; detail: string | null }>;
  packages: Array<{ name: string; importers: number }>;
};

export const AUDIT_ACTIONS = [
  'scan.created', 'scan.cancelled', 'scan.resumed', 'scan.completed', 'scan.failed',
  'repo.private_access', 'secret.verification_attempted', 'finding.triaged', 'finding.untriaged',
  'export.downloaded', 'config.changed', 'audit.verified',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/** apps/api/src/audit/AuditLogger.ts AuditEntry — hash-chained, append-only. */
export type AuditEntry = {
  seq: number; at: string; actor: string; actorIp: string | null; userAgent: string | null;
  action: AuditAction; targetType: string; targetId: string; scanId: string | null;
  details: Record<string, unknown>; prevHash: string; hash: string;
};

export type AuditFilters = {
  action?: AuditAction;
  targetType?: string;
  targetId?: string;
  /** ISO datetime */
  from?: string;
  to?: string;
  limit?: number;
};

/** `nextCursor` is the `before` seq for the next (older) page. */
export type AuditPage = { items: AuditEntry[]; nextCursor: number | null };

export type AuditVerifyResult = { ok: true; checked: number } | { ok: false; checked: number; firstBrokenSeq: number };

export type LlmMode = 'live' | 'record' | 'mock';

/** GET /api/health */
export type Health = {
  status: 'ok';
  scanMode: LlmMode;
  docker: string;
  queue: { pending: number; capacity: number };
  git: string | null;
  llm: { mode: LlmMode; models: { fast: string; deep: string; synthesis: string } };
};

// ---------------------------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------------------------

const enc = encodeURIComponent;

export const api = {
  health: (signal?: AbortSignal) => request<Health>('/health', { signal }),

  createScan: (body: CreateScanRequest, idempotencyKey: string) =>
    request<CreateScanResponse>('/scans', { method: 'POST', body, headers: { 'idempotency-key': idempotencyKey } }),
  getScan: (id: string, signal?: AbortSignal) => request<ScanDto>(`/scans/${enc(id)}`, { signal, schema: ScanDtoSchema }),
  cancelScan: (id: string) => request<ScanDto>(`/scans/${enc(id)}/cancel`, { method: 'POST' }),

  listFindings: (id: string, filters: FindingFilters, cursor?: string, signal?: AbortSignal) =>
    request<FindingsPage>(`/scans/${enc(id)}/findings`, { signal, query: { ...filters, cursor } }),
  getFinding: (id: string, findingId: string, signal?: AbortSignal) =>
    request<Finding>(`/scans/${enc(id)}/findings/${enc(findingId)}`, { signal, schema: FindingSchema }),
  setTriage: (id: string, findingId: string, body: TriageInput) =>
    request<Finding>(`/scans/${enc(id)}/findings/${enc(findingId)}/triage`, { method: 'PUT', body }),
  clearTriage: (id: string, findingId: string) =>
    request<Finding>(`/scans/${enc(id)}/findings/${enc(findingId)}/triage`, { method: 'DELETE' }),

  getFixPlan: (id: string, signal?: AbortSignal) => request<FixPlan>(`/scans/${enc(id)}/fix-plan`, { signal, schema: FixPlanSchema }),
  /** 404 NOT_READY until the summary event fired. */
  getSummary: (id: string, signal?: AbortSignal) => request<ScanSummary>(`/scans/${enc(id)}/summary`, { signal, schema: ScanSummarySchema }),
  getDiagnostics: (id: string, signal?: AbortSignal) => request<Diagnostics>(`/scans/${enc(id)}/diagnostics`, { signal }),
  getIndex: (id: string, signal?: AbortSignal) => request<ScanIndex>(`/scans/${enc(id)}/index`, { signal }),

  listRepos: (signal?: AbortSignal) => request<{ items: Repo[] }>('/repos', { signal }),
  listRepoScans: (repoId: string, signal?: AbortSignal) => request<{ items: ScanDto[] }>(`/repos/${enc(repoId)}/scans`, { signal }),

  listAudit: (filters: AuditFilters, before?: number, signal?: AbortSignal) =>
    request<AuditPage>('/audit', { signal, query: { ...filters, before } }),
  verifyAudit: () => request<AuditVerifyResult>('/audit/verify'),
};

/** Plain URLs for downloads (use as <a href download>; the API sets content-disposition). */
export const exportUrl = (scanId: string, format: 'sarif' | 'cyclonedx'): string => `${BASE}/scans/${enc(scanId)}/export/${format}`;

/** SSE stream URL. `after` replays events with seq > after (same semantics as the Last-Event-ID header). */
export const eventsUrl = (scanId: string, after?: number): string =>
  `${BASE}/scans/${enc(scanId)}/events${after ? `?after=${after}` : ''}`;
