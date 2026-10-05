/**
 * TanStack Query hooks for every API read + the three mutations. Pages should only talk to the API
 * through these (or `api` for one-offs) so caching, keys and invalidation stay consistent.
 */
import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query';
import { isTerminalState, type CreateScanRequest, type Finding, type ScanDto } from '@vibesec/shared';
import { api, isApiError, type AuditFilters, type FindingFilters, type FindingsPage, type TriageInput } from '@/lib/api';

// ---------------------------------------------------------------------------------------------
// Keys — everything scan-scoped lives under ['scans', id] so one invalidation refreshes a scan.
// ---------------------------------------------------------------------------------------------

export const qk = {
  health: ['health'] as const,
  scan: (id: string) => ['scans', id] as const,
  findings: (id: string, filters: FindingFilters) => ['scans', id, 'findings', filters] as const,
  findingsAll: (id: string) => ['scans', id, 'findings'] as const,
  finding: (id: string, findingId: string) => ['scans', id, 'finding', findingId] as const,
  fixPlan: (id: string) => ['scans', id, 'fix-plan'] as const,
  summary: (id: string) => ['scans', id, 'summary'] as const,
  diagnostics: (id: string) => ['scans', id, 'diagnostics'] as const,
  index: (id: string) => ['scans', id, 'index'] as const,
  repos: ['repos'] as const,
  repoScans: (repoId: string) => ['repos', repoId, 'scans'] as const,
  audit: (filters: AuditFilters) => ['audit', filters] as const,
};

/** Default retry policy: retry transient failures (network/5xx/429) up to twice, never 4xx. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (isApiError(error) && !error.transient) return false;
  return failureCount < 2;
}

/** Refresh everything derived from a scan's results (called when a scan finishes). */
export function invalidateScanResults(qc: QueryClient, scanId: string): Promise<void> {
  return qc.invalidateQueries({ queryKey: ['scans', scanId] });
}

// ---------------------------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------------------------

export function useHealth() {
  return useQuery({
    queryKey: qk.health,
    queryFn: ({ signal }) => api.health(signal),
    // Recover quickly from an API restart; otherwise a slow heartbeat.
    refetchInterval: (q) => (q.state.status === 'error' ? 5_000 : 30_000),
    retry: false,
  });
}

/**
 * A scan. While it is running, pass `poll: true` only if you are NOT also using useScanEvents
 * (the SSE hook keeps this query's cache fresh on its own).
 */
export function useScan(id: string | undefined, opts: { poll?: boolean } = {}) {
  return useQuery({
    queryKey: qk.scan(id ?? ''),
    queryFn: ({ signal }) => api.getScan(id!, signal),
    enabled: !!id,
    refetchInterval: (q) => (opts.poll && q.state.data && !isTerminalState(q.state.data.state) ? 3_000 : false),
  });
}

/** Cursor-paginated findings; `data.pages[n].items`, counts are on every page (use pages[0].counts). */
export function useFindings(id: string | undefined, filters: FindingFilters = {}) {
  return useInfiniteQuery({
    queryKey: qk.findings(id ?? '', filters),
    queryFn: ({ pageParam, signal }) => api.listFindings(id!, filters, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: FindingsPage) => last.nextCursor ?? undefined,
    enabled: !!id,
    placeholderData: keepPreviousData,
  });
}

export function useFinding(id: string | undefined, findingId: string | undefined) {
  return useQuery({
    queryKey: qk.finding(id ?? '', findingId ?? ''),
    queryFn: ({ signal }) => api.getFinding(id!, findingId!, signal),
    enabled: !!id && !!findingId,
  });
}

export function useFixPlan(id: string | undefined) {
  return useQuery({
    queryKey: qk.fixPlan(id ?? ''),
    queryFn: ({ signal }) => api.getFixPlan(id!, signal),
    enabled: !!id,
  });
}

/** 404 NOT_READY until the scan's synthesis step ran — check `error.code === 'NOT_READY'`. */
export function useSummary(id: string | undefined, opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: qk.summary(id ?? ''),
    queryFn: ({ signal }) => api.getSummary(id!, signal),
    enabled: !!id && (opts.enabled ?? true),
  });
}

export function useDiagnostics(id: string | undefined) {
  return useQuery({
    queryKey: qk.diagnostics(id ?? ''),
    queryFn: ({ signal }) => api.getDiagnostics(id!, signal),
    enabled: !!id,
  });
}

export function useScanIndex(id: string | undefined) {
  return useQuery({
    queryKey: qk.index(id ?? ''),
    queryFn: ({ signal }) => api.getIndex(id!, signal),
    enabled: !!id,
  });
}

export function useRepos() {
  return useQuery({ queryKey: qk.repos, queryFn: ({ signal }) => api.listRepos(signal), select: (d) => d.items });
}

/** Newest first. */
export function useRepoScans(repoId: string | undefined) {
  return useQuery({
    queryKey: qk.repoScans(repoId ?? ''),
    queryFn: ({ signal }) => api.listRepoScans(repoId!, signal),
    enabled: !!repoId,
    select: (d) => d.items,
  });
}

/** Audit log, newest first, paginated by `before` seq. */
export function useAudit(filters: AuditFilters = {}) {
  return useInfiniteQuery({
    queryKey: qk.audit(filters),
    queryFn: ({ pageParam, signal }) => api.listAudit(filters, pageParam, signal),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
}

// ---------------------------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------------------------

/**
 * Starts a scan. A fresh Idempotency-Key is generated per *submit* (not per retry of the same
 * submit), so a double click or a network retry never creates two scans.
 */
export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ body, idempotencyKey }: { body: CreateScanRequest; idempotencyKey?: string }) =>
      api.createScan(body, idempotencyKey ?? crypto.randomUUID()),
    onSuccess: (res) => {
      qc.setQueryData<ScanDto>(qk.scan(res.scanId), res.scan);
      void qc.invalidateQueries({ queryKey: qk.repos });
      void qc.invalidateQueries({ queryKey: qk.repoScans(res.scan.repo.id) });
    },
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api.cancelScan(scanId),
    onSuccess: (scan) => {
      qc.setQueryData<ScanDto>(qk.scan(scan.id), scan);
      void qc.invalidateQueries({ queryKey: qk.repoScans(scan.repo.id) });
    },
  });
}

export type TriageVars = { findingId: string } & ({ clear: true } | ({ clear?: false } & TriageInput));

/** Set (PUT) or clear (DELETE) a finding's triage. Updates the finding cache and refreshes lists. */
export function useTriage(scanId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: TriageVars): Promise<Finding> =>
      v.clear
        ? api.clearTriage(scanId, v.findingId)
        : api.setTriage(scanId, v.findingId, { status: v.status, reason: v.reason, expiresAt: v.expiresAt }),
    onSuccess: (finding) => {
      qc.setQueryData<Finding>(qk.finding(scanId, finding.id), finding);
      void qc.invalidateQueries({ queryKey: qk.findingsAll(scanId) });
      void qc.invalidateQueries({ queryKey: qk.audit({}).slice(0, 1) });
    },
  });
}
