import { useQuery } from '@tanstack/react-query';
import { LoaderCircle, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api, toApiError } from '@/lib/api';
import { formatInt } from '@/lib/format';
import { cn } from '@/lib/utils';

/**
 * "Audit log intact" — GET /api/audit/verify walks the whole hash chain. The call is side-effect
 * free (it does not itself append to the log), so it is safe to run on every visit and on demand.
 */
export function ChainStatus() {
  const q = useQuery({
    queryKey: ['audit-verify'],
    queryFn: () => api.verifyAudit(),
    staleTime: Infinity,
    gcTime: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });

  const recheck = (
    <button
      type="button"
      onClick={() => void q.refetch()}
      disabled={q.isFetching}
      className="inline-flex size-7 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50"
      aria-label="Verify the audit chain again"
      title="Verify again"
    >
      <RefreshCw className={cn('size-3.5', q.isFetching && 'animate-spin')} />
    </button>
  );

  if (q.isPending) {
    return (
      <div className="inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-sm text-muted-foreground" role="status">
        <LoaderCircle aria-hidden className="size-4 animate-spin" /> Verifying hash chain…
      </div>
    );
  }
  if (q.isError) {
    return (
      <div className="inline-flex h-9 items-center gap-2 rounded-lg border border-sev-medium/40 px-3 text-sm" role="status">
        <ShieldAlert aria-hidden className="size-4 text-sev-medium" />
        <span className="text-muted-foreground">Couldn’t verify: {toApiError(q.error).userMessage}</span>
        {recheck}
      </div>
    );
  }
  const r = q.data;
  return r.ok ? (
    <div
      className="inline-flex h-9 items-center gap-2 rounded-lg border border-status-fixed/40 bg-status-fixed/8 pr-1 pl-3 text-sm"
      role="status"
      title="Every entry's SHA-256 hash covers the previous entry's hash — editing or deleting any row breaks the chain."
    >
      <ShieldCheck aria-hidden className="size-4 text-status-fixed" />
      <span className="font-medium text-status-fixed">Audit log intact</span>
      <span className="font-mono text-[11px] text-muted-foreground tabular">{formatInt(r.checked)} entries verified</span>
      {recheck}
    </div>
  ) : (
    <div className="inline-flex h-9 items-center gap-2 rounded-lg border border-sev-critical/50 bg-sev-critical/10 pr-1 pl-3 text-sm" role="alert">
      <ShieldAlert aria-hidden className="size-4 text-sev-critical" />
      <span className="font-medium text-sev-critical">Chain broken at #{r.firstBrokenSeq}</span>
      <span className="font-mono text-[11px] text-muted-foreground tabular">{formatInt(r.checked)} checked — log was altered</span>
      {recheck}
    </div>
  );
}
