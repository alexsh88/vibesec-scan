import type { ScanDto } from '@vibesec/shared';
import { ArrowRight, CircleSlash, CircleX, Radio, RefreshCw } from 'lucide-react';
import { Link } from 'react-router';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { STATE_LABEL } from '@/lib/scanState';

const scanPath = (scan: ScanDto, sub: string) => `/scans/${encodeURIComponent(scan.id)}/${sub}`;

/** The overview only exists once a scan finished. */
export function ScanRunningNotice({ scan }: { scan: ScanDto }) {
  return (
    <div className="relative overflow-hidden rounded-xl border bg-card">
      <div aria-hidden className="bg-grid absolute inset-0 [mask-image:radial-gradient(ellipse_at_left,black,transparent_70%)]" />
      <div className="relative flex flex-col items-start gap-4 p-6 sm:flex-row sm:items-center">
        <span className="relative grid size-11 shrink-0 place-items-center rounded-full border border-state-running/40 bg-state-running/10">
          <Radio aria-hidden className="size-5 text-state-running" />
          <span aria-hidden className="absolute inset-0 animate-ping rounded-full border border-state-running/30" />
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <p className="eyebrow">Scan in progress · {STATE_LABEL[scan.state]}</p>
          <p className="text-base font-semibold">The overview appears when the scan finishes.</p>
          <p className="text-sm text-muted-foreground">Grade, top risks and next actions are written once all analyzers report.</p>
        </div>
        <Button asChild>
          <Link to={scanPath(scan, 'live')}>
            Watch live <ArrowRight />
          </Link>
        </Button>
      </div>
    </div>
  );
}

export function ScanEndedNotice({ scan }: { scan: ScanDto }) {
  const failed = scan.state === 'FAILED';
  const Icon = failed ? CircleX : CircleSlash;
  return (
    <div role={failed ? 'alert' : 'status'} className={failed ? 'rounded-xl border border-sev-critical/35 bg-sev-critical/5 p-6' : 'rounded-xl border bg-card p-6'}>
      <div className="flex items-start gap-4">
        <Icon aria-hidden className={failed ? 'mt-0.5 size-5 shrink-0 text-sev-critical' : 'mt-0.5 size-5 shrink-0 text-muted-foreground'} />
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-base font-semibold">{failed ? 'This scan failed' : 'This scan was cancelled'}</p>
          <p className="text-sm text-muted-foreground">
            {scan.errorMessage ?? (failed ? 'The scan stopped before producing results.' : 'It was stopped before the summary was written.')}
          </p>
          {scan.errorCode && <p className="font-mono text-[11px] text-muted-foreground/80">{scan.errorCode}</p>}
          <div className="flex flex-wrap gap-2 pt-2">
            <Button asChild size="sm" variant="outline">
              <Link to={scanPath(scan, 'live')}>Event log</Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link to={scanPath(scan, 'diagnostics')}>Diagnostics</Link>
            </Button>
            {!failed && (
              <Button asChild size="sm" variant="outline">
                <Link to={scanPath(scan, 'findings')}>Findings collected so far</Link>
              </Button>
            )}
            <Button asChild size="sm">
              <Link to="/">New scan</Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Summary NOT_READY (synthesis still being written): skeleton of the real layout + a retry. */
export function SummaryPending({ onRetry, retrying }: { onRetry: () => void; retrying: boolean }) {
  return (
    <div aria-busy="true" aria-label="Summary is being prepared" className="space-y-4">
      <div className="flex flex-col gap-5 rounded-xl border bg-card p-6 sm:flex-row">
        <Skeleton className="size-20 rounded-xl" />
        <div className="flex-1 space-y-3">
          <Skeleton className="h-6 w-3/4" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <p className="text-sm text-muted-foreground">The summary isn’t ready yet — it is written right after scoring.</p>
            <Button size="sm" variant="outline" onClick={onRetry} disabled={retrying}>
              <RefreshCw className={retrying ? 'animate-spin' : undefined} /> Check again
            </Button>
          </div>
        </div>
      </div>
      <Skeleton className="h-20 w-full" />
      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <Skeleton className="h-80 w-full" />
        <Skeleton className="h-80 w-full" />
      </div>
    </div>
  );
}
