import { CircleAlert, Clock3, Gauge, Info, Recycle, Timer, TriangleAlert, Wallet } from 'lucide-react';
import { Link } from 'react-router';
import { CoveragePanel } from '@/components/diagnostics/CoveragePanel';
import { IndexPanel } from '@/components/diagnostics/IndexPanel';
import { LlmUsagePanel } from '@/components/diagnostics/LlmUsagePanel';
import { Meter, Panel, Readout } from '@/components/diagnostics/primitives';
import { ErrorState } from '@/components/feedback/ErrorState';
import { Page, PageHeader } from '@/components/layout/Page';
import { Skeleton } from '@/components/ui/skeleton';
import { useDiagnostics, useScanIndex } from '@/hooks/queries';
import { useScanContext } from '@/hooks/useScanContext';
import type { Diagnostics, ScanWarning } from '@/lib/api';
import { formatDateTime, formatDuration, formatInt, formatUsd } from '@/lib/format';
import { isTerminalState } from '@/lib/scanState';
import { cn } from '@/lib/utils';

/** How the scan ran: coverage, AI spend vs budget, reuse from earlier scans, index, warnings, timings. */
export default function DiagnosticsPage() {
  const { scanId, scan } = useScanContext();
  const diag = useDiagnostics(scanId);
  const index = useScanIndex(scanId);

  return (
    <Page wide>
      <PageHeader
        eyebrow="Diagnostics"
        title="How this scan ran"
        description="What the analyzers actually looked at, what the AI review cost against the budget, what was reused from earlier scans, and anything that degraded the result."
      />
      {!isTerminalState(scan.state) && (
        <p className="mb-4 rounded-md border border-state-running/30 bg-state-running/5 px-3 py-2 text-xs text-muted-foreground">
          Scan in progress — figures are a snapshot and refresh when it finishes.
        </p>
      )}
      {diag.isError ? (
        <ErrorState error={diag.error} onRetry={() => void diag.refetch()} title="Couldn’t load diagnostics" />
      ) : diag.isPending ? (
        <DiagSkeleton />
      ) : (
        <DiagnosticsBody d={diag.data} scan={scan} index={index.data} />
      )}
    </Page>
  );
}

function DiagnosticsBody({ d, scan, index }: { d: Diagnostics; scan: ReturnType<typeof useScanContext>['scan']; index: Parameters<typeof IndexPanel>[0]['index'] }) {
  const spent = d.llm.totals.costUsd;
  const used = spent + d.llm.reservedUsd;
  const ratio = d.llm.budgetUsd > 0 ? used / d.llm.budgetUsd : 0;
  const queueMs = scan.startedAt ? Date.parse(scan.startedAt) - Date.parse(scan.createdAt) : null;
  const realWarnings = d.warnings.filter((w) => w.level !== 'info').length;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border lg:grid-cols-4">
        <Readout icon={Timer} label="Run time" value={formatDuration(d.durationMs)} sub={queueMs !== null ? `queued ${formatDuration(Math.max(0, queueMs))}` : 'not started'} />
        <Readout icon={Wallet} label="AI spend" value={formatUsd(spent)} sub={`of ${formatUsd(d.llm.budgetUsd)} budget · ${Math.round(ratio * 100)}%`}>
          <Meter value={ratio} />
        </Readout>
        <Readout
          icon={Gauge}
          label="Model calls"
          value={formatInt(d.llm.totals.calls)}
          sub={d.llm.totals.failedCalls > 0 ? `${d.llm.totals.failedCalls} failed` : 'none failed'}
        />
        <Readout
          icon={Recycle}
          label="Reuse"
          value={d.cacheHit === 'none' ? 'Fresh' : d.cacheHit === 'full' ? 'Full' : 'Partial'}
          sub={d.reuse ? `${formatUsd(d.reuse.estimatedSavedUsd)} saved (est.)` : 'no earlier result reused'}
        />
      </div>

      <CoveragePanel coverage={d.coverage} />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
        <LlmUsagePanel llm={d.llm} />
        <BudgetPanel d={d} spent={spent} />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <ReusePanel d={d} />
        <WarningsPanel warnings={d.warnings} realCount={realWarnings} />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <IndexPanel stats={d.index ?? index?.stats ?? null} index={index} />
        <TimingsPanel scan={scan} durationMs={d.durationMs} />
      </div>
    </div>
  );
}

function BudgetPanel({ d, spent }: { d: Diagnostics; spent: number }) {
  const budget = d.llm.budgetUsd;
  const reserved = d.llm.reservedUsd;
  const pct = (v: number) => (budget > 0 ? Math.min(100, (v / budget) * 100) : 0);
  const left = Math.max(0, budget - spent - reserved);
  return (
    <Panel id="budget-h" icon={Wallet} title="Budget" readout={`${formatUsd(left)} left`}>
      <div className="space-y-4">
        <div className="flex items-baseline justify-between gap-2">
          <span className="font-mono text-3xl font-semibold tabular">{formatUsd(spent)}</span>
          <span className="font-mono text-sm text-muted-foreground tabular">/ {formatUsd(budget)}</span>
        </div>
        <div className="relative h-3 overflow-hidden rounded-full bg-muted" role="img" aria-label={`${formatUsd(spent)} spent, ${formatUsd(reserved)} reserved of ${formatUsd(budget)}`}>
          <span className="absolute inset-y-0 left-0 bg-signal" style={{ width: `${pct(spent)}%` }} />
          <span className="absolute inset-y-0 bg-signal/35" style={{ left: `${pct(spent)}%`, width: `${pct(reserved)}%` }} />
          {/* 75% / 90% ticks */}
          {[75, 90].map((t) => (
            <span key={t} aria-hidden className="absolute inset-y-0 w-px bg-foreground/25" style={{ left: `${t}%` }} />
          ))}
        </div>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Spent</dt>
          <dd className="text-right font-mono tabular">{formatUsd(spent)}</dd>
          <dt className="text-muted-foreground">Reserved (in flight)</dt>
          <dd className="text-right font-mono tabular">{formatUsd(reserved)}</dd>
          <dt className="text-muted-foreground">Budget-skipped reviews</dt>
          <dd className={cn('text-right font-mono tabular', d.coverage.totals['budget-skipped'] > 0 && 'text-sev-medium')}>
            {formatInt(d.coverage.totals['budget-skipped'] ?? 0)}
          </dd>
          <dt className="text-muted-foreground">Cost per call</dt>
          <dd className="text-right font-mono tabular">{d.llm.totals.calls > 0 ? formatUsd(spent / d.llm.totals.calls) : '—'}</dd>
        </dl>
        <p className="text-xs text-muted-foreground">
          The budget is a hard cap: once reservations would exceed it, remaining files are marked budget-skipped instead of reviewed.
        </p>
      </div>
    </Panel>
  );
}

function ReusePanel({ d }: { d: Diagnostics }) {
  const r = d.reuse;
  return (
    <Panel id="reuse-h" icon={Recycle} title="Reuse from earlier scans" readout={`cache hit: ${d.cacheHit}`}>
      {!r ? (
        <p className="text-sm text-muted-foreground">
          Fresh scan — every file was analyzed. A rescan of the same repository reuses unchanged files’ results (incremental) or the
          whole result for the same commit and options.
        </p>
      ) : (
        <div className="space-y-4">
          <p className="text-sm">
            Reused results from{' '}
            <Link to={`/scans/${r.baseScanId}/overview`} className="font-mono text-xs underline underline-offset-2">
              scan {r.baseScanId.slice(0, 8)}
            </Link>
            {d.cacheHit === 'full' ? ' — same commit and options, nothing re-analyzed.' : ' — only changed files were analyzed again.'}
          </p>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Box k="Changed" v={formatInt(r.filesChanged)} />
            <Box k="Deleted" v={r.filesDeleted !== undefined ? formatInt(r.filesDeleted) : '—'} />
            <Box k="Reused" v={formatInt(r.filesReused)} accent />
            <Box k="Saved (est.)" v={formatUsd(r.estimatedSavedUsd)} accent />
          </dl>
          {r.filesChanged + r.filesReused > 0 && (
            <div className="space-y-1">
              <div className="flex h-2 overflow-hidden rounded-full bg-muted">
                <span className="bg-signal" style={{ width: `${(r.filesReused / (r.filesChanged + r.filesReused)) * 100}%` }} />
                <span className="bg-sev-medium" style={{ width: `${(r.filesChanged / (r.filesChanged + r.filesReused)) * 100}%` }} />
              </div>
              <p className="font-mono text-[10.5px] text-muted-foreground">
                {Math.round((r.filesReused / (r.filesChanged + r.filesReused)) * 100)}% of files reused
              </p>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function Box({ k, v, accent }: { k: string; v: string; accent?: boolean }) {
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2">
      <dt className="eyebrow text-[10px]">{k}</dt>
      <dd className={cn('font-mono text-lg font-semibold tabular', accent && 'text-signal')}>{v}</dd>
    </div>
  );
}

function WarningsPanel({ warnings, realCount }: { warnings: ScanWarning[]; realCount: number }) {
  return (
    <Panel
      id="warnings-h"
      icon={TriangleAlert}
      title="Warnings & notes"
      readout={warnings.length === 0 ? 'none' : `${realCount} warning${realCount === 1 ? '' : 's'} · ${warnings.length - realCount} note${warnings.length - realCount === 1 ? '' : 's'}`}
    >
      {warnings.length === 0 ? (
        <p className="text-sm text-muted-foreground">The scan ran without degradation.</p>
      ) : (
        <ul className="space-y-2">
          {warnings.map((w, i) => {
            const info = w.level === 'info';
            return (
              <li key={`${w.code}-${i}`} className={cn('flex gap-3 rounded-md border p-3', info ? 'bg-surface-raised' : 'border-sev-medium/35 bg-sev-medium/5')}>
                {info ? (
                  <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-status-triaged" />
                ) : (
                  <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-medium" />
                )}
                <div className="min-w-0 space-y-1">
                  <p className="text-sm text-pretty">{w.message}</p>
                  <p className="flex flex-wrap gap-x-3 font-mono text-[10.5px] text-muted-foreground">
                    <span>{w.code}</span>
                    {w.stage && <span>stage {w.stage.toLowerCase()}</span>}
                    <span className={info ? '' : 'text-sev-medium'}>{info ? 'note' : 'warning'}</span>
                  </p>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function TimingsPanel({ scan, durationMs }: { scan: ReturnType<typeof useScanContext>['scan']; durationMs: number | null }) {
  const created = Date.parse(scan.createdAt);
  const started = scan.startedAt ? Date.parse(scan.startedAt) : null;
  const finished = scan.finishedAt ? Date.parse(scan.finishedAt) : null;
  const end = finished ?? Date.now();
  const span = Math.max(1, end - created);
  const queued = started !== null ? started - created : end - created;
  return (
    <Panel id="timing-h" icon={Clock3} title="Timings" readout={formatDuration(finished !== null ? finished - created : null) + ' end-to-end'}>
      <div className="space-y-4">
        <div className="space-y-1">
          <div className="flex h-3 overflow-hidden rounded-full bg-muted" role="img" aria-label={`queued ${formatDuration(queued)}, ran ${formatDuration(durationMs)}`}>
            <span className="bg-muted-foreground/40" style={{ width: `${(Math.max(0, queued) / span) * 100}%` }} />
            {started !== null && <span className="bg-state-running" style={{ width: `${((end - started) / span) * 100}%` }} />}
          </div>
          <p className="flex gap-4 font-mono text-[10.5px] text-muted-foreground">
            <span className="flex items-center gap-1.5"><span aria-hidden className="size-2 rounded-[2px] bg-muted-foreground/40" /> queued {formatDuration(Math.max(0, queued))}</span>
            <span className="flex items-center gap-1.5"><span aria-hidden className="size-2 rounded-[2px] bg-state-running" /> running {formatDuration(durationMs)}</span>
          </p>
        </div>
        <dl className="grid grid-cols-[7rem_1fr] gap-y-1.5 text-sm">
          <dt className="text-muted-foreground">Created</dt>
          <dd className="font-mono text-xs tabular">{formatDateTime(scan.createdAt)}</dd>
          <dt className="text-muted-foreground">Started</dt>
          <dd className="font-mono text-xs tabular">{formatDateTime(scan.startedAt)}</dd>
          <dt className="text-muted-foreground">Finished</dt>
          <dd className="font-mono text-xs tabular">{formatDateTime(scan.finishedAt)}</dd>
          <dt className="text-muted-foreground">Final state</dt>
          <dd className="font-mono text-xs">{scan.state.toLowerCase().replaceAll('_', ' ')}</dd>
        </dl>
      </div>
    </Panel>
  );
}

function DiagSkeleton() {
  return (
    <div className="space-y-5" aria-busy="true" aria-label="Loading diagnostics">
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-64 w-full" />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Skeleton className="h-56" />
        <Skeleton className="h-56" />
      </div>
    </div>
  );
}
