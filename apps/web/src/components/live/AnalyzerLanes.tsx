import { formatInt, formatUsd } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { LaneStatus, LaneView } from './liveModel';

const STATUS: Record<LaneStatus, { text: string; cls: string }> = {
  off: { text: 'off', cls: 'text-muted-foreground/60' },
  waiting: { text: 'queued', cls: 'text-muted-foreground' },
  running: { text: 'running', cls: 'text-foreground' },
  done: { text: 'done', cls: 'text-status-fixed' },
  failed: { text: 'failed', cls: 'text-sev-critical' },
  cached: { text: 'cached', cls: 'text-foreground/80' },
  stopped: { text: 'stopped', cls: 'text-muted-foreground' },
  skipped: { text: 'skipped', cls: 'text-muted-foreground' },
};

function Bar({ lane }: { lane: LaneView }) {
  const fill =
    lane.status === 'failed' ? 'bg-sev-critical'
    : lane.status === 'cached' ? 'bg-signal/45'
    : lane.status === 'done' ? 'bg-foreground/70'
    : 'bg-signal';
  return (
    <div
      role="progressbar"
      aria-label={`${lane.label} progress`}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={lane.fraction === null ? undefined : Math.round(lane.fraction * 100)}
      className="relative h-1.5 w-full overflow-hidden rounded-full bg-muted"
    >
      {lane.fraction === null ? (
        <span className="absolute inset-y-0 left-0 w-2/5 rounded-full bg-signal [animation:vs-live-sweep_1.4s_cubic-bezier(.4,0,.2,1)_infinite]" />
      ) : (
        <span
          className={cn('absolute inset-y-0 left-0 rounded-full transition-[width] duration-500 ease-out', fill)}
          style={{ width: `${Math.max(lane.fraction * 100, lane.fraction > 0 ? 2 : 0)}%` }}
        />
      )}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <span className={cn('inline-flex items-baseline gap-1', value === 0 && 'opacity-50')}>
      <span className={cn('tabular text-foreground', tone)}>{formatInt(value)}</span>
      <span>{label}</span>
    </span>
  );
}

/** One row per analyzer: status, progress bar, coverage counts and AI spend (from diagnostics). */
export function AnalyzerLanes({ lanes, coverageReady, finished }: { lanes: LaneView[]; coverageReady: boolean; finished: boolean }) {
  const active = lanes.filter((l) => l.status !== 'off');
  const off = lanes.filter((l) => l.status === 'off');
  return (
    <section aria-label="Analyzers" className="rounded-xl border bg-card">
      <div className="flex items-center justify-between gap-3 border-b px-4 py-2.5">
        <p className="eyebrow">Analyzers</p>
        <p className="font-mono text-[11px] text-muted-foreground">
          {coverageReady ? 'files: reviewed · cached · budget-skipped' : finished ? 'no file coverage recorded' : 'coverage appears when analysis finishes'}
        </p>
      </div>
      <ul className="divide-y">
        {active.map((lane) => {
          const s = STATUS[lane.status];
          return (
            <li key={lane.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1.5 px-4 py-2.5 sm:grid-cols-[11rem_minmax(0,1fr)_auto]">
              <div className="min-w-0">
                <p className="flex items-center gap-2 text-sm font-medium">
                  {lane.status === 'running' && <span aria-hidden className="size-1.5 animate-pulse-dot rounded-full bg-signal" />}
                  <span className="truncate">{lane.label}</span>
                </p>
                <p className="truncate text-xs text-muted-foreground">{lane.blurb}</p>
              </div>
              <span className={cn('font-mono text-[11px] uppercase tracking-wide sm:order-last', s.cls)}>
                {lane.progress && lane.status === 'running' && lane.progress.total > 0
                  ? `${formatInt(lane.progress.done)}/${formatInt(lane.progress.total)}`
                  : s.text}
              </span>
              <div className="col-span-2 min-w-0 space-y-1.5 sm:col-span-1">
                <Bar lane={lane} />
                <div className="flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[11px] text-muted-foreground">
                  {coverageReady && lane.stage === 'ANALYZING' && lane.reviewed + lane.cached + lane.budgetSkipped + lane.failedFiles > 0 && (
                    <>
                      <Stat label="reviewed" value={lane.reviewed} />
                      <Stat label="cached" value={lane.cached} />
                      <Stat label="budget-skipped" value={lane.budgetSkipped} tone={lane.budgetSkipped > 0 ? 'text-sev-medium' : undefined} />
                      {lane.failedFiles > 0 && <Stat label="failed" value={lane.failedFiles} tone="text-sev-critical" />}
                    </>
                  )}
                  {lane.calls > 0 && (
                    <span className="inline-flex items-baseline gap-1">
                      <span className="tabular text-foreground">{formatInt(lane.calls)}</span> AI calls ·
                      <span className="tabular text-foreground">{formatUsd(lane.costUsd)}</span>
                    </span>
                  )}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {off.length > 0 && (
        <p className="border-t px-4 py-2 font-mono text-[11px] text-muted-foreground">
          Not in this scan: {off.map((l) => l.label).join(', ')}
        </p>
      )}
    </section>
  );
}
