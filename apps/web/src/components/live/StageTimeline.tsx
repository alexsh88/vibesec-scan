import type { ScanState } from '@vibesec/shared';
import { Check, CircleSlash, DatabaseZap, Flag, Minus, X } from 'lucide-react';
import { formatDuration, formatInt } from '@/lib/format';
import { STATE_LABEL, isTerminalState } from '@/lib/scanState';
import { cn } from '@/lib/utils';
import type { StageStatus, StageView, Timeline } from './liveModel';

type Props = {
  timeline: Timeline;
  current: ScanState;
  now: number;
  /** Scan wall time so far (or in total once finished), null before it started. */
  elapsedMs: number | null;
};

const STATUS_TEXT: Record<StageStatus, string> = {
  pending: 'waiting',
  active: 'running',
  done: 'done',
  failed: 'failed',
  cancelled: 'cancelled',
  skipped: 'skipped',
  cached: 'from cache',
};

function stageDuration(s: StageView, now: number): number | null {
  if (s.startedAt === null) return null;
  return Math.max(0, (s.endedAt ?? now) - s.startedAt);
}

function progressText(s: StageView): string | null {
  if (!s.progress || s.status !== 'active' || s.progress.total <= 1) return null;
  const { done, total } = s.progress;
  if (s.state === 'CLONING') return `${Math.round((done / total) * 100)}%`;
  return `${formatInt(done)} / ${formatInt(total)}`;
}

function Node({ status, size = 'md' }: { status: StageStatus | 'final-ok' | 'final-warn'; size?: 'md' | 'lg' }) {
  const box = size === 'lg' ? 'size-7' : 'size-6';
  const icon = 'size-3.5';
  switch (status) {
    case 'active':
      return (
        <span className={cn('relative grid place-items-center', box)}>
          <span aria-hidden className="absolute inset-0 rounded-full bg-signal/50 [animation:vs-live-ping_1.6s_cubic-bezier(0,0,.2,1)_infinite]" />
          <span className="relative grid size-full place-items-center rounded-full border-2 border-signal bg-background">
            <span className="size-2 rounded-full bg-signal" />
          </span>
        </span>
      );
    case 'done':
      return (
        <span className={cn('grid place-items-center rounded-full bg-foreground/85 text-background', box)}>
          <Check aria-hidden className={icon} strokeWidth={3} />
        </span>
      );
    case 'final-ok':
      return (
        <span className={cn('grid place-items-center rounded-full bg-status-fixed text-background', box)}>
          <Flag aria-hidden className={icon} strokeWidth={2.5} />
        </span>
      );
    case 'final-warn':
      return (
        <span className={cn('grid place-items-center rounded-full bg-sev-medium text-background', box)}>
          <Flag aria-hidden className={icon} strokeWidth={2.5} />
        </span>
      );
    case 'failed':
      return (
        <span className={cn('grid place-items-center rounded-full bg-sev-critical text-background', box)}>
          <X aria-hidden className={icon} strokeWidth={3} />
        </span>
      );
    case 'cancelled':
      return (
        <span className={cn('grid place-items-center rounded-full border-2 border-muted-foreground/70 bg-muted text-muted-foreground', box)}>
          <CircleSlash aria-hidden className={icon} />
        </span>
      );
    case 'cached':
      return (
        <span className={cn('grid place-items-center rounded-full border border-dashed border-signal/60 bg-signal-soft text-foreground/70', box)}>
          <DatabaseZap aria-hidden className="size-3" />
        </span>
      );
    case 'skipped':
      return (
        <span className={cn('grid place-items-center rounded-full border border-dashed border-muted-foreground/50 text-muted-foreground', box)}>
          <Minus aria-hidden className="size-3" />
        </span>
      );
    default:
      return (
        <span className={cn('grid place-items-center rounded-full border border-border bg-background', box)}>
          <span className="size-1.5 rounded-full bg-muted-foreground/40" />
        </span>
      );
  }
}

/** Connector between node i and i+1: solid once passed, flowing while the left node runs. */
function Connector({ from, to, vertical }: { from: StageStatus; to: StageStatus | 'final'; vertical?: boolean }) {
  const passed = from === 'done' && to !== 'pending';
  const flowing = from === 'active';
  const cached = from === 'cached' || to === 'cached';
  return (
    <span
      aria-hidden
      className={cn(
        'block rounded-full',
        vertical ? 'w-0.5 flex-1' : 'h-0.5 flex-1',
        passed ? 'bg-foreground/70' : flowing ? (vertical ? 'bg-signal/60' : 'vs-live-flow') : cached ? 'bg-signal/25' : 'bg-border',
      )}
    />
  );
}

function finalNode({ current }: { current: ScanState }) {
  const terminal = isTerminalState(current);
  const status =
    current === 'COMPLETED' ? 'final-ok'
    : current === 'COMPLETED_WITH_WARNINGS' ? 'final-warn'
    : current === 'FAILED' ? 'failed'
    : current === 'CANCELLED' ? 'cancelled'
    : 'pending';
  return { status: status as Parameters<typeof Node>[0]['status'], label: terminal ? STATE_LABEL[current] : 'Done' };
}

export function StageTimeline({ timeline, current, now, elapsedMs: totalMs }: Props) {
  const { stages, cacheShortcut } = timeline;
  const final = finalNode({ current });
  const finalStatusForConnector: StageStatus | 'final' = isTerminalState(current) ? 'final' : 'pending';

  return (
    <section aria-label="Pipeline stages" className="rounded-xl border bg-card">
      <div className="flex items-center justify-between gap-3 border-b px-4 py-2.5">
        <p className="eyebrow">Pipeline</p>
        <p className="font-mono text-xs text-muted-foreground tabular">
          {current === 'QUEUED' ? 'queued — waiting for a worker' : totalMs !== null ? `elapsed ${formatDuration(totalMs)}` : '—'}
        </p>
      </div>

      {/* Desktop: horizontal rail */}
      <div className="hidden px-4 pt-4 pb-5 md:block">
        {cacheShortcut && (
          <div className="relative mb-2 grid grid-cols-8" aria-hidden>
            <div className="col-span-8 mx-[6.25%] h-4 rounded-t-lg border-x border-t border-dashed border-signal/70" />
            <span className="absolute -top-2 left-1/2 -translate-x-1/2 rounded-full border border-signal/50 bg-card px-2 font-mono text-[10.5px] whitespace-nowrap text-foreground">
              $0 — served from cache
            </span>
          </div>
        )}
        <ol className="grid grid-cols-8">
          {stages.map((s, i) => {
            const prev = stages[i - 1];
            const next = stages[i + 1];
            const dur = stageDuration(s, now);
            const prog = progressText(s);
            return (
              <li key={s.state} className="flex min-w-0 flex-col items-center text-center" aria-current={s.status === 'active' ? 'step' : undefined}>
                <span className="mb-2 font-mono text-[10px] text-muted-foreground/70">{String(i + 1).padStart(2, '0')}</span>
                <div className="flex w-full items-center gap-1.5">
                  {prev ? <Connector from={prev.status} to={s.status} /> : <span className="flex-1" />}
                  <Node status={s.status} />
                  {next ? <Connector from={s.status} to={next.status} /> : <Connector from={s.status} to={finalStatusForConnector} />}
                </div>
                <span
                  className={cn(
                    'mt-2 truncate px-1 text-[13px] font-medium',
                    s.status === 'pending' || s.status === 'skipped' || s.status === 'cached' ? 'text-muted-foreground' : 'text-foreground',
                    s.status === 'failed' && 'text-sev-critical',
                  )}
                >
                  {s.label}
                </span>
                <span className="mt-0.5 font-mono text-[11px] text-muted-foreground tabular">
                  {prog ?? (dur !== null ? formatDuration(dur) : (isTerminalState(current) && s.status === 'pending' ? 'not run' : STATUS_TEXT[s.status]))}
                </span>
              </li>
            );
          })}
          <li className="flex min-w-0 flex-col items-center text-center">
            <span className="mb-2 font-mono text-[10px] text-muted-foreground/70">{'//'}</span>
            <div className="flex w-full items-center gap-1.5">
              <Connector from={stages[stages.length - 1]!.status} to={finalStatusForConnector} />
              <Node status={final.status} />
              <span className="flex-1" />
            </div>
            <span className={cn('mt-2 truncate px-1 text-[13px] font-medium', !isTerminalState(current) && 'text-muted-foreground')}>
              {final.label}
            </span>
            <span className="mt-0.5 font-mono text-[11px] text-muted-foreground tabular">
              {cacheShortcut && isTerminalState(current) ? '$0.00' : totalMs !== null && isTerminalState(current) ? formatDuration(totalMs) : '—'}
            </span>
          </li>
        </ol>
      </div>

      {/* Mobile: vertical list */}
      <ol className="px-4 py-3 md:hidden">
        {stages.map((s, i) => {
          const dur = stageDuration(s, now);
          const prog = progressText(s);
          return (
            <li key={s.state} className="flex gap-3" aria-current={s.status === 'active' ? 'step' : undefined}>
              <div className="flex flex-col items-center">
                <Node status={s.status} />
                <Connector vertical from={s.status} to={stages[i + 1]?.status ?? finalStatusForConnector} />
              </div>
              <div className="flex min-h-10 flex-1 items-start justify-between gap-2 pt-0.5 pb-3">
                <span className={cn('text-sm font-medium', (s.status === 'pending' || s.status === 'skipped' || s.status === 'cached') && 'text-muted-foreground', s.status === 'failed' && 'text-sev-critical')}>
                  {s.label}
                </span>
                <span className="font-mono text-xs text-muted-foreground tabular">
                  {prog ?? (dur !== null ? formatDuration(dur) : (isTerminalState(current) && s.status === 'pending' ? 'not run' : STATUS_TEXT[s.status]))}
                </span>
              </div>
            </li>
          );
        })}
        <li className="flex gap-3">
          <Node status={final.status} />
          <div className="flex flex-1 items-start justify-between gap-2 pt-0.5">
            <span className={cn('text-sm font-medium', !isTerminalState(current) && 'text-muted-foreground')}>{final.label}</span>
            <span className="font-mono text-xs text-muted-foreground tabular">
              {cacheShortcut && isTerminalState(current) ? '$0 — from cache' : totalMs !== null && isTerminalState(current) ? formatDuration(totalMs) : '—'}
            </span>
          </div>
        </li>
      </ol>
    </section>
  );
}
