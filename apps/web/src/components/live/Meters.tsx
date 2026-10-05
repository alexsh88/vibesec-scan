import type { ScanDto, ScanEvent } from '@vibesec/shared';
import { DatabaseZap, Info, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import type { Diagnostics } from '@/lib/api';
import { formatCompact, formatInt, formatUsd } from '@/lib/format';
import { cn } from '@/lib/utils';
import { warningTitle, type WarningItem } from './liveModel';

function PanelHead({ title, right }: { title: string; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b px-4 py-2.5">
      <p className="eyebrow">{title}</p>
      {right}
    </div>
  );
}

/** Running AI spend vs the scan budget, with token breakdown. */
export function CostMeter({
  scan,
  cost,
  diagnostics,
}: {
  scan: ScanDto;
  cost: Extract<ScanEvent, { type: 'cost' }> | null;
  diagnostics: Diagnostics | undefined;
}) {
  const totals = diagnostics?.llm.totals;
  const usd = Math.max(cost?.usd ?? 0, scan.costUsd, totals?.costUsd ?? 0);
  const budget = diagnostics?.llm.budgetUsd ?? scan.options.budgetUsd ?? null;
  const reserved = diagnostics?.llm.reservedUsd ?? 0;
  const frac = budget ? Math.min(1, usd / budget) : 0;
  const reservedFrac = budget ? Math.min(1 - frac, reserved / budget) : 0;
  const hot = frac >= 0.85;
  const tokens = [
    { label: 'in', value: Math.max(totals?.inputTokens ?? 0, cost?.inputTokens ?? 0) },
    { label: 'out', value: Math.max(totals?.outputTokens ?? 0, cost?.outputTokens ?? 0) },
    { label: 'cache-read', value: Math.max(totals?.cacheReadTokens ?? 0, cost?.cacheReadTokens ?? 0) },
  ];
  const mode = diagnostics?.llm.mode;

  return (
    <section aria-label="AI cost" className="rounded-xl border bg-card">
      <PanelHead
        title="AI spend"
        right={
          mode && mode !== 'live' ? (
            <span className="rounded border px-1.5 font-mono text-[10px] tracking-wide text-muted-foreground uppercase">{mode} llm</span>
          ) : null
        }
      />
      <div className="space-y-3 px-4 py-3.5">
        <div className="flex items-baseline justify-between gap-2">
          <p className="font-mono text-[1.75rem] leading-none font-semibold tabular">{formatUsd(usd)}</p>
          <p className="font-mono text-xs text-muted-foreground tabular">{budget !== null ? `of ${formatUsd(budget)} budget` : 'no budget data'}</p>
        </div>
        {budget !== null && (
          <div>
            <div
              role="meter"
              aria-label="Share of AI budget spent"
              aria-valuemin={0}
              aria-valuemax={budget}
              aria-valuenow={usd}
              className="relative h-2 overflow-hidden rounded-full bg-muted"
            >
              <span
                className={cn('absolute inset-y-0 left-0 transition-[width] duration-700 ease-out', hot ? 'bg-sev-medium' : 'bg-signal')}
                style={{ width: `${frac * 100}%` }}
              />
              {reservedFrac > 0 && (
                <span
                  title="Reserved by in-flight AI calls"
                  className="absolute inset-y-0 bg-[repeating-linear-gradient(135deg,var(--muted-foreground)_0_2px,transparent_2px_5px)] opacity-40"
                  style={{ left: `${frac * 100}%`, width: `${reservedFrac * 100}%` }}
                />
              )}
              {[0.25, 0.5, 0.75].map((t) => (
                <span key={t} aria-hidden className="absolute inset-y-0 w-px bg-background/70" style={{ left: `${t * 100}%` }} />
              ))}
            </div>
            <p className="mt-1 flex justify-between font-mono text-[10.5px] text-muted-foreground tabular">
              <span>{Math.round(frac * 100)}% used</span>
              {reserved > 0 && <span>{formatUsd(reserved)} in flight</span>}
            </p>
          </div>
        )}
        <dl className="grid grid-cols-3 gap-2 border-t pt-3">
          {tokens.map((t) => (
            <div key={t.label}>
              <dt className="font-mono text-[10.5px] text-muted-foreground">tokens {t.label}</dt>
              <dd className="font-mono text-sm tabular" title={formatInt(t.value)}>
                {formatCompact(t.value)}
              </dd>
            </div>
          ))}
        </dl>
        {totals && totals.calls > 0 && (
          <p className="font-mono text-[11px] text-muted-foreground">
            {formatInt(totals.calls)} calls
            {totals.failedCalls > 0 && <span className="text-sev-medium"> · {formatInt(totals.failedCalls)} failed</span>}
            {diagnostics && diagnostics.llm.cacheHitRatio > 0 && <> · {Math.round(diagnostics.llm.cacheHitRatio * 100)}% prompt-cache hits</>}
          </p>
        )}
      </div>
    </section>
  );
}

/** Reuse stats for a cached (full) or incremental (partial) scan. Renders nothing for a fresh scan. */
export function CachePanel({ scan, cache }: { scan: ScanDto; cache: Extract<ScanEvent, { type: 'cache' }> | null }) {
  const kind = scan.cacheHit !== 'none' ? scan.cacheHit : cache ? (cache.filesAnalyzed === 0 ? 'full' : 'partial') : 'none';
  if (kind === 'none') return null;
  const reused = scan.reuse?.filesReused ?? cache?.filesReused ?? 0;
  const saved = scan.reuse?.estimatedSavedUsd ?? cache?.savedUsd ?? 0;
  const changed = scan.reuse?.filesChanged ?? cache?.filesAnalyzed ?? 0;
  const deleted = scan.reuse?.filesDeleted ?? 0;
  return (
    <section aria-label="Cache" className="relative overflow-hidden rounded-xl border border-signal/40 bg-card">
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-signal-soft" />
      <div className="relative">
        <PanelHead
          title={kind === 'full' ? 'Served from cache' : 'Incremental rescan'}
          right={<DatabaseZap aria-hidden className="size-4 text-foreground/70" />}
        />
        <div className="space-y-2 px-4 py-3.5">
          <p className="text-[15px] font-medium">
            <span className="font-mono tabular">{formatInt(reused)}</span> files reused ·{' '}
            <span className="font-mono tabular">{formatUsd(saved)}</span> saved
          </p>
          <p className="text-xs text-muted-foreground">
            {kind === 'full'
              ? 'Same commit and settings as an earlier scan — every result was copied, no AI spend.'
              : `${formatInt(changed)} changed file${changed === 1 ? '' : 's'} analyzed again${deleted > 0 ? `, ${formatInt(deleted)} deleted` : ''}; the rest came from the previous scan.`}
          </p>
          {scan.reuse?.baseScanId && (
            <Link to={`/scans/${scan.reuse.baseScanId}/overview`} className="inline-block font-mono text-[11px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline">
              base scan {scan.reuse.baseScanId.slice(0, 8)} →
            </Link>
          )}
        </div>
      </div>
    </section>
  );
}

export function WarningsList({ warnings }: { warnings: WarningItem[] }) {
  if (warnings.length === 0) return null;
  const n = warnings.filter((w) => w.level === 'warning').length;
  return (
    <section aria-label="Warnings" className="rounded-xl border bg-card">
      <PanelHead
        title="Notes & warnings"
        right={<span className="font-mono text-[11px] text-muted-foreground">{n > 0 ? `${n} warning${n === 1 ? '' : 's'}` : 'info only'}</span>}
      />
      <ul className="divide-y">
        {warnings.map((w) => {
          const warn = w.level === 'warning';
          const Icon = warn ? TriangleAlert : Info;
          return (
            <li key={`${w.code}:${w.message}`} className="flex gap-3 px-4 py-2.5 [animation:vs-live-enter_.9s_ease-out_both]">
              <Icon aria-hidden className={cn('mt-0.5 size-4 shrink-0', warn ? 'text-sev-medium' : 'text-muted-foreground')} />
              <div className="min-w-0 space-y-0.5">
                <p className="text-sm font-medium">
                  {warningTitle(w.code)}
                  {w.stage && <span className="ml-2 font-mono text-[10.5px] font-normal text-muted-foreground uppercase">{w.stage.toLowerCase()}</span>}
                </p>
                <p className="text-xs break-words text-muted-foreground">{w.message}</p>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
