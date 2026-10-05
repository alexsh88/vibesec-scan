import type { FindingSummary, Severity } from '@vibesec/shared';
import { ArrowRight, ChevronRight, Radar } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { CategoryIcon } from '@/components/security/CategoryIcon';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { formatInt } from '@/lib/format';
import { CATEGORY_META, SEVERITY_CLASSES, SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';

const MAX_ROWS = 60;

/** Newest-first stream of `finding` events; rows that arrive after mount animate in. */
export function FindingsFeed({
  scanId,
  findings,
  running,
  emptyHint,
}: {
  scanId: string;
  findings: FindingSummary[];
  running: boolean;
  emptyHint: string;
}) {
  // Rows present on first render (a replayed log) don't animate; only live arrivals do.
  const [initial] = useState(() => new Set(findings.map((f) => f.id)));
  const shown = findings.slice(0, MAX_ROWS);

  return (
    <section aria-label="Live findings" className="flex min-h-0 flex-col rounded-xl border bg-card">
      <div className="flex items-center justify-between gap-3 border-b px-4 py-2.5">
        <p className="eyebrow flex items-center gap-2">
          {running && <span aria-hidden className="size-1.5 animate-pulse-dot rounded-full bg-signal" />}
          Findings stream
        </p>
        <Link
          to={`/scans/${scanId}/findings`}
          className="inline-flex items-center gap-1 font-mono text-[11px] text-muted-foreground hover:text-foreground focus-visible:text-foreground focus-visible:outline-none"
        >
          {formatInt(findings.length)} so far <ArrowRight aria-hidden className="size-3" />
        </Link>
      </div>
      {shown.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 px-6 py-12 text-center">
          <Radar aria-hidden className={cn('size-6 text-muted-foreground', running && 'animate-pulse')} strokeWidth={1.5} />
          <p className="max-w-xs text-sm text-muted-foreground">{emptyHint}</p>
        </div>
      ) : (
        <ol aria-live="polite" aria-relevant="additions" className="max-h-[34rem] divide-y overflow-y-auto">
          {shown.map((f) => (
            <li key={f.id} className={cn(!initial.has(f.id) && '[animation:vs-live-enter_.9s_cubic-bezier(.2,.7,.2,1)_both]')}>
              <Link
                to={`/scans/${scanId}/findings/${f.id}`}
                className="group grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 px-4 py-2.5 hover:bg-accent/60 focus-visible:bg-accent focus-visible:outline-none"
              >
                <SeverityBadge severity={f.severity} className="mt-px w-[5.6rem] justify-start" />
                <span className="min-w-0">
                  <span className="block truncate text-sm leading-5 group-hover:underline">{f.title}</span>
                  <span className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
                    <CategoryIcon category={f.category} className="size-3.5 shrink-0" />
                    <span className="shrink-0">{CATEGORY_META[f.category].short}</span>
                    <span aria-hidden>·</span>
                    <span className="truncate font-mono" title={`${f.location.file}:${f.location.startLine}`}>
                      {f.location.file}:{f.location.startLine}
                    </span>
                  </span>
                </span>
                <ChevronRight aria-hidden className="mt-0.5 size-4 text-muted-foreground/50 group-hover:text-foreground" />
              </Link>
            </li>
          ))}
          {findings.length > MAX_ROWS && (
            <li className="px-4 py-2.5 text-center">
              <Link to={`/scans/${scanId}/findings`} className="font-mono text-xs text-muted-foreground hover:text-foreground">
                + {formatInt(findings.length - MAX_ROWS)} more — open the findings list
              </Link>
            </li>
          )}
        </ol>
      )}
    </section>
  );
}

/** Big live counters per severity; the number nudges when it changes. */
export function SeverityReadout({ counts, caption }: { counts: Record<Severity, number>; caption: string }) {
  const total = SEVERITY_ORDER.reduce((n, s) => n + counts[s], 0);
  return (
    <section aria-label="Findings by severity" className="rounded-xl border bg-card">
      <div className="flex items-center justify-between gap-3 border-b px-4 py-2.5">
        <p className="eyebrow">Findings</p>
        <p className="font-mono text-[11px] text-muted-foreground">{caption}</p>
      </div>
      <dl className="grid grid-cols-3 gap-px overflow-hidden rounded-b-xl bg-border sm:grid-cols-6">
        <div className="bg-card px-4 py-3">
          <dt className="font-mono text-[10.5px] tracking-wide text-muted-foreground uppercase">Total</dt>
          <dd key={total} className="text-2xl font-semibold tabular [animation:vs-live-bump_.4s_ease-out]">
            {formatInt(total)}
          </dd>
        </div>
        {SEVERITY_ORDER.map((s) => (
          <div key={s} className="bg-card px-4 py-3">
            <dt className="flex items-center gap-1.5 font-mono text-[10.5px] tracking-wide text-muted-foreground uppercase">
              <span aria-hidden className={cn('size-1.5 rounded-full', counts[s] > 0 ? SEVERITY_CLASSES[s].dot : 'bg-muted-foreground/30')} />
              {SEVERITY_LABEL[s]}
            </dt>
            <dd
              key={counts[s]}
              className={cn(
                'text-2xl font-semibold tabular [animation:vs-live-bump_.4s_ease-out]',
                counts[s] > 0 ? SEVERITY_CLASSES[s].text : 'text-muted-foreground/50',
              )}
            >
              {formatInt(counts[s])}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
