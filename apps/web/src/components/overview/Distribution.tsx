import { CATEGORIES, type Category, type SummaryStats } from '@vibesec/shared';
import { Link } from 'react-router';
import { CategoryIcon } from '@/components/security/CategoryIcon';
import { formatInt } from '@/lib/format';
import { CATEGORY_META, SEVERITY_CLASSES, SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { findingsHref } from './links';
import { Panel } from '@/components/common/Panel';

/**
 * Severity distribution: a proportional stacked bar (overview at a glance) plus one row per severity
 * with its own bar scaled to the largest bucket. Every row is a link to the filtered findings list,
 * and each carries its number as text, so nothing depends on colour or on the chart being seen.
 */
export function SeverityDistribution({ stats, scanId }: { stats: SummaryStats; scanId: string }) {
  const total = stats.total;
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => stats.bySeverity[s] ?? 0));
  return (
    <Panel id="sev-dist" title="Severity" meta={`${formatInt(total)} total`}>
      <div
        role="img"
        aria-label={`Severity split: ${SEVERITY_ORDER.map((s) => `${stats.bySeverity[s] ?? 0} ${SEVERITY_LABEL[s].toLowerCase()}`).join(', ')}`}
        className="mb-4 flex h-2.5 overflow-hidden rounded-full bg-muted"
      >
        {total > 0 &&
          SEVERITY_ORDER.map((s) => {
            const n = stats.bySeverity[s] ?? 0;
            if (n === 0) return null;
            return <span key={s} className={cn('h-full border-r border-card last:border-r-0', SEVERITY_CLASSES[s].bg)} style={{ width: `${(n / total) * 100}%` }} />;
          })}
      </div>
      <ul className="space-y-0.5">
        {SEVERITY_ORDER.map((s) => {
          const n = stats.bySeverity[s] ?? 0;
          return (
            <li key={s}>
              <Link
                to={findingsHref(scanId, { severity: s })}
                aria-label={`${n} ${SEVERITY_LABEL[s]} findings — view`}
                className="group grid grid-cols-[5.5rem_1fr_2.5rem] items-center gap-3 rounded-md px-1.5 py-1 transition-colors hover:bg-accent/60 focus-visible:bg-accent focus-visible:outline-none"
              >
                <span className="inline-flex items-center gap-2 text-xs">
                  <span aria-hidden className={cn('size-2 rounded-[2px]', SEVERITY_CLASSES[s].bg, n === 0 && 'opacity-30')} />
                  {SEVERITY_LABEL[s]}
                </span>
                <span aria-hidden className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <span
                    className={cn('block h-full rounded-full transition-[width] duration-700', SEVERITY_CLASSES[s].bg)}
                    style={{ width: `${(n / max) * 100}%` }}
                  />
                </span>
                <span className={cn('text-right font-mono text-xs tabular', n === 0 ? 'text-muted-foreground/60' : 'text-foreground')}>
                  {formatInt(n)}
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

/** Findings per category (Credentials, Code, Data flow, …), largest first; each row filters the list. */
export function CategoryBreakdown({ stats, scanId }: { stats: SummaryStats; scanId: string }) {
  const rows = (CATEGORIES as readonly Category[])
    .map((c) => ({ c, n: stats.byCategory[c] ?? 0 }))
    .sort((a, b) => b.n - a.n);
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <Panel id="cat-dist" title="Category">
      <ul className="space-y-0.5">
        {rows.map(({ c, n }) => (
          <li key={c}>
            <Link
              to={findingsHref(scanId, { category: c })}
              aria-label={`${n} ${CATEGORY_META[c].label} findings — view`}
              title={CATEGORY_META[c].description}
              className="group grid grid-cols-[7rem_1fr_2.5rem] items-center gap-3 rounded-md px-1.5 py-1 transition-colors hover:bg-accent/60 focus-visible:bg-accent focus-visible:outline-none"
            >
              <span className="inline-flex min-w-0 items-center gap-2 text-xs">
                <CategoryIcon category={c} className="size-3.5" />
                <span className="truncate">{CATEGORY_META[c].label}</span>
              </span>
              <span aria-hidden className="h-1.5 overflow-hidden rounded-full bg-muted">
                <span className="block h-full rounded-full bg-foreground/55 transition-[width] duration-700 group-hover:bg-signal" style={{ width: `${(n / max) * 100}%` }} />
              </span>
              <span className={cn('text-right font-mono text-xs tabular', n === 0 ? 'text-muted-foreground/60' : 'text-foreground')}>
                {formatInt(n)}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
