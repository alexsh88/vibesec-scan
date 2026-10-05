import type { Finding } from '@vibesec/shared';
import { ArrowUpRight, CircleCheck, CircleDot, Clock, type LucideIcon } from 'lucide-react';
import { Link } from 'react-router';
import { Skeleton } from '@/components/ui/skeleton';
import { formatInt } from '@/lib/format';
import { cn } from '@/lib/utils';
import { findingsHref } from './links';

type Status = Finding['scanStatus'];

const TILES: Array<{ status: Status; label: string; hint: string; icon: LucideIcon; tone: string }> = [
  { status: 'new', label: 'New', hint: 'not in the previous scan', icon: CircleDot, tone: 'text-status-new' },
  { status: 'existing', label: 'Existing', hint: 'still present', icon: Clock, tone: 'text-status-existing' },
  { status: 'fixed', label: 'Fixed', hint: 'gone since last scan', icon: CircleCheck, tone: 'text-status-fixed' },
];

/** new / existing / fixed relative to the previous scan of the repo; each tile filters the findings list. */
export function DeltaStrip({
  scanId,
  counts,
  isFirstScan,
}: {
  scanId: string;
  counts: Record<Status, number> | undefined;
  isFirstScan: boolean;
}) {
  return (
    <section aria-label="Change since the previous scan" className="grid grid-cols-3 divide-x overflow-hidden rounded-lg border bg-card">
      {TILES.map((t) => (
        <Link
          key={t.status}
          to={findingsHref(scanId, { scanStatus: t.status })}
          className="group relative flex flex-col gap-1 px-3 py-3 transition-colors hover:bg-accent/60 focus-visible:bg-accent focus-visible:outline-none sm:px-4"
        >
          <span className="flex items-center gap-1.5">
            <t.icon aria-hidden className={cn('size-3.5', t.tone)} />
            <span className="eyebrow">{t.label}</span>
            <ArrowUpRight aria-hidden className="ml-auto size-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
          </span>
          {counts ? (
            <span className={cn('font-mono text-2xl font-semibold tabular', counts[t.status] > 0 ? t.tone : 'text-muted-foreground/60')}>
              {t.status === 'new' && counts.new > 0 ? '+' : t.status === 'fixed' && counts.fixed > 0 ? '−' : ''}
              {formatInt(counts[t.status])}
            </span>
          ) : (
            <Skeleton className="h-8 w-12" />
          )}
          <span className="hidden text-[11px] text-muted-foreground sm:block">
            {isFirstScan && t.status !== 'existing' ? (t.status === 'new' ? 'first scan of this repo' : 'no baseline yet') : t.hint}
          </span>
        </Link>
      ))}
    </section>
  );
}
