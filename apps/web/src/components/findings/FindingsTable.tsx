import type { Finding } from '@vibesec/shared';
import { activeTriage } from '@vibesec/shared';
import { Link } from 'react-router';
import { CategoryIcon } from '@/components/security/CategoryIcon';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { FindingStatusPill, TriagePill } from '@/components/security/StatusPill';
import { Skeleton } from '@/components/ui/skeleton';
import { CATEGORY_META, SEVERITY_CLASSES } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { AnalyzerChips, ConfidencePips, FileRef, RiskBar } from './FindingBits';

type Props = {
  findings: Finding[];
  activeIndex: number;
  /** The finding currently open in the drawer (if any). */
  openId: string | undefined;
  search: string;
  onActivate: (index: number) => void;
};

const TH = 'eyebrow h-8 px-2 text-left align-middle font-medium whitespace-nowrap';

/**
 * Dense findings table. Rows are links to the drawer route (so middle-click / copy-link work);
 * keyboard navigation (j/k, arrows, Enter) is owned by FindingsPage and reflected via `activeIndex`.
 */
export function FindingsTable({ findings, activeIndex, openId, search, onActivate }: Props) {
  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <table className="w-full table-fixed border-collapse text-sm">
        <thead className="border-b bg-surface-raised/60">
          <tr>
            <th className={cn(TH, 'w-[108px] pl-3')}>Severity</th>
            <th className={TH}>Finding</th>
            <th className={cn(TH, 'hidden w-[28%] lg:table-cell')}>Location</th>
            <th className={cn(TH, 'hidden w-[88px] xl:table-cell')}>Type</th>
            <th className={cn(TH, 'hidden w-[56px] md:table-cell')} title="Confidence">Conf.</th>
            <th className={cn(TH, 'hidden w-[100px] sm:table-cell')}>Risk</th>
            <th className={cn(TH, 'hidden w-[120px] md:table-cell')}>Status</th>
            <th className={cn(TH, 'hidden w-[150px] pr-3 2xl:table-cell')}>Analyzers</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <FindingRow
              key={f.id}
              finding={f}
              index={i}
              active={i === activeIndex}
              open={f.id === openId}
              search={search}
              onActivate={onActivate}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingRow({
  finding: f,
  index,
  active,
  open,
  search,
  onActivate,
}: {
  finding: Finding;
  index: number;
  active: boolean;
  open: boolean;
  search: string;
  onActivate: (index: number) => void;
}) {
  const triage = activeTriage(f);
  const to = { pathname: f.id, search };
  return (
    <tr
      data-index={index}
      aria-selected={active}
      onMouseMove={() => !active && onActivate(index)}
      className={cn(
        'group relative border-b last:border-b-0 transition-colors',
        active ? 'bg-accent/70' : 'hover:bg-accent/40',
        open && 'bg-signal-soft',
        triage && 'opacity-70',
      )}
    >
      <td className="relative py-2 pr-2 pl-3 align-top">
        <span
          aria-hidden
          className={cn('absolute inset-y-0 left-0 w-[3px] transition-opacity', SEVERITY_CLASSES[f.severity].bg, active || open ? 'opacity-100' : 'opacity-0')}
        />
        <SeverityBadge severity={f.severity} />
      </td>
      <td className="min-w-0 px-2 py-2 align-top">
        <Link
          to={to}
          data-finding-link
          className="block min-w-0 font-medium leading-snug text-foreground outline-none after:absolute after:inset-0 after:content-[''] focus-visible:underline"
        >
          <span className="line-clamp-2">{f.title}</span>
        </Link>
        <div className="mt-0.5 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
          <span className="truncate font-mono text-[11px]">{f.ruleId}</span>
          {f.cwe && <span className="shrink-0 font-mono text-[11px]">{f.cwe}</span>}
        </div>
        {/* Narrow screens: location + status move under the title. */}
        <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 lg:hidden">
          <FileRef file={f.location.file} line={f.location.startLine} className="max-w-full" />
          <span className="flex items-center gap-1 md:hidden">
            <FindingStatusPill status={f.scanStatus} />
            {triage && <TriagePill triage={triage} />}
          </span>
        </div>
      </td>
      <td className="hidden px-2 py-2 align-top lg:table-cell">
        <FileRef file={f.location.file} line={f.location.startLine} className="mt-0.5 max-w-full" />
      </td>
      <td className="hidden px-2 py-2 align-top xl:table-cell">
        <span className="mt-0.5 inline-flex items-center gap-1.5 text-xs text-muted-foreground" title={CATEGORY_META[f.category].description}>
          <CategoryIcon category={f.category} className="size-3.5" />
          {CATEGORY_META[f.category].short}
        </span>
      </td>
      <td className="hidden px-2 py-2 align-top md:table-cell">
        <ConfidencePips confidence={f.confidence} className="mt-1" />
      </td>
      <td className="hidden px-2 py-2 align-top sm:table-cell">
        <RiskBar score={f.riskScore} className="mt-0.5" />
      </td>
      <td className="hidden px-2 py-2 align-top md:table-cell">
        <div className="relative z-10 flex flex-wrap gap-1">
          <FindingStatusPill status={f.scanStatus} />
          {triage && <TriagePill triage={triage} />}
        </div>
      </td>
      <td className="hidden py-2 pr-3 pl-2 align-top 2xl:table-cell">
        <AnalyzerChips analyzers={f.producedBy} className="mt-0.5" />
      </td>
    </tr>
  );
}

export function FindingsTableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="overflow-hidden rounded-lg border bg-card" aria-busy="true" aria-label="Loading findings">
      <div className="h-8 border-b bg-surface-raised/60" />
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-start gap-3 border-b px-3 py-2.5 last:border-b-0">
          <Skeleton className="h-5.5 w-20" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-4" style={{ width: `${55 + ((i * 37) % 35)}%` }} />
            <Skeleton className="h-3 w-40" />
          </div>
          <Skeleton className="hidden h-4 w-48 lg:block" />
          <Skeleton className="hidden h-2 w-16 sm:block" />
          <Skeleton className="hidden h-5 w-16 rounded-full md:block" />
        </div>
      ))}
    </div>
  );
}
