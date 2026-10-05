import type { RiskGrade, ScanDto } from '@vibesec/shared';
import { ArrowUpRight, GitBranch } from 'lucide-react';
import { Link } from 'react-router';
import { GradeBadge } from '@/components/security/GradeBadge';
import { SeverityCount } from '@/components/security/SeverityBadge';
import { ScanStatePill } from '@/components/security/StatusPill';
import { Checkbox } from '@/components/ui/checkbox';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { FindingCounts } from '@/lib/api';
import { formatDateTime, formatRelative, formatUsd, shortSha } from '@/lib/format';
import { hasResults } from '@/lib/scanState';
import { SEVERITY_ORDER } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';

export type HistoryRow = {
  scan: ScanDto;
  grade: RiskGrade | undefined;
  gradePending: boolean;
  counts: FindingCounts | undefined;
  countsPending: boolean;
};

const dash = <span className="text-muted-foreground/60">—</span>;

/** One row per scan, newest first. Up to two rows can be ticked for the compare view. */
export function ScanHistoryTable({
  rows,
  selected,
  onToggle,
}: {
  rows: HistoryRow[];
  selected: string[];
  onToggle: (scanId: string, on: boolean) => void;
}) {
  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <Table className="min-w-[860px]">
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-12 pl-4">
              <span className="sr-only">Select to compare</span>
            </TableHead>
            <TableHead className="eyebrow">When</TableHead>
            <TableHead className="eyebrow">Ref · commit</TableHead>
            <TableHead className="eyebrow">State</TableHead>
            <TableHead className="eyebrow text-center">Grade</TableHead>
            <TableHead className="eyebrow">Findings</TableHead>
            <TableHead className="eyebrow">Δ vs previous</TableHead>
            <TableHead className="eyebrow text-right">AI cost</TableHead>
            <TableHead className="w-10" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map(({ scan, grade, gradePending, counts, countsPending }) => {
            const isSel = selected.includes(scan.id);
            const selIndex = selected.indexOf(scan.id);
            const comparable = hasResults(scan.state) || scan.state === 'CANCELLED';
            const label = `Compare scan from ${formatDateTime(scan.createdAt)}`;
            return (
              <TableRow key={scan.id} data-state={isSel ? 'selected' : undefined} className={cn(isSel && 'bg-signal-soft hover:bg-signal-soft')}>
                <TableCell className="pl-4">
                  <span className="inline-flex items-center gap-1">
                    <Checkbox
                      checked={isSel}
                      disabled={!comparable}
                      onCheckedChange={(v) => onToggle(scan.id, v === true)}
                      aria-label={label}
                    />
                    {isSel && (
                      <span aria-hidden className="font-mono text-[10px] font-semibold text-foreground">
                        {selIndex === 0 ? 'A' : 'B'}
                      </span>
                    )}
                  </span>
                </TableCell>
                <TableCell className="whitespace-nowrap">
                  <span className="text-sm" title={formatDateTime(scan.createdAt)}>
                    {formatRelative(scan.createdAt)}
                  </span>
                  <span className="block font-mono text-[11px] text-muted-foreground">{new Date(scan.createdAt).toLocaleDateString()}</span>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  <span className="inline-flex items-center gap-1 text-foreground">
                    <GitBranch aria-hidden className="size-3.5 text-muted-foreground" />
                    {scan.ref ?? 'default'}
                  </span>
                  <span className="block text-muted-foreground" title={scan.commitSha ?? undefined}>
                    {shortSha(scan.commitSha)}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col items-start gap-1">
                    <ScanStatePill state={scan.state} />
                    {scan.cacheHit !== 'none' && (
                      <span className="rounded border border-signal/40 bg-signal-soft px-1.5 font-mono text-[10px] tracking-wide uppercase">
                        {scan.cacheHit === 'full' ? 'cached' : 'incremental'}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-center">
                  {grade ? <GradeBadge grade={grade} size="sm" /> : gradePending ? <Skeleton className="mx-auto size-6" /> : dash}
                </TableCell>
                <TableCell>
                  {counts ? (
                    <span className="flex items-center gap-2.5">
                      <span className="w-8 font-mono text-sm font-medium tabular">{counts.total}</span>
                      {SEVERITY_ORDER.slice(0, 4).map((s) => (
                        <SeverityCount key={s} severity={s} count={counts.bySeverity[s] ?? 0} />
                      ))}
                    </span>
                  ) : countsPending ? (
                    <Skeleton className="h-4 w-36" />
                  ) : (
                    dash
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs tabular">
                  {counts ? (
                    <span className="flex gap-2">
                      <span className={counts.byScanStatus.new > 0 ? 'text-status-new' : 'text-muted-foreground/60'} title="new findings">
                        +{counts.byScanStatus.new}
                      </span>
                      <span className={counts.byScanStatus.fixed > 0 ? 'text-status-fixed' : 'text-muted-foreground/60'} title="fixed findings">
                        −{counts.byScanStatus.fixed}
                      </span>
                    </span>
                  ) : (
                    dash
                  )}
                </TableCell>
                <TableCell className="text-right font-mono text-xs tabular">{formatUsd(scan.costUsd)}</TableCell>
                <TableCell className="pr-3">
                  <Link
                    to={`/scans/${encodeURIComponent(scan.id)}`}
                    aria-label={`Open scan from ${formatDateTime(scan.createdAt)}`}
                    className="grid size-7 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                  >
                    <ArrowUpRight className="size-4" />
                  </Link>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
