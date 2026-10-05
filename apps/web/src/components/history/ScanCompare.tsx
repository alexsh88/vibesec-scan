import type { Finding, RiskGrade, ScanDto, Severity } from '@vibesec/shared';
import { ArrowRight, CircleCheck, CircleDot, Equal, TriangleAlert, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { EmptyState } from '@/components/feedback/EmptyState';
import { ErrorState } from '@/components/feedback/ErrorState';
import { CategoryLabel } from '@/components/security/CategoryIcon';
import { GradeBadge } from '@/components/security/GradeBadge';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { formatDateTime, formatInt, formatUsd, shortSha } from '@/lib/format';
import { SEVERITY_CLASSES, SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { diffFindings } from './diff';
import { COMPARE_CAP, useAllFindings } from './useAllFindings';

const PAGE = 100;
const SEV_SHORT: Record<Severity, string> = { critical: 'Crit', high: 'High', medium: 'Med', low: 'Low', info: 'Info' };

function severityCounts(items: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of items) out[f.severity] += 1;
  return out;
}

function ScanSide({
  tag,
  scan,
  grade,
  items,
  pending,
}: {
  tag: 'A' | 'B';
  scan: ScanDto;
  grade: RiskGrade | undefined;
  items: Finding[] | undefined;
  pending: boolean;
}) {
  const sev = items ? severityCounts(items) : undefined;
  return (
    <div className="min-w-0 flex-1 space-y-3 p-4">
      <div className="flex items-center gap-3">
        <span className="grid size-6 place-items-center rounded-full border font-mono text-[11px] font-semibold">{tag}</span>
        <div className="min-w-0 flex-1">
          <Link to={`/scans/${encodeURIComponent(scan.id)}/overview`} className="block truncate text-sm font-medium hover:underline">
            {formatDateTime(scan.createdAt)}
          </Link>
          <p className="truncate font-mono text-[11px] text-muted-foreground">
            {scan.ref ?? 'default'} · {shortSha(scan.commitSha)} · {formatUsd(scan.costUsd)}
          </p>
        </div>
        {grade ? <GradeBadge grade={grade} /> : <span className="grid size-9 place-items-center rounded-md border border-dashed text-xs text-muted-foreground">—</span>}
      </div>
      <dl className="grid grid-cols-6 gap-1 text-center">
        <div className="rounded-md bg-muted/50 py-1.5">
          <dt className="eyebrow text-[9px]">Total</dt>
          <dd className="font-mono text-sm font-semibold tabular">{pending ? '…' : formatInt(items?.length ?? 0)}</dd>
        </div>
        {SEVERITY_ORDER.map((s) => (
          <div key={s} className="rounded-md bg-muted/50 py-1.5">
            <dt className={cn('eyebrow text-[9px]', SEVERITY_CLASSES[s].text)}><abbr title={SEVERITY_LABEL[s]} className="no-underline">{SEV_SHORT[s]}</abbr></dt>
            <dd className={cn('font-mono text-sm tabular', sev && sev[s] === 0 && 'text-muted-foreground/60')}>{sev ? sev[s] : '…'}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function DiffList({ items, scanId, emptyText }: { items: Finding[]; scanId: string; emptyText: string }) {
  const [shown, setShown] = useState(PAGE);
  if (items.length === 0) return <p className="px-4 py-8 text-center text-sm text-muted-foreground">{emptyText}</p>;
  return (
    <>
      <ul className="max-h-[36rem] divide-y overflow-y-auto">
        {items.slice(0, shown).map((f) => (
          <li key={f.id}>
            <Link
              to={`/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(f.id)}`}
              className="grid grid-cols-[auto_1fr] items-start gap-x-3 gap-y-1 px-4 py-2.5 transition-colors hover:bg-accent/50 focus-visible:bg-accent focus-visible:outline-none sm:grid-cols-[6.5rem_1fr_auto]"
            >
              <SeverityBadge severity={f.severity} className="justify-self-start" />
              <span className="min-w-0">
                <span className="block truncate text-sm">{f.title}</span>
                <span className="block truncate font-mono text-[11px] text-muted-foreground" title={f.location.file}>
                  {f.location.file}:{f.location.startLine}
                </span>
              </span>
              <CategoryLabel category={f.category} short className="col-start-2 sm:col-start-auto" />
            </Link>
          </li>
        ))}
      </ul>
      {items.length > shown && (
        <div className="border-t p-3 text-center">
          <Button size="sm" variant="ghost" onClick={() => setShown((n) => n + PAGE)}>
            Show {Math.min(PAGE, items.length - shown)} more of {formatInt(items.length - shown)}
          </Button>
        </div>
      )}
    </>
  );
}

/**
 * Side-by-side grade/counts of two scans plus a fingerprint diff of their findings:
 * new in B, fixed in B (present in A, gone in B) and unchanged.
 */
export function ScanCompare({
  a,
  b,
  gradeA,
  gradeB,
  onClose,
}: {
  a: ScanDto;
  b: ScanDto;
  gradeA: RiskGrade | undefined;
  gradeB: RiskGrade | undefined;
  onClose: () => void;
}) {
  const fa = useAllFindings(a.id);
  const fb = useAllFindings(b.id);
  const diff = useMemo(() => (fa.data && fb.data ? diffFindings(fa.data.items, fb.data.items) : null), [fa.data, fb.data]);
  const truncated = !!(fa.data?.truncated || fb.data?.truncated);
  const sameCommit = !!a.commitSha && a.commitSha === b.commitSha;

  return (
    <section aria-labelledby="compare-heading" className="animate-rise overflow-hidden rounded-xl border bg-card">
      <header className="flex items-center gap-3 border-b px-4 py-2.5">
        <h2 id="compare-heading" className="eyebrow">
          Compare · A → B
        </h2>
        {sameCommit && <span className="font-mono text-[11px] text-muted-foreground">same commit</span>}
        <Button size="icon-xs" variant="ghost" className="ml-auto" onClick={onClose} aria-label="Close comparison">
          <X />
        </Button>
      </header>

      <div className="relative flex flex-col divide-y sm:flex-row sm:divide-x sm:divide-y-0">
        <ScanSide tag="A" scan={a} grade={gradeA} items={fa.data?.items} pending={fa.isPending} />
        <span aria-hidden className="absolute top-1/2 left-1/2 hidden size-7 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full border bg-card sm:grid">
          <ArrowRight className="size-3.5 text-muted-foreground" />
        </span>
        <ScanSide tag="B" scan={b} grade={gradeB} items={fb.data?.items} pending={fb.isPending} />
      </div>

      {truncated && (
        <div role="status" className="flex items-center gap-2 border-t bg-sev-medium/8 px-4 py-2 text-xs">
          <TriangleAlert aria-hidden className="size-3.5 text-sev-medium" />
          Only the first {formatInt(COMPARE_CAP)} findings of each scan are compared.
        </div>
      )}

      <div className="border-t">
        {fa.isError || fb.isError ? (
          <ErrorState
            className="m-4"
            error={fa.error ?? fb.error}
            title="Couldn’t load findings to compare"
            onRetry={() => {
              void fa.refetch();
              void fb.refetch();
            }}
          />
        ) : !diff ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="Loading findings">
            <Skeleton className="h-8 w-80" />
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : diff.added.length + diff.fixed.length + diff.unchanged.length === 0 ? (
          <EmptyState icon={CircleCheck} title="Neither scan has findings" className="m-4" />
        ) : (
          <Tabs defaultValue={diff.added.length > 0 ? 'added' : diff.fixed.length > 0 ? 'fixed' : 'unchanged'} className="gap-0">
            <div className="overflow-x-auto px-4 pt-3 pb-3">
              <TabsList>
                <TabsTrigger value="added">
                  <CircleDot className="text-status-new" /> New in B <span className="font-mono tabular">{diff.added.length}</span>
                </TabsTrigger>
                <TabsTrigger value="fixed">
                  <CircleCheck className="text-status-fixed" /> Fixed in B <span className="font-mono tabular">{diff.fixed.length}</span>
                </TabsTrigger>
                <TabsTrigger value="unchanged">
                  <Equal /> Unchanged <span className="font-mono tabular">{diff.unchanged.length}</span>
                </TabsTrigger>
              </TabsList>
            </div>
            <TabsContent value="added" className="border-t">
              <DiffList items={diff.added} scanId={b.id} emptyText="Nothing new in B." />
            </TabsContent>
            <TabsContent value="fixed" className="border-t">
              <DiffList items={diff.fixed} scanId={a.id} emptyText="Nothing from A was fixed in B." />
            </TabsContent>
            <TabsContent value="unchanged" className="border-t">
              <DiffList items={diff.unchanged} scanId={b.id} emptyText="No findings in common." />
            </TabsContent>
          </Tabs>
        )}
      </div>
    </section>
  );
}
