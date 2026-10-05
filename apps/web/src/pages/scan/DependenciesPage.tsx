import { Boxes, Crosshair, PackageCheck, ShieldAlert, Wrench } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { EmptyState } from '@/components/feedback/EmptyState';
import { ErrorState } from '@/components/feedback/ErrorState';
import { Page, PageHeader } from '@/components/layout/Page';
import { DepFilterBar } from '@/components/dependencies/DepFilterBar';
import {
  actionAnchor,
  actionByFinding,
  applyFilters,
  DEFAULT_FILTERS,
  hasDependency,
  isSupplyChain,
  type DepFilters,
} from '@/components/dependencies/depModel';
import { FixPlanPanel } from '@/components/dependencies/FixPlanPanel';
import { LibraryList } from '@/components/dependencies/LibraryList';
import { SupplyChainList } from '@/components/dependencies/SupplyChainList';
import { Skeleton } from '@/components/ui/skeleton';
import { useFindings, useFixPlan } from '@/hooks/queries';
import { useScanContext } from '@/hooks/useScanContext';
import { formatInt } from '@/lib/format';
import { isTerminalState } from '@/lib/scanState';
import { cn } from '@/lib/utils';

const toggle = (s: ReadonlySet<string>, id: string): Set<string> => {
  const n = new Set(s);
  if (n.has(id)) n.delete(id);
  else n.add(id);
  return n;
};

/**
 * Spec screen 6. Dependency findings are one-per-library (package@version, all its advisories); the fix
 * plan ranks upgrades by risk removed per effort and lists everything each one resolves.
 */
export default function DependenciesPage() {
  const { scanId, scan } = useScanContext();
  const findings = useFindings(scanId, { category: 'dependency', limit: 200 });
  const plan = useFixPlan(scanId);

  // Dependency findings are bounded (one per vulnerable package) — load every page.
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = findings;
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage) void fetchNextPage();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const all = useMemo(() => findings.data?.pages.flatMap((p) => p.items) ?? [], [findings.data]);
  const libraries = useMemo(() => all.filter((f) => !isSupplyChain(f)).filter(hasDependency), [all]);
  const supplyChain = useMemo(() => all.filter(isSupplyChain), [all]);

  const actions = useMemo(() => plan.data?.actions ?? [], [plan.data]);
  const fixFor = useMemo(() => actionByFinding(actions), [actions]);
  const actionRank = useMemo(() => new Map(actions.map((a, i) => [a.id, i + 1])), [actions]);

  const [filters, setFilters] = useState<DepFilters>(DEFAULT_FILTERS);
  const shown = useMemo(() => applyFilters(libraries, filters), [libraries, filters]);

  const [openActions, setOpenActions] = useState<Set<string>>(() => new Set());
  const [openLibs, setOpenLibs] = useState<Set<string>>(() => new Set());
  const [showAllActions, setShowAllActions] = useState(false);
  const [flashId, setFlashId] = useState<string | null>(null);

  // Open the top action by default once the plan arrives.
  const firstId = actions[0]?.id;
  useEffect(() => {
    if (firstId) setOpenActions((s) => (s.size === 0 ? new Set([firstId]) : s));
  }, [firstId]);

  const jumpToAction = useCallback(
    (id: string) => {
      const rank = actionRank.get(id) ?? 0;
      if (rank > 5) setShowAllActions(true);
      setOpenActions((s) => new Set(s).add(id));
      setFlashId(id);
      requestAnimationFrame(() =>
        document.getElementById(actionAnchor({ id }))?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
      window.setTimeout(() => setFlashId((cur) => (cur === id ? null : cur)), 1_800);
    },
    [actionRank],
  );

  const stats = useMemo(() => {
    const advisories = new Set(libraries.flatMap((f) => f.dependency.advisories.map((a) => a.id))).size;
    const hot = libraries.filter((f) => f.dependency.reachability === 'reachable' || f.dependency.reachability === 'imported').length;
    const fixable = libraries.filter((f) => fixFor.has(f.id)).length;
    return { advisories, hot, fixable };
  }, [libraries, fixFor]);

  const running = !isTerminalState(scan.state);
  const loading = findings.isPending || plan.isPending;

  return (
    <Page wide>
      <PageHeader
        eyebrow="Dependencies"
        title="Vulnerable libraries & fix plan"
        description="Each row is one installed package version with every advisory against it. The plan above ranks the upgrades that remove the most risk for the least change — and shows everything each one fixes."
      />

      {running && (
        <p className="mb-4 rounded-md border border-state-running/30 bg-state-running/5 px-3 py-2 text-xs text-muted-foreground">
          Scan in progress — results update when the dependency analyzer finishes.
        </p>
      )}

      {findings.isError ? (
        <ErrorState error={findings.error} onRetry={() => void findings.refetch()} title="Couldn’t load dependency findings" />
      ) : loading ? (
        <DepsSkeleton />
      ) : libraries.length === 0 && supplyChain.length === 0 ? (
        <EmptyState
          icon={PackageCheck}
          title={running ? 'No vulnerable dependencies yet' : 'No vulnerable dependencies'}
          description={
            running
              ? 'The dependency analyzer hasn’t reported anything so far.'
              : 'No known advisories (OSV) matched the packages in this repository’s lockfiles, and no supply-chain signals were found.'
          }
        />
      ) : (
        <div className="space-y-8">
          <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border md:grid-cols-4">
            <Stat icon={Boxes} label="Vulnerable libraries" value={libraries.length} />
            <Stat icon={ShieldAlert} label="Distinct advisories" value={stats.advisories} />
            <Stat icon={Crosshair} label="Imported by your code" value={stats.hot} tone={stats.hot > 0 ? 'hot' : undefined} />
            <Stat icon={Wrench} label="Fixable via plan" value={stats.fixable} suffix={`/ ${libraries.length}`} tone="signal" />
          </dl>

          {plan.isError ? (
            <ErrorState compact error={plan.error} onRetry={() => void plan.refetch()} title="Couldn’t load the fix plan" />
          ) : plan.data ? (
            <FixPlanPanel
              scanId={scanId}
              plan={plan.data}
              expanded={openActions}
              onToggle={(id) => setOpenActions((s) => toggle(s, id))}
              flashId={flashId}
              showAll={showAllActions}
              onShowAll={() => setShowAllActions(true)}
            />
          ) : null}

          {libraries.length > 0 && (
            <section aria-labelledby="libs-heading" className="space-y-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 id="libs-heading" className="eyebrow">
                  Libraries with known CVEs
                </h2>
                <span className="font-mono text-[11px] text-muted-foreground tabular">
                  {shown.length === libraries.length ? `${libraries.length} libraries` : `${shown.length} of ${libraries.length} libraries`}
                </span>
              </div>
              <DepFilterBar value={filters} onChange={setFilters} />
              <div className="hidden grid-cols-[auto_minmax(0,1.6fr)_minmax(0,1fr)_4.5rem_minmax(0,1fr)_auto] gap-x-3 px-4 sm:grid">
                <span className="w-6" />
                <span className="eyebrow text-[10px]">Package</span>
                <span className="eyebrow text-[10px]">Risk · advisories</span>
                <span className="eyebrow text-right text-[10px]">Max CVSS</span>
                <span className="eyebrow text-[10px]">Reachability · fix</span>
                <span className="w-7" />
              </div>
              {shown.length === 0 ? (
                <EmptyState title="No libraries match these filters" action={<button type="button" className="text-xs underline" onClick={() => setFilters(DEFAULT_FILTERS)}>Reset filters</button>} />
              ) : (
                <LibraryList
                  scanId={scanId}
                  items={shown}
                  fixFor={fixFor}
                  actionRank={actionRank}
                  expanded={openLibs}
                  onToggle={(id) => setOpenLibs((s) => toggle(s, id))}
                  onJumpToAction={jumpToAction}
                />
              )}
              {hasNextPage && <p className="font-mono text-[11px] text-muted-foreground">Loading more…</p>}
            </section>
          )}

          {supplyChain.length > 0 && (
            <section aria-labelledby="sc-heading" className="space-y-3">
              <div className="space-y-1">
                <h2 id="sc-heading" className="eyebrow">
                  Supply-chain signals · {formatInt(supplyChain.length)}
                </h2>
                <p className="text-xs text-muted-foreground">
                  Not CVEs — risks in how packages are published or installed: known-malicious packages, likely typosquats, install
                  scripts and sources outside the public registry.
                </p>
              </div>
              <SupplyChainList scanId={scanId} items={supplyChain} />
            </section>
          )}
        </div>
      )}
    </Page>
  );
}

function Stat({
  icon: Icon, label, value, suffix, tone,
}: { icon: typeof Boxes; label: string; value: number; suffix?: ReactNode; tone?: 'hot' | 'signal' }) {
  return (
    <div className="space-y-1 bg-card px-4 py-3">
      <dt className="eyebrow flex items-center gap-1.5 text-[10px]">
        <Icon aria-hidden className="size-3" /> {label}
      </dt>
      <dd className={cn('font-mono text-2xl font-semibold tabular', tone === 'hot' && 'text-sev-high', tone === 'signal' && 'text-signal')}>
        {formatInt(value)}
        {suffix && <span className="ml-1 text-sm font-normal text-muted-foreground">{suffix}</span>}
      </dd>
    </div>
  );
}

function DepsSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true" aria-label="Loading dependencies">
      <Skeleton className="h-20 w-full" />
      <div className="space-y-2">
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-24 w-full" />
        ))}
      </div>
      <div className="space-y-2">
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-14 w-full" />
        ))}
      </div>
    </div>
  );
}
