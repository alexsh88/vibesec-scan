import { isTerminalState, type Category, type Finding } from '@vibesec/shared';
import { Eye, EyeOff, LoaderCircle, SearchX, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Outlet, useNavigate, useParams, useSearchParams } from 'react-router';
import { EmptyState } from '@/components/feedback/EmptyState';
import { ErrorState } from '@/components/feedback/ErrorState';
import { FindingsFilterBar } from '@/components/findings/FindingsFilterBar';
import { FindingsTable, FindingsTableSkeleton } from '@/components/findings/FindingsTable';
import {
  activeFilterCount,
  infoHidden,
  matchesClient,
  readListState,
  serverFilters,
  writeListState,
  type FindingsOutletContext,
  type ListState,
} from '@/components/findings/filters';
import { Page, PageHeader } from '@/components/layout/Page';
import { Button } from '@/components/ui/button';
import { useFindings } from '@/hooks/queries';
import { useScanContext } from '@/hooks/useScanContext';
import type { FindingCounts } from '@/lib/api';
import { formatInt } from '@/lib/format';
import { FINDING_TABS } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';

/**
 * Spec screen 4 — findings list. Tabs + filters live in the URL search params (components/findings/filters),
 * rows open the finding drawer, which renders into the <Outlet/> below (nested route :findingId) and
 * gets the list order through the outlet context for previous/next navigation.
 */
export default function FindingsPage() {
  const { scanId, scan } = useScanContext();
  const { findingId } = useParams();
  const navigate = useNavigate();
  const [sp, setSp] = useSearchParams();
  const state = useMemo(() => readListState(sp), [sp]);
  const filters = useMemo(() => serverFilters(state), [state]);
  const query = useFindings(scanId, filters);
  const searchRef = useRef<HTMLInputElement>(null);
  const sentinelRef = useRef<HTMLDivElement>(null);

  const all = useMemo(() => {
    const seen = new Set<string>();
    const out: Finding[] = [];
    for (const p of query.data?.pages ?? []) for (const f of p.items) if (!seen.has(f.id)) (seen.add(f.id), out.push(f));
    return out;
  }, [query.data]);
  const visible = useMemo(() => all.filter((f) => matchesClient(f, state)), [all, state]);
  const hiddenInfo = useMemo(
    () => (infoHidden(state) ? all.filter((f) => f.severity === 'info' && matchesClient(f, state, { ignoreInfoToggle: true })).length : 0),
    [all, state],
  );
  const counts = query.data?.pages[0]?.counts;
  const knownFiles = useMemo(() => [...new Set(all.map((f) => f.location.file))].sort(), [all]);
  const search = sp.toString() ? `?${sp.toString()}` : '';

  const update = useCallback(
    (patch: Partial<ListState>) => setSp((prev) => writeListState(prev, patch), { replace: !('tab' in patch) }),
    [setSp],
  );
  // A visit without ?tab/?category lands on Code. When Code is empty but another tab is not (a clean
  // library with only quality findings), open the first non-empty tab rather than "No code findings".
  // Decided once, on the first counts, so choosing Code afterwards still shows Code.
  const tabPicked = useRef(false);
  useEffect(() => {
    if (tabPicked.current || !counts) return;
    tabPicked.current = true;
    if (sp.has('tab') || sp.has('category') || tabCount(counts, FINDING_TABS[0]!.categories) !== 0) return;
    const first = FINDING_TABS.find((t) => (tabCount(counts, t.categories) ?? 0) > 0);
    if (first) setSp((prev) => writeListState(prev, { tab: first.id }), { replace: true });
  }, [counts, sp, setSp]);

  const reset = () =>
    setSp((prev) => writeListState(prev, { category: null, severities: [], status: 'current', triage: 'open', file: '', q: '' }), { replace: true });

  // ---- keyboard cursor -------------------------------------------------------------------------
  const [active, setActive] = useState(0);
  const filterKey = `${state.tab}|${state.category}|${state.severities}|${state.status}|${state.triage}|${state.file}|${state.q}|${state.showInfo}`;
  useEffect(() => setActive(0), [filterKey]);
  const activeIndex = Math.min(active, Math.max(visible.length - 1, 0));

  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query;
  const loadMore = useCallback(() => {
    if (hasNextPage && !isFetchingNextPage) void fetchNextPage();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const open = useCallback(
    (f: Finding | undefined) => f && navigate({ pathname: f.id, search }),
    [navigate, search],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (findingId || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      const typing = !!t && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName));
      if (e.key === '/' && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (typing || document.querySelector('[role="dialog"]')) return;
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        if (activeIndex >= visible.length - 1) loadMore();
        setActive(Math.min(activeIndex + 1, visible.length - 1));
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        setActive(Math.max(activeIndex - 1, 0));
      } else if (e.key === 'Enter' || e.key === 'o') {
        if (t?.closest('a,button') && t.closest('tr') === null) return; // let focused controls handle Enter
        e.preventDefault();
        open(visible[activeIndex]);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [findingId, activeIndex, visible, loadMore, open]);

  useEffect(() => {
    document.querySelector(`tr[data-index="${activeIndex}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  // ---- infinite scroll: keep loading while the sentinel is on screen ----------------------------
  const [sentinelVisible, setSentinelVisible] = useState(false);
  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const io = new IntersectionObserver(([entry]) => setSentinelVisible(!!entry?.isIntersecting), { rootMargin: '400px 0px' });
    io.observe(el);
    return () => io.disconnect();
  });
  useEffect(() => {
    if (sentinelVisible) loadMore();
  }, [sentinelVisible, loadMore, all.length]);

  const onViewed = useCallback(
    (id: string) => {
      const i = visible.findIndex((f) => f.id === id);
      if (i >= 0) setActive(i);
    },
    [visible],
  );
  const outletContext = useMemo<FindingsOutletContext>(
    () => ({ ids: visible.map((f) => f.id), hasMore: !!hasNextPage, loadMore, loadingMore: isFetchingNextPage, onViewed }),
    [visible, hasNextPage, loadMore, isFetchingNextPage, onViewed],
  );

  const running = !isTerminalState(scan.state);

  return (
    <Page wide>
      <PageHeader
        eyebrow="Findings"
        title="Findings"
        description={
          counts ? (
            <>
              <span className="font-mono tabular text-foreground">{formatInt(counts.total)}</span> current findings ·{' '}
              <span className="font-mono tabular text-foreground">{formatInt(counts.byScanStatus.new)}</span> new since the previous scan
              {running && ' · scan still running, results update as analyzers finish'}
            </>
          ) : (
            'Everything the scan found, ranked by contextual risk.'
          )
        }
        actions={<KeyboardHint />}
      />

      <FindingTabs active={state.tab} counts={counts} onSelect={(tab) => update({ tab })} />

      <div className="mt-3 mb-3">
        <FindingsFilterBar ref={searchRef} state={state} counts={counts} knownFiles={knownFiles} onChange={update} onReset={reset} />
      </div>

      {query.isPending ? (
        <FindingsTableSkeleton />
      ) : query.isError && !query.data ? (
        <ErrorState error={query.error} title="Couldn’t load findings" onRetry={() => void query.refetch()} />
      ) : visible.length === 0 && !hasNextPage ? (
        <EmptyResult
          totalForScan={counts?.total ?? 0}
          running={running}
          hiddenInfo={hiddenInfo}
          onShowInfo={() => update({ showInfo: true })}
          onReset={reset}
          filtered={activeFilterCount(state) > 0}
          tabLabel={FINDING_TABS.find((t) => t.id === state.tab)?.label ?? 'matching'}
        />
      ) : (
        <div className={cn('transition-opacity', query.isPlaceholderData && 'opacity-60')}>
          <FindingsTable findings={visible} activeIndex={activeIndex} openId={findingId} search={search} onActivate={setActive} />
          <InfoToggle hidden={hiddenInfo} showing={state.showInfo && !state.severities.includes('info')} more={!!hasNextPage} onToggle={(v) => update({ showInfo: v })} />
        </div>
      )}

      <div ref={sentinelRef} aria-hidden className="h-px" />
      {isFetchingNextPage && (
        <p className="mt-3 flex items-center justify-center gap-2 text-xs text-muted-foreground">
          <LoaderCircle className="size-3.5 animate-spin" /> Loading more findings…
        </p>
      )}
      {query.isFetchNextPageError && (
        <ErrorState compact className="mt-3" error={query.error} title="Couldn’t load more findings" onRetry={() => void fetchNextPage()} />
      )}
      {!hasNextPage && visible.length > 0 && (
        <p className="mt-3 text-center font-mono text-[11px] text-muted-foreground/70">
          {visible.length} shown · end of list
        </p>
      )}

      <Outlet context={outletContext} />
    </Page>
  );
}

// ---------------------------------------------------------------------------------------------

function tabCount(counts: FindingCounts | undefined, categories: readonly Category[]): number | undefined {
  if (!counts) return undefined;
  return categories.reduce((n, c) => n + (counts.byCategory[c] ?? 0), 0);
}

function FindingTabs({
  active,
  counts,
  onSelect,
}: {
  active: ListState['tab'];
  counts: FindingCounts | undefined;
  onSelect: (tab: ListState['tab']) => void;
}) {
  return (
    <div role="tablist" aria-label="Finding categories" className="-mx-4 flex gap-1 overflow-x-auto border-b px-4 sm:mx-0 sm:px-0">
      {FINDING_TABS.map((t) => {
        const on = t.id === active;
        const n = tabCount(counts, t.categories);
        return (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={on}
            onClick={() => onSelect(t.id)}
            className={cn(
              'relative -mb-px inline-flex h-10 shrink-0 items-center gap-2 border-b-2 px-3 text-sm whitespace-nowrap transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
              on ? 'border-signal font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t.label}
            <span
              className={cn(
                'min-w-6 rounded-full px-1.5 py-px text-center font-mono text-[11px] tabular',
                on ? 'bg-signal-soft text-foreground' : 'bg-muted text-muted-foreground',
              )}
            >
              {n ?? '–'}
            </span>
          </button>
        );
      })}
    </div>
  );
}

function InfoToggle({ hidden, showing, more, onToggle }: { hidden: number; showing: boolean; more: boolean; onToggle: (v: boolean) => void }) {
  if (showing) {
    return (
      <button
        type="button"
        onClick={() => onToggle(false)}
        className="mt-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
      >
        <EyeOff className="size-3.5" /> Hide low-signal (info) findings
      </button>
    );
  }
  if (hidden === 0) return null;
  return (
    <button
      type="button"
      onClick={() => onToggle(true)}
      className="mt-2 flex w-full items-center justify-center gap-2 rounded-md border border-dashed py-2 text-xs text-muted-foreground transition-colors hover:border-solid hover:bg-accent/50 hover:text-foreground"
    >
      <Eye className="size-3.5" />
      Show {hidden}
      {more ? '+' : ''} low-signal finding{hidden === 1 ? '' : 's'}
      <span className="text-muted-foreground/60">(info severity)</span>
    </button>
  );
}

function EmptyResult({
  totalForScan,
  running,
  hiddenInfo,
  filtered,
  tabLabel,
  onShowInfo,
  onReset,
}: {
  totalForScan: number;
  running: boolean;
  hiddenInfo: number;
  filtered: boolean;
  tabLabel: string;
  onShowInfo: () => void;
  onReset: () => void;
}) {
  if (hiddenInfo > 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Nothing above info severity here"
        description={`${hiddenInfo} low-signal finding${hiddenInfo === 1 ? ' is' : 's are'} hidden.`}
        action={
          <Button size="sm" variant="outline" onClick={onShowInfo}>
            <Eye /> Show {hiddenInfo} low-signal finding{hiddenInfo === 1 ? '' : 's'}
          </Button>
        }
      />
    );
  }
  if (totalForScan === 0 && !filtered) {
    return running ? (
      <EmptyState icon={LoaderCircle} title="No findings yet" description="Analyzers are still running; findings appear here as they are reported." />
    ) : (
      <EmptyState icon={ShieldCheck} title="No findings" description="This scan didn’t report anything. Nice." />
    );
  }
  if (!filtered) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title={`No ${tabLabel.toLowerCase()} findings`}
        description={running ? 'Analyzers are still running; findings appear here as they are reported.' : 'Clean on this front. Other tabs may still have findings.'}
      />
    );
  }
  return (
    <EmptyState
      icon={SearchX}
      title="No findings match"
      description="Nothing in this tab matches the current filters."
      action={
        <Button size="sm" variant="outline" onClick={onReset}>
          Reset filters
        </Button>
      }
    />
  );
}

function KeyboardHint() {
  const k = 'rounded border bg-muted px-1 font-mono text-[10px] text-foreground/80';
  return (
    <p className="hidden items-center gap-1.5 text-[11px] text-muted-foreground lg:flex" aria-hidden>
      <kbd className={k}>j</kbd>
      <kbd className={k}>k</kbd> move
      <kbd className={cn(k, 'ml-2')}>↵</kbd> open
      <kbd className={cn(k, 'ml-2')}>/</kbd> search
    </p>
  );
}
