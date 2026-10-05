import type { Finding, FixAction } from '@vibesec/shared';
import { useMemo } from 'react';
import { ErrorState } from '@/components/feedback/ErrorState';
import { Page } from '@/components/layout/Page';
import { CategoryBreakdown, SeverityDistribution } from '@/components/overview/Distribution';
import { DeltaStrip } from '@/components/overview/DeltaStrip';
import { GradeHero } from '@/components/overview/GradeHero';
import { NextActions } from '@/components/overview/NextActions';
import { ScanEndedNotice, ScanRunningNotice, SummaryPending } from '@/components/overview/OverviewStates';
import { PositiveObservations } from '@/components/overview/PositiveObservations';
import { ScanMetadata } from '@/components/overview/ScanMetadata';
import { TopRisks } from '@/components/overview/TopRisks';
import { useDiagnostics, useFindings, useFixPlan, useRepoScans, useSummary } from '@/hooks/queries';
import { useScanContext } from '@/hooks/useScanContext';
import { isApiError } from '@/lib/api';
import { hasResults, isTerminalState } from '@/lib/scanState';

/** Spec screen 3 — the first screen of a scan's results. */
export default function OverviewPage() {
  const { scan } = useScanContext();
  if (!isTerminalState(scan.state)) {
    return (
      <Page>
        <ScanRunningNotice scan={scan} />
      </Page>
    );
  }
  if (scan.state === 'FAILED') {
    return (
      <Page>
        <ScanEndedNotice scan={scan} />
      </Page>
    );
  }
  return <OverviewResults />;
}

function OverviewResults() {
  const { scanId, scan } = useScanContext();
  const cancelled = !hasResults(scan.state);
  // Synthesis lands a moment after the scan is marked done; poll a few times while NOT_READY.
  const summary = useSummary(scanId, {
    refetchInterval: (query) => (!cancelled && isApiError(query.state.error) && query.state.error.code === 'NOT_READY' ? 4_000 : false),
  });
  const notReady = isApiError(summary.error) && summary.error.code === 'NOT_READY';
  const { refetch } = summary;

  // One page of findings serves both the counts and title lookups for linked finding ids.
  const findings = useFindings(scanId, { limit: 200 });
  const firstPage = findings.data?.pages[0];
  const byId = useMemo(() => {
    const m = new Map<string, Finding>();
    for (const f of firstPage?.items ?? []) m.set(f.id, f);
    return m;
  }, [firstPage]);

  const fixPlan = useFixPlan(scanId);
  const fixActions = useMemo(() => {
    const m = new Map<string, FixAction>();
    for (const a of fixPlan.data?.actions ?? []) m.set(a.id, a);
    return m;
  }, [fixPlan.data]);

  const diagnostics = useDiagnostics(scanId);
  const repoScans = useRepoScans(scan.repo.id);
  const isFirstScan = !!repoScans.data && !repoScans.data.some((s) => s.id !== scan.id && hasResults(s.state) && s.createdAt < scan.createdAt);

  let body;
  if (summary.isPending) {
    body = <SummaryPending onRetry={() => void refetch()} retrying />;
  } else if (summary.isError) {
    if (notReady && cancelled) body = <ScanEndedNotice scan={scan} />;
    else if (notReady) body = <SummaryPending onRetry={() => void refetch()} retrying={summary.isFetching} />;
    else body = <ErrorState error={summary.error} title="Couldn’t load the summary" onRetry={() => void refetch()} />;
  } else {
    const s = summary.data;
    body = (
      <div className="space-y-4">
        {cancelled && <ScanEndedNotice scan={scan} />}
        <GradeHero summary={s} scanId={scanId} />
        <DeltaStrip scanId={scanId} counts={firstPage?.counts.byScanStatus} isFirstScan={isFirstScan} />
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="min-w-0 space-y-4">
            <TopRisks summary={s} scanId={scanId} byId={byId} />
            <NextActions summary={s} scanId={scanId} byId={byId} fixActions={fixActions} />
            <PositiveObservations items={s.positiveObservations} />
          </div>
          <div className="min-w-0 space-y-4">
            <SeverityDistribution stats={s.stats} scanId={scanId} />
            <CategoryBreakdown stats={s.stats} scanId={scanId} />
            <ScanMetadata scan={scan} diagnostics={diagnostics.data} diagnosticsPending={diagnostics.isPending} />
          </div>
        </div>
      </div>
    );
  }

  return <Page wide>{body}</Page>;
}
