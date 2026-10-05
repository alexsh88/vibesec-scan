/**
 * Spec screen 2 — Live scan. Everything here is derived from the single SSE stream owned by ScanLayout
 * (useScanContext().events — a finished scan's log is replayed, so the full timeline renders too) plus
 * diagnostics polled every 3 s while the scan runs (coverage, per-analyzer AI spend, budget).
 */
import { isTerminalState, type Severity } from '@vibesec/shared';
import { useMemo, useState } from 'react';
import { ErrorState } from '@/components/feedback/ErrorState';
import { Page, PageHeader } from '@/components/layout/Page';
import { AnalyzerLanes } from '@/components/live/AnalyzerLanes';
import { CancelScanButton } from '@/components/live/CancelScanButton';
import { CompletionCard } from '@/components/live/CompletionCard';
import { FindingsFeed, SeverityReadout } from '@/components/live/FindingsFeed';
import {
  countBySeverity,
  deriveLanes,
  deriveTimeline,
  mergeWarnings,
  newestFirstFindings,
  useNow,
  useReducedMotion,
} from '@/components/live/liveModel';
import { CachePanel, CostMeter, WarningsList } from '@/components/live/Meters';
import { StageTimeline } from '@/components/live/StageTimeline';
import { useDiagnostics, useFindings } from '@/hooks/queries';
import { useScanContext } from '@/hooks/useScanContext';
import { hasResults, STATE_LABEL } from '@/lib/scanState';
import { SEVERITY_ORDER } from '@/lib/taxonomy';

export default function LiveScanPage() {
  const { scanId, scan, events } = useScanContext();

  // A terminal DTO wins over a log that is still replaying; otherwise the stream is the freshest source.
  const current = isTerminalState(scan.state) ? scan.state : (events.state ?? scan.state);
  const terminal = isTerminalState(current);
  const running = !terminal;
  const now = useNow(running);
  const reducedMotion = useReducedMotion();
  // Only auto-open results for a scan the user actually watched finish (not one opened after the fact).
  const [watchedLive] = useState(() => !isTerminalState(scan.state));

  const diagnostics = useDiagnostics(scanId, { refetchInterval: running ? 3_000 : false });
  const timeline = useMemo(() => deriveTimeline(events.events, current, scan.cacheHit), [events.events, current, scan.cacheHit]);
  const warnings = useMemo(() => mergeWarnings(events.warnings, scan.warnings), [events.warnings, scan.warnings]);
  const lanes = useMemo(
    () => deriveLanes({ timeline, scan, progress: events.progress, warnings, diagnostics: diagnostics.data }),
    [timeline, scan, events.progress, warnings, diagnostics.data],
  );
  const feed = useMemo(() => newestFirstFindings(events.findings), [events.findings]);

  // Live counts come from the stream (pre-verification); once results exist, the stored counts are authoritative.
  const finalCounts = useFindings(terminal && hasResults(current) ? scanId : undefined, { limit: 1 });
  const stored = finalCounts.data?.pages[0]?.counts.bySeverity;
  const counts: Record<Severity, number> = stored
    ? (Object.fromEntries(SEVERITY_ORDER.map((s) => [s, stored[s] ?? 0])) as Record<Severity, number>)
    : countBySeverity(feed);

  const startedAt = scan.startedAt ? Date.parse(scan.startedAt) : (timeline.stages[0]?.startedAt ?? null);
  const endedAt = scan.finishedAt ? Date.parse(scan.finishedAt) : (timeline.terminalAt ?? (terminal ? null : now));
  const elapsedMs = startedAt !== null && endedAt !== null ? Math.max(0, endedAt - startedAt) : null;

  const activeStage = timeline.stages.find((s) => s.status === 'active');
  const coverageReady = !!diagnostics.data && Object.keys(diagnostics.data.coverage.byAnalyzer).length > 0;
  const emptyHint =
    scan.cacheHit === 'full'
      ? 'Results were copied from an earlier scan, so nothing was streamed — open the findings list to see them.'
      : running
        ? 'Listening… findings appear here the moment an analyzer reports them.'
        : 'No findings were streamed for this scan.';

  return (
    <Page wide>
      <PageHeader
        eyebrow={running ? 'Live scan' : 'Scan run'}
        title={running ? `Scanning ${scan.repo.owner}/${scan.repo.name}` : STATE_LABEL[current]}
        description={
          running
            ? current === 'QUEUED'
              ? 'Waiting for a free worker…'
              : `${activeStage?.label ?? STATE_LABEL[current]} — results stream in as each analyzer reports.`
            : 'The full pipeline run, replayed from the event log.'
        }
        actions={running ? <CancelScanButton scanId={scanId} findingsSoFar={feed.length} /> : null}
      />

      <div className="space-y-4">
        {terminal && (
          <CompletionCard
            scan={scan}
            state={current}
            summary={events.summary}
            errorCode={events.errorCode}
            errorMessage={events.errorMessage}
            elapsedMs={elapsedMs}
            autoNavigate={watchedLive && !reducedMotion}
          />
        )}

        <StageTimeline timeline={timeline} current={current} now={now} elapsedMs={elapsedMs} />

        <SeverityReadout counts={counts} caption={stored ? 'final — after verification & scoring' : running ? 'live — before verification' : 'as streamed'} />

        <div className="grid gap-4 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
          <div className="min-w-0 space-y-4">
            <AnalyzerLanes lanes={lanes} coverageReady={coverageReady} finished={terminal} />
            <WarningsList warnings={warnings} />
          </div>
          <div className="min-w-0 space-y-4">
            <CostMeter scan={scan} cost={events.cost} diagnostics={diagnostics.data} />
            {diagnostics.isError && (
              <ErrorState compact title="Couldn’t load coverage & token details" error={diagnostics.error} onRetry={() => void diagnostics.refetch()} />
            )}
            <CachePanel scan={scan} cache={events.cache} />
            <FindingsFeed scanId={scanId} findings={feed} running={running} emptyHint={emptyHint} />
          </div>
        </div>
      </div>
    </Page>
  );
}
