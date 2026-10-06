import { useQueries } from '@tanstack/react-query';
import { ScanOptionsSchema, type RiskGrade, type ScanDto } from '@vibesec/shared';
import { GitCompareArrows, History, Lock, RotateCw, Trash2 } from 'lucide-react';
import { useMemo } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { toast } from 'sonner';
import { EmptyState } from '@/components/feedback/EmptyState';
import { ErrorState } from '@/components/feedback/ErrorState';
import { DeleteRepoDialog } from '@/components/history/DeleteRepoDialog';
import { ScanCompare } from '@/components/history/ScanCompare';
import { ScanHistoryTable, type HistoryRow } from '@/components/history/ScanHistoryTable';
import { Page, PageHeader } from '@/components/layout/Page';
import { GithubMark } from '@/components/security/GithubMark';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { qk, useRepos, useRepoScans, useStartScan } from '@/hooks/queries';
import { api, toApiError, type FindingsPage } from '@/lib/api';
import { formatInt, formatUsd, githubUrl } from '@/lib/format';
import { hasResults, isTerminalState } from '@/lib/scanState';

/** Spec screen 7 — every scan of one repository, plus a two-scan compare. */
export default function RepoHistoryPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const scansQ = useRepoScans(id);
  const reposQ = useRepos();
  const startScan = useStartScan();
  const scans = useMemo(() => scansQ.data ?? [], [scansQ.data]);

  const repo = reposQ.data?.find((r) => r.id === id) ?? scans[0]?.repo;

  // Grade per finished scan (summary) and finding counts per scan (first page's counts).
  const summaries = useQueries({
    queries: scans.map((s) => ({
      queryKey: qk.summary(s.id),
      queryFn: ({ signal }: { signal: AbortSignal }) => api.getSummary(s.id, signal),
      enabled: hasResults(s.state),
      retry: false,
      staleTime: 60_000,
    })),
  });
  const counts = useQueries({
    queries: scans.map((s) => ({
      queryKey: ['scans', s.id, 'findings', { countsOnly: true }] as const,
      queryFn: ({ signal }: { signal: AbortSignal }): Promise<FindingsPage> => api.listFindings(s.id, { limit: 1 }, undefined, signal),
      enabled: isTerminalState(s.state) && s.state !== 'FAILED',
      staleTime: 60_000,
    })),
  });

  const rows: HistoryRow[] = scans.map((scan, i) => ({
    scan,
    grade: summaries[i]?.data?.riskGrade,
    gradePending: hasResults(scan.state) && !!summaries[i]?.isPending,
    counts: counts[i]?.data?.counts,
    countsPending: isTerminalState(scan.state) && scan.state !== 'FAILED' && !!counts[i]?.isPending,
  }));
  const gradeOf = (scanId: string): RiskGrade | undefined => rows.find((r) => r.scan.id === scanId)?.grade;

  // Compare selection lives in the URL (?a=&b=), always ordered older (A) → newer (B).
  const byId = new Map(scans.map((s) => [s.id, s] as const));
  const selected = [params.get('a'), params.get('b')].filter((x): x is string => !!x && byId.has(x));
  const setSelection = (ids: string[]) => {
    const sorted = ids
      .map((x) => byId.get(x))
      .filter((s): s is ScanDto => !!s)
      .sort((p, q) => p.createdAt.localeCompare(q.createdAt));
    const next = new URLSearchParams(params);
    next.delete('a');
    next.delete('b');
    if (sorted[0]) next.set('a', sorted[0].id);
    if (sorted[1]) next.set('b', sorted[1].id);
    setParams(next, { replace: true });
  };
  const onToggle = (scanId: string, on: boolean) => {
    if (!on) return setSelection(selected.filter((x) => x !== scanId));
    // A third pick replaces the earliest-picked one.
    setSelection([...(selected.length >= 2 ? selected.slice(1) : selected), scanId]);
  };
  const comparable = scans.filter((s) => hasResults(s.state));
  const [scanA, scanB] = selected.map((x) => byId.get(x));

  const rescan = () => {
    if (!repo) return;
    startScan.mutate(
      // Same options as the latest scan, so the rescan is comparable (and cache-eligible).
      { body: { repoUrl: githubUrl(repo.owner, repo.name), options: scans[0]?.options ?? ScanOptionsSchema.parse({}) } },
      {
        onSuccess: (res) => navigate(`/scans/${res.scanId}/${isTerminalState(res.scan.state) ? 'overview' : 'live'}`),
        onError: (e) => toast.error(toApiError(e).userMessage),
      },
    );
  };

  const totalCost = scans.reduce((n, s) => n + s.costUsd, 0);

  return (
    <Page wide>
      <PageHeader
        eyebrow={
          <span className="inline-flex items-center gap-1.5">
            <History aria-hidden className="size-3" /> Scan history
          </span>
        }
        title={
          repo ? (
            <span className="inline-flex items-center gap-2">
              {repo.isPrivate && <Lock aria-label="Private repository" className="size-4 text-muted-foreground" />}
              <span>
                <span className="text-muted-foreground">{repo.owner}/</span>
                {repo.name}
              </span>
            </span>
          ) : scansQ.isPending ? (
            <Skeleton className="h-7 w-56" />
          ) : (
            'Repository'
          )
        }
        description={
          scans.length > 0
            ? `${formatInt(scans.length)} ${scans.length === 1 ? 'scan' : 'scans'} · ${formatUsd(totalCost)} total AI cost`
            : undefined
        }
        actions={
          repo && (
            <>
              <DeleteRepoDialog
                repo={repo}
                scanCount={scansQ.isPending ? undefined : scans.length}
                running={scans.some((s) => !isTerminalState(s.state))}
                onDeleted={() => navigate('/')}
                trigger={
                  <Button size="sm" variant="ghost" className="text-muted-foreground hover:text-destructive">
                    <Trash2 /> Delete history
                  </Button>
                }
              />
              <Button asChild size="sm" variant="ghost">
                <a href={githubUrl(repo.owner, repo.name)} target="_blank" rel="noreferrer">
                  <GithubMark /> GitHub
                </a>
              </Button>
              {repo.isPrivate ? (
                <Button asChild size="sm">
                  <Link to="/">
                    <RotateCw /> Rescan
                  </Link>
                </Button>
              ) : (
                <Button size="sm" onClick={rescan} disabled={startScan.isPending}>
                  <RotateCw className={startScan.isPending ? 'animate-spin' : undefined} /> Rescan
                </Button>
              )}
            </>
          )
        }
      />

      {scansQ.isPending ? (
        <div className="space-y-2" aria-busy="true" aria-label="Loading scans">
          {Array.from({ length: 4 }, (_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : scansQ.isError ? (
        <ErrorState error={scansQ.error} title="Couldn’t load this repository’s scans" onRetry={() => void scansQ.refetch()} />
      ) : scans.length === 0 ? (
        <EmptyState
          icon={History}
          title="No scans yet"
          description="Scans of this repository will be listed here."
          action={
            <Button asChild size="sm">
              <Link to="/">Start a scan</Link>
            </Button>
          }
        />
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-dashed px-4 py-2.5 text-sm">
            <GitCompareArrows aria-hidden className="size-4 text-muted-foreground" />
            <p className="min-w-0 flex-1 text-muted-foreground">
              {selected.length === 0
                ? 'Tick two scans to compare their grades and findings.'
                : selected.length === 1
                  ? 'Tick one more scan to compare.'
                  : 'Comparing A (older) → B (newer).'}
            </p>
            {selected.length < 2 && comparable.length >= 2 && (
              <Button size="xs" variant="outline" onClick={() => setSelection([comparable[1]!.id, comparable[0]!.id])}>
                Compare latest two
              </Button>
            )}
            {selected.length > 0 && (
              <Button size="xs" variant="ghost" onClick={() => setSelection([])}>
                Clear
              </Button>
            )}
          </div>

          <ScanHistoryTable rows={rows} selected={selected} onToggle={onToggle} />

          {scanA && scanB && (
            <ScanCompare a={scanA} b={scanB} gradeA={gradeOf(scanA.id)} gradeB={gradeOf(scanB.id)} onClose={() => setSelection([])} />
          )}
        </div>
      )}
    </Page>
  );
}
