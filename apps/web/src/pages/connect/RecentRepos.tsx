import { useQueries } from '@tanstack/react-query';
import type { ScanDto } from '@vibesec/shared';
import { ArrowUpRight, Clock, FolderGit2, Lock, RotateCw, Trash2 } from 'lucide-react';
import { Link } from 'react-router';
import { EmptyState } from '@/components/feedback/EmptyState';
import { ErrorState } from '@/components/feedback/ErrorState';
import { DeleteRepoDialog } from '@/components/history/DeleteRepoDialog';
import { GradeBadge } from '@/components/security/GradeBadge';
import { ScanStatePill } from '@/components/security/StatusPill';
import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { qk, useRepos } from '@/hooks/queries';
import { api, type Repo } from '@/lib/api';
import { formatRelative, formatUsd, githubUrl } from '@/lib/format';
import { hasResults, isTerminalState } from '@/lib/scanState';

const MAX_REPOS = 6;

/** Recent repositories with their latest scan's grade/status (GET /api/repos + /repos/:id/scans + /summary). */
export function RecentRepos({ onRescan }: { onRescan: (url: string) => void }) {
  const repos = useRepos();
  const shown = (repos.data ?? []).slice(0, MAX_REPOS);

  const scans = useQueries({
    queries: shown.map((r) => ({
      queryKey: qk.repoScans(r.id),
      queryFn: ({ signal }: { signal: AbortSignal }) => api.listRepoScans(r.id, signal),
      select: (d: { items: ScanDto[] }) => d.items,
      refetchInterval: (q: { state: { data?: { items: ScanDto[] } } }) => {
        const latest = q.state.data?.items[0];
        return latest && !isTerminalState(latest.state) ? 5_000 : false;
      },
    })),
  });

  const latestById = new Map<string, { scan: ScanDto | undefined; count: number; pending: boolean }>();
  shown.forEach((r, i) => {
    const q = scans[i];
    latestById.set(r.id, { scan: q?.data?.[0], count: q?.data?.length ?? 0, pending: !!q?.isPending });
  });

  const summaries = useQueries({
    queries: shown.map((r) => {
      const latest = latestById.get(r.id)?.scan;
      return {
        queryKey: qk.summary(latest?.id ?? ''),
        queryFn: ({ signal }: { signal: AbortSignal }) => api.getSummary(latest!.id, signal),
        enabled: !!latest && hasResults(latest.state),
        retry: false,
      };
    }),
  });

  return (
    <section aria-labelledby="recent-heading" className="flex flex-col">
      <div className="mb-3 flex items-baseline justify-between">
        <h2 id="recent-heading" className="eyebrow">
          Recent repositories
        </h2>
        {repos.data && repos.data.length > 0 && (
          <span className="font-mono text-[11px] text-muted-foreground tabular">{repos.data.length} total</span>
        )}
      </div>

      {repos.isPending ? (
        <ul className="divide-y rounded-lg border" aria-busy="true" aria-label="Loading repositories">
          {Array.from({ length: 4 }, (_, i) => (
            <li key={i} className="flex items-center gap-3 px-4 py-3">
              <Skeleton className="size-9 rounded-md" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-3 w-24" />
              </div>
            </li>
          ))}
        </ul>
      ) : repos.isError ? (
        <ErrorState error={repos.error} title="Couldn’t load recent repositories" compact onRetry={() => void repos.refetch()} />
      ) : shown.length === 0 ? (
        <EmptyState
          icon={FolderGit2}
          title="No scans yet"
          description="Repositories you scan show up here with their latest grade, so you can jump back in or rescan."
        />
      ) : (
        <ul className="divide-y overflow-hidden rounded-lg border bg-card/60">
          {shown.map((repo, i) => (
            <RepoRow
              key={repo.id}
              repo={repo}
              latest={latestById.get(repo.id)!}
              grade={summaries[i]?.data?.riskGrade}
              onRescan={onRescan}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function RepoRow({
  repo,
  latest,
  grade,
  onRescan,
}: {
  repo: Repo;
  latest: { scan: ScanDto | undefined; count: number; pending: boolean };
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | undefined;
  onRescan: (url: string) => void;
}) {
  const { scan } = latest;
  const target = scan ? `/scans/${scan.id}` : `/repos/${repo.id}`;
  return (
    <li className="group relative flex items-center gap-3 px-4 py-3 transition-colors focus-within:bg-accent/40 hover:bg-accent/40">
      <div className="grid size-9 shrink-0 place-items-center">
        {latest.pending ? (
          <Skeleton className="size-9 rounded-md" />
        ) : grade ? (
          <GradeBadge grade={grade} />
        ) : (
          <span className="grid size-9 place-items-center rounded-md border border-dashed font-mono text-sm text-muted-foreground" aria-label="No grade yet">
            –
          </span>
        )}
      </div>
      <div className="min-w-0 flex-1">
        <Link
          to={target}
          className="flex items-center gap-1.5 truncate text-sm font-medium after:absolute after:inset-0 focus-visible:outline-none"
        >
          {repo.isPrivate && <Lock aria-label="Private" className="size-3 shrink-0 text-muted-foreground" />}
          <span className="truncate">
            <span className="text-muted-foreground">{repo.owner}/</span>
            {repo.name}
          </span>
        </Link>
        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          {scan ? (
            <>
              {!isTerminalState(scan.state) || !hasResults(scan.state) ? <ScanStatePill state={scan.state} /> : null}
              <span className="inline-flex items-center gap-1">
                <Clock aria-hidden className="size-3" />
                {formatRelative(scan.createdAt)}
              </span>
              <span aria-hidden>·</span>
              <span className="font-mono tabular">{formatUsd(scan.costUsd)}</span>
              {latest.count > 1 && (
                <>
                  <span aria-hidden>·</span>
                  <span>{latest.count} scans</span>
                </>
              )}
            </>
          ) : latest.pending ? (
            <Skeleton className="h-3 w-28" />
          ) : (
            <span>No scans</span>
          )}
        </div>
      </div>
      {/* Secondary actions sit above the row link (z-10). */}
      <div className="relative z-10 flex items-center gap-0.5 opacity-100 transition-opacity sm:opacity-0 sm:group-focus-within:opacity-100 sm:group-hover:opacity-100">
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={() => onRescan(githubUrl(repo.owner, repo.name))}
              className="inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              aria-label={`Rescan ${repo.owner}/${repo.name}`}
            >
              <RotateCw className="size-4" />
            </button>
          </TooltipTrigger>
          <TooltipContent>Rescan</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Link
              to={`/repos/${repo.id}`}
              className="inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              aria-label={`Scan history for ${repo.owner}/${repo.name}`}
            >
              <ArrowUpRight className="size-4" />
            </Link>
          </TooltipTrigger>
          <TooltipContent>History</TooltipContent>
        </Tooltip>
        <DeleteRepoDialog
          repo={repo}
          scanCount={latest.pending ? undefined : latest.count}
          running={!!scan && !isTerminalState(scan.state)}
          trigger={
            <button
              type="button"
              title="Delete history"
              className="inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-destructive/10 hover:text-destructive focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              aria-label={`Delete scan history for ${repo.owner}/${repo.name}`}
            >
              <Trash2 className="size-4" />
            </button>
          }
        />
      </div>
    </li>
  );
}
