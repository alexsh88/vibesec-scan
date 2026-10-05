import { isTerminalState } from '@vibesec/shared';
import {
  Activity,
  GitBranch,
  GitCommitHorizontal,
  LayoutDashboard,
  ListFilter,
  Lock,
  Package,
  Radio,
  Stethoscope,
  Square,
  type LucideIcon,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useParams } from 'react-router';
import { toast } from 'sonner';
import { ErrorState } from '@/components/feedback/ErrorState';
import { LiveUpdatesBanner } from '@/components/feedback/LiveUpdatesBanner';
import { ScanStatePill } from '@/components/security/StatusPill';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { useCancelScan, useScan } from '@/hooks/queries';
import { ScanContext, useScanContext, type ScanContextValue } from '@/hooks/useScanContext';
import { useScanEvents } from '@/hooks/useScanEvents';
import { toApiError } from '@/lib/api';
import { formatUsd, githubUrl, shortSha } from '@/lib/format';
import { cn } from '@/lib/utils';

type NavItem = { to: string; label: string; icon: LucideIcon; end?: boolean };

const NAV: NavItem[] = [
  { to: 'live', label: 'Live', icon: Radio },
  { to: 'overview', label: 'Overview', icon: LayoutDashboard },
  { to: 'findings', label: 'Findings', icon: ListFilter },
  { to: 'dependencies', label: 'Dependencies', icon: Package },
  { to: 'activity', label: 'Activity', icon: Activity },
  { to: 'diagnostics', label: 'Diagnostics', icon: Stethoscope },
];

/** Layout for /scans/:id/*: scan header, left nav (top tabs on mobile), the scan's SSE connection. */
export function ScanLayout() {
  const { id = '' } = useParams();
  const { pathname } = useLocation();
  const scanQuery = useScan(id);
  const scan = scanQuery.data;
  const running = !!scan && !isTerminalState(scan.state);
  const onLive = pathname.endsWith('/live');
  const events = useScanEvents(id, { enabled: !!scan && (running || onLive) });

  const ctx = useMemo<ScanContextValue | null>(() => (scan ? { scanId: id, scan, events } : null), [id, scan, events]);

  if (scanQuery.isPending) return <ScanLayoutSkeleton />;
  if (scanQuery.isError || !ctx || !scan) {
    return (
      <div className="mx-auto w-full max-w-2xl px-4 py-16">
        <ErrorState error={scanQuery.error} title="Couldn’t load this scan" onRetry={() => void scanQuery.refetch()} />
      </div>
    );
  }

  return (
    <ScanContext.Provider value={ctx}>
      <div className="flex flex-1 flex-col">
        <ScanHeader running={running} />
        <div className="flex flex-1 flex-col md:flex-row">
          <nav
            aria-label="Scan sections"
            className="sticky top-13 z-30 flex shrink-0 gap-1 overflow-x-auto border-b bg-background/90 px-3 py-2 backdrop-blur md:h-[calc(100dvh-3.25rem)] md:w-52 md:flex-col md:overflow-visible md:border-r md:border-b-0 md:px-3 md:py-4"
          >
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    'group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm whitespace-nowrap text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                    isActive && 'bg-accent font-medium text-foreground',
                  )
                }
              >
                <item.icon aria-hidden className="size-4" strokeWidth={1.75} />
                {item.label}
                {item.to === 'live' && running && (
                  <span aria-label="scan running" className="ml-auto size-1.5 animate-pulse-dot rounded-full bg-state-running" />
                )}
              </NavLink>
            ))}
          </nav>
          <div className="min-w-0 flex-1">
            <div className="px-4 pt-4 empty:hidden sm:px-6">
              <LiveUpdatesBanner interrupted={events.interrupted} connection={events.connection} onRetry={events.retryLive} />
            </div>
            <Outlet />
          </div>
        </div>
      </div>
    </ScanContext.Provider>
  );
}

function ScanHeader({ running }: { running: boolean }) {
  const { scan } = useScanContext();
  const cancel = useCancelScan();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const onCancel = () => {
    cancel.mutate(scan.id, {
      onSuccess: () => {
        setConfirmOpen(false);
        toast.success('Scan cancelled');
      },
      onError: (e) => toast.error(toApiError(e).userMessage),
    });
  };

  return (
    <div className="border-b bg-surface-raised/40">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 sm:px-6">
        <div className="flex min-w-0 items-center gap-2">
          {scan.repo.isPrivate && <Lock aria-label="Private repository" className="size-3.5 text-muted-foreground" />}
          <Link
            to={`/repos/${scan.repo.id}`}
            className="truncate text-[15px] font-semibold tracking-tight hover:underline focus-visible:underline focus-visible:outline-none"
            title="Scan history for this repository"
          >
            <span className="text-muted-foreground">{scan.repo.owner}/</span>
            {scan.repo.name}
          </Link>
        </div>
        <ScanStatePill state={scan.state} />
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <GitBranch aria-hidden className="size-3.5" />
            {scan.ref ?? 'default branch'}
          </span>
          {scan.commitSha && (
            <a
              href={`${githubUrl(scan.repo.owner, scan.repo.name)}/commit/${scan.commitSha}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 hover:text-foreground"
              title={scan.commitSha}
            >
              <GitCommitHorizontal aria-hidden className="size-3.5" />
              {shortSha(scan.commitSha)}
            </a>
          )}
          <span className="tabular" title="AI cost of this scan">
            {formatUsd(scan.costUsd)}
          </span>
          {scan.cacheHit !== 'none' && (
            <span className="rounded border border-signal/40 bg-signal-soft px-1.5 text-[10px] tracking-wide text-foreground uppercase">
              {scan.cacheHit === 'full' ? 'cached' : 'incremental'}
            </span>
          )}
        </div>
        <div className="flex-1" />
        {running && (
          <Button size="sm" variant="outline" onClick={() => setConfirmOpen(true)} disabled={cancel.isPending}>
            <Square className="fill-current" /> Cancel scan
          </Button>
        )}
      </div>
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel this scan?</DialogTitle>
            <DialogDescription>
              Analysis stops at the next checkpoint. Findings collected so far are kept, but the result will be incomplete.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="ghost">Keep scanning</Button>
            </DialogClose>
            <Button variant="destructive" onClick={onCancel} disabled={cancel.isPending}>
              {cancel.isPending ? 'Cancelling…' : 'Cancel scan'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ScanLayoutSkeleton() {
  return (
    <div className="flex flex-1 flex-col" aria-busy="true" aria-label="Loading scan">
      <div className="flex items-center gap-3 border-b px-6 py-3.5">
        <Skeleton className="h-5 w-56" />
        <Skeleton className="h-5 w-24 rounded-full" />
        <Skeleton className="h-4 w-40" />
      </div>
      <div className="flex flex-1">
        <div className="hidden w-52 space-y-2 border-r p-4 md:block">
          {NAV.map((n) => (
            <Skeleton key={n.to} className="h-7 w-full" />
          ))}
        </div>
        <div className="flex-1 space-y-4 p-6">
          <Skeleton className="h-8 w-72" />
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    </div>
  );
}
