/**
 * Route map. Pages are lazy-loaded (one chunk each) and default-export their component, so page
 * owners never need to touch this file — just fill in the file under src/pages/.
 *
 *  /                                   Connect (new scan)
 *  /scans/:id                          → live while running, overview when done
 *  /scans/:id/live                     Live scan
 *  /scans/:id/overview                 Overview (result)
 *  /scans/:id/findings                 Findings list
 *  /scans/:id/findings/:findingId      Finding drawer (rendered in FindingsPage's <Outlet/>)
 *  /scans/:id/dependencies             Dependencies + fix plan
 *  /scans/:id/activity                 Audit activity
 *  /scans/:id/diagnostics              Diagnostics
 *  /repos/:id                          Repo scan history / compare
 */
import type { ComponentType } from 'react';
import { createBrowserRouter, isRouteErrorResponse, Link, useRouteError } from 'react-router';
import { ErrorState } from '@/components/feedback/ErrorState';
import { AppShell } from '@/components/layout/AppShell';
import { ScanLayout } from '@/components/layout/ScanLayout';
import { Button } from '@/components/ui/button';
import ConnectPage from '@/pages/connect/ConnectPage';

const page = (load: () => Promise<{ default: ComponentType }>) => async () => ({ Component: (await load()).default });

function RouteError() {
  const err = useRouteError();
  if (isRouteErrorResponse(err) && err.status === 404) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16 text-center">
        <p className="eyebrow mb-2">404</p>
        <p className="mb-4 text-muted-foreground">Page not found.</p>
        <Button asChild size="sm">
          <Link to="/">Start a new scan</Link>
        </Button>
      </div>
    );
  }
  // A failed lazy chunk after a deploy, or a render crash.
  return (
    <div className="mx-auto max-w-xl px-4 py-16">
      <ErrorState
        error={err instanceof Error ? err : new Error('Unexpected error')}
        title="This page crashed"
        onRetry={() => window.location.reload()}
      />
    </div>
  );
}

/**
 * Shown (full-page, replacing the root — not nested inside AppShell) only on the very first paint
 * of a path whose matched routes include a `lazy` one still downloading its chunk. This is a CSR-only
 * SPA (no server loaders), so this is the sole hydration gap React Router can hit; without a root
 * `hydrateFallbackElement` it warns "No HydrateFallback element provided" and renders nothing.
 */
function RootHydrateFallback() {
  return (
    <div className="flex min-h-dvh items-center justify-center bg-background" aria-busy="true" aria-label="Loading">
      <span className="size-2 animate-pulse-dot rounded-full bg-signal" />
    </div>
  );
}

export const router = createBrowserRouter([
  {
    element: <AppShell />,
    errorElement: <RouteError />,
    hydrateFallbackElement: <RootHydrateFallback />,
    children: [
      { index: true, element: <ConnectPage /> },
      {
        path: 'scans/:id',
        element: <ScanLayout />,
        errorElement: <RouteError />,
        children: [
          { index: true, lazy: page(() => import('@/pages/scan/ScanIndexRedirect')) },
          { path: 'live', lazy: page(() => import('@/pages/scan/LiveScanPage')) },
          { path: 'overview', lazy: page(() => import('@/pages/scan/OverviewPage')) },
          {
            path: 'findings',
            lazy: page(() => import('@/pages/scan/FindingsPage')),
            children: [{ path: ':findingId', lazy: page(() => import('@/pages/scan/FindingDrawer')) }],
          },
          { path: 'dependencies', lazy: page(() => import('@/pages/scan/DependenciesPage')) },
          { path: 'activity', lazy: page(() => import('@/pages/scan/ActivityPage')) },
          { path: 'diagnostics', lazy: page(() => import('@/pages/scan/DiagnosticsPage')) },
        ],
      },
      { path: 'repos/:id', lazy: page(() => import('@/pages/repos/RepoHistoryPage')) },
      { path: '*', lazy: page(() => import('@/pages/NotFoundPage')) },
    ],
  },
]);
