import { Plus } from 'lucide-react';
import { Link, Outlet, useLocation } from 'react-router';
import { Button } from '@/components/ui/button';
import { HealthIndicator } from './HealthIndicator';
import { Logo } from './Logo';
import { ThemeToggle } from './ThemeToggle';

/** Root layout: sticky top bar + routed content. Scan pages add <ScanLayout> (left nav) inside. */
export function AppShell() {
  const { pathname } = useLocation();
  return (
    <div className="flex min-h-dvh flex-col">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur-md supports-[backdrop-filter]:bg-background/65">
        <div className="flex h-13 items-center gap-3 px-4 sm:px-6">
          <Link to="/" className="rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none" aria-label="VibeSec home">
            <Logo />
          </Link>
          <div className="flex-1" />
          {pathname !== '/' && (
            <Button asChild size="sm" variant="ghost" className="hidden sm:inline-flex">
              <Link to="/">
                <Plus /> New scan
              </Link>
            </Button>
          )}
          <HealthIndicator />
          <ThemeToggle />
        </div>
      </header>
      <main id="main" className="flex flex-1 flex-col">
        <Outlet />
      </main>
    </div>
  );
}
