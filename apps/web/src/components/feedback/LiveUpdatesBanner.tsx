import { RefreshCw, WifiOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { ConnectionStatus } from '@/hooks/useScanEvents';

/**
 * Shown while useScanEvents is degraded to polling (3 failed reconnects). Pass the hook's
 * `interrupted`, `connection` and `retryLive`.
 */
export function LiveUpdatesBanner({
  interrupted,
  connection,
  onRetry,
}: {
  interrupted: boolean;
  connection: ConnectionStatus;
  onRetry: () => void;
}) {
  if (!interrupted) {
    if (connection !== 'reconnecting') return null;
    return (
      <div role="status" className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
        <RefreshCw aria-hidden className="size-3.5 animate-spin" />
        Reconnecting to live updates…
      </div>
    );
  }
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-3 rounded-md border border-sev-medium/35 bg-sev-medium/8 px-3 py-2 text-sm"
    >
      <WifiOff aria-hidden className="size-4 shrink-0 text-sev-medium" />
      <p className="min-w-0 flex-1">
        <span className="font-medium">Live updates interrupted.</span>{' '}
        <span className="text-muted-foreground">Checking scan status every 3 seconds instead.</span>
      </p>
      <Button size="sm" variant="outline" onClick={onRetry}>
        <RefreshCw /> Reconnect
      </Button>
    </div>
  );
}
