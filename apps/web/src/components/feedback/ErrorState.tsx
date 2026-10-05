import { TriangleAlert, ArrowLeft, RefreshCw } from 'lucide-react';
import { Link } from 'react-router';
import { Button } from '@/components/ui/button';
import { toApiError, type ApiError } from '@/lib/api';
import { cn } from '@/lib/utils';

type ErrorAction = { kind: 'retry' } | { kind: 'link'; to: string; label: string } | { kind: 'none' };

/** What a user can do about an API error: every error gets an action (spec "Client resilience"). */
export function errorAction(err: ApiError, onRetry?: () => void): ErrorAction {
  switch (err.code) {
    case 'NOT_FOUND':
    case 'REPO_NOT_FOUND':
      return { kind: 'link', to: '/', label: 'Start a new scan' };
    case 'AUTH_REQUIRED':
    case 'AUTH_INVALID':
    case 'REF_NOT_FOUND':
    case 'VALIDATION':
      return onRetry ? { kind: 'retry' } : { kind: 'link', to: '/', label: 'Back to scan setup' };
    default:
      return onRetry ? { kind: 'retry' } : { kind: 'link', to: '/', label: 'Go home' };
  }
}

type Props = {
  error: unknown;
  onRetry?: () => void;
  title?: string;
  className?: string;
  /** Compact inline variant (inside cards / table bodies). */
  compact?: boolean;
};

/** Renders the API's userMessage plus one clear action. */
export function ErrorState({ error, onRetry, title = 'Something went wrong', className, compact }: Props) {
  const err = toApiError(error);
  const action = errorAction(err, onRetry);
  const retryHint = err.retryAfterSec ? ` Try again in ${err.retryAfterSec}s.` : '';
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/5',
        compact ? 'p-3' : 'p-5',
        className,
      )}
    >
      <div className="flex items-start gap-3">
        <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-destructive" />
        <div className="space-y-1">
          <p className="text-sm font-medium">{title}</p>
          <p className="text-sm text-muted-foreground">
            {err.userMessage}
            {retryHint}
          </p>
          {err.issues.length > 0 && (
            <ul className="list-inside list-disc text-xs text-muted-foreground">
              {err.issues.map((i) => (
                <li key={`${i.path}:${i.message}`}>
                  {i.path && <code className="code-ref">{i.path}</code>} {i.message}
                </li>
              ))}
            </ul>
          )}
          {err.requestId && <p className="font-mono text-[11px] text-muted-foreground/70">request {err.requestId}</p>}
        </div>
      </div>
      {action.kind === 'retry' && onRetry && (
        <Button size="sm" variant="outline" onClick={onRetry} className="ml-7">
          <RefreshCw /> Try again
        </Button>
      )}
      {action.kind === 'link' && (
        <Button size="sm" variant="outline" asChild className="ml-7">
          <Link to={action.to}>
            <ArrowLeft /> {action.label}
          </Link>
        </Button>
      )}
    </div>
  );
}
