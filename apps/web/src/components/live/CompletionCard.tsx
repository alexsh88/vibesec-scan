import { isTerminalState, type ScanDto, type ScanEvent, type ScanState } from '@vibesec/shared';
import { ArrowRight, CircleSlash, CircleX, DatabaseZap, Plus, Stethoscope } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { GradeBadge } from '@/components/security/GradeBadge';
import { Button } from '@/components/ui/button';
import { useSummary } from '@/hooks/queries';
import { formatDuration, formatUsd } from '@/lib/format';
import { hasResults, STATE_LABEL } from '@/lib/scanState';
import { cn } from '@/lib/utils';

const AUTO_NAV_MS = 1_500;
/** Interaction this recent counts as "the user is busy here" — don't yank the page away. */
const RECENT_INTERACTION_MS = 4_000;

/** Timestamp of the user's last pointer/key/scroll input on the page (module-level, cheap). */
let lastInteraction = 0;
const mark = () => {
  lastInteraction = Date.now();
};
if (typeof window !== 'undefined') {
  for (const t of ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const) window.addEventListener(t, mark, { passive: true, capture: true });
}

type Props = {
  scan: ScanDto;
  state: ScanState;
  summary: Extract<ScanEvent, { type: 'summary' }> | null;
  errorCode: string | null;
  errorMessage: string | null;
  elapsedMs: number | null;
  /** Auto-open the results (the user watched this scan finish and motion is allowed). */
  autoNavigate: boolean;
};

/** Shown once the scan is terminal: outcome, grade and the way forward. */
export function CompletionCard({ scan, state, summary, errorCode, errorMessage, elapsedMs, autoNavigate }: Props) {
  const ok = hasResults(state);
  const summaryQuery = useSummary(scan.id, { enabled: ok && !summary });
  const grade = summary?.riskGrade ?? summaryQuery.data?.riskGrade ?? null;
  const headline = summary?.headline ?? summaryQuery.data?.headline ?? null;
  const resultsTo = `/scans/${scan.id}/overview`;

  const navigate = useNavigate();
  const hovering = useRef(false);
  const [countdown, setCountdown] = useState<'armed' | 'stopped' | 'idle'>('idle');

  useEffect(() => {
    if (!ok || !autoNavigate || !isTerminalState(state)) return;
    if (Date.now() - lastInteraction < RECENT_INTERACTION_MS || document.querySelector('[role="dialog"]')) {
      setCountdown('stopped');
      return;
    }
    setCountdown('armed');
    const armedAt = Date.now();
    const timer = setTimeout(() => {
      if (lastInteraction > armedAt || hovering.current || document.querySelector('[role="dialog"]')) {
        setCountdown('stopped');
        return;
      }
      void navigate(resultsTo);
    }, AUTO_NAV_MS);
    const stop = () => {
      clearTimeout(timer);
      setCountdown('stopped');
    };
    const opts = { passive: true, capture: true, once: true } as const;
    window.addEventListener('pointerdown', stop, opts);
    window.addEventListener('keydown', stop, opts);
    window.addEventListener('wheel', stop, opts);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('pointerdown', stop, opts);
      window.removeEventListener('keydown', stop, opts);
      window.removeEventListener('wheel', stop, opts);
    };
  }, [ok, autoNavigate, state, navigate, resultsTo]);

  const failed = state === 'FAILED';
  const cancelled = state === 'CANCELLED';
  const fromCache = scan.cacheHit === 'full';

  return (
    <section
      aria-label="Scan result"
      aria-live="polite"
      onPointerEnter={() => (hovering.current = true)}
      onPointerLeave={() => (hovering.current = false)}
      className={cn(
        'relative animate-rise overflow-hidden rounded-xl border bg-card',
        ok && 'border-foreground/15',
        failed && 'border-sev-critical/40',
      )}
    >
      {ok && <div aria-hidden className="bg-grid pointer-events-none absolute inset-0 [mask-image:linear-gradient(to_right,black,transparent_70%)]" />}
      <div className="relative flex flex-wrap items-center gap-x-5 gap-y-4 p-4 sm:p-5">
        {ok ? (
          grade ? (
            <GradeBadge grade={grade} size="lg" className="size-16 text-4xl" />
          ) : (
            <span className="grid size-16 place-items-center rounded-xl border border-dashed font-mono text-xs text-muted-foreground">
              {summaryQuery.isPending ? '…' : '—'}
            </span>
          )
        ) : (
          <span
            className={cn(
              'grid size-16 place-items-center rounded-xl border',
              failed ? 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical' : 'bg-muted text-muted-foreground',
            )}
          >
            {failed ? <CircleX aria-hidden className="size-7" /> : <CircleSlash aria-hidden className="size-7" />}
          </span>
        )}

        <div className="min-w-0 flex-1 basis-64 space-y-1">
          <p className="eyebrow flex items-center gap-2">
            {STATE_LABEL[state]}
            {elapsedMs !== null && <span className="normal-case tracking-normal">· {formatDuration(elapsedMs)}</span>}
            <span className="normal-case tracking-normal">· {formatUsd(scan.costUsd)}</span>
            {fromCache && (
              <span className="inline-flex items-center gap-1 normal-case tracking-normal text-foreground">
                <DatabaseZap aria-hidden className="size-3" /> $0 — served from cache
              </span>
            )}
          </p>
          <p className="text-lg font-semibold tracking-tight text-balance">
            {ok
              ? (headline ?? 'Scan finished — results are ready.')
              : failed
                ? 'The scan failed before it could finish.'
                : 'The scan was cancelled.'}
          </p>
          {failed && (
            <p className="text-sm text-muted-foreground">
              {errorMessage ?? scan.errorMessage ?? 'No error detail was recorded.'}
              {(errorCode ?? scan.errorCode) && <code className="code-ref ml-2 text-[11px]">{errorCode ?? scan.errorCode}</code>}
            </p>
          )}
          {cancelled && <p className="text-sm text-muted-foreground">Findings collected before the cancel are kept but incomplete.</p>}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {ok && (
            <Button asChild className="bg-signal text-signal-foreground hover:bg-signal/90">
              <Link to={resultsTo}>
                View results <ArrowRight />
              </Link>
            </Button>
          )}
          {cancelled && (
            <Button asChild variant="outline">
              <Link to={`/scans/${scan.id}/findings`}>Partial findings</Link>
            </Button>
          )}
          {failed && (
            <Button asChild variant="outline">
              <Link to={`/scans/${scan.id}/diagnostics`}>
                <Stethoscope /> Diagnostics
              </Link>
            </Button>
          )}
          {!ok && (
            <Button asChild variant={failed ? 'default' : 'ghost'}>
              <Link to="/">
                <Plus /> New scan
              </Link>
            </Button>
          )}
        </div>
      </div>
      {countdown === 'armed' && (
        <div className="relative flex items-center gap-3 border-t px-4 py-1.5 sm:px-5">
          <span className="font-mono text-[11px] text-muted-foreground">Opening results…</span>
          <span className="relative h-0.5 flex-1 overflow-hidden rounded-full bg-muted">
            <span
              className="absolute inset-0 origin-left bg-signal"
              style={{ animation: `vs-live-countdown ${AUTO_NAV_MS}ms linear forwards` }}
            />
          </span>
          <button
            type="button"
            className="font-mono text-[11px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
            onClick={() => setCountdown('stopped')}
          >
            Stay here
          </button>
        </div>
      )}
    </section>
  );
}
