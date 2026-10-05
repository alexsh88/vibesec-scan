import { activeTriage, type Finding } from '@vibesec/shared';
import { ChevronLeft, ChevronRight, ExternalLink, LoaderCircle, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useLocation, useNavigate, useOutletContext, useParams } from 'react-router';
import { ErrorState } from '@/components/feedback/ErrorState';
import { CredentialDetails } from '@/components/findings/CredentialDetails';
import { DependencyDetails } from '@/components/findings/DependencyDetails';
import { AnalyzerChip, ConfidencePips } from '@/components/findings/FindingBits';
import type { FindingsOutletContext } from '@/components/findings/filters';
import { cweUrl } from '@/components/findings/meta';
import { PatchDiff } from '@/components/findings/PatchDiff';
import { RiskFactors } from '@/components/findings/RiskFactors';
import { TaintFlow } from '@/components/findings/TaintFlow';
import { TriagePanel } from '@/components/findings/TriagePanel';
import { CategoryLabel } from '@/components/security/CategoryIcon';
import { CodeBlock } from '@/components/security/CodeBlock';
import { GithubMark } from '@/components/security/GithubMark';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { FindingStatusPill, TriagePill } from '@/components/security/StatusPill';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { useFinding } from '@/hooks/queries';
import { useScanContext } from '@/hooks/useScanContext';
import { cn } from '@/lib/utils';

/**
 * Spec screen 5 — finding drawer (nested route /scans/:id/findings/:findingId, rendered in
 * FindingsPage's <Outlet/>). Previous/next follow the list's current filtered order (outlet context);
 * ← / → (or k / j) step through it, Esc closes and returns to the list with its filters intact.
 */
export default function FindingDrawer() {
  const { findingId = '' } = useParams();
  const { scanId } = useScanContext();
  const navigate = useNavigate();
  const location = useLocation();
  const list = useOutletContext<FindingsOutletContext | undefined>();
  const query = useFinding(scanId, findingId);
  const bodyRef = useRef<HTMLDivElement>(null);

  const close = () => navigate({ pathname: '..', search: location.search }, { relative: 'path' });
  const goTo = useCallback(
    (id: string) => navigate({ pathname: `../${id}`, search: location.search }, { relative: 'path', replace: true }),
    [navigate, location.search],
  );

  // ---- previous / next within the list ------------------------------------------------------------
  const ids = list?.ids ?? [];
  const idx = ids.indexOf(findingId);
  const prevId = idx > 0 ? ids[idx - 1] : undefined;
  const nextId = idx >= 0 ? ids[idx + 1] : undefined;
  const canLoadMore = idx >= 0 && idx === ids.length - 1 && !!list?.hasMore;
  const [wantNext, setWantNext] = useState(false);

  const goNext = useCallback(() => {
    if (nextId) goTo(nextId);
    else if (canLoadMore) {
      setWantNext(true);
      list?.loadMore();
    }
  }, [nextId, canLoadMore, goTo, list]);
  const goPrev = useCallback(() => prevId && goTo(prevId), [prevId, goTo]);

  useEffect(() => {
    if (!wantNext) return;
    if (nextId) {
      setWantNext(false);
      goTo(nextId);
    } else if (!list?.hasMore && !list?.loadingMore) setWantNext(false);
  }, [wantNext, nextId, list?.hasMore, list?.loadingMore, goTo]);

  const onViewed = list?.onViewed;
  useEffect(() => {
    onViewed?.(findingId);
    bodyRef.current?.scrollTo({ top: 0 });
  }, [findingId, onViewed]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) return;
      if (document.querySelectorAll('[role="dialog"]').length > 1) return; // a triage dialog is open
      if (e.key === 'ArrowRight' || e.key === 'j') {
        e.preventDefault();
        goNext();
      } else if (e.key === 'ArrowLeft' || e.key === 'k') {
        e.preventDefault();
        goPrev();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [goNext, goPrev]);

  const f = query.data;

  return (
    <Sheet open onOpenChange={(open) => !open && close()}>
      <SheetContent side="right" showCloseButton={false} className="w-full gap-0 p-0 sm:max-w-3xl">
        {/* Top bar: position + navigation */}
        <div className="flex h-11 shrink-0 items-center gap-1 border-b bg-surface-raised/60 px-2 sm:px-3">
          <Button size="icon" variant="ghost" className="size-8" onClick={goPrev} disabled={!prevId} aria-label="Previous finding (←)" title="Previous (← or k)">
            <ChevronLeft />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            className="size-8"
            onClick={goNext}
            disabled={!nextId && !canLoadMore}
            aria-label="Next finding (→)"
            title="Next (→ or j)"
          >
            {wantNext ? <LoaderCircle className="animate-spin" /> : <ChevronRight />}
          </Button>
          <span className="ml-1 font-mono text-xs text-muted-foreground tabular">
            {idx >= 0 ? (
              <>
                {idx + 1} / {ids.length}
                {list?.hasMore ? '+' : ''}
              </>
            ) : (
              'not in the current list'
            )}
          </span>
          <span className="ml-3 hidden items-center gap-1 text-[11px] text-muted-foreground sm:inline-flex" aria-hidden>
            <kbd className="rounded border bg-muted px-1 font-mono text-[10px]">←</kbd>
            <kbd className="rounded border bg-muted px-1 font-mono text-[10px]">→</kbd> navigate
            <kbd className="ml-2 rounded border bg-muted px-1 font-mono text-[10px]">esc</kbd> close
          </span>
          <div className="flex-1" />
          <Button size="icon" variant="ghost" className="size-8" onClick={close} aria-label="Close finding">
            <X />
          </Button>
        </div>

        <div ref={bodyRef} className="min-h-0 flex-1 overflow-y-auto">
          {query.isPending ? (
            <DrawerSkeleton />
          ) : query.isError ? (
            <div className="p-5">
              <SheetTitle className="sr-only">Finding</SheetTitle>
              <SheetDescription className="sr-only">The finding could not be loaded.</SheetDescription>
              <ErrorState error={query.error} title="Couldn’t load this finding" onRetry={() => void query.refetch()} />
            </div>
          ) : f ? (
            <FindingDetail finding={f} scanId={scanId} />
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------------------------

function FindingDetail({ finding: f, scanId }: { finding: Finding; scanId: string }) {
  const triage = activeTriage(f);
  const cwe = f.cwe ? cweUrl(f.cwe) : null;
  const [primary, ...also] = f.producedBy ?? [];
  const lines = f.location.endLine > f.location.startLine ? `${f.location.startLine}–${f.location.endLine}` : `${f.location.startLine}`;

  return (
    <article className="animate-rise">
      {/* Header */}
      <header className="space-y-3 border-b px-4 pt-4 pb-4 sm:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} variant="solid" />
          <CategoryLabel category={f.category} />
          <FindingStatusPill status={f.scanStatus} />
          {triage && <TriagePill triage={triage} />}
        </div>
        <SheetTitle className="text-lg leading-snug font-semibold tracking-tight text-balance sm:text-xl">{f.title}</SheetTitle>
        <SheetDescription asChild>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-muted-foreground">
            <code className="code-ref text-[11px]">{f.ruleId}</code>
            {f.cwe &&
              (cwe ? (
                <a href={cwe} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono hover:text-foreground hover:underline">
                  {f.cwe} <ExternalLink aria-hidden className="size-3" />
                </a>
              ) : (
                <span className="font-mono">{f.cwe}</span>
              ))}
            <span className="inline-flex items-center gap-1.5">
              Confidence <ConfidencePips confidence={f.confidence} withLabel />
            </span>
          </div>
        </SheetDescription>
      </header>

      <div className="space-y-7 px-4 py-5 sm:px-6">
        <Section title="Risk score" hint="Base impact adjusted by context; hover a factor for its reason">
          <RiskFactors finding={f} />
        </Section>

        <Section
          title="Location"
          aside={
            <Button asChild size="sm" variant="outline" className="h-7">
              <a href={f.location.permalink} target="_blank" rel="noreferrer">
                <GithubMark className="size-3.5" /> Open on GitHub
              </a>
            </Button>
          }
        >
          <p className="mb-2 font-mono text-xs">
            {f.location.file}
            <span className="text-muted-foreground">:{lines}</span>
          </p>
          {f.location.snippet.trim() ? (
            <CodeBlock
              code={f.location.snippet.replace(/\n+$/, '')}
              path={f.location.file}
              startLine={f.location.startLine}
              highlight={{ from: f.location.startLine, to: f.location.endLine }}
            />
          ) : (
            <p className="text-xs text-muted-foreground">No snippet captured for this location.</p>
          )}
        </Section>

        {f.taintTrace && f.taintTrace.length > 0 && (
          <Section title="Data flow" hint="How untrusted input reaches the sink">
            <TaintFlow trace={f.taintTrace} permalinkBase={f.location.permalink} />
          </Section>
        )}

        {f.secret && (
          <Section title="Credential">
            <CredentialDetails cred={f.secret} permalinkBase={f.location.permalink} />
          </Section>
        )}

        {f.dependency && (
          <Section title="Dependency">
            <DependencyDetails dep={f.dependency} permalinkBase={f.location.permalink} />
          </Section>
        )}

        <div className="grid gap-6 md:grid-cols-2">
          <Section title="Explanation">
            <Prose>{f.explanation}</Prose>
          </Section>
          <Section title="Impact">
            <Prose>{f.impact}</Prose>
          </Section>
        </div>

        <Section title="Remediation">
          <Prose>{f.remediation.summary}</Prose>
          {f.remediation.patch && <PatchDiff patch={f.remediation.patch} className="mt-3" />}
        </Section>

        <Section title="Triage">
          <TriagePanel finding={f} scanId={scanId} />
        </Section>

        {(primary || (f.mergedFingerprints?.length ?? 0) > 0) && (
          <Section title="Provenance">
            <div className="space-y-2 text-xs">
              {primary && (
                <p className="flex flex-wrap items-center gap-1.5">
                  <span className="w-28 text-muted-foreground">Reported by</span>
                  <AnalyzerChip name={primary} className="text-foreground" />
                </p>
              )}
              {also.length > 0 && (
                <p className="flex flex-wrap items-center gap-1.5">
                  <span className="w-28 text-muted-foreground">Also reported by</span>
                  {also.map((a) => (
                    <AnalyzerChip key={a} name={a} />
                  ))}
                </p>
              )}
              {(f.mergedFingerprints?.length ?? 0) > 0 && (
                <p className="text-muted-foreground">
                  Merged {f.mergedFingerprints!.length} duplicate report{f.mergedFingerprints!.length === 1 ? '' : 's'} from other analyzers.
                </p>
              )}
              <p className="font-mono text-[10px] text-muted-foreground/70" title="Stable across scans">
                fingerprint {f.fingerprint.slice(0, 16)}
              </p>
            </div>
          </Section>
        )}
      </div>
    </article>
  );
}

function Section({ title, hint, aside, children }: { title: string; hint?: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2.5 flex items-center gap-3">
        <h3 className="eyebrow shrink-0">{title}</h3>
        <span aria-hidden className="h-px flex-1 bg-border" />
        {aside}
      </div>
      {hint && <p className="-mt-1.5 mb-2.5 text-[11px] text-muted-foreground/80">{hint}</p>}
      {children}
    </section>
  );
}

function Prose({ children, className }: { children: string; className?: string }) {
  return <p className={cn('text-sm leading-relaxed whitespace-pre-wrap text-foreground/90', className)}>{children}</p>;
}

function DrawerSkeleton() {
  return (
    <div className="space-y-6 p-6" aria-busy="true" aria-label="Loading finding">
      <SheetTitle className="sr-only">Loading finding</SheetTitle>
      <SheetDescription className="sr-only">Finding details are loading.</SheetDescription>
      <div className="flex gap-2">
        <Skeleton className="h-5.5 w-20" />
        <Skeleton className="h-5.5 w-24" />
      </div>
      <Skeleton className="h-7 w-3/4" />
      <Skeleton className="h-4 w-1/2" />
      <Skeleton className="h-16 w-full" />
      <Skeleton className="h-40 w-full" />
      <Skeleton className="h-24 w-full" />
    </div>
  );
}
