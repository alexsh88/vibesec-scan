import type { ScanDto } from '@vibesec/shared';
import { ArrowRight, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Skeleton } from '@/components/ui/skeleton';
import type { Diagnostics } from '@/lib/api';
import { formatCompact, formatDateTime, formatDuration, formatInt, formatUsd, githubUrl, shortSha } from '@/lib/format';
import { cn } from '@/lib/utils';
import { Panel } from '@/components/common/Panel';

function Row({ k, children, className }: { k: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn('grid grid-cols-[6.5rem_1fr] items-baseline gap-3 py-1.5', className)}>
      <dt className="eyebrow text-[10px]">{k}</dt>
      <dd className="min-w-0 text-xs break-words">{children}</dd>
    </div>
  );
}

function durationOf(scan: ScanDto, diag: Diagnostics | undefined): number | null {
  if (diag?.durationMs != null) return diag.durationMs;
  if (scan.startedAt && scan.finishedAt) return Date.parse(scan.finishedAt) - Date.parse(scan.startedAt);
  return null;
}

/** Repo, ref, commit, timing, AI cost/tokens, cache reuse, coverage and warnings. */
export function ScanMetadata({
  scan,
  diagnostics,
  diagnosticsPending,
}: {
  scan: ScanDto;
  diagnostics: Diagnostics | undefined;
  diagnosticsPending: boolean;
}) {
  const repoUrl = githubUrl(scan.repo.owner, scan.repo.name);
  const llm = diagnostics?.llm;
  const cov = diagnostics?.coverage;
  const warnings = (diagnostics?.warnings ?? scan.warnings).filter((w) => w.level !== 'info');
  const notes = (diagnostics?.warnings ?? scan.warnings).filter((w) => w.level === 'info');
  const budgetSkipped = cov?.totals['budget-skipped'] ?? 0;
  const diagHref = `/scans/${encodeURIComponent(scan.id)}/diagnostics`;
  const pending = <Skeleton className="h-3.5 w-20" />;

  return (
    <Panel id="scan-meta" title="Scan" meta={scan.id.slice(0, 8)}>
      {budgetSkipped > 0 && (
        <div role="status" className="mb-3 flex gap-2.5 rounded-md border border-sev-medium/35 bg-sev-medium/8 p-3 text-xs">
          <TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0 text-sev-medium" />
          <div className="space-y-1">
            <p className="font-medium">
              {formatInt(budgetSkipped)} {budgetSkipped === 1 ? 'file was' : 'files were'} not AI-reviewed (budget reached)
            </p>
            <p className="text-muted-foreground">Results may be incomplete for those files.</p>
            <Link to={diagHref} className="inline-flex items-center gap-1 font-medium text-foreground underline-offset-2 hover:underline">
              See coverage in diagnostics <ArrowRight aria-hidden className="size-3" />
            </Link>
          </div>
        </div>
      )}
      <dl className="divide-y divide-border/60">
        <Row k="Repository">
          <a href={repoUrl} target="_blank" rel="noreferrer" className="font-medium hover:underline">
            {scan.repo.owner}/{scan.repo.name}
          </a>
          {scan.repo.isPrivate && <span className="ml-1.5 text-muted-foreground">(private)</span>}
        </Row>
        <Row k="Ref">
          <span className="font-mono">{scan.ref ?? 'default branch'}</span>
        </Row>
        <Row k="Commit">
          {scan.commitSha ? (
            <a
              href={`${repoUrl}/commit/${scan.commitSha}`}
              target="_blank"
              rel="noreferrer"
              title={scan.commitSha}
              className="font-mono hover:underline"
            >
              {shortSha(scan.commitSha)}
            </a>
          ) : (
            '—'
          )}
        </Row>
        <Row k="Started">{formatDateTime(scan.startedAt ?? scan.createdAt)}</Row>
        <Row k="Duration">
          <span className="font-mono tabular">{formatDuration(durationOf(scan, diagnostics))}</span>
        </Row>
        <Row k="AI cost">
          <span className="font-mono tabular">{formatUsd(llm?.totals.costUsd ?? scan.costUsd)}</span>
          {llm && <span className="text-muted-foreground"> of {formatUsd(llm.budgetUsd)} budget</span>}
        </Row>
        <Row k="Tokens">
          {llm ? (
            <span className="font-mono tabular">
              {formatCompact(llm.totals.inputTokens)} in · {formatCompact(llm.totals.outputTokens)} out
              <span className="text-muted-foreground">
                {' '}
                · {formatInt(llm.totals.calls)} calls · {Math.round(llm.cacheHitRatio * 100)}% prompt-cached
              </span>
            </span>
          ) : diagnosticsPending ? (
            pending
          ) : (
            '—'
          )}
        </Row>
        <Row k="Reuse">
          {scan.cacheHit === 'none' ? (
            <span className="text-muted-foreground">Full analysis</span>
          ) : (
            <span>
              <span className="mr-1.5 rounded border border-signal/40 bg-signal-soft px-1.5 font-mono text-[10px] tracking-wide uppercase">
                {scan.cacheHit === 'full' ? 'cached' : 'incremental'}
              </span>
              {scan.reuse && (
                <span className="text-muted-foreground">
                  {scan.cacheHit === 'full'
                    ? `results reused from scan ${scan.reuse.baseScanId.slice(0, 8)}`
                    : `${formatInt(scan.reuse.filesChanged)} changed, ${formatInt(scan.reuse.filesReused)} reused`}
                  {scan.reuse.estimatedSavedUsd > 0 && ` · ~${formatUsd(scan.reuse.estimatedSavedUsd)} saved`}
                </span>
              )}
            </span>
          )}
        </Row>
        <Row k="Coverage">
          {cov ? (
            <span className="font-mono tabular">
              {formatInt((cov.totals.reviewed ?? 0) + (cov.totals['reviewed-fast'] ?? 0))} reviewed · {formatInt(cov.totals.cached ?? 0)} cached
              {budgetSkipped > 0 && <span className="text-sev-medium"> · {formatInt(budgetSkipped)} budget-skipped</span>}
              {(cov.totals.failed ?? 0) > 0 && <span className="text-sev-high"> · {formatInt(cov.totals.failed)} failed</span>}
            </span>
          ) : diagnosticsPending ? (
            pending
          ) : (
            '—'
          )}
        </Row>
      </dl>
      {(warnings.length > 0 || notes.length > 0) && (
        <ul className="mt-3 space-y-1.5 border-t pt-3">
          {warnings.map((w, i) => (
            <li key={`w${i}`} className="flex gap-2 text-xs">
              <TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0 text-sev-medium" />
              <span>
                {w.message} {w.stage && <span className="font-mono text-[10px] text-muted-foreground">[{w.stage}]</span>}
              </span>
            </li>
          ))}
          {notes.map((w, i) => (
            <li key={`n${i}`} className="pl-5.5 text-xs text-muted-foreground">
              {w.message}
            </li>
          ))}
        </ul>
      )}
      <Link to={diagHref} className="mt-3 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
        Full diagnostics <ArrowRight aria-hidden className="size-3" />
      </Link>
    </Panel>
  );
}
