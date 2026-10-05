import { FindingSummarySchema, type Finding } from '@vibesec/shared';
import type { Analyzer, AnalyzerContext, CoverageEntry, CoverageStatus, IncrementalContext } from '../../analyzers/types';
import type { CoverageRepo } from '../../db/coverageRepo';
import type { FindingRepo } from '../../db/findingRepo';
import type { IndexRepo } from '../../db/indexRepo';
import type { ScanRepo } from '../../db/scanRepo';
import { AppError, toAppError } from '../../errors/AppError';
import type { GitService } from '../../git/GitService';
import { planIncremental, reuseStats, type IncrementalDeps } from '../incremental';
import type { PipelineContext, StageSpec } from '../types';
import { requireCommitSha } from './common';

export type AnalyzeStageDeps = {
  analyzers: readonly Analyzer[];
  findings: FindingRepo;
  indexRepo: Pick<IndexRepo, 'files'>;
  git: Pick<GitService, 'repoDir'>;
  /** Persists per-file AI-review coverage (budget-skipped files are listed in diagnostics). */
  coverage?: Pick<CoverageRepo, 'replaceForScan'>;
  /** Incremental rescans (pipeline/incremental.ts); absent → every scan analyzes every file. */
  incremental?: IncrementalDeps & { scans: Pick<ScanRepo, 'setReuse'> };
};

type AnalyzerOutcome =
  | { analyzer: Analyzer; ok: true }
  | { analyzer: Analyzer; ok: false; cancelled: boolean; appErr: AppError };

/** I5 safety net: `replaceForAnalyzer` persists via `ON CONFLICT (scan_id, fingerprint) DO NOTHING`,
 *  so only the first-inserted row per fingerprint actually survives — mirror that here (same
 *  insertion order) so a `finding` event is never emitted for a duplicate that was never persisted. */
function dedupeByFingerprint(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const f of findings) {
    if (seen.has(f.fingerprint)) continue;
    seen.add(f.fingerprint);
    result.push(f);
  }
  return result;
}

/**
 * Runs one analyzer to completion: persists its findings and emits summary events as soon as it finishes,
 * independent of the others. Never throws — every failure (thrown error or invalid finding from
 * `replaceForAnalyzer`'s schema check) is captured and classified so the caller can decide whether it is
 * a per-analyzer failure (warn and continue) or a cancellation (propagate).
 *
 * M6 (accepted): on a resumed scan, this re-runs the analyzer and re-emits `finding` events for
 * findings that were already persisted by an earlier attempt. That's intentional, not a bug — SSE/
 * event consumers are expected to dedupe by finding id, so a duplicate emission is harmless.
 */
async function runAnalyzer(
  analyzer: Analyzer, actx: AnalyzerContext, deps: Pick<AnalyzeStageDeps, 'findings'>, ctx: PipelineContext,
): Promise<AnalyzerOutcome> {
  try {
    const result: Finding[] = await analyzer.run(actx);
    deps.findings.replaceForAnalyzer(ctx.scanId, analyzer.id, result);
    // The analyzer's own output, before VERIFYING/SCORING rewrite the rows: a later incremental rescan re-attaches from it.
    deps.findings.saveAnalyzerResult(ctx.scanId, analyzer.id, result);
    for (const finding of dedupeByFingerprint(result)) {
      ctx.emit({ type: 'finding', finding: FindingSummarySchema.parse(finding) });
    }
    return { analyzer, ok: true };
  } catch (raw) {
    const appErr = toAppError(raw);
    const cancelled = ctx.signal.aborted || appErr.kind === 'cancelled';
    return { analyzer, ok: false, cancelled, appErr };
  }
}

/**
 * The real ANALYZING stage (replaces the stub once wired in). `fatal: true` here only governs what happens
 * if `run` itself throws — which only occurs when every enabled analyzer failed (see below). Individual
 * analyzer failures are handled inside `run` as warnings, so the stage stays "degradable per analyzer".
 */
export function analyzeStage(deps: AnalyzeStageDeps): StageSpec {
  return {
    name: 'ANALYZING',
    fatal: true,
    run: async (ctx) => {
      const enabled = deps.analyzers.filter((a) => ctx.scan.options.categories.includes(a.category));
      if (enabled.length === 0) return;

      const commitSha = requireCommitSha(ctx);
      const repoDir = deps.git.repoDir(ctx.scanId);
      const files = deps.indexRepo.files(ctx.scanId, { includeSkipped: true });
      const repo = { owner: ctx.scan.repo.owner, name: ctx.scan.repo.name };
      const token = ctx.secrets.token;
      const plan: IncrementalContext | undefined = deps.incremental
        ? await planIncremental(deps.incremental, ctx, { repoDir, commitSha, files })
        : undefined;
      const coverage = new Map<string, CoverageEntry>();
      const recordCoverage = (analyzer: string, path: string, status: CoverageStatus) => {
        coverage.set(`${analyzer}\0${path}`, { analyzer, path, status });
      };

      const settled = await Promise.allSettled(
        enabled.map((analyzer) => {
          const actx: AnalyzerContext = {
            scanId: ctx.scanId,
            scan: ctx.scan,
            repoDir,
            commitSha,
            repo,
            ...(token !== undefined ? { token } : {}),
            files,
            signal: ctx.signal,
            touch: ctx.touch,
            warn: (code, message) => ctx.warn({ code, message, stage: 'ANALYZING' }),
            // No free-text log/progress ScanEvent exists today (only structured `progress` with done/total);
            // a no-op until one does. See report for this deviation.
            progress: () => {},
            recordCoverage,
            ...(plan ? { incremental: plan } : {}),
          };
          return runAnalyzer(analyzer, actx, deps, ctx);
        }),
      );

      let succeeded = 0;
      let cancellation: AppError | undefined;
      for (const settledResult of settled) {
        if (settledResult.status === 'rejected') {
          // runAnalyzer never throws, so this should not happen; handled defensively rather than crashing.
          const appErr = toAppError(settledResult.reason);
          ctx.warn({ code: 'ANALYZER_FAILED', message: `analyzer failed: ${appErr.userMessage}`, stage: 'ANALYZING' });
          continue;
        }
        const outcome = settledResult.value;
        if (outcome.ok) { succeeded++; continue; }
        if (outcome.cancelled) { cancellation ??= outcome.appErr; continue; }
        ctx.warn({ code: 'ANALYZER_FAILED', message: `${outcome.analyzer.id} failed: ${outcome.appErr.userMessage}`, stage: 'ANALYZING' });
      }

      if (cancellation) throw cancellation;
      reportCoverage(ctx, [...coverage.values()], deps.coverage);
      if (deps.incremental) reportReuse(ctx, deps.incremental, plan, files, [...coverage.values()]);
      if (succeeded === 0) throw new AppError('ALL_ANALYZERS_FAILED', 'permanent', 'All analyzers failed');
    },
  };
}

/** Marks the scan 'partial' with its reuse stats (or clears a stale mark) and tells the UI via a `cache` event. */
function reportReuse(
  ctx: PipelineContext, deps: NonNullable<AnalyzeStageDeps['incremental']>, plan: IncrementalContext | undefined,
  files: AnalyzerContext['files'], entries: CoverageEntry[],
): void {
  if (!plan) {
    deps.scans.setReuse(ctx.scanId, 'none', null);
    return;
  }
  const stats = reuseStats(deps, plan, { files, coverage: entries });
  deps.scans.setReuse(ctx.scanId, 'partial', stats);
  ctx.emit({ type: 'cache', filesReused: stats.filesReused, filesAnalyzed: stats.filesChanged, savedUsd: stats.estimatedSavedUsd });
}

/**
 * Persists the coverage and, when the dollar budget left any file without its AI review, warns
 * BUDGET_COVERAGE_PARTIAL with the counts (the full list is in GET /api/scans/:id/diagnostics).
 */
function reportCoverage(ctx: PipelineContext, entries: CoverageEntry[], repo: AnalyzeStageDeps['coverage']): void {
  repo?.replaceForScan(ctx.scanId, entries);
  const skipped = entries.filter((e) => e.status === 'budget-skipped');
  if (skipped.length === 0) return;
  const perAnalyzer = new Map<string, number>();
  for (const e of skipped) perAnalyzer.set(e.analyzer, (perAnalyzer.get(e.analyzer) ?? 0) + 1);
  const reviewed = entries.filter((e) => e.status === 'reviewed' || e.status === 'reviewed-fast' || e.status === 'cached').length;
  const breakdown = [...perAnalyzer.entries()].sort((a, b) => b[1] - a[1]).map(([a, n]) => `${a}: ${n}`).join(', ');
  ctx.warn({
    code: 'BUDGET_COVERAGE_PARTIAL',
    message: `The AI budget ran out before every file got its deep review: ${skipped.length} file review(s) were skipped (${breakdown}); ${reviewed} were completed. `
      + 'Raise budgetUsd for this scan or rescan (unchanged files are served from cache) — the skipped files are listed in the scan diagnostics.',
    stage: 'ANALYZING',
  });
}
