// Full-scan cache (spec §11): a scan of the same repo at the same commit with the same result
// configuration (ScanOptions + analyzerVersionsHash, see scans/cacheKeys.ts) as an earlier COMPLETED /
// COMPLETED_WITH_WARNINGS scan is answered instantly, for $0, by copying that scan's results. Only a clean,
// fresh, original result is served (ScanRepo.findFullCacheSource: COMPLETED or info-only warnings, finished
// less than FULL_CACHE_TTL_HOURS ago, never itself a copy).
//
// Runs as part of RESOLVING, right after the commit SHA is known (the GitHub metadata call before it
// also re-checks access, so a private repo's cached results are only served to a caller whose token
// can still read it). On a hit the new scan record gets cache_hit 'full', base_scan_id = the source,
// copies of the findings, analyzer outputs, coverage, index, fix plan and summary (finding ids re-derived
// per scan, references remapped) and the source's warnings. What is per-SCAN rather than per-commit is NOT
// copied but recomputed, exactly as SCORING would: the triage annotations (the repo's suppressions are
// re-applied — a decision cleared or expired since the source ran must not come back), new/existing/fixed
// (against THIS scan's baseline; the source's fixed rows are dropped) and the summary stats. It then skips
// every remaining stage (JobRunner SKIP_REMAINING_STAGES) — the SSE stream goes straight to the terminal
// state. Copying (rather than pointing at the source) keeps every read API unchanged.
//
// Idempotent: every copy replaces what a previous attempt of this stage may have written.

import { createHash } from 'node:crypto';
import type { Finding, ReuseStats, ScanOptions } from '@vibesec/shared';
import type { CoverageRepo } from '../../db/coverageRepo';
import type { FindingRepo } from '../../db/findingRepo';
import type { FixPlanRepo } from '../../db/fixPlanRepo';
import type { IndexRepo } from '../../db/indexRepo';
import type { ScanCacheKeys, ScanRepo, ScanRow, ScanWarning } from '../../db/scanRepo';
import type { SummaryRepo } from '../../db/summaryRepo';
import { AppError, toAppError } from '../../errors/AppError';
import type { SuppressionService } from '../../suppressions/suppressionService';
import { refreshSummary } from '../../synthesis/synthesize';
import { SKIP_REMAINING_STAGES, type PipelineContext, type StageSpec } from '../types';
import { requireCommitSha } from './common';
import { applyScanStatus, type ScanStatusDeps } from './scanStatus';

export type FullCacheDeps = {
  scans: Pick<ScanRepo, 'setCacheKeys' | 'findFullCacheSource' | 'setReuse' | 'getDiagnostics'> & ScanStatusDeps['scans'];
  findings: Pick<FindingRepo, 'all' | 'replaceAll' | 'analyzerResults' | 'saveAnalyzerResult'> & ScanStatusDeps['findings'];
  /** Re-applies the repo's triage decisions to the copy. */
  suppressions: Pick<SuppressionService, 'applySuppressions'>;
  /** new/existing/fixed baseline ancestry check (see scanStatus.ts). */
  git?: ScanStatusDeps['git'];
  /** Only results younger than this are served (FULL_CACHE_TTL_HOURS); omit for no age limit. */
  fullCacheTtlMs?: number;
  coverage: Pick<CoverageRepo, 'list' | 'replaceForScan'>;
  indexRepo: Pick<IndexRepo, 'files' | 'imports' | 'entrypoints' | 'stats' | 'replace'>;
  summaries: Pick<SummaryRepo, 'get' | 'save'>;
  fixPlans: Pick<FixPlanRepo, 'get' | 'save'>;
  /** The scan's cache keys (result options + analyzer/prompt/model versions). */
  cacheKeys: (options: ScanOptions) => ScanCacheKeys;
  /** One DB transaction around the copy (a crash never leaves a half-copied scan behind). */
  atomically: <T>(fn: () => T) => T;
};

/** A copied finding's id: deterministic per (new scan, source id), unique like the source's (findings.id is a global key). */
export function copiedFindingId(scanId: string, sourceId: string): string {
  return createHash('sha256').update(`${scanId}:${sourceId}`).digest('hex').slice(0, 32);
}

/** Deep-copies `value`, replacing every string that is exactly a key of `ids` (finding-id references). */
function remapIds<T>(value: T, ids: ReadonlyMap<string, string>): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return ids.get(v) ?? v;
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}

type CopyResult = { reuse: ReuseStats; warnings: ScanWarning[]; summary: ReturnType<SummaryRepo['get']> };

function copyScan(deps: FullCacheDeps, source: ScanRow, scanId: string): CopyResult {
  // The source's fixed rows describe ITS predecessor; this scan's are recomputed (applyScanStatus).
  const rows = deps.findings.all(source.id);
  const ids = new Map<string, string>();
  const retarget = (f: Finding): Finding => {
    const id = copiedFindingId(scanId, f.id);
    ids.set(f.id, id);
    const copy: Finding = { ...f, id, scanId };
    delete copy.triage; // re-applied from the repo's current suppressions
    return copy;
  };
  deps.findings.replaceAll(scanId, rows.map((r) => ({ analyzer: r.analyzer, finding: retarget(r.finding) })));
  for (const { analyzer, findings } of deps.findings.analyzerResults(source.id)) {
    deps.findings.saveAnalyzerResult(scanId, analyzer, findings.map(retarget));
  }
  deps.coverage.replaceForScan(scanId, deps.coverage.list(source.id));

  const stats = deps.indexRepo.stats(source.id);
  const files = deps.indexRepo.files(source.id, { includeSkipped: true });
  if (stats) {
    deps.indexRepo.replace(scanId, { files, imports: deps.indexRepo.imports(source.id), entrypoints: deps.indexRepo.entrypoints(source.id), stats });
  }
  const plan = deps.fixPlans.get(source.id);
  if (plan) deps.fixPlans.save(remapIds({ ...plan, scanId }, ids));
  const summary = deps.summaries.get(source.id);
  const copiedSummary = summary ? remapIds({ ...summary, scanId }, ids) : undefined;
  if (copiedSummary) deps.summaries.save(copiedSummary);

  // What this result would have cost to compute: the source's own spend plus whatever IT reused.
  const sourceSaved = deps.scans.getDiagnostics(source.id).reuse?.estimatedSavedUsd ?? 0;
  const reuse: ReuseStats = {
    baseScanId: source.id,
    filesChanged: 0,
    filesReused: files.filter((f) => f.skipReason === null).length,
    estimatedSavedUsd: Math.round((source.cost_usd + sourceSaved) * 1e6) / 1e6,
  };
  deps.scans.setReuse(scanId, 'full', reuse);
  return { reuse, warnings: JSON.parse(source.warnings_json) as ScanWarning[], summary: copiedSummary };
}

/** RESOLVING, extended with the full-scan cache check (see the header). */
export function withFullScanCache(resolve: StageSpec, deps: FullCacheDeps): StageSpec {
  return {
    name: resolve.name,
    fatal: resolve.fatal,
    run: async (ctx: PipelineContext) => {
      await resolve.run(ctx);
      const sha = requireCommitSha(ctx);
      const keys = deps.cacheKeys(ctx.scan.options);
      deps.scans.setCacheKeys(ctx.scanId, keys);
      const source = deps.scans.findFullCacheSource(
        ctx.scan.repo.id, sha, keys, ctx.scanId, deps.fullCacheTtlMs !== undefined ? { maxAgeMs: deps.fullCacheTtlMs } : {},
      );
      if (!source) return;
      if (ctx.signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');

      let copied: CopyResult;
      try {
        copied = deps.atomically(() => copyScan(deps, source, ctx.scanId));
      } catch (raw) {
        // Never fail a scan over its cache: run it normally instead.
        ctx.warn({
          code: 'CACHE_UNAVAILABLE', level: 'info', stage: 'RESOLVING',
          message: `The cached result of scan ${source.id} could not be reused (${toAppError(raw).userMessage}); running a full scan instead.`,
        });
        return;
      }
      // Per-scan state, recomputed as SCORING would (the copied rows carry no triage and no fixed rows).
      let summary = copied.summary;
      try {
        deps.suppressions.applySuppressions(ctx.scanId);
        await applyScanStatus({
          scans: deps.scans, findings: deps.findings, coverage: deps.coverage, indexRepo: deps.indexRepo, ...(deps.git ? { git: deps.git } : {}),
        }, ctx.scanId, { signal: ctx.signal, touch: ctx.touch });
        if (summary) {
          summary = refreshSummary(summary, deps.findings.all(ctx.scanId).map((r) => r.finding));
          deps.summaries.save(summary);
        }
      } catch (raw) {
        const err = toAppError(raw);
        if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
        ctx.warn({
          code: 'CACHE_STATUS_PARTIAL', stage: 'RESOLVING',
          message: `Triage and new/existing/fixed could not be recomputed for the cached result (${err.userMessage}).`,
        });
      }

      for (const w of copied.warnings) ctx.warn(w);
      ctx.emit({ type: 'cache', filesReused: copied.reuse.filesReused, filesAnalyzed: 0, savedUsd: copied.reuse.estimatedSavedUsd });
      if (summary) {
        ctx.emit({ type: 'summary', riskGrade: summary.riskGrade, headline: summary.headline, generatedBy: summary.generatedBy });
      }
      ctx.checkpointData[SKIP_REMAINING_STAGES] = true;
      ctx.checkpointData.fullCacheSource = source.id;
    },
  };
}
