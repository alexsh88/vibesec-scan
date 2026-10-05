import type { ScanOptions } from '@vibesec/shared';
import type { Analyzer } from '../analyzers/types';
import type { CoverageRepo } from '../db/coverageRepo';
import type { FindingRepo } from '../db/findingRepo';
import type { FixPlanRepo } from '../db/fixPlanRepo';
import type { IndexRepo } from '../db/indexRepo';
import type { LlmCallRepo } from '../db/llmCallRepo';
import type { ScanCacheKeys, ScanRepo } from '../db/scanRepo';
import type { SummaryRepo } from '../db/summaryRepo';
import { AppError, toAppError } from '../errors/AppError';
import type { GitService } from '../git/GitService';
import type { LlmClient } from '../llm/LlmClient';
import type { SuppressionService } from '../suppressions/suppressionService';
import { analyzeStage } from './stages/analyzeStage';
import { cloneStage } from './stages/cloneStage';
import { withFullScanCache } from './stages/fullCache';
import { indexStage, type IndexDeps } from './stages/indexStage';
import { resolveStage, type ResolveDeps } from './stages/resolveStage';
import { scoreStage } from './stages/scoreStage';
import { createSynthesizeStage } from './stages/synthesizeStage';
import { verifyStage } from './stages/verifyStage';
import type { Pipeline, PipelineContext, StageSpec } from './types';

export type ScanPipelineDeps = Omit<ResolveDeps, 'git' | 'scans'> & Omit<IndexDeps, 'git' | 'indexRepo'> & {
  git: Pick<GitService, 'remoteUrl' | 'resolveRef' | 'ensureCheckout' | 'removeScanDir' | 'repoDir' | 'diffNameStatus' | 'fetchCommit'>;
  scans: Pick<ScanRepo,
    | 'updateRepoMeta' | 'setCommitSha' | 'getRow' | 'getDto' | 'setCacheKeys' | 'findFullCacheSource' | 'findIncrementalBase'
    | 'setReuse' | 'getDiagnostics'>;
  indexRepo: Pick<IndexRepo, 'replace' | 'files' | 'imports' | 'entrypoints' | 'stats'>;
  analyzers: readonly Analyzer[];
  findings: FindingRepo;
  coverage: CoverageRepo;
  fixPlans: Pick<FixPlanRepo, 'get' | 'save'>;
  summaries: Pick<SummaryRepo, 'get' | 'save'>;
  llmCalls: Pick<LlmCallRepo, 'byAnalyzer'>;
  /** VERIFYING's skeptic pass and SYNTHESIZING's summary. */
  llm: Pick<LlmClient, 'structured'>;
  /** Re-applies the repo's triage decisions after SCORING. */
  suppressions: Pick<SuppressionService, 'applySuppressions'>;
  /** The scan's cache keys (scans/cacheKeys.ts); omit to disable the full-scan cache and incremental rescans. */
  cacheKeys?: (options: ScanOptions) => ScanCacheKeys;
  /** One DB transaction (the full-scan cache copy). */
  atomically: <T>(fn: () => T) => T;
  /** Called after cleanup, once the scan reaches a terminal state (e.g. budget-tracker cleanup). */
  onFinished?: (scanId: string) => void;
};

/**
 * SCORING = risk scoring, then the repo's triage suppressions. Each step is idempotent and runs even if an earlier one failed (findings then keep
 * their pre-scoring values); the first failure is re-thrown afterwards so it surfaces as a warning.
 */
function scoringStage(deps: ScanPipelineDeps): StageSpec {
  const score = scoreStage({ findings: deps.findings, indexRepo: deps.indexRepo });
  return {
    name: 'SCORING',
    fatal: score.fatal,
    run: async (ctx: PipelineContext) => {
      let failure: AppError | undefined;
      const step = async (fn: () => unknown) => {
        try {
          await fn();
        } catch (raw) {
          const err = toAppError(raw);
          if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
          failure ??= err;
        }
      };
      await step(() => score.run(ctx));
      await step(() => deps.suppressions.applySuppressions(ctx.scanId));
      if (failure) throw failure;
    },
  };
}

/**
 * RESOLVING (+ full-scan cache) → CLONING → INDEXING → ANALYZING (incremental when a base exists) →
 * VERIFYING → SCORING (+ suppressions) → SYNTHESIZING. Every stage is idempotent, so
 * JobRunner's resume (skip checkpointed stages, re-run the interrupted one) is safe.
 */
export function createScanPipeline(deps: ScanPipelineDeps): Pipeline {
  const resolve = resolveStage(deps);
  const cacheKeys = deps.cacheKeys;
  return {
    stages: [
      cacheKeys ? withFullScanCache(resolve, { ...deps, cacheKeys }) : resolve,
      cloneStage(deps),
      indexStage(deps),
      analyzeStage({
        analyzers: deps.analyzers, findings: deps.findings, indexRepo: deps.indexRepo, git: deps.git, coverage: deps.coverage,
        ...(cacheKeys ? { incremental: deps } : {}),
      }),
      verifyStage({ findings: deps.findings, llm: deps.llm, git: deps.git }),
      scoringStage(deps),
      createSynthesizeStage({
        llm: deps.llm, findings: deps.findings, fixPlans: deps.fixPlans, summaries: deps.summaries, coverage: deps.coverage, scans: deps.scans,
      }),
    ],
    onScanFinished: async (scanId) => {
      await deps.git.removeScanDir(scanId);
      deps.onFinished?.(scanId);
    },
  };
}
