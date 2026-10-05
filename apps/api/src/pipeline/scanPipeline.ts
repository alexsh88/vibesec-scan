import type { Analyzer } from '../analyzers/types';
import type { CoverageRepo } from '../db/coverageRepo';
import type { FindingRepo } from '../db/findingRepo';
import type { FixPlanRepo } from '../db/fixPlanRepo';
import type { IndexRepo } from '../db/indexRepo';
import type { ScanRepo } from '../db/scanRepo';
import type { SummaryRepo } from '../db/summaryRepo';
import { AppError, toAppError } from '../errors/AppError';
import type { GitService } from '../git/GitService';
import type { LlmClient } from '../llm/LlmClient';
import type { SuppressionService } from '../suppressions/suppressionService';
import { analyzeStage } from './stages/analyzeStage';
import { cloneStage } from './stages/cloneStage';
import { indexStage, type IndexDeps } from './stages/indexStage';
import { resolveStage, type ResolveDeps } from './stages/resolveStage';
import { scoreStage } from './stages/scoreStage';
import { createSynthesizeStage } from './stages/synthesizeStage';
import { verifyStage } from './stages/verifyStage';
import type { Pipeline, PipelineContext, StageSpec } from './types';

export type ScanPipelineDeps = Omit<ResolveDeps, 'git' | 'scans'> & Omit<IndexDeps, 'git' | 'indexRepo'> & {
  git: Pick<GitService, 'remoteUrl' | 'resolveRef' | 'ensureCheckout' | 'removeScanDir' | 'repoDir'>;
  scans: Pick<ScanRepo, 'updateRepoMeta' | 'setCommitSha' | 'getDto'>;
  indexRepo: Pick<IndexRepo, 'replace' | 'files' | 'entrypoints'>;
  analyzers: readonly Analyzer[];
  findings: FindingRepo;
  coverage: CoverageRepo;
  fixPlans: Pick<FixPlanRepo, 'get'>;
  summaries: Pick<SummaryRepo, 'save'>;
  /** VERIFYING's skeptic pass and SYNTHESIZING's summary. */
  llm: Pick<LlmClient, 'structured'>;
  /** Re-applies the repo's triage decisions after SCORING. */
  suppressions: Pick<SuppressionService, 'applySuppressions'>;
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
 * RESOLVING → CLONING → INDEXING → ANALYZING → VERIFYING → SCORING (+ suppressions) → SYNTHESIZING. Every stage is idempotent, so
 * JobRunner's resume (skip checkpointed stages, re-run the interrupted one) is safe.
 */
export function createScanPipeline(deps: ScanPipelineDeps): Pipeline {
  return {
    stages: [
      resolveStage(deps),
      cloneStage(deps),
      indexStage(deps),
      analyzeStage({ analyzers: deps.analyzers, findings: deps.findings, indexRepo: deps.indexRepo, git: deps.git, coverage: deps.coverage }),
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
