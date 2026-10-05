import type { CoverageRepo } from '../../db/coverageRepo';
import type { FindingRepo } from '../../db/findingRepo';
import type { FixPlanRepo } from '../../db/fixPlanRepo';
import type { ScanRepo } from '../../db/scanRepo';
import type { SummaryRepo } from '../../db/summaryRepo';
import { AppError } from '../../errors/AppError';
import type { LlmClient } from '../../llm/LlmClient';
import { synthesizeSummary } from '../../synthesis/synthesize';
import type { StageSpec } from '../types';

export type SynthesizeStageDeps = {
  llm: Pick<LlmClient, 'structured'>;
  findings: Pick<FindingRepo, 'all'>;
  fixPlans: Pick<FixPlanRepo, 'get'>;
  summaries: Pick<SummaryRepo, 'save'>;
  coverage?: Pick<CoverageRepo, 'summary'>;
  /** Fresh scan warnings (ctx.scan is the snapshot taken when the scan started). */
  scans?: Pick<ScanRepo, 'getDto'>;
};

/**
 * SYNTHESIZING (spec §9.3): one Opus call over the findings digest (never code) → the scan summary.
 * Degradable: if the model is unavailable/over budget/refuses, a deterministic summary is stored instead
 * (warning SYNTHESIS_FALLBACK), so a finished scan always has a first screen.
 */
export function createSynthesizeStage(deps: SynthesizeStageDeps): StageSpec {
  return {
    name: 'SYNTHESIZING',
    fatal: false,
    async run(ctx) {
      const findings = deps.findings.all(ctx.scanId).map((r) => r.finding);
      const warningCodes = (deps.scans?.getDto(ctx.scanId)?.warnings ?? ctx.scan.warnings).map((w) => w.code);
      const { summary, fallbackReason } = await synthesizeSummary({ llm: deps.llm }, {
        scanId: ctx.scanId,
        findings,
        fixPlan: deps.fixPlans.get(ctx.scanId),
        coverage: deps.coverage?.summary(ctx.scanId).totals,
        warningCodes,
        scannedCategories: ctx.scan.options.categories,
      }, { signal: ctx.signal, onActivity: () => ctx.touch() });
      if (ctx.signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
      deps.summaries.save(summary);
      if (fallbackReason) {
        ctx.warn({
          code: 'SYNTHESIS_FALLBACK',
          message: `The AI scan summary could not be generated (${fallbackReason}); a deterministic summary was used instead.`,
          stage: 'SYNTHESIZING',
        });
      }
      ctx.emit({ type: 'summary', riskGrade: summary.riskGrade, headline: summary.headline, generatedBy: summary.generatedBy });
    },
  };
}
