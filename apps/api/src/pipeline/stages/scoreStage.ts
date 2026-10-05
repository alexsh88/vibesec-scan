// The real SCORING stage (P7): reads every persisted finding, turns it into risk signals
// (scoring/factors.ts), scores it (scoring/riskScore.ts), applies the non-negotiable policy guards,
// and writes the result back. `fatal: false` — a bug here degrades a scan to COMPLETED_WITH_WARNINGS
// rather than failing it outright (spec §14.6); findings simply keep their pre-scoring values.

import type { Finding } from '@vibesec/shared';
import type { FindingRepo } from '../../db/findingRepo';
import type { IndexRepo } from '../../db/indexRepo';
import { applyPolicyGuards, riskScore, severityFromScore, type ScoredFactor } from '../../scoring/riskScore';
import { extractRiskSignals, type RiskSignalContext } from '../../scoring/factors';
import type { PipelineContext, StageSpec } from '../types';

export type ScoreStageDeps = {
  findings: Pick<FindingRepo, 'all' | 'update'>;
  indexRepo: Pick<IndexRepo, 'entrypoints'>;
};

/**
 * Factors an analyzer (or the skeptic) already recorded, overlaid with this stage's own factors (dedupe
 * by `factor` name). On a collision the scoring EFFECT wins (it is the current score movement) but the
 * analyzer's REASON is kept: it is specific ("admin-only setting, line 4"), the scoring one is generic.
 * Order is otherwise preserved: analyzer factors first, then any scoring factor that didn't collide.
 */
function mergeRiskFactors(analyzerFactors: readonly ScoredFactor[], scoringFactors: readonly ScoredFactor[]): ScoredFactor[] {
  const byName = new Map<string, ScoredFactor>();
  for (const f of analyzerFactors) byName.set(f.factor, f);
  for (const f of scoringFactors) {
    const prior = byName.get(f.factor);
    byName.set(f.factor, prior ? { ...f, reason: prior.reason } : f);
  }
  return [...byName.values()];
}

/**
 * Scores one finding. Idempotent by construction: every input (`baseSeverity`, `riskFactors`,
 * `secret`/`dependency`/`taintTrace`, …) comes from fields analyzers set once and SCORING never
 * rewrites (`baseSeverity` is never touched here), so re-running this stage on an already-scored
 * finding recomputes the same signals and — once the weighting function is deterministic — the same
 * result, rather than drifting further from the original signals on every re-run.
 */
function scoreFinding(finding: Finding, signalCtx: RiskSignalContext): Finding {
  const signals = extractRiskSignals(finding, signalCtx);
  const raw = riskScore(signals);
  const guarded = applyPolicyGuards(finding, raw);
  const score = Math.min(100, Math.max(0, guarded.score));
  return {
    ...finding,
    riskScore: score,
    severity: severityFromScore(score),
    riskFactors: mergeRiskFactors(finding.riskFactors, guarded.factors),
  };
}

export function scoreStage(deps: ScoreStageDeps): StageSpec {
  return {
    name: 'SCORING',
    fatal: false,
    run: async (ctx: PipelineContext) => {
      const all = deps.findings.all(ctx.scanId);
      if (all.length === 0) return;

      const entrypoints = new Set(deps.indexRepo.entrypoints(ctx.scanId).map((e) => e.path));
      const signalCtx: RiskSignalContext = { entrypoints };

      const scored = all.map(({ finding }) => scoreFinding(finding, signalCtx));
      ctx.touch();
      deps.findings.update(ctx.scanId, scored);
    },
  };
}
