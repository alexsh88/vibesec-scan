// SCORING stage, part 2/2 (P7): turns `RiskSignals` (factors.ts) into the 0-100 `riskScore` and
// `severity` persisted on a Finding. The weighting itself (`riskScore` below) is deliberately a
// placeholder — see its doc comment — but the severity bands and the policy guards around it are
// real product rules, not placeholders, and are exercised by scoreStage.ts on every finding.

import type { Finding, Severity } from '@vibesec/shared';
import type { RiskSignals } from './factors';
import { MALICIOUS_RULE_ID } from './factors';
import { provisionalScore } from '../findings/helpers';

export type ScoredFactor = { factor: string; effect: number; reason: string };
export type RiskResult = { score: number /* 0–100 */; factors: ScoredFactor[] };

/** Bands from the spec, shared by `severityFromScore` and the policy guards below so the two
 *  always agree on where a band starts. */
export const SEVERITY_BANDS = { critical: 85, high: 65, medium: 40, low: 15 } as const;

/** Bands from the spec: ≥85 critical, ≥65 high, ≥40 medium, ≥15 low, else info. Pure range checks —
 *  a score outside [0, 100] (shouldn't happen past `applyPolicyGuards`, but this function doesn't
 *  assume it) still lands in a sensible band (e.g. -5 → info, 150 → critical). */
export function severityFromScore(score: number): Severity {
  if (score >= SEVERITY_BANDS.critical) return 'critical';
  if (score >= SEVERITY_BANDS.high) return 'high';
  if (score >= SEVERITY_BANDS.medium) return 'medium';
  if (score >= SEVERITY_BANDS.low) return 'low';
  return 'info';
}

/**
 * TODO(user): the weighting is a deliberate product decision written by the author.
 * Turn the signals into a 0–100 score and the list of factors shown in the UI
 * (e.g. "Live AWS key +25", "Dev dependency −20", "Reachable from a public route +15").
 *
 * Trade-offs to weigh before writing this:
 *   - Additive (sum of signed effects off a base score) vs. multiplicative (e.g. confidence as a
 *     scaling factor on the total) — additive is easier to explain per-factor in the UI, since each
 *     effect is independently meaningful; multiplicative compounds uncertainty across every factor
 *     at once instead of discounting the final total by it.
 *   - Caps: should a refuted or AI-unreviewed finding be capped below a confirmed one of the same
 *     base severity, no matter how many positive factors it accumulates? (`applyPolicyGuards` below
 *     enforces the *hard* floor/ceiling for malicious/refuted findings either way — this is about
 *     the *soft* shape of the weighting underneath, e.g. whether a merely-low-confidence finding
 *     should also be discounted.)
 *   - Malicious packages: pin to critical inside this function too, or leave that entirely to the
 *     policy guard and let this function treat `malicious` as just another large positive factor?
 *   - Confidence as a multiplier on the whole score, vs. only on the factors that are inherently
 *     uncertain (AI-judged ones), vs. not used at all (confidence is already baked into each
 *     analyzer's base severity before this ever runs, so double-counting it here would be easy).
 *   - How many factors to surface in `factors` — every signal that nudged the score at all, or only
 *     the ones large enough to be worth a UI chip (e.g. |effect| above some threshold)?
 */
export function riskScore(s: RiskSignals): RiskResult {
  // Placeholder until the author writes the weighting: base severity only.
  return { score: provisionalScore(s.baseSeverity), factors: [] };
}

/**
 * Product-rule invariants that MUST hold regardless of what `riskScore` computes — enforced here,
 * outside the user's weighting function, so a bug (or a future rewrite) of the weighting can never
 * violate them. Keep this list short and load-bearing; ordinary scoring nuance belongs in
 * `riskScore`, not here.
 *
 *   - The score is always clamped to the schema's documented 0–100 range.
 *   - A known-malicious supply-chain package (ruleId `supply-chain/malicious-package`, or a
 *     `malicious` riskFactor) is never scored below the 'critical' band — malicious packages are a
 *     "drop everything" signal, not a nudge the weighting function could cancel out.
 *   - A finding the AI review explicitly refuted (`ai_refuted` / `ai_false_positive` riskFactor) is
 *     never scored above the top of the 'info' band — once a reviewable AI pass has said "this isn't
 *     real", the UI must not still present it as risky, whatever the raw signals say.
 *
 * Pure: returns a new `RiskResult` (never mutates `result`). Each applied guard is itself recorded
 * as a `policy:*`-prefixed factor, so the UI can show *why* the score was overridden.
 */
export function applyPolicyGuards(finding: Pick<Finding, 'ruleId' | 'riskFactors'>, result: RiskResult): RiskResult {
  let score = Math.min(100, Math.max(0, result.score));
  const factors = [...result.factors];

  const isMalicious = finding.ruleId === MALICIOUS_RULE_ID || finding.riskFactors.some((f) => f.factor === 'malicious');
  if (isMalicious && score < SEVERITY_BANDS.critical) {
    factors.push({
      factor: 'policy:malicious-floor', effect: SEVERITY_BANDS.critical - score,
      reason: 'Known malicious packages are never scored below critical',
    });
    score = SEVERITY_BANDS.critical;
  }

  const infoCeiling = SEVERITY_BANDS.low - 1;
  const isAiRefuted = finding.riskFactors.some((f) => f.factor === 'ai_refuted' || f.factor === 'ai_false_positive');
  // Malicious always wins: a malicious package is never itself AI-reviewed, but guard the ordering
  // explicitly so these two rules can never fight over the same score.
  if (!isMalicious && isAiRefuted && score > infoCeiling) {
    factors.push({
      factor: 'policy:ai-refuted-ceiling', effect: infoCeiling - score,
      reason: 'AI review refuted this finding; never scored above info',
    });
    score = infoCeiling;
  }

  return { score, factors };
}
