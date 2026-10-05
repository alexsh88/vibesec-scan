// SCORING stage, part 2/2 (P7): turns `RiskSignals` (factors.ts) into the 0-100 `riskScore` and
// `severity` persisted on a Finding. The weighting itself (`riskScore` below) is deliberately a
// placeholder — see its doc comment — but the severity bands and the policy guards around it are
// real product rules, not placeholders, and are exercised by scoreStage.ts on every finding.

import type { Finding, Severity } from '@vibesec/shared';
import type { RiskSignals } from './factors';
import { MALICIOUS_RULE_ID } from './factors';

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

/** Impact anchor per base severity (0–100), before any likelihood/context adjustment. */
const IMPACT: Record<Severity, number> = { critical: 92, high: 75, medium: 52, low: 28, info: 8 };
/** Chips smaller than this many points are not shown (they still move the score). */
const MIN_VISIBLE_EFFECT = 2;

/**
 * Risk = impact × likelihood, adjusted by context — the model used by contextual-prioritization
 * products (OX Security: reachability, exploitability, exposure, business impact on top of raw
 * CVSS; Snyk Risk Score: CVSS impact × likelihood incl. exploit signals, reachability, transitive
 * depth, malicious packages).
 *
 * - Impact: the base-severity anchor, or the advisory CVSS (×10) when higher.
 * - Likelihood/context: multipliers applied in a fixed order. Each one is converted into the point
 *   difference it caused, so every factor becomes an explainable UI chip ("Live credential +23").
 * - Confidence is applied once, here (analyzers set confidence; they don't fold it into severity).
 * - Hard product rules (malicious ⇒ critical, AI-refuted ⇒ info, 0–100 clamp) are NOT here: they
 *   live in `applyPolicyGuards`, so a weighting tweak can never break them.
 */
export function riskScore(s: RiskSignals): RiskResult {
  const factors: ScoredFactor[] = [];
  let score = s.cvss !== null ? Math.max(IMPACT[s.baseSeverity], s.cvss * 10) : IMPACT[s.baseSeverity];
  const apply = (factor: string, multiplier: number, reason: string) => {
    const next = Math.min(100, score * multiplier);
    const effect = Math.round(next - score);
    score = next;
    if (Math.abs(effect) >= MIN_VISIBLE_EFFECT) factors.push({ factor, effect, reason });
  };

  // Exploitability — credentials
  if (s.liveness === 'live') apply('live_credential', 1.3, 'Credential verified live against the provider');
  if (s.liveness === 'revoked') apply('revoked_credential', 0.35, 'Credential rejected by the provider (revoked)');
  if (s.inHistoryOnly && s.liveness !== 'live') apply('history_only', 0.75, 'Only in git history, not in current code');
  if (s.clientExposed) apply('client_exposed', 1.2, 'Shipped to browsers via a public env prefix');
  // Exploitability — dependencies (root vs inner library)
  if (s.reachability === 'reachable') apply('reachable', 1.15, 'Vulnerable code is called from the application');
  if (s.reachability === 'unknown' && s.direct === false) apply('transitive_unknown', 0.85, 'Transitive dependency; reachable only through its parent');
  if (s.reachability === 'unreachable') apply('unreachable', 0.45, 'Package is never imported by application code');
  if (s.scope === 'dev') apply('dev_dependency', 0.6, 'Development-only dependency, not shipped');
  // Exposure — code
  if (s.publicRouteExposure) apply('public_route', 1.2, 'Reachable from a public route');
  else if (s.entrypointExposure) apply('entrypoint', 1.1, 'Starts at an application entrypoint');
  // Context
  if (s.fileContext === 'test' || s.fileContext === 'example' || s.fileContext === 'docs') {
    apply('non_production_code', 0.4, `Located in ${s.fileContext} code`);
  } else if (s.fileContext === 'generated') apply('generated_code', 0.7, 'Located in generated/vendored code');
  // Confidence and AI review
  if (s.confidence === 'medium') apply('medium_confidence', 0.9, 'Medium confidence');
  if (s.confidence === 'low') apply('low_confidence', 0.7, 'Low confidence');
  // skeptic_weakened: no multiplier here — the skeptic already lowered the confidence one step, and that
  // confidence is applied just above; a second ×0.85 would penalize the same verdict twice.
  if (s.aiUnreviewed) apply('ai_unreviewed', 0.95, 'AI review returned no verdict');

  return { score: Math.round(score), factors };
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
 *     real", the UI must not still present it as risky, whatever the raw signals say. EXCEPT a
 *     credential verified live against its provider: liveness is ground truth, so no AI verdict caps it.
 *   - A credential verified live is never scored below the 'high' band (history-only, test-path or
 *     AI-doubted context may lower the weighting, but a working key is always a high-priority issue).
 *
 * Pure: returns a new `RiskResult` (never mutates `result`). Each applied guard is itself recorded
 * as a `policy:*`-prefixed factor, so the UI can show *why* the score was overridden.
 */
export function applyPolicyGuards(finding: Pick<Finding, 'ruleId' | 'riskFactors' | 'secret'>, result: RiskResult): RiskResult {
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
  const isLive = finding.secret?.liveness === 'live';
  const isAiRefuted = finding.riskFactors.some((f) => f.factor === 'ai_refuted' || f.factor === 'ai_false_positive');
  // Malicious always wins: a malicious package is never itself AI-reviewed, but guard the ordering
  // explicitly so these two rules can never fight over the same score. A credential the provider
  // ACCEPTED is ground truth: no AI opinion can hide it.
  if (!isMalicious && !isLive && isAiRefuted && score > infoCeiling) {
    factors.push({
      factor: 'policy:ai-refuted-ceiling', effect: infoCeiling - score,
      reason: 'AI review refuted this finding; never scored above info',
    });
    score = infoCeiling;
  }

  if (isLive && score < SEVERITY_BANDS.high) {
    factors.push({
      factor: 'policy:live-credential-floor', effect: SEVERITY_BANDS.high - score,
      reason: 'Credentials verified live are never scored below high',
    });
    score = SEVERITY_BANDS.high;
  }

  return { score, factors };
}
