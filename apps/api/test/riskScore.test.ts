import { describe, expect, it } from 'vitest';
import type { Finding, Severity } from '@vibesec/shared';
import { extractRiskSignals, type RiskSignalContext } from '../src/scoring/factors';
import { applyPolicyGuards, riskScore, severityFromScore, type RiskResult } from '../src/scoring/riskScore';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1',
    scanId: 'scan-1',
    fingerprint: 'fp-1',
    category: 'secret',
    ruleId: 'secret/aws-access-key',
    title: 'Test finding',
    baseSeverity: 'high',
    riskScore: 70,
    severity: 'high',
    riskFactors: [],
    confidence: 'high',
    location: { file: 'src/a.ts', startLine: 1, endLine: 1, snippet: 'const x = 1;', permalink: 'https://example.com' },
    explanation: 'because',
    impact: 'bad things',
    remediation: { summary: 'fix it' },
    scanStatus: 'new',
    ...overrides,
  };
}

const emptyCtx: RiskSignalContext = { entrypoints: new Set() };
const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

describe('severityFromScore', () => {
  it.each([
    [100, 'critical'], [85, 'critical'],
    [84, 'high'], [65, 'high'],
    [64, 'medium'], [40, 'medium'],
    [39, 'low'], [15, 'low'],
    [14, 'info'], [0, 'info'],
  ] as const)('maps %d to %s', (score, expected) => {
    expect(severityFromScore(score)).toBe(expected);
  });

  it('is well-defined outside [0, 100] (defensive — callers should clamp first)', () => {
    expect(severityFromScore(-5)).toBe('info');
    expect(severityFromScore(150)).toBe('critical');
  });
});

describe('riskScore (placeholder weighting)', () => {
  it.each(SEVERITIES)('returns a score in [0, 100] and a factors array for baseSeverity=%s', (baseSeverity) => {
    const finding = makeFinding({ baseSeverity });
    const signals = extractRiskSignals(finding, emptyCtx);
    const result = riskScore(signals);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(Array.isArray(result.factors)).toBe(true);
  });

  it('is deterministic for the same signals', () => {
    const signals = extractRiskSignals(makeFinding({ baseSeverity: 'medium' }), emptyCtx);
    expect(riskScore(signals)).toEqual(riskScore(signals));
  });
});

describe('applyPolicyGuards', () => {
  it('clamps a score above 100 down to 100', () => {
    const result = applyPolicyGuards(makeFinding(), { score: 140, factors: [] });
    expect(result.score).toBe(100);
  });

  it('clamps a score below 0 up to 0', () => {
    const result = applyPolicyGuards(makeFinding(), { score: -20, factors: [] });
    expect(result.score).toBe(0);
  });

  it('leaves an ordinary in-range score untouched', () => {
    const base: RiskResult = { score: 55, factors: [{ factor: 'x', effect: 5, reason: 'r' }] };
    const result = applyPolicyGuards(makeFinding(), base);
    expect(result).toEqual(base);
  });

  it('never scores a malicious-ruleId finding below the critical band, and records why', () => {
    const finding = makeFinding({ ruleId: 'supply-chain/malicious-package', riskFactors: [] });
    const result = applyPolicyGuards(finding, { score: 30, factors: [] });
    expect(result.score).toBe(85);
    expect(result.factors.some((f) => f.factor === 'policy:malicious-floor')).toBe(true);
    expect(severityFromScore(result.score)).toBe('critical');
  });

  it('never scores a finding with a malicious riskFactor below the critical band', () => {
    const finding = makeFinding({ ruleId: 'dependency/vulnerable-package', riskFactors: [{ factor: 'malicious', effect: 0, reason: 'known malicious' }] });
    const result = applyPolicyGuards(finding, { score: 10, factors: [] });
    expect(result.score).toBe(85);
  });

  it('does not touch a malicious finding already scored at or above critical', () => {
    const finding = makeFinding({ ruleId: 'supply-chain/malicious-package' });
    const result = applyPolicyGuards(finding, { score: 95, factors: [] });
    expect(result.score).toBe(95);
    expect(result.factors.some((f) => f.factor === 'policy:malicious-floor')).toBe(false);
  });

  it('never scores an ai_refuted finding above the top of the info band, and records why', () => {
    const finding = makeFinding({ riskFactors: [{ factor: 'ai_refuted', effect: -60, reason: 'refuted' }] });
    const result = applyPolicyGuards(finding, { score: 70, factors: [] });
    expect(result.score).toBe(14);
    expect(result.factors.some((f) => f.factor === 'policy:ai-refuted-ceiling')).toBe(true);
    expect(severityFromScore(result.score)).toBe('info');
  });

  it('also honours the credentials-analyzer spelling, ai_false_positive', () => {
    const finding = makeFinding({ riskFactors: [{ factor: 'ai_false_positive', effect: -60, reason: 'refuted' }] });
    const result = applyPolicyGuards(finding, { score: 90, factors: [] });
    expect(result.score).toBe(14);
  });

  it('does not touch an ai_refuted finding already at or below the info band', () => {
    const finding = makeFinding({ riskFactors: [{ factor: 'ai_refuted', effect: -60, reason: 'refuted' }] });
    const result = applyPolicyGuards(finding, { score: 5, factors: [] });
    expect(result.score).toBe(5);
    expect(result.factors.some((f) => f.factor === 'policy:ai-refuted-ceiling')).toBe(false);
  });

  it('lets a malicious floor win over a (contradictory, real-world-impossible) ai_refuted ceiling on the same finding', () => {
    const finding = makeFinding({
      ruleId: 'supply-chain/malicious-package',
      riskFactors: [{ factor: 'ai_refuted', effect: -60, reason: 'refuted' }],
    });
    const result = applyPolicyGuards(finding, { score: 10, factors: [] });
    expect(result.score).toBe(85);
  });

  it('does not mutate the result it was given', () => {
    const input: RiskResult = { score: 10, factors: [] };
    applyPolicyGuards(makeFinding({ ruleId: 'supply-chain/malicious-package' }), input);
    expect(input).toEqual({ score: 10, factors: [] });
  });
});
