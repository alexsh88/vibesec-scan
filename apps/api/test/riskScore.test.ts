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

  it('never lets an AI verdict hide a credential verified live: no info ceiling, and a high-band floor', () => {
    const live = makeFinding({
      secret: { type: 'github-pat', redacted: 'ghp_…', liveness: 'live', inHistoryOnly: false },
      riskFactors: [{ factor: 'ai_false_positive', effect: 0, reason: 'looks like a test value' }],
    });
    const capped = applyPolicyGuards(live, { score: 90, factors: [] });
    expect(capped.score).toBe(90);
    expect(capped.factors.some((f) => f.factor === 'policy:ai-refuted-ceiling')).toBe(false);
    const floored = applyPolicyGuards(live, { score: 20, factors: [] });
    expect(floored.score).toBe(65);
    expect(severityFromScore(floored.score)).toBe('high');
    expect(floored.factors).toContainEqual(expect.objectContaining({ factor: 'policy:live-credential-floor', effect: 45 }));
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

describe('riskScore weighting (impact × likelihood/context)', () => {
  const score = (f: Finding, ctx: RiskSignalContext = emptyCtx) => {
    const r = riskScore(extractRiskSignals(f, ctx));
    return { ...r, severity: severityFromScore(r.score) };
  };
  const dep = (over: Partial<NonNullable<Finding['dependency']>>, base: Severity = 'critical') => makeFinding({
    category: 'dependency', ruleId: 'dependency/vulnerable-package', baseSeverity: base,
    dependency: { ecosystem: 'npm', name: 'lodash', version: '4.17.15', scope: 'prod', direct: true, paths: [], advisories: [], reachability: 'imported', ...over },
  });

  it('a live high credential becomes critical, with an explaining chip', () => {
    const r = score(makeFinding({ secret: { type: 'aws-access-key', redacted: 'AKIA…', liveness: 'live', inHistoryOnly: false } }));
    expect(r.severity).toBe('critical');
    expect(r.factors.find((f) => f.factor === 'live_credential')?.effect).toBeGreaterThan(0);
  });

  it('a revoked credential drops to low', () => {
    expect(score(makeFinding({ secret: { type: 'aws-access-key', redacted: 'AKIA…', liveness: 'revoked', inHistoryOnly: false } })).severity).toBe('low');
  });

  it('root vs inner library: reachable direct > imported > transitive-unknown > unreachable > dev+unreachable', () => {
    const s = [
      score(dep({ reachability: 'reachable' })).score,
      score(dep({ reachability: 'imported' })).score,
      score(dep({ reachability: 'unknown', direct: false })).score,
      score(dep({ reachability: 'unreachable' })).score,
      score(dep({ reachability: 'unreachable', scope: 'dev' })).score,
    ];
    expect([...s].sort((a, b) => b - a)).toEqual(s);
    expect(severityFromScore(s[0]!)).toBe('critical');
    expect(severityFromScore(s[3]!)).toBe('medium');
    expect(severityFromScore(s[4]!)).toBe('low');
  });

  it('a critical finding in test code is not ranked as critical', () => {
    const r = score(makeFinding({ category: 'sast', ruleId: 'sast/sql-injection', baseSeverity: 'critical', secret: undefined, location: { file: 'test/fixtures/db.test.ts', startLine: 1, endLine: 1, snippet: '', permalink: '' } }));
    expect(['low', 'medium']).toContain(r.severity);
    expect(r.factors.map((f) => f.factor)).toContain('non_production_code');
  });

  it('public-route exposure raises a high code finding', () => {
    const f = makeFinding({ category: 'sast', ruleId: 'sast/ssrf', baseSeverity: 'high', location: { file: 'src/routes/x.ts', startLine: 1, endLine: 1, snippet: '', permalink: '' } });
    expect(score(f, { entrypoints: new Set(['src/routes/x.ts']), publicRoutes: new Set(['src/routes/x.ts']) }).score)
      .toBeGreaterThan(score(f).score);
  });
});
