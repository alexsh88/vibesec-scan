import { describe, expect, it } from 'vitest';
import type { Finding } from '@vibesec/shared';
import { classifyFileContext, extractRiskSignals, type RiskSignalContext } from '../src/scoring/factors';

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

describe('classifyFileContext', () => {
  it.each([
    ['test/foo.ts', 'test'],
    ['src/__tests__/foo.ts', 'test'],
    ['src/foo.test.ts', 'test'],
    ['src/foo.spec.tsx', 'test'],
    ['fixtures/data.json', 'test'],
    ['examples/demo.ts', 'example'],
    ['example/demo.ts', 'example'],
    ['docs/readme.ts', 'docs'],
    ['README.md', 'docs'],
    ['vendor/lib/foo.js', 'generated'],
    ['src/index.ts', 'source'],
  ] as const)('classifies %s as %s', (path, expected) => {
    expect(classifyFileContext(path)).toBe(expected);
  });

  it('prefers test over docs when a path matches both (test/README.md)', () => {
    expect(classifyFileContext('test/README.md')).toBe('test');
  });

  it('prefers test over generated when a path matches both (vendor/foo.test.ts)', () => {
    expect(classifyFileContext('vendor/foo.test.ts')).toBe('test');
  });
});

describe('extractRiskSignals', () => {
  it('passes baseSeverity and confidence through unchanged', () => {
    const finding = makeFinding({ baseSeverity: 'critical', confidence: 'low' });
    const signals = extractRiskSignals(finding, emptyCtx);
    expect(signals.baseSeverity).toBe('critical');
    expect(signals.confidence).toBe('low');
  });

  describe('cvss', () => {
    it('is null for a finding with no dependency block', () => {
      expect(extractRiskSignals(makeFinding(), emptyCtx).cvss).toBeNull();
    });

    it('is the max advisory cvss, ignoring nulls', () => {
      const finding = makeFinding({
        category: 'dependency',
        dependency: {
          ecosystem: 'npm', name: 'left-pad', version: '1.0.0', scope: 'prod', direct: true, paths: [],
          advisories: [
            { id: 'GHSA-1', aliases: [], summary: '', severity: 'high', cvss: 5, fixedIn: null, url: null },
            { id: 'GHSA-2', aliases: [], summary: '', severity: 'high', cvss: null, fixedIn: null, url: null },
            { id: 'GHSA-3', aliases: [], summary: '', severity: 'critical', cvss: 9.1, fixedIn: null, url: null },
          ],
          reachability: 'reachable',
        },
      });
      expect(extractRiskSignals(finding, emptyCtx).cvss).toBe(9.1);
    });

    it('is null when every advisory lacks a cvss', () => {
      const finding = makeFinding({
        category: 'dependency',
        dependency: {
          ecosystem: 'npm', name: 'left-pad', version: '1.0.0', scope: 'prod', direct: true, paths: [],
          advisories: [{ id: 'GHSA-1', aliases: [], summary: '', severity: 'high', cvss: null, fixedIn: null, url: null }],
          reachability: 'reachable',
        },
      });
      expect(extractRiskSignals(finding, emptyCtx).cvss).toBeNull();
    });
  });

  describe('secret signals', () => {
    it('defaults to null/false with no secret block', () => {
      const signals = extractRiskSignals(makeFinding(), emptyCtx);
      expect(signals.liveness).toBeNull();
      expect(signals.inHistoryOnly).toBe(false);
    });

    it('reads liveness and inHistoryOnly straight off the schema field', () => {
      const finding = makeFinding({
        secret: { type: 'aws_access_key', redacted: 'AKIA***', liveness: 'live', inHistoryOnly: true },
      });
      const signals = extractRiskSignals(finding, emptyCtx);
      expect(signals.liveness).toBe('live');
      expect(signals.inHistoryOnly).toBe(true);
    });
  });

  describe('clientExposed', () => {
    it('is false with no matching riskFactor', () => {
      expect(extractRiskSignals(makeFinding(), emptyCtx).clientExposed).toBe(false);
    });

    it('is true when a clientExposed riskFactor is present', () => {
      const finding = makeFinding({ riskFactors: [{ factor: 'clientExposed', effect: 1, reason: 'public asset' }] });
      expect(extractRiskSignals(finding, emptyCtx).clientExposed).toBe(true);
    });
  });

  describe('dependency signals', () => {
    it('defaults to null with no dependency block', () => {
      const signals = extractRiskSignals(makeFinding(), emptyCtx);
      expect(signals.reachability).toBeNull();
      expect(signals.scope).toBeNull();
      expect(signals.direct).toBeNull();
    });

    it('reads reachability, scope and direct off the dependency block', () => {
      const finding = makeFinding({
        category: 'dependency',
        dependency: {
          ecosystem: 'npm', name: 'left-pad', version: '1.0.0', scope: 'dev', direct: false, paths: [],
          advisories: [], reachability: 'unreachable',
        },
      });
      const signals = extractRiskSignals(finding, emptyCtx);
      expect(signals.reachability).toBe('unreachable');
      expect(signals.scope).toBe('dev');
      expect(signals.direct).toBe(false);
    });
  });

  describe('entrypointExposure', () => {
    it('is true when the finding file is a known entrypoint', () => {
      const finding = makeFinding({ location: { ...makeFinding().location, file: 'api/handler.ts' } });
      const ctx: RiskSignalContext = { entrypoints: new Set(['api/handler.ts']) };
      expect(extractRiskSignals(finding, ctx).entrypointExposure).toBe(true);
    });

    it('is true when the taint trace starts inside a known entrypoint, even if the finding file is not one', () => {
      const finding = makeFinding({
        taintTrace: [
          { kind: 'source', file: 'api/handler.ts', line: 1, code: 'req.body', note: 'tainted input' },
          { kind: 'sink', file: 'src/db.ts', line: 10, code: 'query(x)', note: 'sink' },
        ],
      });
      const ctx: RiskSignalContext = { entrypoints: new Set(['api/handler.ts']) };
      expect(extractRiskSignals(finding, ctx).entrypointExposure).toBe(true);
    });

    it('is false when neither the file nor the trace start is a known entrypoint', () => {
      const finding = makeFinding();
      const ctx: RiskSignalContext = { entrypoints: new Set(['other/file.ts']) };
      expect(extractRiskSignals(finding, ctx).entrypointExposure).toBe(false);
    });
  });

  describe('publicRouteExposure', () => {
    it('is false when ctx.publicRoutes is omitted, even if entrypoints exposes the file', () => {
      const finding = makeFinding();
      const ctx: RiskSignalContext = { entrypoints: new Set(['src/a.ts']) };
      expect(extractRiskSignals(finding, ctx).publicRouteExposure).toBe(false);
    });

    it('is true when the finding file is in the public-routes subset', () => {
      const finding = makeFinding();
      const ctx: RiskSignalContext = { entrypoints: new Set(['src/a.ts']), publicRoutes: new Set(['src/a.ts']) };
      expect(extractRiskSignals(finding, ctx).publicRouteExposure).toBe(true);
    });

    it('is false when publicRoutes is provided but does not contain the file', () => {
      const finding = makeFinding();
      const ctx: RiskSignalContext = { entrypoints: new Set(['src/a.ts']), publicRoutes: new Set(['other.ts']) };
      expect(extractRiskSignals(finding, ctx).publicRouteExposure).toBe(false);
    });
  });

  describe('AI/skeptic/malicious flags', () => {
    it('detects ai_refuted from either analyzer-specific factor name', () => {
      expect(extractRiskSignals(makeFinding({ riskFactors: [{ factor: 'ai_refuted', effect: -3, reason: 'r' }] }), emptyCtx).aiRefuted).toBe(true);
      expect(extractRiskSignals(makeFinding({ riskFactors: [{ factor: 'ai_false_positive', effect: -3, reason: 'r' }] }), emptyCtx).aiRefuted).toBe(true);
      expect(extractRiskSignals(makeFinding(), emptyCtx).aiRefuted).toBe(false);
    });

    it('detects ai_unreviewed', () => {
      const finding = makeFinding({ riskFactors: [{ factor: 'ai_unreviewed', effect: 0, reason: 'no verdict' }] });
      expect(extractRiskSignals(finding, emptyCtx).aiUnreviewed).toBe(true);
      expect(extractRiskSignals(makeFinding(), emptyCtx).aiUnreviewed).toBe(false);
    });

    it('detects a skeptic-downgrade factor by case-insensitive substring match', () => {
      const finding = makeFinding({ riskFactors: [{ factor: 'skepticWeakened', effect: -1, reason: 'weakened' }] });
      expect(extractRiskSignals(finding, emptyCtx).skepticWeakened).toBe(true);
      const altName = makeFinding({ riskFactors: [{ factor: 'verify.SKEPTIC_downgrade', effect: -1, reason: 'weakened' }] });
      expect(extractRiskSignals(altName, emptyCtx).skepticWeakened).toBe(true);
      expect(extractRiskSignals(makeFinding(), emptyCtx).skepticWeakened).toBe(false);
    });

    it('detects malicious from the ruleId alone', () => {
      const finding = makeFinding({ ruleId: 'supply-chain/malicious-package', riskFactors: [] });
      expect(extractRiskSignals(finding, emptyCtx).malicious).toBe(true);
    });

    it('detects malicious from a riskFactor alone, even with an unrelated ruleId', () => {
      const finding = makeFinding({ ruleId: 'dependency/vulnerable-package', riskFactors: [{ factor: 'malicious', effect: 0, reason: 'known malicious' }] });
      expect(extractRiskSignals(finding, emptyCtx).malicious).toBe(true);
    });

    it('is false for an ordinary finding', () => {
      expect(extractRiskSignals(makeFinding(), emptyCtx).malicious).toBe(false);
    });
  });

  describe('otherFactors', () => {
    it('passes through riskFactors not already surfaced as a typed flag, and excludes the ones that are', () => {
      const finding = makeFinding({
        riskFactors: [
          { factor: 'live', effect: 2, reason: 'verified live' },
          { factor: 'reachability:reachable', effect: 0, reason: 'reachable' },
          { factor: 'ai_refuted', effect: -3, reason: 'refuted' },
          { factor: 'clientExposed', effect: 1, reason: 'public' },
        ],
      });
      const signals = extractRiskSignals(finding, emptyCtx);
      expect(signals.otherFactors).toEqual([
        { factor: 'live', effect: 2, reason: 'verified live' },
        { factor: 'reachability:reachable', effect: 0, reason: 'reachable' },
      ]);
    });
  });

  it('is deterministic: the same finding and context always produce an equal result', () => {
    const finding = makeFinding({
      riskFactors: [{ factor: 'live', effect: 2, reason: 'verified live' }],
      secret: { type: 'aws_access_key', redacted: 'AKIA***', liveness: 'live', inHistoryOnly: false },
    });
    const ctx: RiskSignalContext = { entrypoints: new Set(['src/a.ts']) };
    expect(extractRiskSignals(finding, ctx)).toEqual(extractRiskSignals(finding, ctx));
  });
});
