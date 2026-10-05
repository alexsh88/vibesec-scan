import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Finding, ScanEvent } from '@vibesec/shared';
import { FindingRepo } from '../src/db/findingRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { ScanRepo, type ScanWarning } from '../src/db/scanRepo';
import { scoreStage } from '../src/pipeline/stages/scoreStage';
import type { PipelineContext } from '../src/pipeline/types';
import { severityFromScore } from '../src/scoring/riskScore';
import { memoryDb } from './helpers';
import type { RepoIndex } from '../src/index/types';

let findingSeq = 0;
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  findingSeq += 1;
  return {
    id: `f-${findingSeq}`,
    scanId: 'scan-1',
    fingerprint: `fp-${findingSeq}`,
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

function emptyIndex(): RepoIndex {
  return {
    files: [], imports: [], entrypoints: [],
    stats: { totalFiles: 0, indexedFiles: 0, skipped: {}, byLanguage: {}, imports: 0, entrypoints: 0, truncated: false },
  };
}

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const findings = new FindingRepo(db);
  const indexRepo = new IndexRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null,
    options: { verifySecrets: false, historyDepth: 50, categories: ['secret', 'dependency'] },
    optionsHash: randomUUID(), idempotencyKey: null, hasAuth: false,
  }).id;
  scans.setCommitSha(scanId, '0'.repeat(40));
  const scan = scans.getDto(scanId)!;
  const controller = new AbortController();
  const warnings: ScanWarning[] = [];
  const events: ScanEvent[] = [];
  const ctx: PipelineContext = {
    scanId,
    scan,
    secrets: {},
    signal: controller.signal,
    checkpointData: { commitSha: '0'.repeat(40) },
    emit: (event) => { events.push(event); },
    warn: (w) => { warnings.push(w); },
    touch: () => {},
  };
  return { ctx, findings, indexRepo, scanId, db };
}

describe('scoreStage', () => {
  it('is a no-op when there are no findings', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const stage = scoreStage({ findings, indexRepo });
    await expect(stage.run(ctx)).resolves.toBeUndefined();
    expect(findings.all(ctx.scanId)).toHaveLength(0);
  });

  it('scores every finding, leaving baseSeverity untouched and syncing severity to the new score', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const secretFinding = makeFinding({ scanId: ctx.scanId, category: 'secret', baseSeverity: 'high' });
    const depFinding = makeFinding({ scanId: ctx.scanId, category: 'dependency', baseSeverity: 'medium' });
    findings.replaceForAnalyzer(ctx.scanId, 'credentials', [secretFinding]);
    findings.replaceForAnalyzer(ctx.scanId, 'dependencies', [depFinding]);

    const stage = scoreStage({ findings, indexRepo });
    await stage.run(ctx);

    const secretAfter = findings.get(ctx.scanId, secretFinding.id)!;
    const depAfter = findings.get(ctx.scanId, depFinding.id)!;
    expect(secretAfter.baseSeverity).toBe('high');
    expect(depAfter.baseSeverity).toBe('medium');
    expect(secretAfter.severity).toBe(severityFromScore(secretAfter.riskScore));
    expect(depAfter.severity).toBe(severityFromScore(depAfter.riskScore));
    expect(secretAfter.riskScore).toBeGreaterThanOrEqual(0);
    expect(secretAfter.riskScore).toBeLessThanOrEqual(100);
  });

  it('keeps informative analyzer riskFactors (e.g. ai_refuted) after scoring', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const finding = makeFinding({
      scanId: ctx.scanId,
      riskFactors: [{ factor: 'ai_refuted', effect: -3, reason: 'AI judged this a false positive' }],
    });
    findings.replaceForAnalyzer(ctx.scanId, 'config', [finding]);

    await scoreStage({ findings, indexRepo }).run(ctx);

    const after = findings.get(ctx.scanId, finding.id)!;
    const refuted = after.riskFactors.find((f) => f.factor === 'ai_refuted');
    expect(refuted).toMatchObject({ reason: 'AI judged this a false positive' });
  });

  it('on a factor-name collision keeps the analyzer/skeptic reason with the scoring effect', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const finding = makeFinding({
      scanId: ctx.scanId, confidence: 'medium',
      riskFactors: [{ factor: 'medium_confidence', effect: 0, reason: 'Analyzer: only partial evidence in the diff' }],
    });
    findings.replaceForAnalyzer(ctx.scanId, 'config', [finding]);
    await scoreStage({ findings, indexRepo }).run(ctx);
    const merged = findings.get(ctx.scanId, finding.id)!.riskFactors.filter((f) => f.factor === 'medium_confidence');
    expect(merged).toHaveLength(1);
    expect(merged[0]!.reason).toBe('Analyzer: only partial evidence in the diff');
    expect(merged[0]!.effect).toBeLessThan(0);
  });

  it('keeps the skeptic reason and does not penalize a weakened finding twice (confidence step only)', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const weakened = makeFinding({
      scanId: ctx.scanId, confidence: 'medium',
      riskFactors: [{ factor: 'skeptic_weakened', effect: 0, reason: 'input is an admin-only setting (evidence: line 4)' }],
    });
    const plain = makeFinding({ scanId: ctx.scanId, confidence: 'medium' });
    findings.replaceForAnalyzer(ctx.scanId, 'config', [weakened, plain]);
    await scoreStage({ findings, indexRepo }).run(ctx);
    const w = findings.get(ctx.scanId, weakened.id)!;
    expect(w.riskScore).toBe(findings.get(ctx.scanId, plain.id)!.riskScore);
    expect(w.riskFactors.find((f) => f.factor === 'skeptic_weakened')).toMatchObject({ reason: 'input is an admin-only setting (evidence: line 4)' });
  });

  it('never leaves a malicious-package finding scored below critical (policy guard, not the weighting)', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    // baseSeverity intentionally low to prove the FLOOR comes from the policy guard, not from
    // provisionalScore(baseSeverity) happening to already be high.
    const finding = makeFinding({ scanId: ctx.scanId, category: 'dependency', ruleId: 'supply-chain/malicious-package', baseSeverity: 'low' });
    findings.replaceForAnalyzer(ctx.scanId, 'dependencies', [finding]);

    await scoreStage({ findings, indexRepo }).run(ctx);

    const after = findings.get(ctx.scanId, finding.id)!;
    expect(after.severity).toBe('critical');
    expect(after.riskScore).toBeGreaterThanOrEqual(85);
    expect(after.baseSeverity).toBe('low');
    expect(after.riskFactors.some((f) => f.factor === 'policy:malicious-floor')).toBe(true);
  });

  it('never leaves an ai_refuted finding scored above info (policy guard, not the weighting)', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const finding = makeFinding({
      scanId: ctx.scanId, baseSeverity: 'critical',
      riskFactors: [{ factor: 'ai_refuted', effect: -80, reason: 'refuted' }],
    });
    findings.replaceForAnalyzer(ctx.scanId, 'credentials', [finding]);

    await scoreStage({ findings, indexRepo }).run(ctx);

    const after = findings.get(ctx.scanId, finding.id)!;
    expect(after.severity).toBe('info');
    expect(after.riskScore).toBeLessThanOrEqual(14);
    expect(after.baseSeverity).toBe('critical');
  });

  it('is idempotent: scoring an already-scored finding again produces the same result', async () => {
    const { ctx, findings, indexRepo } = setup();
    indexRepo.replace(ctx.scanId, emptyIndex());
    const finding = makeFinding({
      scanId: ctx.scanId, baseSeverity: 'high',
      riskFactors: [{ factor: 'ai_refuted', effect: -3, reason: 'refuted' }],
    });
    findings.replaceForAnalyzer(ctx.scanId, 'credentials', [finding]);

    const stage = scoreStage({ findings, indexRepo });
    await stage.run(ctx);
    const afterFirst = findings.get(ctx.scanId, finding.id)!;
    await stage.run(ctx);
    const afterSecond = findings.get(ctx.scanId, finding.id)!;

    expect(afterSecond).toEqual(afterFirst);
  });

  it('reads entrypoints for the scan without throwing when the finding file is one', async () => {
    const { ctx, findings, indexRepo } = setup();
    const index = emptyIndex();
    index.entrypoints = [{ path: 'src/a.ts', kind: 'http-route', line: 1, detail: 'GET /x' }];
    indexRepo.replace(ctx.scanId, index);
    const finding = makeFinding({ scanId: ctx.scanId, location: { ...makeFinding().location, file: 'src/a.ts' } });
    findings.replaceForAnalyzer(ctx.scanId, 'credentials', [finding]);

    await expect(scoreStage({ findings, indexRepo }).run(ctx)).resolves.toBeUndefined();
    expect(findings.get(ctx.scanId, finding.id)).toBeDefined();
  });
});
