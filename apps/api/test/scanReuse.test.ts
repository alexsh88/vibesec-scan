import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema, type Finding } from '@vibesec/shared';
import { FindingRepo } from '../src/db/findingRepo';
import { ScanRepo } from '../src/db/scanRepo';
import type { Entrypoint, ImportEdge } from '../src/index/types';
import { computeAffected } from '../src/pipeline/incremental';
import { applyScanStatus } from '../src/pipeline/stages/scanStatus';
import { analyzerVersionsHash, resultOptionsHash } from '../src/scans/cacheKeys';
import { memoryDb } from './helpers';

const local = (from: string, to: string): ImportEdge => ({ from, specifier: `./${to}`, kind: 'local', to, pkg: null, line: 1 });
const ep = (path: string): Entrypoint => ({ path, kind: 'http-route', line: 1, detail: null });

describe('computeAffected', () => {
  // server → routes/a → services/x → db ;  routes/b → services/y ; cli → util
  const imports = [
    local('server.ts', 'routes/a.ts'), local('server.ts', 'routes/b.ts'), local('routes/a.ts', 'services/x.ts'),
    local('services/x.ts', 'db.ts'), local('routes/b.ts', 'services/y.ts'), local('cli.ts', 'util.ts'),
  ];
  const entrypoints = [ep('server.ts'), ep('routes/a.ts'), ep('routes/b.ts'), ep('cli.ts')];

  it('is C ∪ reverse imports (depth 2) ∪ entrypoints whose import closure reaches C', () => {
    const affected = computeAffected({ changed: new Set(['db.ts']), deleted: new Set(), imports, entrypoints });
    // depth 1: services/x, depth 2: routes/a; server.ts only via its forward closure (depth 3)
    expect([...affected].sort()).toEqual(['db.ts', 'routes/a.ts', 'server.ts', 'services/x.ts']);
  });

  it('leaves unrelated entrypoints out and counts deleted files as seeds (not as affected files)', () => {
    const affected = computeAffected({ changed: new Set(), deleted: new Set(['services/y.ts']), imports, entrypoints });
    expect([...affected].sort()).toEqual(['routes/b.ts', 'server.ts']);
  });
});

describe('cache keys', () => {
  const cfg = { analyzers: [{ id: 'sast', version: '2' }, { id: 'taint', version: '2' }], promptVersions: ['sast-v2'], models: { fast: 'h', deep: 's' }, llmMode: 'mock' };

  it('analyzerVersionsHash changes with any analyzer version, prompt version, model or LLM mode', () => {
    const h = analyzerVersionsHash(cfg);
    expect(analyzerVersionsHash({ ...cfg, analyzers: [...cfg.analyzers].reverse() })).toBe(h);
    expect(analyzerVersionsHash({ ...cfg, analyzers: [{ id: 'sast', version: '3' }, { id: 'taint', version: '2' }] })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, promptVersions: ['sast-v3'] })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, models: { fast: 'h', deep: 's2' } })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, llmMode: 'live' })).not.toBe(h);
  });

  it('resultOptionsHash ignores category order but not the options themselves', () => {
    const a = ScanOptionsSchema.parse({ categories: ['secret', 'sast'] });
    expect(resultOptionsHash(a)).toBe(resultOptionsHash(ScanOptionsSchema.parse({ categories: ['sast', 'secret'] })));
    expect(resultOptionsHash(a)).not.toBe(resultOptionsHash({ ...a, budgetUsd: 2 }));
  });
});

describe('applyScanStatus (new / existing / fixed)', () => {
  const finding = (scanId: string, fp: string, over: Partial<Finding> = {}): Finding => ({
    id: `${scanId.slice(0, 8)}-${fp}`, scanId, fingerprint: fp, category: 'sast', ruleId: 'sast/x', title: `issue ${fp}`,
    baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [], confidence: 'high',
    location: { file: 'a.ts', startLine: 1, endLine: 1, snippet: 'x', permalink: '' },
    explanation: 'e', impact: 'i', remediation: { summary: 'r' }, scanStatus: 'new', ...over,
  });

  function setup() {
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const findings = new FindingRepo(db);
    const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
    const scan = (categories: Finding['category'][] = ['sast', 'secret']) => scans.insertScan({
      repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({ categories }), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
    }).id;
    const complete = (id: string) => scans.transitionState(id, 'COMPLETED');
    return { scans, findings, scan, complete, deps: { scans, findings } };
  }

  it('marks findings existing/new and copies the previous scan\'s vanished findings as fixed rows (excluded from counts)', () => {
    const { findings, scan, complete, deps } = setup();
    const prev = scan();
    findings.replaceForAnalyzer(prev, 'sast', [finding(prev, 'keep'), finding(prev, 'gone', { severity: 'critical' })]);
    findings.saveAnalyzerResult(prev, 'sast', []);
    complete(prev);

    const cur = scan();
    findings.replaceForAnalyzer(cur, 'sast', [finding(cur, 'keep'), finding(cur, 'fresh')]);
    findings.saveAnalyzerResult(cur, 'sast', []);
    expect(applyScanStatus(deps, cur)).toEqual({ previousScanId: prev, new: 1, existing: 1, fixed: 1 });
    expect(applyScanStatus(deps, cur)).toEqual({ previousScanId: prev, new: 1, existing: 1, fixed: 1 }); // idempotent

    const byFp = new Map(findings.all(cur, { includeFixed: true }).map((r) => [r.finding.fingerprint, r.finding]));
    expect(byFp.get('keep')?.scanStatus).toBe('existing');
    expect(byFp.get('fresh')?.scanStatus).toBe('new');
    expect(byFp.get('gone')).toMatchObject({ scanStatus: 'fixed', severity: 'critical', scanId: cur });
    expect(findings.all(cur).map((r) => r.finding.fingerprint).sort()).toEqual(['fresh', 'keep']);
    expect(findings.counts(cur)).toMatchObject({ total: 2, byScanStatus: { new: 1, existing: 1, fixed: 1 } });
    expect(findings.list(cur, {}).items.map((f) => f.fingerprint).sort()).toEqual(['fresh', 'keep']);
    expect(findings.list(cur, { scanStatus: 'fixed' }).items.map((f) => f.fingerprint)).toEqual(['gone']);
  });

  it('never marks fixed what this scan could not have found again (category off, or its analyzer did not complete)', () => {
    const { findings, scan, complete, deps } = setup();
    const prev = scan();
    findings.replaceForAnalyzer(prev, 'sast', [finding(prev, 's1')]);
    findings.replaceForAnalyzer(prev, 'credentials', [finding(prev, 'c1', { category: 'secret' })]);
    complete(prev);
    const cur = scan(['sast']); // secret category off; sast analyzer failed (no stored result)
    expect(applyScanStatus(deps, cur)).toMatchObject({ new: 0, existing: 0, fixed: 0 });
  });
});
