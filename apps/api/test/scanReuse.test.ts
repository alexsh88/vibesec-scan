import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema, type Finding } from '@vibesec/shared';
import { CoverageRepo } from '../src/db/coverageRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { ScanRepo } from '../src/db/scanRepo';
import type { Entrypoint, ImportEdge, IndexedFile, RepoIndex } from '../src/index/types';
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
  const at = (file: string) => ({ location: { file, startLine: 1, endLine: 1, snippet: 'x', permalink: '' } });
  const SHA1 = '1'.repeat(40);
  const SHA2 = '2'.repeat(40);
  type ScanOpts = { categories?: Finding['category'][]; ref?: string | null; sha?: string; optionsHash?: string };

  function setup(ancestry: (a: string, b: string) => boolean | null = () => true) {
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const findings = new FindingRepo(db);
    const coverage = new CoverageRepo(db);
    const indexRepo = new IndexRepo(db);
    const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
    const scan = (o: ScanOpts = {}) => {
      const id = scans.insertScan({
        repoId: repo.id, ref: o.ref ?? null, options: ScanOptionsSchema.parse({ categories: o.categories ?? ['sast', 'secret', 'dependency'] }),
        optionsHash: 'h', idempotencyKey: null, hasAuth: false,
      }).id;
      scans.setCommitSha(id, o.sha ?? SHA2);
      scans.setCacheKeys(id, { resultOptionsHash: o.optionsHash ?? 'opts', analyzerVersionsHash: 'v' });
      return id;
    };
    const complete = (id: string) => scans.transitionState(id, 'COMPLETED');
    const git = { repoDir: () => '/nowhere', isAncestor: async (_dir: string, a: string, b: string) => ancestry(a, b) };
    return { db, scans, findings, coverage, indexRepo, scan, complete, deps: { scans, findings, coverage, indexRepo, git } };
  }

  it('marks findings existing/new and copies the previous scan\'s vanished findings as fixed rows (excluded from counts)', async () => {
    const { findings, scan, complete, deps } = setup();
    const prev = scan({ sha: SHA1 });
    findings.replaceForAnalyzer(prev, 'sast', [finding(prev, 'keep'), finding(prev, 'gone', { severity: 'critical' })]);
    findings.saveAnalyzerResult(prev, 'sast', []);
    complete(prev);

    const cur = scan();
    findings.replaceForAnalyzer(cur, 'sast', [finding(cur, 'keep'), finding(cur, 'fresh')]);
    findings.saveAnalyzerResult(cur, 'sast', []);
    expect(await applyScanStatus(deps, cur)).toEqual({ previousScanId: prev, new: 1, existing: 1, fixed: 1 });
    expect(await applyScanStatus(deps, cur)).toEqual({ previousScanId: prev, new: 1, existing: 1, fixed: 1 }); // idempotent

    const byFp = new Map(findings.all(cur, { includeFixed: true }).map((r) => [r.finding.fingerprint, r.finding]));
    expect(byFp.get('keep')?.scanStatus).toBe('existing');
    expect(byFp.get('fresh')?.scanStatus).toBe('new');
    expect(byFp.get('gone')).toMatchObject({ scanStatus: 'fixed', severity: 'critical', scanId: cur });
    expect(findings.all(cur).map((r) => r.finding.fingerprint).sort()).toEqual(['fresh', 'keep']);
    expect(findings.counts(cur)).toMatchObject({ total: 2, byScanStatus: { new: 1, existing: 1, fixed: 1 } });
    expect(findings.list(cur, {}).items.map((f) => f.fingerprint).sort()).toEqual(['fresh', 'keep']);
    expect(findings.list(cur, { scanStatus: 'fixed' }).items.map((f) => f.fingerprint)).toEqual(['gone']);
  });

  it('never marks fixed what this scan could not have found again (category off, or its analyzer did not complete)', async () => {
    const { findings, scan, complete, deps } = setup();
    const prev = scan({ categories: ['sast', 'secret'] });
    findings.replaceForAnalyzer(prev, 'sast', [finding(prev, 's1')]);
    findings.replaceForAnalyzer(prev, 'credentials', [finding(prev, 'c1', { category: 'secret' })]);
    complete(prev);
    const cur = scan({ categories: ['sast'] }); // secret category off; sast analyzer failed (no stored result)
    expect(await applyScanStatus(deps, cur)).toMatchObject({ new: 0, existing: 0, fixed: 0 });
  });

  it('matches findings through mergedFingerprints in both directions (another analyzer winning a merge is not new+fixed)', async () => {
    const { findings, scan, complete, deps } = setup();
    const prev = scan({ sha: SHA1 });
    findings.replaceForAnalyzer(prev, 'sast', [finding(prev, 'taint-fp', { mergedFingerprints: ['sast-fp'] }), finding(prev, 'plain-fp')]);
    findings.saveAnalyzerResult(prev, 'sast', []);
    complete(prev);
    const cur = scan();
    findings.replaceForAnalyzer(cur, 'sast', [finding(cur, 'sast-fp'), finding(cur, 'other-fp', { mergedFingerprints: ['plain-fp'] })]);
    findings.saveAnalyzerResult(cur, 'sast', []);
    expect(await applyScanStatus(deps, cur)).toEqual({ previousScanId: prev, new: 0, existing: 2, fixed: 0 });
  });

  describe('baseline selection (no false "fixed")', () => {
    function withPrevious(prevOpts: ScanOpts, ancestry?: (a: string, b: string) => boolean | null, curOpts: ScanOpts = {}) {
      const s = setup(ancestry);
      const prev = s.scan({ sha: SHA1, ...prevOpts });
      s.findings.replaceForAnalyzer(prev, 'sast', [finding(prev, 'old')]);
      s.findings.saveAnalyzerResult(prev, 'sast', []);
      s.complete(prev);
      const cur = s.scan(curOpts);
      s.findings.replaceForAnalyzer(cur, 'sast', [finding(cur, 'now')]);
      s.findings.saveAnalyzerResult(cur, 'sast', []);
      return { ...s, prev, cur };
    }

    it('ignores a previous scan run with other result options', async () => {
      const { deps, cur } = withPrevious({ optionsHash: 'other' });
      expect(await applyScanStatus(deps, cur)).toEqual({ previousScanId: null, new: 1, existing: 0, fixed: 0 });
    });

    it('ignores a previous scan of another ref', async () => {
      const { deps, cur } = withPrevious({ ref: 'feature' }, undefined, { ref: 'main' });
      expect(await applyScanStatus(deps, cur)).toMatchObject({ previousScanId: null, fixed: 0 });
    });

    it('lets a SHA-pinned scan use an earlier SHA-pinned scan (not a branch scan)', async () => {
      const pinned = withPrevious({ ref: SHA1 }, undefined, { ref: SHA2 });
      expect(await applyScanStatus(pinned.deps, pinned.cur)).toMatchObject({ previousScanId: pinned.prev });
      const branch = withPrevious({ ref: 'main' }, undefined, { ref: SHA2 });
      expect(await applyScanStatus(branch.deps, branch.cur)).toMatchObject({ previousScanId: null });
    });

    it('uses a previous scan only when its commit is an ancestor (unknown ancestry = no baseline)', async () => {
      const notAncestor = withPrevious({}, () => false);
      expect(await applyScanStatus(notAncestor.deps, notAncestor.cur)).toMatchObject({ previousScanId: null, fixed: 0 });
      const unknown = withPrevious({}, () => null);
      expect(await applyScanStatus(unknown.deps, unknown.cur)).toMatchObject({ previousScanId: null, fixed: 0 });
      const ancestor = withPrevious({}, (a, b) => a === SHA1 && b === SHA2);
      expect(await applyScanStatus(ancestor.deps, ancestor.cur)).toMatchObject({ previousScanId: ancestor.prev, fixed: 1 });
    });

    it('ignores a scan requested after this one', async () => {
      const s = setup();
      const cur = s.scan();
      const later = s.scan({ sha: SHA1 });
      s.findings.replaceForAnalyzer(later, 'sast', [finding(later, 'old')]);
      s.complete(later);
      s.db.prepare(`UPDATE scans SET created_at = '2999-01-01T00:00:00.000Z' WHERE id = ?`).run(later);
      expect(await applyScanStatus(s.deps, cur)).toMatchObject({ previousScanId: null });
    });
  });

  it('only marks fixed where this scan really looked: reviewed/cached file, deleted file, or a repo-level finding', async () => {
    const { findings, coverage, indexRepo, scan, complete, deps } = setup();
    const prev = scan({ sha: SHA1 });
    findings.replaceForAnalyzer(prev, 'sast', [
      finding(prev, 'skipped', at('budget.ts')), finding(prev, 'reviewed', at('seen.ts')),
      finding(prev, 'deleted', at('removed.ts')), finding(prev, 'too-big', at('huge.ts')),
    ]);
    findings.replaceForAnalyzer(prev, 'dependencies', [finding(prev, 'dep', { category: 'dependency', ...at('package-lock.json') })]);
    complete(prev);

    const cur = scan();
    findings.saveAnalyzerResult(cur, 'sast', []);
    findings.saveAnalyzerResult(cur, 'dependencies', []);
    const file = (path: string, skipReason: IndexedFile['skipReason']): IndexedFile => ({ path, blobSha: 'b', size: 1, language: 'typescript', category: 'source', tags: [], skipReason });
    indexRepo.replace(cur, {
      files: [file('budget.ts', null), file('seen.ts', null), file('huge.ts', 'too_large'), file('package-lock.json', null)],
      imports: [], entrypoints: [], stats: { totalFiles: 4, indexedFiles: 3, skipped: { too_large: 1 }, byLanguage: {}, imports: 0, entrypoints: 0, truncated: false },
    } as RepoIndex);
    coverage.replaceForScan(cur, [
      { analyzer: 'sast', path: 'budget.ts', status: 'budget-skipped' },
      { analyzer: 'sast', path: 'seen.ts', status: 'reviewed' },
    ]);
    await applyScanStatus(deps, cur);
    expect(findings.list(cur, { scanStatus: 'fixed' }).items.map((f) => f.fingerprint).sort()).toEqual(['deleted', 'dep', 'reviewed']);
  });
});
