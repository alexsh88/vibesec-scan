// Full-scan cache hits (spec §11): a copied result must have its triage / new-existing-fixed recomputed for
// THIS scan, and only clean (COMPLETED or info-only warnings), fresh, originally-analyzed scans are served.
import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema, type Finding } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { CoverageRepo } from '../src/db/coverageRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { FixPlanRepo } from '../src/db/fixPlanRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { ScanRepo, type ScanWarning } from '../src/db/scanRepo';
import { SummaryRepo } from '../src/db/summaryRepo';
import { withFullScanCache, type FullCacheDeps } from '../src/pipeline/stages/fullCache';
import { SKIP_REMAINING_STAGES, type PipelineContext, type StageSpec } from '../src/pipeline/types';
import { analyzerVersionsHash, resultOptionsHash } from '../src/scans/cacheKeys';
import { SuppressionRepo } from '../src/suppressions/suppressionRepo';
import { SuppressionService } from '../src/suppressions/suppressionService';
import { mkFinding } from './findingFactory';
import { memoryDb } from './helpers';
import { sampleSummary } from './summaryFixture';

const SHA = 'a'.repeat(40);
const KEYS = { resultOptionsHash: 'r', analyzerVersionsHash: 'v' };
const HOUR = 3_600_000;

function setup(opts: { queryNow?: () => string } = {}) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const findings = new FindingRepo(db);
  const summaries = new SummaryRepo(db);
  const suppressionRepo = new SuppressionRepo(db);
  const suppressions = new SuppressionService(suppressionRepo, findings, scans, new AuditLogger(db));
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const newScan = () => scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  const finish = (id: string, state: 'COMPLETED' | 'COMPLETED_WITH_WARNINGS' = 'COMPLETED', warnings: ScanWarning[] = []) => {
    scans.setCommitSha(id, SHA);
    scans.setCacheKeys(id, KEYS);
    for (const w of warnings) scans.addWarning(id, w);
    scans.transitionState(id, state);
  };
  const deps: FullCacheDeps = {
    scans: opts.queryNow ? new ScanRepo(db, opts.queryNow) : scans,
    findings, coverage: new CoverageRepo(db), indexRepo: new IndexRepo(db), summaries, fixPlans: new FixPlanRepo(db),
    suppressions, cacheKeys: () => KEYS, atomically: (fn) => db.transaction(fn)(), fullCacheTtlMs: 24 * HOUR,
  };
  const resolve: StageSpec = { name: 'RESOLVING', fatal: true, run: async (ctx) => { ctx.checkpointData.commitSha = SHA; scans.setCommitSha(ctx.scanId, SHA); } };
  const run = async (scanId: string) => {
    const warnings: ScanWarning[] = [];
    const ctx: PipelineContext = {
      scanId, scan: scans.getDto(scanId)!, secrets: {}, signal: new AbortController().signal, checkpointData: {},
      emit: () => {}, warn: (w) => { warnings.push(w); }, touch: () => {},
    };
    await withFullScanCache(resolve, deps).run(ctx);
    return { hit: ctx.checkpointData[SKIP_REMAINING_STAGES] === true, warnings };
  };
  return { db, scans, findings, summaries, suppressionRepo, repo, newScan, finish, run };
}

const f = (scanId: string, fp: string, over: Partial<Finding> = {}): Finding =>
  mkFinding({ id: `${scanId.slice(0, 8)}-${fp}`, scanId, fingerprint: fp, ...over });

describe('full-scan cache hit recomputes per-scan state', () => {
  it('drops the copied triage and fixed rows, then re-applies suppressions, new/existing and the summary stats', async () => {
    const { scans, findings, summaries, suppressionRepo, repo, newScan, finish, run } = setup();
    const src = newScan();
    findings.replaceForAnalyzer(src, 'sast', [
      f(src, 'triaged', { triage: { status: 'false_positive', reason: 'old decision, since cleared', at: '2026-01-01T00:00:00.000Z' } }),
      f(src, 'plain'),
    ]);
    findings.saveAnalyzerResult(src, 'sast', []);
    findings.replaceFixed(src, [{ analyzer: 'sast', finding: f(src, 'gone', { scanStatus: 'fixed' }) }]);
    summaries.save(sampleSummary(src));
    finish(src);
    suppressionRepo.set({ repoId: repo.id, fingerprint: 'plain', status: 'accepted_risk', reason: 'known', createdBy: 'local-user', expiresAt: null });

    const cur = newScan();
    expect((await run(cur)).hit).toBe(true);
    expect(scans.getDto(cur)?.cacheHit).toBe('full');
    const byFp = new Map(findings.all(cur, { includeFixed: true }).map((r) => [r.finding.fingerprint, r.finding]));
    expect([...byFp.keys()].sort()).toEqual(['plain', 'triaged']); // the source's fixed row is not copied
    expect(byFp.get('triaged')?.triage).toBeUndefined(); // the cleared decision is not resurrected
    expect(byFp.get('plain')?.triage).toMatchObject({ status: 'accepted_risk', reason: 'known' });
    // Same commit, same configuration: the source is the baseline, so nothing is new.
    expect([...byFp.values()].map((x) => x.scanStatus)).toEqual(['existing', 'existing']);
    expect(summaries.get(cur)?.stats.total).toBe(2);
  });
});

describe('full-scan cache source selection', () => {
  it('never serves a scan whose warnings are not all info-level', async () => {
    const { newScan, finish, run } = setup();
    const degraded = newScan();
    finish(degraded, 'COMPLETED_WITH_WARNINGS', [{ code: 'ANALYZER_FAILED', message: 'sast failed', stage: 'ANALYZING' }]);
    expect((await run(newScan())).hit).toBe(false);
  });

  it('serves a scan whose warnings are all info-level', async () => {
    const { newScan, finish, run } = setup();
    const src = newScan();
    finish(src, 'COMPLETED_WITH_WARNINGS', [{ code: 'INCREMENTAL_DIFF_TOO_LARGE', message: 'm', stage: 'ANALYZING', level: 'info' }]);
    expect((await run(newScan())).hit).toBe(true);
  });

  it('never serves a result older than FULL_CACHE_TTL_HOURS', async () => {
    const { newScan, finish, run } = setup({ queryNow: () => new Date(Date.now() + 25 * HOUR).toISOString() });
    finish(newScan());
    expect((await run(newScan())).hit).toBe(false);
  });

  it('never serves a copy (the TTL counts from the original analysis)', async () => {
    const { db, newScan, finish, run } = setup();
    const copy = newScan();
    finish(copy);
    db.prepare(`UPDATE scans SET cache_hit = 'full' WHERE id = ?`).run(copy);
    expect((await run(newScan())).hit).toBe(false);
  });
});

describe('cache keys cover every input that changes a result', () => {
  it('resultOptionsHash uses the effective budget (server default when the scan sets none)', () => {
    const o = ScanOptionsSchema.parse({});
    expect(resultOptionsHash(o, { defaultBudgetUsd: 10 })).not.toBe(resultOptionsHash(o, { defaultBudgetUsd: 2 }));
    expect(resultOptionsHash(o, { defaultBudgetUsd: 10 })).toBe(resultOptionsHash({ ...o, budgetUsd: 10 }, { defaultBudgetUsd: 3 }));
  });

  it('analyzerVersionsHash covers index limits and sandbox flags', () => {
    const cfg = { analyzers: [], promptVersions: [], models: {}, llmMode: 'mock', environment: { maxFiles: 10, maxFileBytes: 1, sandboxEnabled: false, sandboxInstall: false } };
    const h = analyzerVersionsHash(cfg);
    expect(analyzerVersionsHash({ ...cfg, environment: { ...cfg.environment, maxFiles: 11 } })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, environment: { ...cfg.environment, sandboxEnabled: true } })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, environment: { ...cfg.environment, sandboxInstall: true } })).not.toBe(h);
  });
});
