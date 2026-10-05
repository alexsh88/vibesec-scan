// planIncremental (spec §11): an analyzer that did not complete in the base scan (no stored result) must
// not lend its coverage to a rescan — its files are analyzed again, never "reused" from a failed run.
import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { CoverageRepo } from '../src/db/coverageRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { planIncremental } from '../src/pipeline/incremental';
import type { PipelineContext } from '../src/pipeline/types';
import { memoryDb } from './helpers';

describe('planIncremental', () => {
  it('gives no base coverage for an analyzer without a stored result in the base scan', async () => {
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const findings = new FindingRepo(db);
    const coverage = new CoverageRepo(db);
    const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
    const keys = { resultOptionsHash: 'r', analyzerVersionsHash: 'v' };
    const scan = (sha: string) => {
      const id = scans.insertScan({ repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false }).id;
      scans.setCommitSha(id, sha);
      scans.setCacheKeys(id, keys);
      return id;
    };
    const base = scan('1'.repeat(40));
    findings.saveAnalyzerResult(base, 'sast', []); // sast completed; quality crashed (no stored result)
    coverage.replaceForScan(base, [
      { analyzer: 'sast', path: 'a.ts', status: 'reviewed' },
      { analyzer: 'quality', path: 'a.ts', status: 'reviewed' },
    ]);
    scans.transitionState(base, 'COMPLETED');
    const cur = scan('2'.repeat(40));

    const ctx = {
      scanId: cur, scan: scans.getDto(cur)!, secrets: {}, signal: new AbortController().signal, checkpointData: {},
      emit: () => {}, warn: () => {}, touch: () => {},
    } satisfies PipelineContext;
    const plan = await planIncremental({
      scans, findings, coverage, indexRepo: new IndexRepo(db), llmCalls: new LlmCallRepo(db),
      git: { diffNameStatus: async () => [], fetchCommit: async () => true },
    }, ctx, { repoDir: '/x', commitSha: '2'.repeat(40), files: [] });
    expect(plan?.baseScanId).toBe(base);
    expect(plan!.baseCoverage('sast').get('a.ts')).toBe('reviewed');
    expect(plan!.baseCoverage('quality').size).toBe(0);
  });
});
