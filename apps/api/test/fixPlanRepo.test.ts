import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema, type FixPlan } from '@vibesec/shared';
import { FixPlanRepo } from '../src/db/fixPlanRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { memoryDb } from './helpers';

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  return { scanId, repo: new FixPlanRepo(db, () => new Date('2026-01-01T00:00:00Z')) };
}

const plan = (scanId: string, to = '4.17.21'): FixPlan => ({
  scanId,
  actions: [{
    id: 'fx_1', scanId, ecosystem: 'npm', manifestDir: '', lockfile: 'package-lock.json', kind: 'upgrade-direct', package: 'lodash',
    from: '4.17.20', to, semverJump: 'patch', breakingRisk: false,
    resolves: [{ findingId: 'f1', advisoryId: 'GHSA-1', severity: 'high', package: 'lodash', version: '4.17.20' }],
    resolvedCount: 1, riskReduced: 70, effort: 1, priority: 70, command: `npm install lodash@${to}`, notes: [],
  }],
  unfixable: [{ package: 'evil', version: '1.0.0', advisoryIds: ['MAL-1'], reason: 'no fixed version published' }],
});

describe('FixPlanRepo', () => {
  it('returns undefined when no plan is stored', () => {
    const { repo, scanId } = setup();
    expect(repo.get(scanId)).toBeUndefined();
  });

  it('saves and reads back; saving again replaces', () => {
    const { repo, scanId } = setup();
    repo.save(plan(scanId));
    expect(repo.get(scanId)).toEqual(plan(scanId));
    repo.save(plan(scanId, '4.18.0'));
    expect(repo.get(scanId)?.actions[0]?.to).toBe('4.18.0');
  });

  it('rejects an invalid plan', () => {
    const { repo, scanId } = setup();
    expect(() => repo.save({ ...plan(scanId), actions: [{ ...plan(scanId).actions[0]!, kind: 'nope' as never }] })).toThrow();
  });
});
