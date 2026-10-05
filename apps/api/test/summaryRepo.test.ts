import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { ScanRepo } from '../src/db/scanRepo';
import { SummaryRepo } from '../src/db/summaryRepo';
import { memoryDb } from './helpers';
import { sampleSummary } from './summaryFixture';

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  return { scanId, repo: new SummaryRepo(db, () => new Date('2026-01-01T00:00:00Z')) };
}

describe('SummaryRepo', () => {
  it('returns undefined when no summary is stored', () => {
    const { repo, scanId } = setup();
    expect(repo.get(scanId)).toBeUndefined();
  });

  it('saves and reads back; saving again replaces', () => {
    const { repo, scanId } = setup();
    repo.save(sampleSummary(scanId));
    expect(repo.get(scanId)).toEqual(sampleSummary(scanId));
    repo.save(sampleSummary(scanId, 'F'));
    expect(repo.get(scanId)?.riskGrade).toBe('F');
  });

  it('rejects an invalid summary', () => {
    const { repo, scanId } = setup();
    expect(() => repo.save({ ...sampleSummary(scanId), riskGrade: 'E' as never })).toThrow();
    expect(() => repo.save({ ...sampleSummary(scanId), headline: 'x'.repeat(161) })).toThrow();
    expect(() => repo.save({ ...sampleSummary(scanId), topRisks: [{ ...sampleSummary(scanId).topRisks[0]!, findingIds: [] }] })).toThrow();
  });
});
