import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { IndexRepo } from '../src/db/indexRepo';
import { ScanRepo } from '../src/db/scanRepo';
import type { RepoIndex } from '../src/index/types';
import { memoryDb } from './helpers';

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  return { db, scans, repo, scanId, index: new IndexRepo(db) };
}

const sample: RepoIndex = {
  files: [
    { path: 'src/a.ts', blobSha: 'a'.repeat(40), size: 10, language: 'typescript', category: 'source', tags: [], skipReason: null },
    { path: 'node_modules/x/i.js', blobSha: 'b'.repeat(40), size: 5, language: 'javascript', category: 'source', tags: [], skipReason: 'vendor' },
  ],
  imports: [
    { from: 'src/a.ts', specifier: './b', kind: 'local', to: 'src/b.ts', pkg: null, line: 1 },
    { from: 'src/a.ts', specifier: 'express', kind: 'package', to: null, pkg: 'express', line: 2 },
  ],
  entrypoints: [{ path: 'src/a.ts', kind: 'http-route', line: 3, detail: 'GET /' }],
  stats: { totalFiles: 2, indexedFiles: 1, skipped: { vendor: 1 }, byLanguage: { typescript: 1 }, imports: 2, entrypoints: 1, truncated: false },
};

describe('IndexRepo', () => {
  it('round-trips an index and its stats', () => {
    const { index, scanId } = setup();
    index.replace(scanId, sample);
    expect(index.files(scanId)).toEqual([sample.files[0]]);
    expect(index.files(scanId, { includeSkipped: true })).toHaveLength(2);
    expect(index.imports(scanId)).toEqual(sample.imports);
    expect(index.entrypoints(scanId)).toEqual(sample.entrypoints);
    expect(index.stats(scanId)).toEqual(sample.stats);
  });

  it('replace is idempotent (a resumed INDEXING stage rewrites, never duplicates)', () => {
    const { index, scanId } = setup();
    index.replace(scanId, sample);
    index.replace(scanId, sample);
    expect(index.imports(scanId)).toHaveLength(2);
  });

  it('returns null stats for an unindexed scan', () => {
    const { index, scanId } = setup();
    expect(index.stats(scanId)).toBeNull();
  });
});

describe('ScanRepo.updateRepoMeta', () => {
  it('updates visibility and default branch', () => {
    const { scans, repo } = setup();
    scans.updateRepoMeta(repo.id, { isPrivate: true, defaultBranch: 'develop' });
    expect(scans.getRepo(repo.id)).toMatchObject({ isPrivate: true, defaultBranch: 'develop' });
  });
});
