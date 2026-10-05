import type { IndexRepo } from '../../db/indexRepo';
import type { RepoIndexer } from '../../index/RepoIndexer';
import type { StageSpec } from '../types';
import { checkout, type CloneDeps } from './cloneStage';
import { requireCommitSha, throttle } from './common';

export type IndexDeps = CloneDeps & {
  indexer: Pick<RepoIndexer, 'index'>;
  indexRepo: Pick<IndexRepo, 'replace'>;
  maxFiles: number;
};

export function indexStage(deps: IndexDeps): StageSpec {
  return {
    name: 'INDEXING',
    fatal: true,
    run: async (ctx) => {
      const sha = requireCommitSha(ctx);
      const dir = await checkout(deps, ctx);
      const index = await deps.indexer.index(dir, sha, {
        signal: ctx.signal,
        touch: ctx.touch,
        onProgress: throttle((done: number, total: number) => ctx.emit({ type: 'progress', analyzer: 'index', done, total }), 500, (d, t) => d === t),
      });
      deps.indexRepo.replace(ctx.scanId, index);
      ctx.checkpointData.indexStats = index.stats;

      if (index.stats.truncated) {
        ctx.warn({ code: 'REPO_TOO_LARGE', message: `Only the first ${deps.maxFiles} files were analyzed`, stage: 'INDEXING' });
      }
      if (!index.files.some((f) => f.skipReason === null && f.category === 'source')) {
        ctx.warn({ code: 'NO_SOURCE_FILES', message: 'No JavaScript, TypeScript or Python source files were found', stage: 'INDEXING' });
      }
    },
  };
}
