import { AppError, toAppError } from '../../errors/AppError';
import type { GitService } from '../../git/GitService';
import type { GitHubClient, RepoMeta } from '../../github/GitHubClient';
import type { ScanRepo } from '../../db/scanRepo';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../../resilience/retry';
import type { StageSpec } from '../types';

export type ResolveDeps = {
  github: Pick<GitHubClient, 'getRepo'>;
  git: Pick<GitService, 'remoteUrl' | 'resolveRef'>;
  scans: Pick<ScanRepo, 'updateRepoMeta' | 'setCommitSha'>;
  maxRepoBytes: number;
  retryDeps?: RetryDeps;
};

const MB = 1024 * 1024;

export function resolveStage(deps: ResolveDeps): StageSpec {
  return {
    name: 'RESOLVING',
    fatal: true,
    run: async (ctx) => {
      const { id: repoId, owner, name } = ctx.scan.repo;
      const token = ctx.secrets.token;

      // Metadata is mandatory: without it there is no size check, and a git-only fallback would let git talk
      // to the remote without the API having vouched for the repository. A transient failure (the client
      // has already retried) fails the scan so the user can simply try again.
      let meta: RepoMeta;
      try {
        meta = await deps.github.getRepo(owner, name, token, ctx.signal);
      } catch (raw) {
        const err = toAppError(raw);
        if (err.kind !== 'transient') throw err;
        throw new AppError(err.code === 'GITHUB_RATE_LIMITED' ? 'GITHUB_RATE_LIMITED' : 'INTERNAL', 'transient',
          'GitHub is unavailable or rate-limited right now; please try the scan again shortly', { cause: err });
      }
      ctx.touch();

      if (meta.sizeBytes > deps.maxRepoBytes) {
        throw new AppError('REPO_TOO_LARGE', 'permanent',
          `The repository is ${Math.round(meta.sizeBytes / MB)} MB; the limit is ${Math.round(deps.maxRepoBytes / MB)} MB`);
      }
      deps.scans.updateRepoMeta(repoId, { isPrivate: meta.isPrivate, defaultBranch: meta.defaultBranch });

      const ref = ctx.scan.ref ?? meta.defaultBranch;
      const remote = deps.git.remoteUrl(owner, name);
      const sha = await withRetry(
        () => deps.git.resolveRef(remote, ref, { token, signal: ctx.signal, onActivity: ctx.touch }),
        RETRY_POLICIES.github, ctx.signal, deps.retryDeps,
      );
      deps.scans.setCommitSha(ctx.scanId, sha);
      Object.assign(ctx.checkpointData, { commitSha: sha, resolvedRef: ref, defaultBranch: meta.defaultBranch });
      ctx.emit({ type: 'progress', analyzer: 'resolve', done: 1, total: 1 });
    },
  };
}
