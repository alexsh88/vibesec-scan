import type { GitService } from '../../git/GitService';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../../resilience/retry';
import type { PipelineContext, StageSpec } from '../types';
import { requireCommitSha, throttle } from './common';

export type CloneDeps = { git: Pick<GitService, 'remoteUrl' | 'ensureCheckout'>; retryDeps?: RetryDeps };

/** Shared by CLONING and INDEXING: idempotent, so INDEXING can re-clone after a restart wiped the workspace. */
export function checkout(deps: CloneDeps, ctx: PipelineContext): Promise<string> {
  const sha = requireCommitSha(ctx);
  const { owner, name } = ctx.scan.repo;
  const progress = throttle(
    (phase: string, done: number, total: number) =>
      ctx.emit({ type: 'progress', analyzer: `clone:${phase.toLowerCase().replace(/\s+/g, '-')}`, done, total }),
    500,
    (_phase, done, total) => done === total,
  );
  return withRetry(
    () => deps.git.ensureCheckout(ctx.scanId, deps.git.remoteUrl(owner, name), sha, {
      token: ctx.secrets.token, signal: ctx.signal, onActivity: ctx.touch, onProgress: progress,
    }),
    RETRY_POLICIES.gitClone, ctx.signal, deps.retryDeps,
  );
}

export function cloneStage(deps: CloneDeps): StageSpec {
  return {
    name: 'CLONING',
    fatal: true,
    run: async (ctx) => {
      await checkout(deps, ctx);
      ctx.emit({ type: 'progress', analyzer: 'clone', done: 1, total: 1 });
    },
  };
}
