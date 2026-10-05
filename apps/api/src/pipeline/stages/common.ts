import { AppError } from '../../errors/AppError';
import type { PipelineContext } from '../types';

export function requireCommitSha(ctx: PipelineContext): string {
  const sha = ctx.checkpointData.commitSha;
  if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) {
    throw new AppError('INTERNAL', 'permanent', 'The commit was not resolved before this stage');
  }
  return sha;
}

/** Calls `fn` at most once per `ms`, but always for a final call (`isFinal`). Every event is a DB row. */
export function throttle<A extends unknown[]>(fn: (...args: A) => void, ms: number, isFinal: (...args: A) => boolean): (...args: A) => void {
  let last = 0;
  return (...args: A) => {
    const now = Date.now();
    if (now - last >= ms || isFinal(...args)) {
      last = now;
      fn(...args);
    }
  };
}
