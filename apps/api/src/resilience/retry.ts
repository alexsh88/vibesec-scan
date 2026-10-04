import { setTimeout as sleepTimer } from 'node:timers/promises';
import { AppError, toAppError } from '../errors/AppError';

export type RetryPolicy = { retries: number; baseMs: number; capMs: number };

/** Spec §14.3 attempt budgets. Anthropic SDK maxRetries is set to 0; these are the only retries. */
export const RETRY_POLICIES = {
  anthropic: { retries: 4, baseMs: 500, capMs: 30_000 },
  github: { retries: 3, baseMs: 500, capMs: 30_000 },
  osv: { retries: 3, baseMs: 500, capMs: 30_000 },
  registry: { retries: 3, baseMs: 500, capMs: 30_000 },
  gitClone: { retries: 2, baseMs: 1_000, capMs: 30_000 },
  sandbox: { retries: 1, baseMs: 2_000, capMs: 10_000 },
  none: { retries: 0, baseMs: 0, capMs: 0 },
} as const satisfies Record<string, RetryPolicy>;

export type RetryInfo = { attempt: number; delayMs: number; error: AppError };

export type RetryDeps = {
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  random?: () => number;
  onRetry?: (info: RetryInfo) => void;
};

export function computeBackoff(attempt: number, policy: RetryPolicy, random: () => number = Math.random): number {
  const ceiling = Math.min(policy.capMs, policy.baseMs * 2 ** attempt);
  return Math.floor(random() * ceiling);
}

const cancelled = () => new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');

const defaultSleep = async (ms: number, signal?: AbortSignal): Promise<void> => {
  await sleepTimer(ms, undefined, { signal });
};

export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  policy: RetryPolicy,
  signal?: AbortSignal,
  deps: RetryDeps = {},
): Promise<T> {
  const sleep = deps.sleep ?? defaultSleep;
  const random = deps.random ?? Math.random;

  for (let attempt = 0; ; attempt++) {
    if (signal?.aborted) throw cancelled();
    try {
      return await fn(attempt);
    } catch (raw) {
      const err = toAppError(raw);
      if (signal?.aborted) throw cancelled();
      if (!err.retryable || attempt >= policy.retries) throw err;
      const delayMs = err.retryAfterMs ?? computeBackoff(attempt, policy, random);
      deps.onRetry?.({ attempt: attempt + 1, delayMs, error: err });
      try {
        await sleep(delayMs, signal);
      } catch {
        throw cancelled();
      }
    }
  }
}
