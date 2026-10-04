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

/** Default ceiling for a server-supplied retryAfterMs; see RetryDeps.maxRetryAfterMs. */
export const MAX_RETRY_AFTER_MS = 60_000;

export type RetryDeps = {
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  random?: () => number;
  onRetry?: (info: RetryInfo) => void;
  /** Ceiling for err.retryAfterMs; beyond this we fail fast instead of sleeping. Defaults to MAX_RETRY_AFTER_MS. */
  maxRetryAfterMs?: number;
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
  const maxRetryAfterMs = deps.maxRetryAfterMs ?? MAX_RETRY_AFTER_MS;

  for (let attempt = 0; ; attempt++) {
    if (signal?.aborted) throw cancelled();
    try {
      return await fn(attempt);
    } catch (raw) {
      const err = toAppError(raw);
      if (signal?.aborted) throw cancelled();
      if (!err.retryable) throw err;
      // A rate limiter asking us to wait longer than we're willing to sleep is not
      // something a retry loop should honor — surface it to the caller immediately.
      if (err.retryAfterMs !== undefined && err.retryAfterMs > maxRetryAfterMs) throw err;
      if (attempt >= policy.retries) throw err;
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
