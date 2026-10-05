import { setTimeout as sleepTimer } from 'node:timers/promises';
import { AppError } from '../errors/AppError';

export type RateLimiterOptions = {
  requestsPerMinute: number;
  inputTokensPerMinute: number;
  now?: () => number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
};

const MINUTE = 60_000;
const cancelled = () => new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
const defaultSleep = (ms: number, signal?: AbortSignal) => sleepTimer(ms, undefined, { signal }).then(() => undefined);

/** Client-side throttle so we stay under the account's Anthropic rate limits instead of collecting 429s. */
export class RateLimiter {
  private requests: number;
  private tokens: number;
  private last: number;
  private penaltyUntil = 0;
  private readonly now: () => number;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Serializes waiters strictly FIFO: each acquire() only runs once the previous one has settled. */
  private tail: Promise<void> = Promise.resolve();

  constructor(private readonly opts: RateLimiterOptions) {
    this.now = opts.now ?? Date.now;
    this.sleep = opts.sleep ?? defaultSleep;
    this.requests = opts.requestsPerMinute;
    this.tokens = opts.inputTokensPerMinute;
    this.last = this.now();
  }

  /** Acquires capacity in strict call order, so a large request can't be starved behind a stream of small ones. */
  acquire(estimatedInputTokens: number, signal?: AbortSignal): Promise<void> {
    const turn = this.tail.then(() => this.acquireNow(estimatedInputTokens, signal));
    // The tail always awaits `turn` itself (not the raced promise below), so later waiters keep
    // queueing strictly in call order regardless of how/when an earlier waiter's public promise
    // settles.
    this.tail = turn.catch(() => undefined);
    if (!signal) return turn;
    if (signal.aborted) return Promise.reject(cancelled());
    // A waiter can be aborted while still queued behind an earlier turn that is itself blocked
    // (e.g. sleeping for refill) — `turn` won't settle until the queue actually reaches it, which
    // could be arbitrarily far away. Race it against the abort signal so cancellation is prompt
    // instead of waiting for its turn. Once its turn does arrive, acquireNow's own
    // `signal?.aborted` check skips it immediately, so it never delays whoever queued up next.
    return new Promise<void>((resolve, reject) => {
      const onAbort = () => reject(cancelled());
      signal.addEventListener('abort', onAbort, { once: true });
      turn.then(
        (value) => { signal.removeEventListener('abort', onAbort); resolve(value); },
        (err) => { signal.removeEventListener('abort', onAbort); reject(err); },
      );
    });
  }

  private async acquireNow(estimatedInputTokens: number, signal?: AbortSignal): Promise<void> {
    // Non-finite or negative estimates (NaN, Infinity, -5, ...) would otherwise poison the
    // buckets with NaN, making every `tokens >= needTokens` comparison false and hanging forever.
    const estimate = Number.isFinite(estimatedInputTokens) && estimatedInputTokens > 0 ? estimatedInputTokens : 0;
    for (;;) {
      if (signal?.aborted) throw cancelled();
      this.refill();
      const { reqCap, tokCap } = this.capacities();
      const needTokens = Math.min(estimate, tokCap);
      if (this.requests >= 1 && this.tokens >= needTokens) {
        this.requests -= 1;
        this.tokens -= needTokens;
        return;
      }
      const reqWait = this.requests >= 1 ? 0 : ((1 - this.requests) / reqCap) * MINUTE;
      const tokWait = this.tokens >= needTokens ? 0 : ((needTokens - this.tokens) / tokCap) * MINUTE;
      try {
        await this.sleep(Math.max(Math.ceil(Math.max(reqWait, tokWait)), 1), signal);
      } catch (err) {
        // Only an abort becomes CANCELLED; any other sleep failure propagates unchanged.
        if (signal?.aborted || (err instanceof Error && err.name === 'AbortError')) throw cancelled();
        throw err;
      }
    }
  }

  /** After a 429: halve capacity for `ms` (default 60 s). */
  penalize(ms = MINUTE): void {
    this.penaltyUntil = Math.max(this.penaltyUntil, this.now() + ms);
    const { reqCap, tokCap } = this.capacities();
    this.requests = Math.min(this.requests, reqCap);
    this.tokens = Math.min(this.tokens, tokCap);
  }

  private capacities(): { reqCap: number; tokCap: number } {
    const factor = this.now() < this.penaltyUntil ? 0.5 : 1;
    return {
      reqCap: Math.max(this.opts.requestsPerMinute * factor, 1),
      tokCap: Math.max(this.opts.inputTokensPerMinute * factor, 1),
    };
  }

  private refill(): void {
    const now = this.now();
    const elapsed = Math.max(now - this.last, 0);
    this.last = now;
    const { reqCap, tokCap } = this.capacities();
    this.requests = Math.min(reqCap, this.requests + (elapsed / MINUTE) * reqCap);
    this.tokens = Math.min(tokCap, this.tokens + (elapsed / MINUTE) * tokCap);
  }
}

/** Caps concurrent in-flight LLM calls. `acquire` resolves to an idempotent release function. */
export class Semaphore {
  private available: number;
  private readonly waiters: Array<() => void> = [];

  constructor(size: number) {
    this.available = size;
  }

  acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) return Promise.reject(cancelled());
    if (this.available > 0) {
      this.available--;
      return Promise.resolve(this.releaser());
    }
    return new Promise((resolve, reject) => {
      const grant = () => {
        signal?.removeEventListener('abort', onAbort);
        resolve(this.releaser());
      };
      const onAbort = () => {
        const i = this.waiters.indexOf(grant);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(cancelled());
      };
      this.waiters.push(grant);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  private releaser(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = this.waiters.shift();
      if (next) next();
      else this.available++;
    };
  }
}
