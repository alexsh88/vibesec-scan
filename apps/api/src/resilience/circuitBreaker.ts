import type { ErrorCode } from '@vibesec/shared';
import { AppError, toAppError } from '../errors/AppError';

export type BreakerState = 'closed' | 'open' | 'half_open';
export type BreakerOptions = { failureThreshold: number; resetMs: number; unavailableCode: ErrorCode };

/**
 * Wrap the *whole* retry chain: breaker.run(() => withRetry(fn, policy, signal)).
 * Open ⇒ fail fast (no retries); one exhausted retry chain = one breaker failure.
 * Only transient errors count toward tripping.
 */
export class CircuitBreaker {
  private state: BreakerState = 'closed';
  private failures = 0;
  private openedAt = 0;
  private probeInFlight = false;
  trips = 0;

  constructor(
    readonly name: string,
    private readonly opts: BreakerOptions = { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'INTERNAL' },
    private readonly now: () => number = Date.now,
  ) {}

  getState(): BreakerState {
    if (this.state === 'open' && this.now() - this.openedAt >= this.opts.resetMs) this.state = 'half_open';
    return this.state;
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    const state = this.getState();
    if (state === 'open' || (state === 'half_open' && this.probeInFlight)) {
      throw new AppError(this.opts.unavailableCode, 'transient', `${this.name} is temporarily unavailable`);
    }
    const isProbe = state === 'half_open';
    if (isProbe) this.probeInFlight = true;
    try {
      const result = await fn();
      this.failures = 0;
      this.state = 'closed';
      return result;
    } catch (err) {
      this.recordFailure(err, isProbe);
      throw err;
    } finally {
      if (isProbe) this.probeInFlight = false;
    }
  }

  private recordFailure(err: unknown, isProbe: boolean): void {
    if (toAppError(err).kind !== 'transient') return;
    if (isProbe) {
      this.open();
      return;
    }
    this.failures += 1;
    if (this.failures >= this.opts.failureThreshold) this.open();
  }

  private open(): void {
    this.state = 'open';
    this.openedAt = this.now();
    this.failures = 0;
    this.trips += 1;
  }
}
