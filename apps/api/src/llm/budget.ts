import { AppError } from '../errors/AppError';

/** Called once an attempt finishes: frees its reservation and commits the actual cost. Idempotent. */
export type SettleBudget = (actualUsd: number) => void;

export class BudgetTracker {
  /** Committed spend (completed calls). */
  private readonly spent = new Map<string, number>();
  /** Worst-case cost of in-flight attempts, keyed per scan by reservation token. */
  private readonly reserved = new Map<string, Map<symbol, number>>();
  /** Reservations waiting for an in-flight attempt of the scan to settle. */
  private readonly waiters = new Map<string, Set<() => void>>();

  /** `loadPersisted` returns the scan's stored cost (scans.cost_usd) for resumed scans. */
  constructor(readonly limitUsd: number, private readonly loadPersisted: (scanId: string) => number) {}

  /** Committed spend only (excludes in-flight reservations). */
  spentUsd(scanId: string): number {
    if (!this.spent.has(scanId)) this.spent.set(scanId, this.loadPersisted(scanId));
    return this.spent.get(scanId)!;
  }

  /** Sum of the worst-case estimates of attempts currently in flight. */
  reservedUsd(scanId: string): number {
    let total = 0;
    for (const usd of this.reserved.get(scanId)?.values() ?? []) total += usd;
    return total;
  }

  add(scanId: string, usd: number): void {
    this.spent.set(scanId, this.spentUsd(scanId) + usd);
  }

  /** Committed spend as a fraction of the limit. */
  ratio(scanId: string): number {
    return this.spentUsd(scanId) / this.limitUsd;
  }

  ensureAvailable(scanId: string): void {
    if (this.spentUsd(scanId) >= this.limitUsd) throw this.exhausted();
  }

  /**
   * Reserves `estimateUsd` (an attempt's worst-case cost) before it is sent, so concurrent attempts
   * cannot each pass a committed-spend check and jointly overshoot the cap.
   *
   * - committed >= limit → BUDGET_EXHAUSTED.
   * - committed + estimate > limit → waiting cannot help (settles only add spend), so BUDGET_EXHAUSTED —
   *   except on an untouched budget (nothing committed): a single first attempt whose worst case alone
   *   exceeds the whole budget is still allowed once nothing else is in flight, otherwise a small budget
   *   could never run anything (actual cost is usually far below the max_tokens worst case).
   * - committed + reserved + estimate > limit → only in-flight worst cases block: WAIT for a settle
   *   (or forget) and re-evaluate, instead of failing work the real spend would still fit.
   * Abortable via `signal` (CANCELLED).
   */
  async reserve(scanId: string, estimateUsd: number, signal?: AbortSignal): Promise<SettleBudget> {
    for (;;) {
      if (signal?.aborted) throw cancelled();
      const committed = this.spentUsd(scanId);
      if (committed >= this.limitUsd) throw this.exhausted();
      const inFlight = this.reservedUsd(scanId);
      const fits = committed + inFlight + estimateUsd <= this.limitUsd;
      const firstOversized = committed === 0 && inFlight === 0;
      if (fits || firstOversized) return this.hold(scanId, estimateUsd);
      if (committed + estimateUsd > this.limitUsd && committed > 0) throw this.exhausted();
      await this.waitForSettle(scanId, signal);
    }
  }

  /** Drops committed spend and reservations so the next access reloads from persistence. */
  forget(scanId: string): void {
    this.spent.delete(scanId);
    this.reserved.delete(scanId);
    this.wake(scanId);
  }

  private hold(scanId: string, estimateUsd: number): SettleBudget {
    let scanReservations = this.reserved.get(scanId);
    if (!scanReservations) this.reserved.set(scanId, (scanReservations = new Map()));
    const owner = scanReservations;
    const token = Symbol('reservation');
    owner.set(token, estimateUsd);
    let settled = false;
    return (actualUsd) => {
      if (settled) return;
      settled = true;
      owner.delete(token);
      // forget() replaced/dropped this scan's reservation map: the scan's in-memory state is gone, so only
      // the reservation bookkeeping is cleared — re-adding spend here would resurrect a forgotten entry.
      if (this.reserved.get(scanId) !== owner) return;
      if (owner.size === 0) this.reserved.delete(scanId);
      if (actualUsd > 0) this.add(scanId, actualUsd);
      this.wake(scanId);
    };
  }

  private waitForSettle(scanId: string, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let set = this.waiters.get(scanId);
      if (!set) this.waiters.set(scanId, (set = new Set()));
      const waiters = set;
      const onAbort = (): void => {
        waiters.delete(wake);
        if (waiters.size === 0 && this.waiters.get(scanId) === waiters) this.waiters.delete(scanId);
        reject(cancelled());
      };
      const wake = (): void => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      };
      waiters.add(wake);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  /** Wakes every waiter of the scan; each re-evaluates (and re-waits if still blocked). */
  private wake(scanId: string): void {
    const waiters = this.waiters.get(scanId);
    if (!waiters) return;
    this.waiters.delete(scanId);
    for (const w of waiters) w();
  }

  private exhausted(): AppError {
    return new AppError('BUDGET_EXHAUSTED', 'budget', `This scan reached its AI budget of $${this.limitUsd.toFixed(2)}`);
  }
}

function cancelled(): AppError {
  return new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
}
