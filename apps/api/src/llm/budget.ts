import { AppError } from '../errors/AppError';

/** Called once an attempt finishes: frees its reservation and commits the actual cost. Idempotent. */
export type SettleBudget = (actualUsd: number) => void;

export class BudgetTracker {
  /** Committed spend (completed calls). */
  private readonly spent = new Map<string, number>();
  /** Worst-case cost of in-flight attempts, keyed per scan by reservation token. */
  private readonly reserved = new Map<string, Map<symbol, number>>();

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
   * Throws BUDGET_EXHAUSTED when spent + reserved + estimate would exceed the limit — except when
   * nothing is spent or reserved yet: a single first attempt whose worst case alone exceeds the
   * whole budget is still allowed, otherwise a small budget could never run anything (its actual
   * cost is usually far below the max_tokens worst case).
   */
  reserve(scanId: string, estimateUsd: number): SettleBudget {
    const committed = this.spentUsd(scanId);
    const inFlight = this.reservedUsd(scanId);
    if (committed + inFlight + estimateUsd > this.limitUsd && (committed > 0 || inFlight > 0)) throw this.exhausted();
    let scanReservations = this.reserved.get(scanId);
    if (!scanReservations) this.reserved.set(scanId, (scanReservations = new Map()));
    const token = Symbol('reservation');
    scanReservations.set(token, estimateUsd);
    let settled = false;
    return (actualUsd) => {
      if (settled) return;
      settled = true;
      const current = this.reserved.get(scanId);
      // Absent after forget(): the reservation is already gone, but the actual cost still counts.
      if (current?.delete(token) && current.size === 0) this.reserved.delete(scanId);
      if (actualUsd > 0) this.add(scanId, actualUsd);
    };
  }

  /** Drops committed spend and reservations so the next access reloads from persistence. */
  forget(scanId: string): void {
    this.spent.delete(scanId);
    this.reserved.delete(scanId);
  }

  private exhausted(): AppError {
    return new AppError('BUDGET_EXHAUSTED', 'budget', `This scan reached its AI budget of $${this.limitUsd.toFixed(2)}`);
  }
}
