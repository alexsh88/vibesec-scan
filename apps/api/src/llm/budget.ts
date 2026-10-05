import { AppError } from '../errors/AppError';

export class BudgetTracker {
  private readonly spent = new Map<string, number>();

  /** `loadPersisted` returns the scan's stored cost (scans.cost_usd) for resumed scans. */
  constructor(readonly limitUsd: number, private readonly loadPersisted: (scanId: string) => number) {}

  spentUsd(scanId: string): number {
    if (!this.spent.has(scanId)) this.spent.set(scanId, this.loadPersisted(scanId));
    return this.spent.get(scanId)!;
  }

  add(scanId: string, usd: number): void {
    this.spent.set(scanId, this.spentUsd(scanId) + usd);
  }

  ratio(scanId: string): number {
    return this.spentUsd(scanId) / this.limitUsd;
  }

  ensureAvailable(scanId: string): void {
    if (this.spentUsd(scanId) >= this.limitUsd) {
      throw new AppError('BUDGET_EXHAUSTED', 'budget', `This scan reached its AI budget of $${this.limitUsd.toFixed(2)}`);
    }
  }

  forget(scanId: string): void {
    this.spent.delete(scanId);
  }
}
