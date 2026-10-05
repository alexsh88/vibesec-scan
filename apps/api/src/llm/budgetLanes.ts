import type { BudgetTracker, WorkLease } from './budget';
import { costUsd, type ModelRole } from './models';

/**
 * What tier-1 analyzers need from the budget lanes (policy: see llm/budget.ts header): a work lease
 * whose projection tells lower tiers how much of the budget tier 1 still expects to need, and a
 * price estimate for projecting it.
 */
export type BudgetLanes = {
  /** Opens a tier-1 work lease for the scan (undeclared until the first `project`). Always `close()` it. */
  open(scanId: string): WorkLease;
  /** Realistic (not worst-case) USD of one call on `role`. */
  estimateUsd(role: ModelRole, inputTokens: number, outputTokens: number): number;
};

export const NO_LEASE: WorkLease = { project() {}, close() {} };

/** chars/3.5, like llm/prompt.ts estimateTokens, for sizes known only in bytes. */
export function tokensForBytes(bytes: number): number {
  return Math.ceil(bytes / 3.5);
}

export function createBudgetLanes(budget: Pick<BudgetTracker, 'openWork'>, models: Record<ModelRole, string>): BudgetLanes {
  return {
    open: (scanId) => budget.openWork(scanId),
    estimateUsd: (role, inputTokens, outputTokens) =>
      costUsd(models[role], { inputTokens, outputTokens, cacheReadTokens: 0, cacheWriteTokens: 0 }),
  };
}
