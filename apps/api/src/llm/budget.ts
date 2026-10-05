import { AppError } from '../errors/AppError';

/** Called once an attempt finishes: frees its reservation and commits the actual cost. Idempotent. */
export type SettleBudget = (actualUsd: number) => void;

/**
 * Budget lanes — risk-first scheduling of one shared per-scan dollar budget across analyzers that run
 * concurrently.
 *
 *   tier 1 — security-critical work: Haiku triage, Sonnet SAST deep review, the taint agent, the config
 *            review and the credential hunter. Gated only by the whole scan budget (first claim).
 *   tier 2 — the cheaper Haiku SAST pass over low-relevance (triage relevance 1) files. May only spend
 *            while committed + in-flight + projected tier-1 demand stays <= 70% of the budget.
 *   tier 3 — AI code-quality review. Same rule with a 50% ceiling: lowest priority.
 *
 * "Projected tier-1 demand": every tier-1 analyzer holds a WorkLease while it has work left and keeps
 * its projection (a realistic USD estimate of its remaining calls) up to date. A lower-tier call waits
 * (abortably) while any lease is still undeclared, and while the projection leaves no room under its
 * ceiling — so lower tiers only ever spend what tier 1 does not expect to need, and a scan whose budget
 * is too small for its tier-1 work runs tier 1 first and refuses lower tiers afterwards. Once tier 1
 * itself has been refused, every lower tier is refused too. Lower tiers therefore never push tier-1
 * work out of the budget (up to projection error). Refused work is recorded by each analyzer as
 * `budget-skipped` coverage and reported (BUDGET_COVERAGE_PARTIAL) — never skipped silently.
 */
export type BudgetTier = 1 | 2 | 3;

/** Share of the scan budget a tier may fill (committed + in flight + projected tier-1 demand). */
export const TIER_CEILING: Readonly<Record<BudgetTier, number>> = { 1: 1, 2: 0.7, 3: 0.5 };

/** Pending tier-1 demand. `project` replaces the remaining-work estimate; `close` when done. No-ops after close. */
export type WorkLease = { project(remainingUsd: number): void; close(): void };

export class BudgetTracker {
  /** Committed spend (completed calls). */
  private readonly spent = new Map<string, number>();
  /** Worst-case cost of in-flight attempts, keyed per scan by reservation token. */
  private readonly reserved = new Map<string, Map<symbol, number>>();
  /** Reservations waiting for an in-flight attempt of the scan to settle. */
  private readonly waiters = new Map<string, Set<() => void>>();

  /** Open tier-1 work leases per scan: projected remaining USD, or null while still undeclared. */
  private readonly leases = new Map<string, Map<symbol, number | null>>();
  /** Scans where a tier-1 reservation was refused: lower tiers are closed for them. */
  private readonly tier1Refused = new Set<string>();
  /** Per-scan limits (scan.options.budgetUsd or the default), loaded lazily. */
  private readonly limits = new Map<string, number>();

  /**
   * `limitUsd` is the default per-scan budget (config SCAN_BUDGET_USD); `loadLimit` returns a scan's own
   * budget (options.budgetUsd) when it has one; `loadPersisted` returns the scan's stored cost
   * (scans.cost_usd) for resumed scans.
   */
  constructor(
    readonly limitUsd: number,
    private readonly loadPersisted: (scanId: string) => number,
    private readonly loadLimit: (scanId: string) => number | undefined = () => undefined,
  ) {}

  /** This scan's budget (its own budgetUsd, else the default). */
  limitFor(scanId: string): number {
    let limit = this.limits.get(scanId);
    if (limit === undefined) {
      limit = this.loadLimit(scanId) ?? this.limitUsd;
      this.limits.set(scanId, limit);
    }
    return limit;
  }

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
    return this.spentUsd(scanId) / this.limitFor(scanId);
  }

  ensureAvailable(scanId: string, tier: BudgetTier = 1): void {
    if (tier !== 1 && this.tier1Refused.has(scanId)) throw this.exhausted(scanId, tier);
    if (this.spentUsd(scanId) >= this.limitFor(scanId) * TIER_CEILING[tier]) throw this.exhausted(scanId, tier);
  }

  /** Opens a tier-1 work lease (undeclared until its first `project`). See the header comment. */
  openWork(scanId: string): WorkLease {
    let scanLeases = this.leases.get(scanId);
    if (!scanLeases) this.leases.set(scanId, (scanLeases = new Map()));
    const owner = scanLeases;
    const token = Symbol('lease');
    owner.set(token, null);
    let closed = false;
    return {
      project: (remainingUsd) => {
        if (closed || !owner.has(token)) return;
        owner.set(token, Math.max(0, remainingUsd));
        this.wake(scanId);
      },
      close: () => {
        if (closed) return;
        closed = true;
        owner.delete(token);
        if (owner.size === 0 && this.leases.get(scanId) === owner) this.leases.delete(scanId);
        this.wake(scanId);
      },
    };
  }

  /** Sum of open tier-1 projections; null while any open lease is still undeclared. */
  pendingTier1Usd(scanId: string): number | null {
    let total = 0;
    for (const usd of this.leases.get(scanId)?.values() ?? []) {
      if (usd === null) return null;
      total += usd;
    }
    return total;
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
  async reserve(scanId: string, estimateUsd: number, signal?: AbortSignal, tier: BudgetTier = 1): Promise<SettleBudget> {
    if (tier !== 1) return this.reserveLowerTier(scanId, estimateUsd, tier, signal);
    for (;;) {
      if (signal?.aborted) throw cancelled();
      const limit = this.limitFor(scanId);
      const committed = this.spentUsd(scanId);
      if (committed >= limit) throw this.refuseTier1(scanId);
      const inFlight = this.reservedUsd(scanId);
      const fits = committed + inFlight + estimateUsd <= limit;
      const firstOversized = committed === 0 && inFlight === 0;
      if (fits || firstOversized) return this.hold(scanId, estimateUsd);
      if (committed + estimateUsd > limit && committed > 0) throw this.refuseTier1(scanId);
      await this.waitForSettle(scanId, signal);
    }
  }

  /**
   * Tier 2/3 (see header): fits only under the tier ceiling counting committed + in flight + projected
   * tier-1 demand; waits while tier-1 work is undeclared or its projection blocks; refused once waiting
   * cannot help (no tier-1 work open and committed + estimate exceeds the ceiling) or tier 1 was refused.
   * No oversized-first exception: a lower tier never gets more than its share.
   */
  private async reserveLowerTier(scanId: string, estimateUsd: number, tier: BudgetTier, signal?: AbortSignal): Promise<SettleBudget> {
    for (;;) {
      if (signal?.aborted) throw cancelled();
      if (this.tier1Refused.has(scanId)) throw this.exhausted(scanId, tier);
      const ceiling = this.limitFor(scanId) * TIER_CEILING[tier];
      const committed = this.spentUsd(scanId);
      if (committed >= ceiling) throw this.exhausted(scanId, tier);
      const inFlight = this.reservedUsd(scanId);
      const pending = this.pendingTier1Usd(scanId);
      if (pending !== null && committed + inFlight + pending + estimateUsd <= ceiling) return this.hold(scanId, estimateUsd);
      const tier1Open = (this.leases.get(scanId)?.size ?? 0) > 0;
      if (!tier1Open && committed + estimateUsd > ceiling) throw this.exhausted(scanId, tier);
      await this.waitForSettle(scanId, signal);
    }
  }

  /** Drops committed spend, reservations, leases and the per-scan limit so the next access reloads. */
  forget(scanId: string): void {
    this.spent.delete(scanId);
    this.reserved.delete(scanId);
    this.leases.delete(scanId);
    this.limits.delete(scanId);
    this.tier1Refused.delete(scanId);
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

  /** Tier 1 refused: lower tiers close for this scan, and their waiters re-evaluate (and fail). */
  private refuseTier1(scanId: string): AppError {
    this.tier1Refused.add(scanId);
    this.wake(scanId);
    return this.exhausted(scanId, 1);
  }

  private exhausted(scanId: string, tier: BudgetTier = 1): AppError {
    const limit = this.limitFor(scanId);
    const message = tier === 1
      ? `This scan reached its AI budget of $${limit.toFixed(2)}`
      : `This scan's AI budget share for lower-priority work (${Math.round(TIER_CEILING[tier] * 100)}% of $${limit.toFixed(2)}) is used up`;
    return new AppError('BUDGET_EXHAUSTED', 'budget', message, { details: { tier } });
  }
}

function cancelled(): AppError {
  return new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
}
