import { COVERAGE_STATUSES, type CoverageEntry, type CoverageStatus } from '../analyzers/types';
import type { Db } from './database';

export type CoverageSummary = {
  /** Files per status over every analyzer. */
  totals: Record<CoverageStatus, number>;
  /** analyzer -> status -> files. */
  byAnalyzer: Record<string, Record<CoverageStatus, number>>;
  /** Every file an analyzer did not review because the budget ran out (never skipped silently). */
  budgetSkipped: Array<{ analyzer: string; path: string }>;
};

function zeroCounts(): Record<CoverageStatus, number> {
  return Object.fromEntries(COVERAGE_STATUSES.map((s) => [s, 0])) as Record<CoverageStatus, number>;
}

/** Per-scan coverage of the AI review (migration 008). Rewritten as a whole each time ANALYZING completes. */
export class CoverageRepo {
  constructor(private readonly db: Db) {}

  replaceForScan(scanId: string, entries: readonly CoverageEntry[]): void {
    const insert = this.db.prepare(
      `INSERT INTO scan_coverage (scan_id, analyzer, path, status) VALUES (?, ?, ?, ?)
       ON CONFLICT (scan_id, analyzer, path) DO UPDATE SET status = excluded.status`,
    );
    this.db.transaction(() => {
      this.db.prepare(`DELETE FROM scan_coverage WHERE scan_id = ?`).run(scanId);
      for (const e of entries) insert.run(scanId, e.analyzer, e.path, e.status);
    })();
  }

  list(scanId: string): CoverageEntry[] {
    return this.db
      .prepare(`SELECT analyzer, path, status FROM scan_coverage WHERE scan_id = ? ORDER BY analyzer, path`)
      .all(scanId) as CoverageEntry[];
  }

  summary(scanId: string): CoverageSummary {
    const totals = zeroCounts();
    const byAnalyzer: Record<string, Record<CoverageStatus, number>> = {};
    const budgetSkipped: CoverageSummary['budgetSkipped'] = [];
    for (const e of this.list(scanId)) {
      totals[e.status]++;
      (byAnalyzer[e.analyzer] ??= zeroCounts())[e.status]++;
      if (e.status === 'budget-skipped') budgetSkipped.push({ analyzer: e.analyzer, path: e.path });
    }
    return { totals, byAnalyzer, budgetSkipped };
  }
}
