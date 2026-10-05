import { FixPlanSchema, type FixPlan } from '@vibesec/shared';
import type { Db } from './database';

/** One fix plan ("Next actions") per scan, stored as validated JSON. */
export class FixPlanRepo {
  constructor(private readonly db: Db, private readonly now: () => Date = () => new Date()) {}

  /** Idempotent: replaces any plan already stored for the scan. */
  save(plan: FixPlan): void {
    const valid = FixPlanSchema.parse(plan);
    this.db
      .prepare(
        `INSERT INTO fix_plans (scan_id, json, created_at) VALUES (?, ?, ?)
         ON CONFLICT (scan_id) DO UPDATE SET json = excluded.json, created_at = excluded.created_at`,
      )
      .run(valid.scanId, JSON.stringify(valid), this.now().toISOString());
  }

  get(scanId: string): FixPlan | undefined {
    const row = this.db.prepare(`SELECT json FROM fix_plans WHERE scan_id = ?`).get(scanId) as { json: string } | undefined;
    return row ? FixPlanSchema.parse(JSON.parse(row.json)) : undefined;
  }
}
