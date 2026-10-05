import { ScanSummarySchema, type ScanSummary } from '@vibesec/shared';
import type { Db } from './database';

/** One scan summary per scan (migration 010), stored as validated JSON. */
export class SummaryRepo {
  constructor(private readonly db: Db, private readonly now: () => Date = () => new Date()) {}

  /** Idempotent: replaces any summary already stored for the scan. */
  save(summary: ScanSummary): void {
    const valid = ScanSummarySchema.parse(summary);
    this.db
      .prepare(
        `INSERT INTO scan_summaries (scan_id, json, created_at) VALUES (?, ?, ?)
         ON CONFLICT (scan_id) DO UPDATE SET json = excluded.json, created_at = excluded.created_at`,
      )
      .run(valid.scanId, JSON.stringify(valid), this.now().toISOString());
  }

  get(scanId: string): ScanSummary | undefined {
    const row = this.db.prepare(`SELECT json FROM scan_summaries WHERE scan_id = ?`).get(scanId) as { json: string } | undefined;
    return row ? ScanSummarySchema.parse(JSON.parse(row.json)) : undefined;
  }
}
