import type { ScanEvent, StoredScanEvent } from '@vibesec/shared';
import type { Db } from './database';

type EventRow = { scan_id: string; seq: number; payload_json: string; at: string };

export class EventRepo {
  constructor(private readonly db: Db, private readonly now: () => string = () => new Date().toISOString()) {}

  append(scanId: string, event: ScanEvent): StoredScanEvent {
    const at = this.now();
    const row = this.db.prepare(
      `INSERT INTO scan_events (scan_id, seq, type, payload_json, at)
       SELECT ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ? FROM scan_events WHERE scan_id = ?
       RETURNING seq`,
    ).get(scanId, event.type, JSON.stringify(event), at, scanId) as { seq: number };
    return { scanId, seq: row.seq, at, event };
  }

  listAfter(scanId: string, afterSeq: number): StoredScanEvent[] {
    const rows = this.db.prepare(`SELECT * FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq`)
      .all(scanId, afterSeq) as EventRow[];
    return rows.map((r) => ({ scanId: r.scan_id, seq: r.seq, at: r.at, event: JSON.parse(r.payload_json) as ScanEvent }));
  }
}
