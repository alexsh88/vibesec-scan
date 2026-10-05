import { FindingSchema, type Category, type Finding, type Severity } from '@vibesec/shared';
import { AppError } from '../errors/AppError';
import { SEVERITY_RANK } from '../findings/helpers';
import type { Db } from './database';

export type FindingFilter = {
  category?: Category;
  severity?: Severity;
  file?: string;
  q?: string;
  cursor?: string;
  limit?: number;
};

export type FindingCounts = {
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  byCategory: Partial<Record<Category, number>>;
};

type DataRow = { data_json: string };
type SeverityCountRow = { severity: Severity; c: number };
type CategoryCountRow = { category: Category; c: number };

/** Escapes LIKE metacharacters so `q` is matched literally, then the caller wraps it in `%...%`. */
function escapeLike(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
}

/** M2: a decoded cursor must be a real, boundable offset. Anything else (garbage base64, NaN, a
 *  negative number, or a technically-`Number.isInteger`-true-but-unsafe value like `1e308`, which
 *  `better-sqlite3` cannot bind as a 64-bit integer and would otherwise throw a raw 500) is rejected
 *  with a 400 before it ever reaches a SQL bind parameter. 1,000,000 is far beyond any real result
 *  set; it only exists to keep `offset` itself boundable. */
const MAX_CURSOR_OFFSET = 1_000_000;

function encodeCursor(offset: number): string {
  return Buffer.from(String(offset), 'utf8').toString('base64url');
}

function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  let n: number;
  try {
    n = Number(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    throw new AppError('VALIDATION', 'permanent', 'Invalid pagination cursor');
  }
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_CURSOR_OFFSET) {
    throw new AppError('VALIDATION', 'permanent', 'Invalid pagination cursor');
  }
  return n;
}

export class FindingRepo {
  constructor(private readonly db: Db, private readonly now: () => string = () => new Date().toISOString()) {}

  /** Atomically replaces one analyzer's findings for a scan (idempotent re-runs never duplicate rows). */
  replaceForAnalyzer(scanId: string, analyzer: string, findings: readonly Finding[]): void {
    const parsed = findings.map((f) => FindingSchema.parse(f));
    const createdAt = this.now();
    this.db.transaction(() => {
      this.db.prepare(`DELETE FROM findings WHERE scan_id = ? AND analyzer = ?`).run(scanId, analyzer);
      const insert = this.db.prepare(
        `INSERT INTO findings (id, scan_id, analyzer, fingerprint, category, rule_id, title, severity, severity_rank, risk_score, file, start_line, data_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (scan_id, fingerprint) DO NOTHING`,
      );
      for (const f of parsed) {
        insert.run(
          f.id, scanId, analyzer, f.fingerprint, f.category, f.ruleId, f.title, f.severity,
          SEVERITY_RANK[f.severity], f.riskScore, f.location.file, f.location.startLine,
          JSON.stringify(f), createdAt,
        );
      }
    })();
  }

  /** Every finding of a scan with the analyzer that produced it (post-analysis stages: verify, score). */
  all(scanId: string): { analyzer: string; finding: Finding }[] {
    const rows = this.db.prepare(`SELECT analyzer, data_json FROM findings WHERE scan_id = ? ORDER BY id`)
      .all(scanId) as { analyzer: string; data_json: string }[];
    return rows.map((r) => ({ analyzer: r.analyzer, finding: JSON.parse(r.data_json) as Finding }));
  }

  /**
   * Atomically rewrites existing findings in place (matched by id) and deletes `removeIds`.
   * Used by VERIFYING (dedupe/skeptic) and SCORING; re-running a stage is idempotent.
   */
  update(scanId: string, findings: readonly Finding[], removeIds: readonly string[] = []): void {
    const parsed = findings.map((f) => FindingSchema.parse(f));
    this.db.transaction(() => {
      const del = this.db.prepare(`DELETE FROM findings WHERE scan_id = ? AND id = ?`);
      for (const id of removeIds) del.run(scanId, id);
      const upd = this.db.prepare(
        `UPDATE findings SET title = ?, severity = ?, severity_rank = ?, risk_score = ?, file = ?, start_line = ?, data_json = ?
         WHERE scan_id = ? AND id = ?`,
      );
      for (const f of parsed) {
        upd.run(f.title, f.severity, SEVERITY_RANK[f.severity], f.riskScore, f.location.file, f.location.startLine,
          JSON.stringify(f), scanId, f.id);
      }
    })();
  }

  get(scanId: string, id: string): Finding | undefined {
    const row = this.db.prepare(`SELECT data_json FROM findings WHERE scan_id = ? AND id = ?`).get(scanId, id) as DataRow | undefined;
    return row ? (JSON.parse(row.data_json) as Finding) : undefined;
  }

  /**
   * M6 (accepted limitation): pagination here is plain offset-based. If findings are still being
   * inserted for a scan that is actively running, a row can shift between pages fetched a moment
   * apart (a new finding sorting ahead of the current offset pushes everything down one slot, so a
   * row can be skipped or repeated across `cursor`s). This is tolerated because the UI only paginates
   * a scan's findings after it has reached a terminal state, by which point the result set is frozen.
   */
  list(scanId: string, filter: FindingFilter): { items: Finding[]; nextCursor: string | null } {
    const limit = Math.min(Math.max(filter.limit ?? 50, 1), 200);
    const offset = decodeCursor(filter.cursor);
    const clauses = ['scan_id = ?'];
    const params: unknown[] = [scanId];
    if (filter.category) { clauses.push('category = ?'); params.push(filter.category); }
    if (filter.severity) { clauses.push('severity = ?'); params.push(filter.severity); }
    if (filter.file) { clauses.push('file = ?'); params.push(filter.file); }
    if (filter.q) {
      clauses.push(`(title LIKE ? ESCAPE '\\' OR file LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\')`);
      const like = `%${escapeLike(filter.q)}%`;
      params.push(like, like, like);
    }
    const rows = this.db.prepare(
      `SELECT data_json FROM findings WHERE ${clauses.join(' AND ')}
       ORDER BY severity_rank, risk_score DESC, file, start_line, id
       LIMIT ? OFFSET ?`,
    ).all(...params, limit + 1, offset) as DataRow[];
    const hasMore = rows.length > limit;
    const items = rows.slice(0, limit).map((r) => JSON.parse(r.data_json) as Finding);
    return { items, nextCursor: hasMore ? encodeCursor(offset + limit) : null };
  }

  counts(scanId: string): FindingCounts {
    const total = (this.db.prepare(`SELECT COUNT(*) as c FROM findings WHERE scan_id = ?`).get(scanId) as { c: number }).c;
    const bySeverity: Partial<Record<Severity, number>> = {};
    for (const row of this.db.prepare(`SELECT severity, COUNT(*) as c FROM findings WHERE scan_id = ? GROUP BY severity`).all(scanId) as SeverityCountRow[]) {
      bySeverity[row.severity] = row.c;
    }
    const byCategory: Partial<Record<Category, number>> = {};
    for (const row of this.db.prepare(`SELECT category, COUNT(*) as c FROM findings WHERE scan_id = ? GROUP BY category`).all(scanId) as CategoryCountRow[]) {
      byCategory[row.category] = row.c;
    }
    return { total, bySeverity, byCategory };
  }
}
