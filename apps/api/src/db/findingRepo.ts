import { FindingSchema, type Category, type Finding, type Severity } from '@vibesec/shared';
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

function encodeCursor(offset: number): string {
  return Buffer.from(String(offset), 'utf8').toString('base64url');
}

function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const n = Number(Buffer.from(cursor, 'base64url').toString('utf8'));
    return Number.isInteger(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
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

  get(scanId: string, id: string): Finding | undefined {
    const row = this.db.prepare(`SELECT data_json FROM findings WHERE scan_id = ? AND id = ?`).get(scanId, id) as DataRow | undefined;
    return row ? (JSON.parse(row.data_json) as Finding) : undefined;
  }

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
