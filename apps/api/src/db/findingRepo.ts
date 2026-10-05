import { FindingSchema, type Category, type Finding, type Severity } from '@vibesec/shared';
import { AppError } from '../errors/AppError';
import { SEVERITY_RANK } from '../findings/helpers';
import type { Db } from './database';

export type TriageFilter = 'open' | 'suppressed' | 'all';
export type ScanStatus = Finding['scanStatus'];
export type FindingRow = { analyzer: string; finding: Finding };

/** `fixed` rows are findings of the previous scan that this scan no longer has (P7 new/existing/fixed). */
const NOT_FIXED_SQL = `json_extract(data_json, '$.scanStatus') IS NOT 'fixed'`;

export type FindingFilter = {
  category?: Category;
  severity?: Severity;
  file?: string;
  q?: string;
  triage?: TriageFilter;
  /** Omitted: the scan's current findings (new + existing); 'fixed' lists what the previous scan had and this one no longer does. */
  scanStatus?: ScanStatus;
  cursor?: string;
  limit?: number;
};

/** Counts of the scan's current findings (fixed ones excluded), plus the new/existing/fixed split. */
export type FindingCounts = {
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  byCategory: Partial<Record<Category, number>>;
  byScanStatus: Record<ScanStatus, number>;
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

  /**
   * Every current finding of a scan with the analyzer that produced it (post-analysis stages: verify,
   * score, synthesis, exports). `fixed` rows (findings of the previous scan this one no longer has) are
   * left out unless `includeFixed`.
   */
  all(scanId: string, opts: { includeFixed?: boolean } = {}): FindingRow[] {
    const where = opts.includeFixed ? '' : ` AND ${NOT_FIXED_SQL}`;
    const rows = this.db.prepare(`SELECT analyzer, data_json FROM findings WHERE scan_id = ?${where} ORDER BY id`)
      .all(scanId) as { analyzer: string; data_json: string }[];
    return rows.map((r) => ({ analyzer: r.analyzer, finding: JSON.parse(r.data_json) as Finding }));
  }

  /** Atomically replaces every finding row of a scan (fixed ones included) — the full-scan cache copy. */
  replaceAll(scanId: string, rows: readonly FindingRow[]): void {
    const parsed = rows.map((r) => ({ analyzer: r.analyzer, finding: FindingSchema.parse(r.finding) }));
    this.db.transaction(() => {
      this.db.prepare(`DELETE FROM findings WHERE scan_id = ?`).run(scanId);
      this.insertRows(scanId, parsed);
    })();
  }

  /** Atomically replaces the scan's `fixed` rows (idempotent re-runs of the new/existing/fixed comparison). */
  replaceFixed(scanId: string, rows: readonly FindingRow[]): void {
    const parsed = rows.map((r) => ({ analyzer: r.analyzer, finding: FindingSchema.parse(r.finding) }));
    if (parsed.some((r) => r.finding.scanStatus !== 'fixed')) {
      throw new AppError('INTERNAL', 'permanent', 'replaceFixed only stores fixed findings');
    }
    this.db.transaction(() => {
      this.db.prepare(`DELETE FROM findings WHERE scan_id = ? AND json_extract(data_json, '$.scanStatus') = 'fixed'`).run(scanId);
      this.insertRows(scanId, parsed);
    })();
  }

  private insertRows(scanId: string, rows: readonly FindingRow[]): void {
    const createdAt = this.now();
    const insert = this.db.prepare(
      `INSERT INTO findings (id, scan_id, analyzer, fingerprint, category, rule_id, title, severity, severity_rank, risk_score, file, start_line, data_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (scan_id, fingerprint) DO NOTHING`,
    );
    for (const { analyzer, finding: f } of rows) {
      insert.run(
        f.id, scanId, analyzer, f.fingerprint, f.category, f.ruleId, f.title, f.severity,
        SEVERITY_RANK[f.severity], f.riskScore, f.location.file, f.location.startLine, JSON.stringify(f), createdAt,
      );
    }
  }

  /**
   * Stores one analyzer's output exactly as it returned it (before VERIFYING/SCORING rewrite the
   * persisted rows): what an incremental rescan re-attaches for unchanged files (migration 012).
   */
  saveAnalyzerResult(scanId: string, analyzer: string, findings: readonly Finding[]): void {
    const json = JSON.stringify(findings.map((f) => FindingSchema.parse(f)));
    this.db.prepare(
      `INSERT INTO analyzer_results (scan_id, analyzer, findings_json, created_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (scan_id, analyzer) DO UPDATE SET findings_json = excluded.findings_json, created_at = excluded.created_at`,
    ).run(scanId, analyzer, json, this.now());
  }

  /** One analyzer's stored output for a scan; [] when it never ran (or the scan predates migration 012). */
  analyzerResult(scanId: string, analyzer: string): Finding[] {
    const row = this.db.prepare(`SELECT findings_json FROM analyzer_results WHERE scan_id = ? AND analyzer = ?`)
      .get(scanId, analyzer) as { findings_json: string } | undefined;
    return row ? (JSON.parse(row.findings_json) as Finding[]) : [];
  }

  /** The analyzers that completed for a scan (they stored their output). */
  analyzersWithResults(scanId: string): Set<string> {
    const rows = this.db.prepare(`SELECT analyzer FROM analyzer_results WHERE scan_id = ?`).all(scanId) as Array<{ analyzer: string }>;
    return new Set(rows.map((r) => r.analyzer));
  }

  /** Every analyzer output stored for a scan (the full-scan cache copies them along). */
  analyzerResults(scanId: string): Array<{ analyzer: string; findings: Finding[] }> {
    const rows = this.db.prepare(`SELECT analyzer, findings_json FROM analyzer_results WHERE scan_id = ? ORDER BY analyzer`)
      .all(scanId) as Array<{ analyzer: string; findings_json: string }>;
    return rows.map((r) => ({ analyzer: r.analyzer, findings: JSON.parse(r.findings_json) as Finding[] }));
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
    // Triage isn't its own column (it lives on the finding JSON so it round-trips with the rest of the
    // finding); filtering via json_extract keeps `all` (the default) a plain no-op clause.
    if (filter.triage === 'open') clauses.push(`json_extract(data_json, '$.triage.status') IS NULL`);
    else if (filter.triage === 'suppressed') clauses.push(`json_extract(data_json, '$.triage.status') IS NOT NULL`);
    if (filter.scanStatus) {
      clauses.push(`json_extract(data_json, '$.scanStatus') = ?`);
      params.push(filter.scanStatus);
    } else {
      clauses.push(NOT_FIXED_SQL);
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

  /** Counts over the scan's current findings (fixed rows excluded), plus the new/existing/fixed split. */
  counts(scanId: string): FindingCounts {
    const current = `scan_id = ? AND ${NOT_FIXED_SQL}`;
    const total = (this.db.prepare(`SELECT COUNT(*) as c FROM findings WHERE ${current}`).get(scanId) as { c: number }).c;
    const bySeverity: Partial<Record<Severity, number>> = {};
    for (const row of this.db.prepare(`SELECT severity, COUNT(*) as c FROM findings WHERE ${current} GROUP BY severity`).all(scanId) as SeverityCountRow[]) {
      bySeverity[row.severity] = row.c;
    }
    const byCategory: Partial<Record<Category, number>> = {};
    for (const row of this.db.prepare(`SELECT category, COUNT(*) as c FROM findings WHERE ${current} GROUP BY category`).all(scanId) as CategoryCountRow[]) {
      byCategory[row.category] = row.c;
    }
    const byScanStatus: Record<ScanStatus, number> = { new: 0, existing: 0, fixed: 0 };
    const statusRows = this.db.prepare(
      `SELECT json_extract(data_json, '$.scanStatus') AS s, COUNT(*) as c FROM findings WHERE scan_id = ? GROUP BY s`,
    ).all(scanId) as Array<{ s: string; c: number }>;
    for (const row of statusRows) if (row.s === 'new' || row.s === 'existing' || row.s === 'fixed') byScanStatus[row.s] = row.c;
    return { total, bySeverity, byCategory, byScanStatus };
  }
}
