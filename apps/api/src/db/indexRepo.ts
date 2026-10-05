import type { Entrypoint, ImportEdge, IndexedFile, IndexStats, RepoIndex } from '../index/types';
import type { Db } from './database';

type FileRow = {
  path: string; blob_sha: string; size: number; language: IndexedFile['language']; category: IndexedFile['category'];
  tags_json: string; skip_reason: IndexedFile['skipReason'];
};
type ImportRow = { from_path: string; specifier: string; kind: ImportEdge['kind']; to_path: string | null; package: string | null; line: number };
type EntrypointRow = { path: string; kind: Entrypoint['kind']; line: number | null; detail: string | null };

export class IndexRepo {
  constructor(private readonly db: Db) {}

  /** Atomically replaces the scan's index (idempotent, so a resumed INDEXING stage never duplicates rows). */
  replace(scanId: string, index: RepoIndex): void {
    this.db.transaction(() => {
      for (const table of ['scan_files', 'scan_imports', 'scan_entrypoints']) {
        this.db.prepare(`DELETE FROM ${table} WHERE scan_id = ?`).run(scanId);
      }
      const insertFile = this.db.prepare(
        `INSERT INTO scan_files (scan_id, path, blob_sha, size, language, category, tags_json, skip_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const f of index.files) {
        insertFile.run(scanId, f.path, f.blobSha, f.size, f.language, f.category, JSON.stringify(f.tags), f.skipReason);
      }
      const insertImport = this.db.prepare(
        `INSERT INTO scan_imports (scan_id, from_path, specifier, kind, to_path, package, line) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const e of index.imports) insertImport.run(scanId, e.from, e.specifier, e.kind, e.to, e.pkg, e.line);
      const insertEntrypoint = this.db.prepare(
        `INSERT INTO scan_entrypoints (scan_id, path, kind, line, detail) VALUES (?, ?, ?, ?, ?)`,
      );
      for (const ep of index.entrypoints) insertEntrypoint.run(scanId, ep.path, ep.kind, ep.line, ep.detail);
      this.db.prepare(`UPDATE scans SET index_stats_json = ? WHERE id = ?`).run(JSON.stringify(index.stats), scanId);
    })();
  }

  files(scanId: string, opts: { includeSkipped?: boolean } = {}): IndexedFile[] {
    const where = opts.includeSkipped ? '' : 'AND skip_reason IS NULL';
    const rows = this.db.prepare(`SELECT * FROM scan_files WHERE scan_id = ? ${where} ORDER BY path`).all(scanId) as FileRow[];
    return rows.map((r) => ({
      path: r.path, blobSha: r.blob_sha, size: r.size, language: r.language, category: r.category,
      tags: JSON.parse(r.tags_json) as IndexedFile['tags'], skipReason: r.skip_reason,
    }));
  }

  imports(scanId: string): ImportEdge[] {
    const rows = this.db.prepare(`SELECT * FROM scan_imports WHERE scan_id = ? ORDER BY rowid`).all(scanId) as ImportRow[];
    return rows.map((r) => ({ from: r.from_path, specifier: r.specifier, kind: r.kind, to: r.to_path, pkg: r.package, line: r.line }));
  }

  entrypoints(scanId: string): Entrypoint[] {
    return this.db.prepare(`SELECT path, kind, line, detail FROM scan_entrypoints WHERE scan_id = ? ORDER BY rowid`)
      .all(scanId) as EntrypointRow[];
  }

  stats(scanId: string): IndexStats | null {
    const row = this.db.prepare(`SELECT index_stats_json FROM scans WHERE id = ?`).get(scanId) as { index_stats_json: string | null } | undefined;
    return row?.index_stats_json ? (JSON.parse(row.index_stats_json) as IndexStats) : null;
  }
}
