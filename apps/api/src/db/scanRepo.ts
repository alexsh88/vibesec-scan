import { randomUUID } from 'node:crypto';
import { isTerminalState, ReuseStatsSchema, type ReuseStats, type ScanDto, type ScanOptions, type ScanState } from '@vibesec/shared';
import type { Db } from './database';

export type RepoRecord = { id: string; owner: string; name: string; isPrivate: boolean; defaultBranch: string | null };

export type ScanRow = {
  id: string; repo_id: string; ref: string | null; commit_sha: string | null; base_scan_id: string | null;
  state: ScanState; error_code: string | null; error_message: string | null;
  options_json: string; options_hash: string; analyzer_versions_hash: string | null;
  cache_hit: 'none' | 'partial' | 'full'; idempotency_key: string | null; has_auth: number;
  checkpoint_json: string | null; heartbeat_at: string | null; diagnostics_json: string | null;
  warnings_json: string; cost_usd: number; tokens_json: string | null; summary_json: string | null;
  created_at: string; started_at: string | null; finished_at: string | null;
  result_options_hash: string | null;
};

export type ScanWarning = { code: string; message: string; stage?: string; level?: 'info' | 'warning' };
/** Persisted in scans.diagnostics_json (free-form per-scan diagnostics; today only the reuse stats). */
export type ScanDiagnostics = { reuse?: ReuseStats };
/** The scan configuration the result caches key on (spec §11), besides the repo and the commit. */
export type ScanCacheKeys = { resultOptionsHash: string; analyzerVersionsHash: string };
export type Checkpoint = { completedStages: ScanState[]; data: Record<string, unknown> };

type RepoRow = { id: string; owner: string; name: string; is_private: number; default_branch: string | null };

const TERMINAL_SQL = `('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED')`;
const COMPLETED_SQL = `('COMPLETED','COMPLETED_WITH_WARNINGS')`;

export class ScanRepo {
  constructor(private readonly db: Db, private readonly now: () => string = () => new Date().toISOString()) {}

  upsertRepo(input: { owner: string; name: string; isPrivate: boolean }): RepoRecord {
    this.db.prepare(
      `INSERT INTO repos (id, owner, name, is_private, created_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (owner, name) DO UPDATE SET is_private = excluded.is_private`,
    ).run(randomUUID(), input.owner, input.name, input.isPrivate ? 1 : 0, this.now());
    const row = this.db.prepare(`SELECT * FROM repos WHERE owner = ? AND name = ?`).get(input.owner, input.name) as RepoRow;
    return toRepo(row);
  }

  /** Pure lookup: never creates the repo or touches is_private (for dedupe/reject paths). */
  findRepo(owner: string, name: string): RepoRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM repos WHERE owner = ? AND name = ?`).get(owner, name) as RepoRow | undefined;
    return row ? toRepo(row) : undefined;
  }

  getRepo(id: string): RepoRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM repos WHERE id = ?`).get(id) as RepoRow | undefined;
    return row ? toRepo(row) : undefined;
  }

  updateRepoMeta(repoId: string, meta: { isPrivate: boolean; defaultBranch: string }): void {
    this.db.prepare(`UPDATE repos SET is_private = ?, default_branch = ? WHERE id = ?`).run(meta.isPrivate ? 1 : 0, meta.defaultBranch, repoId);
  }

  insertScan(input: {
    repoId: string; ref: string | null; options: ScanOptions; optionsHash: string;
    idempotencyKey: string | null; hasAuth: boolean;
  }): ScanRow {
    const id = randomUUID();
    this.db.prepare(
      `INSERT INTO scans (id, repo_id, ref, state, options_json, options_hash, idempotency_key, has_auth, created_at)
       VALUES (?, ?, ?, 'QUEUED', ?, ?, ?, ?, ?)`,
    ).run(id, input.repoId, input.ref, JSON.stringify(input.options), input.optionsHash,
      input.idempotencyKey, input.hasAuth ? 1 : 0, this.now());
    return this.getRow(id)!;
  }

  getRow(id: string): ScanRow | undefined {
    return this.db.prepare(`SELECT * FROM scans WHERE id = ?`).get(id) as ScanRow | undefined;
  }

  getDto(id: string): ScanDto | undefined {
    const row = this.getRow(id);
    if (!row) return undefined;
    const repo = this.getRepo(row.repo_id)!;
    return {
      id: row.id,
      repo: { id: repo.id, owner: repo.owner, name: repo.name, isPrivate: repo.isPrivate },
      ref: row.ref,
      commitSha: row.commit_sha,
      state: row.state,
      errorCode: row.error_code,
      errorMessage: row.error_message,
      cacheHit: row.cache_hit,
      options: JSON.parse(row.options_json) as ScanOptions,
      costUsd: row.cost_usd,
      createdAt: row.created_at,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
      warnings: JSON.parse(row.warnings_json) as ScanWarning[],
      reuse: this.diagnosticsOf(row).reuse ?? null,
    };
  }

  private diagnosticsOf(row: ScanRow): ScanDiagnostics {
    if (!row.diagnostics_json) return {};
    const raw = JSON.parse(row.diagnostics_json) as ScanDiagnostics;
    const reuse = ReuseStatsSchema.safeParse(raw.reuse);
    return reuse.success ? { ...raw, reuse: reuse.data } : { ...raw, reuse: undefined };
  }

  getDiagnostics(id: string): ScanDiagnostics {
    const row = this.getRow(id);
    return row ? this.diagnosticsOf(row) : {};
  }

  /** Records the cache keys a scan was run with (set once the commit is resolved). */
  setCacheKeys(id: string, keys: ScanCacheKeys): void {
    this.db.prepare(`UPDATE scans SET result_options_hash = ?, analyzer_versions_hash = ? WHERE id = ?`)
      .run(keys.resultOptionsHash, keys.analyzerVersionsHash, id);
  }

  /**
   * Marks a scan as served (fully or partly) from an earlier one: cache_hit, base_scan_id and the reuse
   * stats in diagnostics_json. `cacheHit: 'none'` clears it (a resumed scan that fell back to a full scan).
   */
  setReuse(id: string, cacheHit: 'none' | 'partial' | 'full', reuse: ReuseStats | null): void {
    const row = this.getRow(id);
    if (!row) return;
    const diagnostics = this.diagnosticsOf(row);
    if (reuse) diagnostics.reuse = reuse;
    else delete diagnostics.reuse;
    this.db.prepare(`UPDATE scans SET cache_hit = ?, base_scan_id = ?, diagnostics_json = ? WHERE id = ?`)
      .run(cacheHit, reuse?.baseScanId ?? null, JSON.stringify(diagnostics), id);
  }

  /**
   * Full-scan cache (spec §11): the most recent completed scan of the same repo at the same commit with
   * the same result configuration — its results can be served as-is.
   */
  findFullCacheSource(repoId: string, commitSha: string, keys: ScanCacheKeys, excludeId: string): ScanRow | undefined {
    return this.db.prepare(
      `SELECT * FROM scans WHERE repo_id = ? AND commit_sha = ? AND result_options_hash = ? AND analyzer_versions_hash = ?
         AND state IN ${COMPLETED_SQL} AND id <> ?
       ORDER BY finished_at DESC, rowid DESC LIMIT 1`,
    ).get(repoId, commitSha, keys.resultOptionsHash, keys.analyzerVersionsHash, excludeId) as ScanRow | undefined;
  }

  /** Incremental rescans: the latest completed scan of the same repo + configuration at a DIFFERENT commit. */
  findIncrementalBase(repoId: string, commitSha: string, keys: ScanCacheKeys, excludeId: string): ScanRow | undefined {
    return this.db.prepare(
      `SELECT * FROM scans WHERE repo_id = ? AND commit_sha IS NOT NULL AND commit_sha <> ? AND result_options_hash = ?
         AND analyzer_versions_hash = ? AND state IN ${COMPLETED_SQL} AND id <> ?
       ORDER BY finished_at DESC, rowid DESC LIMIT 1`,
    ).get(repoId, commitSha, keys.resultOptionsHash, keys.analyzerVersionsHash, excludeId) as ScanRow | undefined;
  }

  /**
   * new/existing/fixed: the latest completed scan of the same repo (any options or commit) that was
   * requested no later than `scanId` (a scan never compares itself against a newer one).
   */
  findPreviousCompleted(repoId: string, scanId: string): ScanRow | undefined {
    return this.db.prepare(
      `SELECT * FROM scans WHERE repo_id = ? AND state IN ${COMPLETED_SQL} AND id <> ?
         AND created_at <= (SELECT created_at FROM scans WHERE id = ?)
       ORDER BY finished_at DESC, rowid DESC LIMIT 1`,
    ).get(repoId, scanId, scanId) as ScanRow | undefined;
  }

  findActiveDuplicate(repoId: string, ref: string | null, optionsHash: string): ScanRow | undefined {
    return this.db.prepare(
      `SELECT * FROM scans WHERE repo_id = ? AND ref IS ? AND options_hash = ? AND state NOT IN ${TERMINAL_SQL}
       ORDER BY created_at DESC LIMIT 1`,
    ).get(repoId, ref, optionsHash) as ScanRow | undefined;
  }

  findByIdempotencyKey(key: string): ScanRow | undefined {
    return this.db.prepare(`SELECT * FROM scans WHERE idempotency_key = ?`).get(key) as ScanRow | undefined;
  }

  updateState(id: string, state: ScanState, err: { errorCode?: string; errorMessage?: string } = {}): void {
    const now = this.now();
    this.db.prepare(
      `UPDATE scans SET state = ?, error_code = CASE WHEN ? = 'FAILED' THEN ? ELSE NULL END, error_message = CASE WHEN ? = 'FAILED' THEN ? ELSE NULL END,
         started_at = CASE WHEN started_at IS NULL AND ? <> 'QUEUED' THEN ? ELSE started_at END,
         finished_at = CASE WHEN ? = 1 THEN ? ELSE finished_at END
       WHERE id = ?`,
    ).run(state, state, err.errorCode ?? null, state, err.errorMessage ?? null, state, now, isTerminalState(state) ? 1 : 0, now, id);
  }

  /**
   * Terminal-once state change: only applies while the scan is still non-terminal, so a scan can never
   * leave (or re-enter) a terminal state. Returns whether the row changed.
   */
  transitionState(id: string, state: ScanState, err: { errorCode?: string; errorMessage?: string } = {}): boolean {
    const now = this.now();
    const failed = state === 'FAILED';
    const result = this.db.prepare(
      `UPDATE scans SET state = ?, error_code = ?, error_message = ?,
         started_at = CASE WHEN started_at IS NULL AND ? <> 'QUEUED' THEN ? ELSE started_at END,
         finished_at = CASE WHEN ? = 1 THEN ? ELSE finished_at END
       WHERE id = ? AND state NOT IN ${TERMINAL_SQL}`,
    ).run(state, failed ? err.errorCode ?? null : null, failed ? err.errorMessage ?? null : null,
      state, now, isTerminalState(state) ? 1 : 0, now, id);
    return result.changes > 0;
  }

  setCommitSha(id: string, sha: string): void {
    this.db.prepare(`UPDATE scans SET commit_sha = ? WHERE id = ?`).run(sha, id);
  }

  addWarning(id: string, warning: ScanWarning): void {
    this.db.prepare(`UPDATE scans SET warnings_json = json_insert(warnings_json, '$[#]', json(?)) WHERE id = ?`)
      .run(JSON.stringify(warning), id);
  }

  /** Drops warnings attributed to any of `stages` (order preserved; warnings without a stage are kept). */
  removeWarningsForStages(id: string, stages: readonly string[]): void {
    if (stages.length === 0) return;
    const row = this.db.prepare(`SELECT warnings_json FROM scans WHERE id = ?`).get(id) as { warnings_json: string } | undefined;
    if (!row) return;
    const drop = new Set(stages);
    const warnings = JSON.parse(row.warnings_json) as ScanWarning[];
    const kept = warnings.filter((w) => w.stage === undefined || !drop.has(w.stage));
    if (kept.length !== warnings.length) {
      this.db.prepare(`UPDATE scans SET warnings_json = ? WHERE id = ?`).run(JSON.stringify(kept), id);
    }
  }

  setCheckpoint(id: string, checkpoint: Checkpoint): void {
    this.db.prepare(`UPDATE scans SET checkpoint_json = ? WHERE id = ?`).run(JSON.stringify(checkpoint), id);
  }

  getCheckpoint(id: string): Checkpoint | null {
    const raw = this.getRow(id)?.checkpoint_json;
    return raw ? (JSON.parse(raw) as Checkpoint) : null;
  }

  heartbeat(id: string): void {
    this.db.prepare(`UPDATE scans SET heartbeat_at = ? WHERE id = ?`).run(this.now(), id);
  }

  listNonTerminal(): ScanRow[] {
    return this.db.prepare(`SELECT * FROM scans WHERE state NOT IN ${TERMINAL_SQL} ORDER BY created_at, id`).all() as ScanRow[];
  }

  listByRepo(repoId: string, limit = 50): ScanDto[] {
    const ids = this.db.prepare(`SELECT id FROM scans WHERE repo_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`)
      .all(repoId, limit) as { id: string }[];
    return ids.map((r) => this.getDto(r.id)!);
  }

  listRepos(): RepoRecord[] {
    return (this.db.prepare(`SELECT * FROM repos ORDER BY created_at DESC`).all() as RepoRow[]).map(toRepo);
  }

  addCost(scanId: string, usd: number): void {
    this.db.prepare(`UPDATE scans SET cost_usd = cost_usd + ? WHERE id = ?`).run(usd, scanId);
  }
}

function toRepo(row: RepoRow): RepoRecord {
  return { id: row.id, owner: row.owner, name: row.name, isPrivate: row.is_private === 1, defaultBranch: row.default_branch };
}
