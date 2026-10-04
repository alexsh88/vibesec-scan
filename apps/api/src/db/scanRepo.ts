import { randomUUID } from 'node:crypto';
import { isTerminalState, type ScanDto, type ScanOptions, type ScanState } from '@vibesec/shared';
import type { Db } from './database';

export type RepoRecord = { id: string; owner: string; name: string; isPrivate: boolean };

export type ScanRow = {
  id: string; repo_id: string; ref: string | null; commit_sha: string | null; base_scan_id: string | null;
  state: ScanState; error_code: string | null; error_message: string | null;
  options_json: string; options_hash: string; analyzer_versions_hash: string | null;
  cache_hit: 'none' | 'partial' | 'full'; idempotency_key: string | null; has_auth: number;
  checkpoint_json: string | null; heartbeat_at: string | null; diagnostics_json: string | null;
  warnings_json: string; cost_usd: number; tokens_json: string | null; summary_json: string | null;
  created_at: string; started_at: string | null; finished_at: string | null;
};

export type ScanWarning = { code: string; message: string; stage?: string };
export type Checkpoint = { completedStages: ScanState[]; data: Record<string, unknown> };

type RepoRow = { id: string; owner: string; name: string; is_private: number };

const TERMINAL_SQL = `('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED')`;

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

  getRepo(id: string): RepoRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM repos WHERE id = ?`).get(id) as RepoRow | undefined;
    return row ? toRepo(row) : undefined;
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
      repo,
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
    };
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
      `UPDATE scans SET state = ?, error_code = COALESCE(?, error_code), error_message = COALESCE(?, error_message),
         started_at = CASE WHEN started_at IS NULL AND ? <> 'QUEUED' THEN ? ELSE started_at END,
         finished_at = CASE WHEN ? = 1 THEN ? ELSE finished_at END
       WHERE id = ?`,
    ).run(state, err.errorCode ?? null, err.errorMessage ?? null, state, now, isTerminalState(state) ? 1 : 0, now, id);
  }

  setCommitSha(id: string, sha: string): void {
    this.db.prepare(`UPDATE scans SET commit_sha = ? WHERE id = ?`).run(sha, id);
  }

  addWarning(id: string, warning: ScanWarning): void {
    this.db.prepare(`UPDATE scans SET warnings_json = json_insert(warnings_json, '$[#]', json(?)) WHERE id = ?`)
      .run(JSON.stringify(warning), id);
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
    return this.db.prepare(`SELECT * FROM scans WHERE state NOT IN ${TERMINAL_SQL} ORDER BY created_at`).all() as ScanRow[];
  }

  listByRepo(repoId: string, limit = 50): ScanDto[] {
    const ids = this.db.prepare(`SELECT id FROM scans WHERE repo_id = ? ORDER BY created_at DESC LIMIT ?`)
      .all(repoId, limit) as { id: string }[];
    return ids.map((r) => this.getDto(r.id)!);
  }

  listRepos(): RepoRecord[] {
    return (this.db.prepare(`SELECT * FROM repos ORDER BY created_at DESC`).all() as RepoRow[]).map(toRepo);
  }
}

function toRepo(row: RepoRow): RepoRecord {
  return { id: row.id, owner: row.owner, name: row.name, isPrivate: row.is_private === 1 };
}
