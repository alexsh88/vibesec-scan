import { randomUUID } from 'node:crypto';
import type { TriageStatus } from '@vibesec/shared';
import type { Db } from '../db/database';

export type Suppression = {
  id: string;
  repoId: string;
  fingerprint: string;
  status: TriageStatus;
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
};

type Row = {
  id: string; repo_id: string; fingerprint: string; status: TriageStatus;
  reason: string; created_by: string; created_at: string; expires_at: string | null;
};

function toSuppression(r: Row): Suppression {
  return {
    id: r.id, repoId: r.repo_id, fingerprint: r.fingerprint, status: r.status,
    reason: r.reason, createdBy: r.created_by, createdAt: r.created_at, expiresAt: r.expires_at,
  };
}

/** One triage decision per (repo, fingerprint); re-applied to every future scan of that repo until cleared or it expires. */
export class SuppressionRepo {
  constructor(private readonly db: Db, private readonly now: () => string = () => new Date().toISOString()) {}

  /** Upsert by (repoId, fingerprint); the row's id and original created_at are kept across an update. */
  set(input: { repoId: string; fingerprint: string; status: TriageStatus; reason: string; createdBy: string; expiresAt: string | null }): Suppression {
    const existing = this.get(input.repoId, input.fingerprint);
    const id = existing?.id ?? randomUUID();
    const createdAt = existing?.createdAt ?? this.now();
    this.db.prepare(
      `INSERT INTO suppressions (id, repo_id, fingerprint, status, reason, created_by, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (repo_id, fingerprint) DO UPDATE SET
         status = excluded.status, reason = excluded.reason, created_by = excluded.created_by, expires_at = excluded.expires_at`,
    ).run(id, input.repoId, input.fingerprint, input.status, input.reason, input.createdBy, createdAt, input.expiresAt);
    return this.get(input.repoId, input.fingerprint)!;
  }

  clear(repoId: string, fingerprint: string): boolean {
    return this.db.prepare(`DELETE FROM suppressions WHERE repo_id = ? AND fingerprint = ?`).run(repoId, fingerprint).changes > 0;
  }

  get(repoId: string, fingerprint: string): Suppression | undefined {
    const row = this.db.prepare(`SELECT * FROM suppressions WHERE repo_id = ? AND fingerprint = ?`).get(repoId, fingerprint) as Row | undefined;
    return row ? toSuppression(row) : undefined;
  }

  listByRepo(repoId: string): Suppression[] {
    return (this.db.prepare(`SELECT * FROM suppressions WHERE repo_id = ? ORDER BY created_at DESC`).all(repoId) as Row[]).map(toSuppression);
  }

  /** Non-expired suppressions for a repo, keyed by fingerprint (for applySuppressions on a (re)scan). */
  activeByRepo(repoId: string, nowIso: string): Map<string, Suppression> {
    const rows = this.db.prepare(
      `SELECT * FROM suppressions WHERE repo_id = ? AND (expires_at IS NULL OR expires_at > ?)`,
    ).all(repoId, nowIso) as Row[];
    return new Map(rows.map((r) => [r.fingerprint, toSuppression(r)]));
  }
}
