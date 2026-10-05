import { createHash } from 'node:crypto';
import type { Db } from '../db/database';
import { scrubDeep } from '../security/scrub';
import { canonicalJson } from './canonicalJson';

export const GENESIS_HASH = '0'.repeat(64);

export const AUDIT_ACTIONS = [
  'scan.created', 'scan.cancelled', 'scan.resumed', 'scan.completed', 'scan.failed',
  'repo.private_access', 'secret.verification_attempted', 'finding.triaged', 'finding.untriaged',
  'export.downloaded', 'config.changed', 'audit.verified',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export type AuditInput = {
  action: AuditAction; targetType: string; targetId: string;
  scanId?: string | null; details?: Record<string, unknown>;
  actor?: string; actorIp?: string | null; userAgent?: string | null;
};

export type AuditEntry = {
  seq: number; at: string; actor: string; actorIp: string | null; userAgent: string | null;
  action: AuditAction; targetType: string; targetId: string; scanId: string | null;
  details: Record<string, unknown>; prevHash: string; hash: string;
};

type AuditRow = {
  seq: number; at: string; actor: string; actor_ip: string | null; user_agent: string | null;
  action: AuditAction; target_type: string; target_id: string; scan_id: string | null;
  details_json: string; prev_hash: string; hash: string;
};

export type AuditListFilter = {
  action?: AuditAction; targetType?: string; targetId?: string;
  from?: string; to?: string; beforeSeq?: number; limit?: number;
};

export type VerifyResult = { ok: true; checked: number } | { ok: false; checked: number; firstBrokenSeq: number };

function hashEntry(e: Omit<AuditEntry, 'seq' | 'hash'>): string {
  const payload = canonicalJson({
    at: e.at, actor: e.actor, actorIp: e.actorIp, userAgent: e.userAgent, action: e.action,
    targetType: e.targetType, targetId: e.targetId, scanId: e.scanId, details: e.details,
  });
  return createHash('sha256').update(e.prevHash).update(payload).digest('hex');
}

function toEntry(r: AuditRow): AuditEntry {
  return {
    seq: r.seq, at: r.at, actor: r.actor, actorIp: r.actor_ip, userAgent: r.user_agent, action: r.action,
    targetType: r.target_type, targetId: r.target_id, scanId: r.scan_id,
    details: JSON.parse(r.details_json) as Record<string, unknown>, prevHash: r.prev_hash, hash: r.hash,
  };
}

export class AuditLogger {
  constructor(private readonly db: Db, private readonly now: () => string = () => new Date().toISOString()) {}

  append(input: AuditInput): AuditEntry {
    return this.db.transaction((): AuditEntry => {
      const last = this.db.prepare(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).get() as { hash: string } | undefined;
      const base = {
        at: this.now(),
        actor: input.actor ?? 'local-user',
        actorIp: input.actorIp ?? null,
        userAgent: input.userAgent ?? null,
        action: input.action,
        targetType: input.targetType,
        targetId: input.targetId,
        scanId: input.scanId ?? null,
        details: scrubDeep(input.details ?? {}),
        prevHash: last?.hash ?? GENESIS_HASH,
      };
      const hash = hashEntry(base);
      const { lastInsertRowid } = this.db.prepare(
        `INSERT INTO audit_log (at, actor, actor_ip, user_agent, action, target_type, target_id, scan_id, details_json, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(base.at, base.actor, base.actorIp, base.userAgent, base.action, base.targetType, base.targetId,
        base.scanId, JSON.stringify(base.details), base.prevHash, hash);
      return { ...base, seq: Number(lastInsertRowid), hash };
    })();
  }

  verify(): VerifyResult {
    let prev = GENESIS_HASH;
    let checked = 0;
    const rows = this.db.prepare(`SELECT * FROM audit_log ORDER BY seq`).iterate() as IterableIterator<AuditRow>;
    for (const row of rows) {
      const e = toEntry(row);
      if (e.prevHash !== prev || hashEntry(e) !== e.hash) return { ok: false, checked, firstBrokenSeq: e.seq };
      prev = e.hash;
      checked += 1;
    }
    return { ok: true, checked };
  }

  list(f: AuditListFilter): { items: AuditEntry[]; nextCursor: number | null } {
    const where: string[] = [];
    const args: unknown[] = [];
    if (f.action) { where.push('action = ?'); args.push(f.action); }
    if (f.targetType) { where.push('target_type = ?'); args.push(f.targetType); }
    if (f.targetId) { where.push('target_id = ?'); args.push(f.targetId); }
    if (f.from) { where.push('at >= ?'); args.push(f.from); }
    if (f.to) { where.push('at <= ?'); args.push(f.to); }
    if (f.beforeSeq != null) { where.push('seq < ?'); args.push(f.beforeSeq); }
    const limit = Math.min(Math.max(f.limit ?? 50, 1), 200);
    const sql = `SELECT * FROM audit_log ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT ?`;
    const rows = this.db.prepare(sql).all(...args, limit + 1) as AuditRow[];
    const items = rows.slice(0, limit).map(toEntry);
    return { items, nextCursor: rows.length > limit ? items[items.length - 1]!.seq : null };
  }
}
