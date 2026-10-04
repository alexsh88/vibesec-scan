import { createHash } from 'node:crypto';
import { isTerminalState, parseRepoUrl, type CreateScanRequest, type ScanDto } from '@vibesec/shared';
import type { AuditInput, AuditLogger } from '../audit/AuditLogger';
import { canonicalJson } from '../audit/canonicalJson';
import type { Db } from '../db/database';
import type { RepoRecord, ScanRepo } from '../db/scanRepo';
import { AppError } from '../errors/AppError';
import type { ScanQueue } from '../jobs/JobRunner';
import type { ScanLifecycle } from './ScanLifecycle';

export type RequestMeta = { ip: string | null; userAgent: string | null; idempotencyKey: string | null };

export type ScanServiceDeps = {
  db: Db; scans: ScanRepo; lifecycle: ScanLifecycle; audit: AuditLogger; queue: ScanQueue; queueCapacity: number;
};

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export class ScanService {
  constructor(private readonly d: ScanServiceDeps) {}

  create(req: CreateScanRequest, meta: RequestMeta): { scan: ScanDto; deduplicated: boolean } {
    const { scans, audit, queue, lifecycle } = this.d;

    if (meta.idempotencyKey) {
      const existing = scans.findByIdempotencyKey(meta.idempotencyKey);
      if (existing) return { scan: scans.getDto(existing.id)!, deduplicated: true };
    }

    const parsed = parseRepoUrl(req.repoUrl);
    if (!parsed) throw new AppError('VALIDATION', 'permanent', 'Invalid GitHub repository URL');

    const hasAuth = req.auth !== undefined;
    const ref = req.ref ?? null;
    const optionsHash = sha256(canonicalJson({ ref, options: req.options }));

    // Dedupe is a pure read: it must not create the repo or flip is_private.
    const known = scans.findRepo(parsed.owner, parsed.name);
    const duplicate = known ? scans.findActiveDuplicate(known.id, ref, optionsHash) : undefined;
    // Never attach a token-bearing request to a scan running without one: the new token would be dropped.
    if (duplicate && (duplicate.has_auth === 1 || !hasAuth)) {
      return { scan: scans.getDto(duplicate.id)!, deduplicated: true };
    }

    // Admission is checked before any write, so a rejected request leaves nothing behind.
    if (!queue.accepting()) {
      throw new AppError('QUEUE_FULL', 'transient', 'Server is shutting down; try again shortly', { retryAfterMs: 30_000 });
    }
    if (queue.pendingCount() >= this.d.queueCapacity) {
      throw new AppError('QUEUE_FULL', 'transient', 'Too many scans in progress; try again shortly', { retryAfterMs: 30_000 });
    }

    const actor = { actorIp: meta.ip, userAgent: meta.userAgent };
    // Insert + audit + QUEUED + enqueue are one unit: if enqueue throws, everything rolls back (no orphan
    // row, idempotency key stays free) and no event is ever notified. enqueue is the last step.
    const scanId = lifecycle.atomically(() => {
      const repo = scans.upsertRepo({ ...parsed, isPrivate: hasAuth });
      const r = scans.insertScan({ repoId: repo.id, ref, options: req.options, optionsHash, idempotencyKey: meta.idempotencyKey, hasAuth });
      audit.append({
        action: 'scan.created', targetType: 'scan', targetId: r.id, scanId: r.id, ...actor,
        details: { repo: `${parsed.owner}/${parsed.name}`, ref, options: req.options, private: hasAuth },
      });
      if (req.auth) {
        audit.append({
          action: 'repo.private_access', targetType: 'repo', targetId: repo.id, scanId: r.id, ...actor,
          details: { tokenType: req.auth.type, tokenFingerprint: sha256(req.auth.token).slice(0, 12) },
        });
      }
      lifecycle.transition(r.id, 'QUEUED');
      queue.enqueue(r.id, { token: req.auth?.token });
      return r.id;
    });
    return { scan: scans.getDto(scanId)!, deduplicated: false };
  }

  get(id: string): ScanDto {
    const dto = this.d.scans.getDto(id);
    if (!dto) throw new AppError('NOT_FOUND', 'permanent', 'Scan not found');
    return dto;
  }

  cancel(id: string, meta: RequestMeta): ScanDto {
    const dto = this.get(id);
    if (isTerminalState(dto.state)) {
      throw new AppError('CONFLICT', 'permanent', `Scan is already ${dto.state.toLowerCase().replaceAll('_', ' ')}`);
    }
    const audit: AuditInput = {
      action: 'scan.cancelled', targetType: 'scan', targetId: id, scanId: id,
      actorIp: meta.ip, userAgent: meta.userAgent, details: { while: dto.state },
    };
    // A running scan is aborted and the runner's CANCELLED transition carries this audit entry;
    // otherwise the transition happens here, with the audit in the same transaction (only if it applied).
    const result = this.d.queue.cancel(id, audit);
    if (result !== 'aborted') this.d.lifecycle.transition(id, 'CANCELLED', undefined, audit);
    return this.get(id);
  }

  listRepos(): RepoRecord[] {
    return this.d.scans.listRepos();
  }

  listScans(repoId: string): ScanDto[] {
    if (!this.d.scans.getRepo(repoId)) throw new AppError('NOT_FOUND', 'permanent', 'Repository not found');
    return this.d.scans.listByRepo(repoId);
  }
}
