import { createHash } from 'node:crypto';
import { isTerminalState, parseRepoUrl, type CreateScanRequest, type ScanDto } from '@vibesec/shared';
import type { AuditLogger } from '../audit/AuditLogger';
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
    const { db, scans, audit, queue, lifecycle } = this.d;

    if (meta.idempotencyKey) {
      const existing = scans.findByIdempotencyKey(meta.idempotencyKey);
      if (existing) return { scan: scans.getDto(existing.id)!, deduplicated: true };
    }

    const parsed = parseRepoUrl(req.repoUrl);
    if (!parsed) throw new AppError('VALIDATION', 'permanent', 'Invalid GitHub repository URL');

    const repo = scans.upsertRepo({ ...parsed, isPrivate: req.auth !== undefined });
    const ref = req.ref ?? null;
    const optionsHash = sha256(canonicalJson({ ref, options: req.options }));

    const duplicate = scans.findActiveDuplicate(repo.id, ref, optionsHash);
    if (duplicate) return { scan: scans.getDto(duplicate.id)!, deduplicated: true };

    if (queue.pendingCount() >= this.d.queueCapacity) {
      throw new AppError('QUEUE_FULL', 'transient', 'Too many scans in progress; try again shortly', { retryAfterMs: 30_000 });
    }

    const actor = { actorIp: meta.ip, userAgent: meta.userAgent };
    const row = db.transaction(() => {
      const r = scans.insertScan({
        repoId: repo.id, ref, options: req.options, optionsHash,
        idempotencyKey: meta.idempotencyKey, hasAuth: req.auth !== undefined,
      });
      audit.append({
        action: 'scan.created', targetType: 'scan', targetId: r.id, scanId: r.id, ...actor,
        details: { repo: `${parsed.owner}/${parsed.name}`, ref, options: req.options, private: req.auth !== undefined },
      });
      if (req.auth) {
        audit.append({
          action: 'repo.private_access', targetType: 'repo', targetId: repo.id, scanId: r.id, ...actor,
          details: { tokenType: req.auth.type, tokenFingerprint: sha256(req.auth.token).slice(0, 12) },
        });
      }
      return r;
    })();

    lifecycle.transition(row.id, 'QUEUED');
    queue.enqueue(row.id, { token: req.auth?.token });
    return { scan: scans.getDto(row.id)!, deduplicated: false };
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
    const result = this.d.queue.cancel(id);
    if (result !== 'aborted') this.d.lifecycle.transition(id, 'CANCELLED');
    this.d.audit.append({
      action: 'scan.cancelled', targetType: 'scan', targetId: id, scanId: id,
      actorIp: meta.ip, userAgent: meta.userAgent, details: { while: dto.state },
    });
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
