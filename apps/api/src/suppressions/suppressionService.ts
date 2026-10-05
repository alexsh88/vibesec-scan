import type { Finding, Triage, TriageStatus } from '@vibesec/shared';
import type { AuditLogger } from '../audit/AuditLogger';
import type { FindingRepo } from '../db/findingRepo';
import type { ScanRepo } from '../db/scanRepo';
import { AppError } from '../errors/AppError';
import type { Suppression, SuppressionRepo } from './suppressionRepo';

export type TriageInput = { status: TriageStatus; reason: string; expiresAt?: string };
/** Shaped like scans/ScanService's RequestMeta (minus idempotencyKey, irrelevant here) so routes can pass `requestMeta(req)` directly. */
export type TriageMeta = { ip: string | null; userAgent: string | null };

/** Length of the fingerprint prefix recorded on audit entries (never the full value, never finding text). */
const FP_PREFIX_LEN = 12;

/** Finding triage (P7 Task A): suppress false positives/accepted risks by fingerprint, across rescans of the same repo. */
export class SuppressionService {
  constructor(
    private readonly suppressions: SuppressionRepo,
    private readonly findings: FindingRepo,
    private readonly scans: ScanRepo,
    private readonly audit: AuditLogger,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  private resolve(scanId: string, findingId: string): { repoId: string; finding: Finding } {
    const scan = this.scans.getRow(scanId);
    if (!scan) throw new AppError('NOT_FOUND', 'permanent', 'Scan not found');
    const finding = this.findings.get(scanId, findingId);
    if (!finding) throw new AppError('NOT_FOUND', 'permanent', 'Finding not found');
    return { repoId: scan.repo_id, finding };
  }

  setTriage(scanId: string, findingId: string, input: TriageInput, meta: TriageMeta): Finding {
    const { repoId, finding } = this.resolve(scanId, findingId);
    const at = this.now();
    this.suppressions.set({
      repoId, fingerprint: finding.fingerprint, status: input.status, reason: input.reason,
      createdBy: 'local-user', expiresAt: input.expiresAt ?? null,
    });
    const triage: Triage = { status: input.status, reason: input.reason, at, ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}) };
    const updated: Finding = { ...finding, triage };
    this.findings.update(scanId, [updated]);
    this.audit.append({
      action: 'finding.triaged', targetType: 'finding', targetId: findingId, scanId,
      actorIp: meta.ip, userAgent: meta.userAgent,
      details: { fingerprint: finding.fingerprint.slice(0, FP_PREFIX_LEN), status: input.status },
    });
    return updated;
  }

  clearTriage(scanId: string, findingId: string, meta: TriageMeta): Finding {
    const { repoId, finding } = this.resolve(scanId, findingId);
    this.suppressions.clear(repoId, finding.fingerprint);
    const previousStatus = finding.triage?.status;
    const updated: Finding = { ...finding };
    delete updated.triage;
    this.findings.update(scanId, [updated]);
    this.audit.append({
      action: 'finding.untriaged', targetType: 'finding', targetId: findingId, scanId,
      actorIp: meta.ip, userAgent: meta.userAgent,
      details: { fingerprint: finding.fingerprint.slice(0, FP_PREFIX_LEN), ...(previousStatus ? { status: previousStatus } : {}) },
    });
    return updated;
  }

  listByRepo(repoId: string): Suppression[] {
    return this.suppressions.listByRepo(repoId);
  }

  /**
   * Re-annotates every finding of `scanId` whose fingerprint carries an active (non-expired)
   * suppression for its repo — called by the pipeline after SCORING so a rescan remembers prior
   * triage decisions. Idempotent: a finding already carrying the identical triage is left untouched.
   */
  applySuppressions(scanId: string): void {
    const scan = this.scans.getRow(scanId);
    if (!scan) return;
    const active = this.suppressions.activeByRepo(scan.repo_id, this.now());
    if (active.size === 0) return;
    const updates: Finding[] = [];
    for (const { finding } of this.findings.all(scanId)) {
      const sup = active.get(finding.fingerprint);
      if (!sup) continue;
      const triage: Triage = { status: sup.status, reason: sup.reason, at: sup.createdAt, ...(sup.expiresAt ? { expiresAt: sup.expiresAt } : {}) };
      const current = finding.triage;
      if (current && current.status === triage.status && current.reason === triage.reason && current.at === triage.at && current.expiresAt === triage.expiresAt) continue;
      updates.push({ ...finding, triage });
    }
    if (updates.length > 0) this.findings.update(scanId, updates);
  }
}
