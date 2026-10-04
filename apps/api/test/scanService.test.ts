import { describe, expect, it } from 'vitest';
import { CreateScanRequestSchema } from '@vibesec/shared';
import { AuditLogger, type AuditInput } from '../src/audit/AuditLogger';
import { EventRepo } from '../src/db/eventRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { EventBus } from '../src/events/EventBus';
import type { CancelResult, ScanQueue } from '../src/jobs/JobRunner';
import type { ScanSecrets } from '../src/pipeline/types';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { ScanService, type RequestMeta } from '../src/scans/ScanService';
import { memoryDb } from './helpers';

class FakeQueue implements ScanQueue {
  enqueued: { scanId: string; secrets: ScanSecrets }[] = [];
  cancelled: { scanId: string; audit: AuditInput | undefined }[] = [];
  cancelResult: CancelResult = 'dequeued';
  pending = 0;
  open = true;
  failEnqueue = false;
  enqueue(scanId: string, secrets: ScanSecrets) {
    if (this.failEnqueue) throw new AppError('QUEUE_FULL', 'transient', 'Server is shutting down; try again shortly');
    this.enqueued.push({ scanId, secrets });
  }
  cancel(scanId: string, audit?: AuditInput): CancelResult { this.cancelled.push({ scanId, audit }); return this.cancelResult; }
  pendingCount() { return this.pending; }
  accepting() { return this.open; }
}

const meta: RequestMeta = { ip: '127.0.0.1', userAgent: 'vitest', idempotencyKey: null };
const req = (body: unknown) => CreateScanRequestSchema.parse(body);
const pat = { type: 'pat', token: 'github_pat_SUPERSECRET_1234567890' };

function setup(queueCapacity = 10) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, new EventBus(new EventRepo(db)), db, audit);
  const queue = new FakeQueue();
  const service = new ScanService({ db, scans, lifecycle, audit, queue, queueCapacity });
  const counts = () => ({
    scans: (db.prepare('SELECT COUNT(*) AS n FROM scans').get() as { n: number }).n,
    events: (db.prepare('SELECT COUNT(*) AS n FROM scan_events').get() as { n: number }).n,
    audit: (db.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as { n: number }).n,
    repos: (db.prepare('SELECT COUNT(*) AS n FROM repos').get() as { n: number }).n,
  });
  return { scans, audit, queue, service, counts };
}

describe('ScanService.create', () => {
  it('creates a QUEUED scan, enqueues it and audits it', () => {
    const { service, queue, audit } = setup();
    const { scan, deduplicated } = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    expect(deduplicated).toBe(false);
    expect(scan.state).toBe('QUEUED');
    expect(queue.enqueued).toEqual([{ scanId: scan.id, secrets: { token: undefined } }]);
    const created = audit.list({ action: 'scan.created' }).items[0]!;
    expect(created).toMatchObject({ targetId: scan.id, actorIp: '127.0.0.1', userAgent: 'vitest' });
  });

  it('audits private-repo access with a token fingerprint, never the token', () => {
    const { service, audit, queue } = setup();
    service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), meta);
    const entry = audit.list({ action: 'repo.private_access' }).items[0]!;
    expect(JSON.stringify(entry)).not.toContain('SUPERSECRET');
    expect(entry.details).toMatchObject({ tokenType: 'pat' });
    expect((entry.details.tokenFingerprint as string)).toHaveLength(12);
    expect(queue.enqueued[0]?.secrets.token).toBe(pat.token);
  });

  it('returns the same scan for a repeated idempotency key', () => {
    const { service } = setup();
    const m = { ...meta, idempotencyKey: 'abc' };
    const a = service.create(req({ repoUrl: 'https://github.com/acme/app' }), m);
    const b = service.create(req({ repoUrl: 'https://github.com/acme/other' }), m);
    expect(b).toEqual({ scan: a.scan, deduplicated: true });
  });

  it('dedupes an identical active scan', () => {
    const { service, queue } = setup();
    const a = service.create(req({ repoUrl: 'https://github.com/acme/app', ref: 'main' }), meta);
    const b = service.create(req({ repoUrl: 'https://github.com/acme/app', ref: 'main' }), meta);
    expect(b.deduplicated).toBe(true);
    expect(b.scan.id).toBe(a.scan.id);
    expect(queue.enqueued).toHaveLength(1);
  });

  it('rejects when the queue is full', () => {
    const { service, queue } = setup(1);
    queue.pending = 1;
    expect(() => service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta))
      .toThrow(expect.objectContaining({ code: 'QUEUE_FULL' }));
  });

  it('#1: rejects with QUEUE_FULL before writing anything when the queue is not accepting (shutdown)', () => {
    const { service, queue, counts } = setup();
    queue.open = false;
    expect(() => service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), { ...meta, idempotencyKey: 'k' }))
      .toThrow(expect.objectContaining({ code: 'QUEUE_FULL' }));
    expect(counts()).toEqual({ scans: 0, events: 0, audit: 0, repos: 0 });
    expect(queue.enqueued).toEqual([]);
  });

  it('#1: rolls back the scan, its audit rows and events when enqueue throws; the idempotency key stays free', () => {
    const { service, queue, counts } = setup();
    queue.failEnqueue = true;
    const m = { ...meta, idempotencyKey: 'k' };
    expect(() => service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), m))
      .toThrow(expect.objectContaining({ code: 'QUEUE_FULL' }));
    expect(counts()).toEqual({ scans: 0, events: 0, audit: 0, repos: 0 });
    queue.failEnqueue = false;
    const retry = service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), m);
    expect(retry.deduplicated).toBe(false);
    expect(queue.enqueued).toEqual([{ scanId: retry.scan.id, secrets: { token: pat.token } }]);
  });

  it('#5: does not dedupe a token-bearing request onto an active scan without a token', () => {
    const { service, queue } = setup();
    const a = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    const b = service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), meta);
    expect(b.deduplicated).toBe(false);
    expect(b.scan.id).not.toBe(a.scan.id);
    expect(queue.enqueued.map((e) => e.secrets.token)).toEqual([undefined, pat.token]);
    expect(b.scan.repo.isPrivate).toBe(true);
  });

  it('#5: dedupes a tokenless request onto an active private scan without flipping repos.is_private', () => {
    const { service, scans } = setup();
    const a = service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), meta);
    const b = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    expect(b).toMatchObject({ deduplicated: true, scan: { id: a.scan.id } });
    expect(scans.getRepo(a.scan.repo.id)?.isPrivate).toBe(true);
  });

  it('#5: a rejected (503) request does not change repos.is_private', () => {
    const { service, scans, queue } = setup();
    const a = service.create(req({ repoUrl: 'https://github.com/acme/app', ref: 'main' }), meta);
    queue.open = false;
    expect(() => service.create(req({ repoUrl: 'https://github.com/acme/app', auth: pat }), meta)).toThrow();
    expect(scans.getRepo(a.scan.repo.id)?.isPrivate).toBe(false);
  });
});

describe('ScanService.cancel', () => {
  it('cancels a queued scan immediately and audits it', () => {
    const { service, audit } = setup();
    const { scan } = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    expect(service.cancel(scan.id, meta).state).toBe('CANCELLED');
    expect(audit.list({ action: 'scan.cancelled' }).items).toHaveLength(1);
  });

  it('#6: leaves the transition and its audit to the runner when the scan is running', () => {
    const { service, queue, audit } = setup();
    const { scan } = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    queue.cancelResult = 'aborted';
    expect(service.cancel(scan.id, meta).state).toBe('QUEUED');
    expect(audit.list({ action: 'scan.cancelled' }).items).toHaveLength(0);
    expect(queue.cancelled[0]?.audit).toMatchObject({
      action: 'scan.cancelled', targetId: scan.id, actorIp: '127.0.0.1', userAgent: 'vitest', details: { while: 'QUEUED' },
    });
  });

  it('rejects cancelling a terminal scan with CONFLICT', () => {
    const { service } = setup();
    const { scan } = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    service.cancel(scan.id, meta);
    expect(() => service.cancel(scan.id, meta)).toThrow(expect.objectContaining({ code: 'CONFLICT' }));
  });

  it('rejects unknown scans with NOT_FOUND', () => {
    const { service } = setup();
    expect(() => service.get('missing')).toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });
});
