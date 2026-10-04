import { describe, expect, it } from 'vitest';
import { CreateScanRequestSchema } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { EventRepo } from '../src/db/eventRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { EventBus } from '../src/events/EventBus';
import type { CancelResult, ScanQueue } from '../src/jobs/JobRunner';
import type { ScanSecrets } from '../src/pipeline/types';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { ScanService, type RequestMeta } from '../src/scans/ScanService';
import { memoryDb } from './helpers';

class FakeQueue implements ScanQueue {
  enqueued: { scanId: string; secrets: ScanSecrets }[] = [];
  cancelResult: CancelResult = 'dequeued';
  pending = 0;
  enqueue(scanId: string, secrets: ScanSecrets) { this.enqueued.push({ scanId, secrets }); }
  cancel(): CancelResult { return this.cancelResult; }
  pendingCount() { return this.pending; }
}

const meta: RequestMeta = { ip: '127.0.0.1', userAgent: 'vitest', idempotencyKey: null };
const req = (body: unknown) => CreateScanRequestSchema.parse(body);

function setup(queueCapacity = 10) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const lifecycle = new ScanLifecycle(scans, new EventBus(new EventRepo(db)));
  const audit = new AuditLogger(db);
  const queue = new FakeQueue();
  const service = new ScanService({ db, scans, lifecycle, audit, queue, queueCapacity });
  return { scans, audit, queue, service };
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
    const token = 'github_pat_SUPERSECRET_1234567890';
    service.create(req({ repoUrl: 'https://github.com/acme/app', auth: { type: 'pat', token } }), meta);
    const entry = audit.list({ action: 'repo.private_access' }).items[0]!;
    expect(JSON.stringify(entry)).not.toContain('SUPERSECRET');
    expect(entry.details).toMatchObject({ tokenType: 'pat' });
    expect((entry.details.tokenFingerprint as string)).toHaveLength(12);
    expect(queue.enqueued[0]?.secrets.token).toBe(token);
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
});

describe('ScanService.cancel', () => {
  it('cancels a queued scan immediately and audits it', () => {
    const { service, audit } = setup();
    const { scan } = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    expect(service.cancel(scan.id, meta).state).toBe('CANCELLED');
    expect(audit.list({ action: 'scan.cancelled' }).items).toHaveLength(1);
  });

  it('leaves the transition to the runner when the scan is running', () => {
    const { service, queue } = setup();
    const { scan } = service.create(req({ repoUrl: 'https://github.com/acme/app' }), meta);
    queue.cancelResult = 'aborted';
    expect(service.cancel(scan.id, meta).state).toBe('QUEUED');
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
