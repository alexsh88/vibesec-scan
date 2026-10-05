import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { EventRepo } from '../src/db/eventRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { EventBus } from '../src/events/EventBus';
import { JobRunner } from '../src/jobs/JobRunner';
import type { Pipeline, PipelineContext, StageSpec } from '../src/pipeline/types';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { memoryDb, waitFor } from './helpers';

function make(pipeline: Pipeline) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);
  const runner = new JobRunner({
    scans, lifecycle, bus, audit, pipeline,
    config: { maxConcurrentScans: 1, scanDeadlineMs: 5_000, heartbeatMs: 1_000, stuckAfterMs: 60_000, staleHeartbeatMs: 30_000, queueCapacity: 10 },
  });
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const newScan = () => scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: randomUUID(), idempotencyKey: null, hasAuth: false,
  }).id;
  return { scans, runner, newScan };
}

const stage = (run: StageSpec['run'], fatal = true): StageSpec => ({ name: 'RESOLVING', fatal, run });
const blockUntilAborted = (ctx: PipelineContext) =>
  new Promise<void>((_, reject) => ctx.signal.addEventListener('abort', () => reject(ctx.signal.reason), { once: true }));

describe('Pipeline.onScanFinished', () => {
  it('runs once after a scan completes', async () => {
    const hook = vi.fn(async () => {});
    const { runner, newScan } = make({ stages: [stage(async () => {})], onScanFinished: hook });
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(hook).toHaveBeenCalledExactlyOnceWith(id);
  });

  it('runs after a scan fails', async () => {
    const hook = vi.fn(async () => {});
    const { runner, newScan, scans } = make({
      stages: [stage(async () => { throw new AppError('AUTH_INVALID', 'permanent', 'bad'); })], onScanFinished: hook,
    });
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)!.state).toBe('FAILED');
    expect(hook).toHaveBeenCalledOnce();
  });

  it('does not run when shutdown leaves the scan resumable', async () => {
    const hook = vi.fn(async () => {});
    const { runner, newScan, scans } = make({ stages: [stage(blockUntilAborted)], onScanFinished: hook });
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'RESOLVING');
    await runner.shutdown(10);
    expect(hook).not.toHaveBeenCalled();
  });

  it('a throwing hook never changes the outcome', async () => {
    const { runner, newScan, scans } = make({
      stages: [stage(async () => {})], onScanFinished: async () => { throw new Error('rm failed'); },
    });
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)!.state).toBe('COMPLETED');
  });
});
