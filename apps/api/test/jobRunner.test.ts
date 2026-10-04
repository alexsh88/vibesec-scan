import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { EventRepo } from '../src/db/eventRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { EventBus } from '../src/events/EventBus';
import { JobRunner, type JobRunnerConfig } from '../src/jobs/JobRunner';
import type { PipelineContext, StageName, StageSpec } from '../src/pipeline/types';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { memoryDb, waitFor } from './helpers';

const stage = (name: StageName, opts: { fatal?: boolean; run?: StageSpec['run'] } = {}): StageSpec => ({
  name, fatal: opts.fatal ?? false, run: opts.run ?? (async () => {}),
});

const blockUntilAborted = (ctx: PipelineContext) =>
  new Promise<void>((_, reject) => ctx.signal.addEventListener('abort', () => reject(ctx.signal.reason), { once: true }));

function setup(stages: StageSpec[], cfg: Partial<JobRunnerConfig> = {}, now?: () => number) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const events = new EventRepo(db);
  const bus = new EventBus(events);
  const lifecycle = new ScanLifecycle(scans, bus);
  const audit = new AuditLogger(db);
  const runner = new JobRunner({
    scans, lifecycle, bus, audit, pipeline: { stages }, now,
    config: { maxConcurrentScans: 2, scanDeadlineMs: 5_000, heartbeatMs: 1_000, stuckAfterMs: 60_000, ...cfg },
  });
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const newScan = (hasAuth = false) => scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: randomUUID(), idempotencyKey: null, hasAuth,
  }).id;
  const states = (id: string) => events.listAfter(id, 0)
    .flatMap((e) => (e.event.type === 'state' ? [e.event.state] : []));
  return { scans, audit, runner, newScan, states };
}

describe('JobRunner', () => {
  it('runs all stages in order and completes', async () => {
    const { runner, newScan, states, audit } = setup([stage('RESOLVING'), stage('CLONING'), stage('ANALYZING')]);
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(states(id)).toEqual(['RESOLVING', 'CLONING', 'ANALYZING', 'COMPLETED']);
    expect(audit.list({ action: 'scan.completed' }).items).toHaveLength(1);
  });

  it('turns a degradable stage failure into a warning and continues', async () => {
    const verifying = vi.fn(async () => {});
    const { runner, newScan, scans } = setup([
      stage('ANALYZING', { run: async () => { throw new AppError('OSV_UNAVAILABLE', 'transient', 'osv down'); } }),
      stage('VERIFYING', { run: verifying }),
    ]);
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    const dto = scans.getDto(id)!;
    expect(dto.state).toBe('COMPLETED_WITH_WARNINGS');
    expect(dto.warnings).toEqual([{ code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' }]);
    expect(verifying).toHaveBeenCalledOnce();
  });

  it('fails the scan when a fatal stage fails', async () => {
    const analyzing = vi.fn(async () => {});
    const { runner, newScan, scans, audit } = setup([
      stage('CLONING', { fatal: true, run: async () => { throw new AppError('AUTH_INVALID', 'permanent', 'bad token'); } }),
      stage('ANALYZING', { run: analyzing }),
    ]);
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)).toMatchObject({ state: 'FAILED', errorCode: 'AUTH_INVALID', errorMessage: 'bad token' });
    expect(analyzing).not.toHaveBeenCalled();
    expect(audit.list({ action: 'scan.failed' }).items).toHaveLength(1);
  });

  it('cancels a running scan', async () => {
    const verifying = vi.fn(async () => {});
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted }), stage('VERIFYING', { run: verifying })]);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    expect(runner.cancel(id)).toBe('aborted');
    await runner.whenIdle();
    expect(scans.getDto(id)!.state).toBe('CANCELLED');
    expect(verifying).not.toHaveBeenCalled();
  });

  it('dequeues a scan that has not started', async () => {
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted })], { maxConcurrentScans: 1 });
    const first = newScan();
    const second = newScan();
    runner.enqueue(first, {});
    runner.enqueue(second, {});
    await waitFor(() => scans.getDto(first)!.state === 'ANALYZING');
    expect(runner.cancel(second)).toBe('dequeued');
    runner.cancel(first);
    await runner.whenIdle();
    expect(runner.cancel('nope')).toBe('unknown');
  });

  it('respects maxConcurrentScans', async () => {
    let active = 0;
    let peak = 0;
    const { runner, newScan } = setup([stage('ANALYZING', {
      run: async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 30));
        active--;
      },
    })], { maxConcurrentScans: 2 });
    for (let i = 0; i < 4; i++) runner.enqueue(newScan(), {});
    await runner.whenIdle();
    expect(peak).toBe(2);
  });

  it('resumes from a checkpoint, skipping completed stages', async () => {
    const resolving = vi.fn(async () => {});
    let seenSha: unknown;
    const { runner, newScan, scans } = setup([
      stage('RESOLVING', { run: resolving }),
      stage('ANALYZING', { run: async (ctx) => { seenSha = ctx.checkpointData.commitSha; } }),
    ]);
    const id = newScan();
    scans.setCheckpoint(id, { completedStages: ['RESOLVING'], data: { commitSha: 'abc' } });
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(resolving).not.toHaveBeenCalled();
    expect(seenSha).toBe('abc');
    expect(scans.getCheckpoint(id)?.completedStages).toEqual(['RESOLVING', 'ANALYZING']);
  });

  it('recovers non-terminal scans on boot; private-repo scans need the token again', async () => {
    const { runner, newScan, scans, audit } = setup([stage('ANALYZING')]);
    const publicScan = newScan(false);
    const privateScan = newScan(true);
    expect(runner.recover()).toEqual({ resumed: [publicScan], failed: [privateScan] });
    await runner.whenIdle();
    expect(scans.getDto(publicScan)!.state).toBe('COMPLETED');
    expect(scans.getDto(privateScan)).toMatchObject({ state: 'FAILED', errorCode: 'AUTH_REQUIRED' });
    expect(audit.list({ action: 'scan.resumed' }).items).toHaveLength(1);
  });

  it('fails with SCAN_DEADLINE when the deadline hits before analysis completes', async () => {
    const { runner, newScan, scans } = setup([stage('RESOLVING', { run: blockUntilAborted })], { scanDeadlineMs: 50 });
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)).toMatchObject({ state: 'FAILED', errorCode: 'SCAN_DEADLINE' });
  });

  it('keeps partial results when the deadline hits after analysis', async () => {
    const { runner, newScan, scans } = setup(
      [stage('ANALYZING'), stage('VERIFYING', { run: blockUntilAborted })], { scanDeadlineMs: 80 },
    );
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    const dto = scans.getDto(id)!;
    expect(dto.state).toBe('COMPLETED_WITH_WARNINGS');
    expect(dto.warnings.map((w) => w.code)).toContain('SCAN_DEADLINE');
  });

  it('watchdog fails a scan with no activity for stuckAfterMs', async () => {
    let t = 0;
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted })], { stuckAfterMs: 60_000 }, () => t);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    t += 61_000;
    runner.checkStuck();
    await runner.whenIdle();
    expect(scans.getDto(id)).toMatchObject({ state: 'FAILED', errorCode: 'INTERNAL' });
    expect(scans.getDto(id)!.errorMessage).toMatch(/stopped making progress/);
  });

  it('shutdown leaves running scans resumable', async () => {
    const { runner, newScan, scans } = setup([stage('RESOLVING'), stage('ANALYZING', { run: blockUntilAborted })]);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    await runner.shutdown(20);
    expect(scans.getDto(id)!.state).toBe('ANALYZING');
    expect(scans.getCheckpoint(id)?.completedStages).toEqual(['RESOLVING']);
    expect(() => runner.enqueue(newScan(), {})).toThrow(AppError);
  });
});
