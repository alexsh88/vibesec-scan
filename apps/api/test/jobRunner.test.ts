import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { EventRepo } from '../src/db/eventRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { EventBus } from '../src/events/EventBus';
import { JobRunner, type JobRunnerConfig } from '../src/jobs/JobRunner';
import { SKIP_REMAINING_STAGES, type PipelineContext, type StageName, type StageSpec } from '../src/pipeline/types';
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
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);
  const runner = new JobRunner({
    scans, lifecycle, bus, audit, pipeline: { stages }, now,
    config: {
      maxConcurrentScans: 2, queueCapacity: 50, scanDeadlineMs: 5_000, heartbeatMs: 1_000, stuckAfterMs: 60_000,
      staleHeartbeatMs: 30_000, ...cfg,
    },
  });
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const newScan = (hasAuth = false) => scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: randomUUID(), idempotencyKey: null, hasAuth,
  }).id;
  const states = (id: string) => events.listAfter(id, 0)
    .flatMap((e) => (e.event.type === 'state' ? [e.event.state] : []));
  const allEvents = (id: string) => events.listAfter(id, 0).map((e) => e.event);
  return { scans, lifecycle, audit, runner, newScan, states, allEvents };
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
    expect(scans.getDto(privateScan)).toMatchObject({
      state: 'FAILED', errorCode: 'AUTH_REQUIRED',
      errorMessage: 'The server restarted and private-repo tokens are never stored. Start a new scan with your token.',
    });
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
    // M-4: the deadline warning names the stage that was running.
    expect(dto.warnings).toContainEqual(expect.objectContaining({ code: 'SCAN_DEADLINE', stage: 'VERIFYING' }));
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

/** Resolves once the abort fires, i.e. a stage that swallows the abort instead of rejecting. */
const resolveOnAbort = (ctx: PipelineContext) =>
  new Promise<void>((resolve) => ctx.signal.addEventListener('abort', () => resolve(), { once: true }));

describe('JobRunner regressions (code review)', () => {
  it('#6: an audit failure on completion rolls back the terminal transition; the scan stays resumable', async () => {
    const { runner, newScan, scans, states, audit, allEvents } = setup([stage('ANALYZING')]);
    const original = audit.append.bind(audit);
    let thrown = false;
    vi.spyOn(audit, 'append').mockImplementation((input) => {
      if (input.action === 'scan.completed' && !thrown) { thrown = true; throw new Error('disk full'); }
      return original(input);
    });
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
    expect(states(id)).toEqual(['ANALYZING']);
    expect(allEvents(id).filter((e) => e.type === 'done')).toHaveLength(0);
    expect(scans.getDto(id)!.state).toBe('ANALYZING');
    expect(audit.list({ action: 'scan.completed' }).items).toHaveLength(0);
  });

  it('C-1: a throwing finalizer never rejects job.done and leaves the scan resumable', async () => {
    const { runner, newScan, scans, lifecycle } = setup([
      stage('CLONING', { fatal: true, run: async () => { throw new AppError('AUTH_INVALID', 'permanent', 'bad token'); } }),
    ]);
    const original = lifecycle.transition.bind(lifecycle);
    vi.spyOn(lifecycle, 'transition').mockImplementation((scanId, state, err, a) => {
      if (state === 'FAILED') throw new Error('db locked');
      return original(scanId, state, err, a);
    });
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const id = newScan();
      runner.enqueue(id, {});
      await expect(runner.whenIdle()).resolves.toBeUndefined();
      await new Promise((r) => setTimeout(r, 20));
      expect(unhandled).not.toHaveBeenCalled();
      expect(scans.getDto(id)!.state).toBe('CLONING');
      expect(errSpy).toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', unhandled);
      errSpy.mockRestore();
    }
  });

  it('I-1: enqueueing an active scan twice runs it once', async () => {
    const run = vi.fn(async () => { await new Promise((r) => setTimeout(r, 20)); });
    const { runner, newScan } = setup([stage('ANALYZING', { run })], { maxConcurrentScans: 1 });
    const running = newScan();
    const queued = newScan();
    runner.enqueue(running, {});
    runner.enqueue(running, {});
    runner.enqueue(queued, {});
    runner.enqueue(queued, {});
    expect(runner.pendingCount()).toBe(2);
    await runner.whenIdle();
    expect(run).toHaveBeenCalledTimes(2);
  });

  it('I-2: shutdown does not overwrite a user cancel', async () => {
    const slowAbort = (ctx: PipelineContext) => new Promise<void>((_, reject) => {
      ctx.signal.addEventListener('abort', () => setTimeout(() => reject(new Error('aborted')), 50), { once: true });
    });
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: slowAbort })]);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    expect(runner.cancel(id)).toBe('aborted');
    await runner.shutdown(5);
    expect(scans.getDto(id)!.state).toBe('CANCELLED');
  });

  it('I-3: a stage that swallows the abort is not checkpointed as complete', async () => {
    let t = 0;
    const { runner, newScan, scans } = setup(
      [stage('RESOLVING'), stage('ANALYZING', { run: resolveOnAbort })], { stuckAfterMs: 60_000 }, () => t,
    );
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    t += 61_000;
    runner.checkStuck();
    await runner.whenIdle();
    expect(scans.getDto(id)).toMatchObject({ state: 'FAILED', errorCode: 'INTERNAL' });
    expect(scans.getCheckpoint(id)?.completedStages).toEqual(['RESOLVING']);
  });

  it('I-3: a shutdown-aborted stage that swallows the abort stays resumable', async () => {
    const { runner, newScan, scans } = setup([stage('RESOLVING'), stage('ANALYZING', { run: resolveOnAbort })]);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    await runner.shutdown(5);
    expect(scans.getDto(id)!.state).toBe('ANALYZING');
    expect(scans.getCheckpoint(id)?.completedStages).toEqual(['RESOLVING']);
  });

  it('M-1: a user cancel ends CANCELLED even when the last stage ignores the signal and resolves', async () => {
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: resolveOnAbort })]);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    expect(runner.cancel(id)).toBe('aborted');
    await runner.whenIdle();
    expect(scans.getDto(id)!.state).toBe('CANCELLED');
  });

  it('I-4: re-running a stage on resume does not duplicate its warnings', async () => {
    const { runner, newScan, scans } = setup([
      stage('ANALYZING'),
      stage('VERIFYING', { run: async (ctx) => { ctx.warn({ code: 'VERIFY_SKIPPED', message: 'skipped', stage: 'VERIFYING' }); } }),
    ]);
    const id = newScan();
    scans.addWarning(id, { code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' });
    scans.addWarning(id, { code: 'VERIFY_SKIPPED', message: 'skipped', stage: 'VERIFYING' });
    scans.setCheckpoint(id, { completedStages: ['ANALYZING'], data: {} });
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)!.warnings).toEqual([
      { code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' },
      { code: 'VERIFY_SKIPPED', message: 'skipped', stage: 'VERIFYING' },
    ]);
  });

  it('I-4: stale warnings from a re-run stage that now succeeds cleanly do not mark the scan as warned', async () => {
    const { runner, newScan, scans } = setup([stage('ANALYZING'), stage('VERIFYING')]);
    const id = newScan();
    scans.addWarning(id, { code: 'VERIFY_SKIPPED', message: 'skipped', stage: 'VERIFYING' });
    scans.setCheckpoint(id, { completedStages: ['ANALYZING'], data: {} });
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)).toMatchObject({ state: 'COMPLETED', warnings: [] });
  });

  it('I-5: ctx.touch() keeps a long, quiet stage alive under the watchdog', async () => {
    let t = 0;
    let runner!: JobRunner;
    const long = async (ctx: PipelineContext) => {
      for (let i = 0; i < 4; i++) {
        t += 40_000;
        ctx.touch();
        runner.checkStuck();
        await new Promise((r) => setTimeout(r, 1));
      }
    };
    const s = setup([stage('ANALYZING', { run: long })], { stuckAfterMs: 60_000 }, () => t);
    runner = s.runner;
    const id = s.newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(s.scans.getDto(id)!.state).toBe('COMPLETED');
  });

  it('M-2: the deadline timer does not outlive the scan', async () => {
    let signal: AbortSignal | undefined;
    const { runner, newScan, scans } = setup(
      [stage('ANALYZING', { run: async (ctx) => { signal = ctx.signal; } })], { scanDeadlineMs: 30 },
    );
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)!.state).toBe('COMPLETED');
    await new Promise((r) => setTimeout(r, 80));
    expect(signal!.aborted).toBe(false);
  });

  it('M-3: recover() while shutting down neither throws nor audits a resume', async () => {
    const { runner, newScan, audit } = setup([stage('ANALYZING')]);
    newScan();
    await runner.shutdown(0);
    let result: ReturnType<JobRunner['recover']> | undefined;
    expect(() => { result = runner.recover(); }).not.toThrow();
    expect(result?.resumed).toEqual([]);
    expect(audit.list({ action: 'scan.resumed' }).items).toHaveLength(0);
  });

  it('deadline: the first run persists deadlineAt in the checkpoint immediately', async () => {
    const t = 1_000;
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted })], { scanDeadlineMs: 5_000 }, () => t);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    expect(scans.getCheckpoint(id)?.data.deadlineAt).toBe(6_000);
    runner.cancel(id);
    await runner.whenIdle();
  });

  it('deadline: a resumed scan uses the remaining whole-scan time, not a fresh deadline', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const t = 0;
      const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted })], { scanDeadlineMs: 10_000 }, () => t);
      const id = newScan();
      scans.setCheckpoint(id, { completedStages: ['RESOLVING'], data: { deadlineAt: 90_000 } });
      runner.enqueue(id, {});
      await vi.advanceTimersByTimeAsync(89_000);
      expect(scans.getDto(id)!.state).toBe('ANALYZING');
      await vi.advanceTimersByTimeAsync(2_000);
      await runner.whenIdle();
      expect(scans.getDto(id)).toMatchObject({ state: 'FAILED', errorCode: 'SCAN_DEADLINE' });
      expect(scans.getCheckpoint(id)?.data.deadlineAt).toBe(90_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it('deadline: a resumed scan past its deadline still gets at least 60s', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const t = 100_000;
      const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted })], { scanDeadlineMs: 10_000 }, () => t);
      const id = newScan();
      scans.setCheckpoint(id, { completedStages: ['RESOLVING'], data: { deadlineAt: 50_000 } });
      runner.enqueue(id, {});
      await vi.advanceTimersByTimeAsync(59_000);
      expect(scans.getDto(id)!.state).toBe('ANALYZING');
      await vi.advanceTimersByTimeAsync(2_000);
      await runner.whenIdle();
      expect(scans.getDto(id)).toMatchObject({ state: 'FAILED', errorCode: 'SCAN_DEADLINE' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('recover() skips scans whose heartbeat is fresh (another live process may own them)', async () => {
    const base = Date.parse('2026-10-05T12:00:00.000Z');
    const { runner, newScan, scans, db } = setupWithClock(base);
    const fresh = newScan();
    const freshPrivate = newScan(true);
    const stale = newScan();
    const never = newScan();
    db.prepare(`UPDATE scans SET heartbeat_at = ? WHERE id IN (?, ?)`).run(new Date(base - 10_000).toISOString(), fresh, freshPrivate);
    db.prepare(`UPDATE scans SET heartbeat_at = ? WHERE id = ?`).run(new Date(base - 31_000).toISOString(), stale);
    expect(runner.recover()).toEqual({ resumed: [stale, never], failed: [] });
    await runner.whenIdle();
    expect(scans.getDto(fresh)!.state).toBe('QUEUED');
    expect(scans.getDto(freshPrivate)!.state).toBe('QUEUED');
  });

  it('sweep() resumes a crashed scan once its heartbeat goes stale (fast restart case)', async () => {
    const base = Date.parse('2026-10-05T12:00:00.000Z');
    const { runner, newScan, scans, db, advance } = setupWithClock(base);
    const orphan = newScan();
    db.prepare(`UPDATE scans SET state = 'ANALYZING', heartbeat_at = ? WHERE id = ?`).run(new Date(base - 5_000).toISOString(), orphan);
    expect(runner.recover().resumed).toEqual([]);
    advance(30_000);
    runner.sweep();
    await runner.whenIdle();
    expect(scans.getDto(orphan)!.state).toBe('COMPLETED');
  });

  it('#3: a scan that keeps crashing outside a stage is resumed at most 3 times, then FAILED', async () => {
    const base = Date.parse('2026-10-05T12:00:00.000Z');
    const { runner, newScan, scans, lifecycle, audit, advance } = setupWithClock(base);
    const original = lifecycle.transition.bind(lifecycle);
    vi.spyOn(lifecycle, 'transition').mockImplementation((scanId, state, err, a) => {
      if (state === 'COMPLETED') throw new Error('finalize crashed');
      return original(scanId, state, err, a);
    });
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const id = newScan();
      for (let i = 0; i < 5; i++) {
        advance(31_000);
        runner.sweep();
        await runner.whenIdle();
      }
      expect(scans.getDto(id)).toMatchObject({
        state: 'FAILED', errorCode: 'INTERNAL', errorMessage: 'The scan could not be resumed after repeated failures',
      });
      expect(audit.list({ action: 'scan.resumed' }).items).toHaveLength(3);
      expect(audit.list({ action: 'scan.failed' }).items).toHaveLength(1);
    } finally {
      errSpy.mockRestore();
    }
  });

  it('#4: a queued scan gets a heartbeat at enqueue and on every sweep, so a second process skips it', async () => {
    const base = Date.parse('2026-10-05T12:00:00.000Z');
    const { runner, newScan, scans, makeRunner, advance, now } = setupWithClock(
      base, [stage('ANALYZING', { run: blockUntilAborted })], { maxConcurrentScans: 1, heartbeatMs: 5 },
    );
    const running = newScan();
    const queued = newScan();
    runner.enqueue(running, {});
    runner.enqueue(queued, {});
    await waitFor(() => scans.getDto(running)!.state === 'ANALYZING');
    expect(scans.getDto(queued)!.state).toBe('QUEUED');
    expect(Date.parse(scans.getRow(queued)!.heartbeat_at!)).toBeGreaterThanOrEqual(base);
    const other = makeRunner().runner;
    expect(other.recover()).toEqual({ resumed: [], failed: [] });

    advance(20_000);
    runner.sweep();
    expect(Date.parse(scans.getRow(queued)!.heartbeat_at!)).toBeGreaterThanOrEqual(now());
    advance(20_000);
    await new Promise((r) => setTimeout(r, 30)); // let the running scan's own heartbeat interval fire
    expect(other.recover()).toEqual({ resumed: [], failed: [] });
    await runner.shutdown(0);
  });

  it('#6: a user cancel of a running scan is audited by the runner, with the request meta, in the CANCELLED transition', async () => {
    const { runner, newScan, scans, audit } = setup([stage('ANALYZING', { run: blockUntilAborted })]);
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    expect(runner.cancel(id, {
      action: 'scan.cancelled', targetType: 'scan', targetId: id, scanId: id, actorIp: '10.0.0.1', userAgent: 'ua',
    })).toBe('aborted');
    await runner.whenIdle();
    expect(scans.getDto(id)!.state).toBe('CANCELLED');
    expect(audit.list({ action: 'scan.cancelled' }).items).toEqual([expect.objectContaining({ targetId: id, actorIp: '10.0.0.1' })]);
  });

  it('#7: a throwing heartbeat inside the interval is logged, never thrown', async () => {
    const { runner, newScan, scans } = setup([stage('ANALYZING', { run: blockUntilAborted })], { heartbeatMs: 5 });
    const id = newScan();
    runner.enqueue(id, {});
    await waitFor(() => scans.getDto(id)!.state === 'ANALYZING');
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const hb = vi.spyOn(scans, 'heartbeat').mockImplementation(() => { throw new Error('SQLITE_BUSY'); });
    try {
      await new Promise((r) => setTimeout(r, 40));
      expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('heartbeat'));
    } finally {
      hb.mockRestore();
      errSpy.mockRestore();
    }
    runner.cancel(id);
    await runner.whenIdle();
  });

  it('#7: sweep() logs instead of throwing when the database fails', () => {
    const { runner, scans } = setup([stage('ANALYZING')]);
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(scans, 'listNonTerminal').mockImplementation(() => { throw new Error('SQLITE_IOERR'); });
    try {
      expect(() => runner.sweep()).not.toThrow();
      expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('sweep'));
    } finally {
      errSpy.mockRestore();
    }
  });

  it('#8: recover() stops enqueuing at queueCapacity; a later sweep picks up the rest', async () => {
    const base = Date.parse('2026-10-05T12:00:00.000Z');
    const { runner, newScan, scans } = setupWithClock(base, [stage('ANALYZING')], { maxConcurrentScans: 1, queueCapacity: 2 });
    const ids = [newScan(), newScan(), newScan()];
    expect(runner.recover().resumed).toEqual(ids.slice(0, 2));
    await runner.whenIdle();
    expect(scans.getDto(ids[2]!)!.state).toBe('QUEUED');
    runner.sweep();
    await runner.whenIdle();
    expect(ids.map((id) => scans.getDto(id)!.state)).toEqual(['COMPLETED', 'COMPLETED', 'COMPLETED']);
  });
});

function setupWithClock(nowMs: number, stages: StageSpec[] = [stage('ANALYZING')], cfg: Partial<JobRunnerConfig> = {}) {
  let clock = nowMs;
  const db = memoryDb();
  // Timestamps follow the test clock; the tick keeps created_at distinct and ordered so listNonTerminal is deterministic.
  let tick = 0;
  const audit = new AuditLogger(db);
  /** A runner with its own repo/lifecycle over the shared DB: calling it again simulates a second process. */
  const makeRunner = () => {
    const scans = new ScanRepo(db, () => new Date(clock + tick++).toISOString());
    const bus = new EventBus(new EventRepo(db));
    const lifecycle = new ScanLifecycle(scans, bus, db, audit);
    const runner = new JobRunner({
      scans, lifecycle, bus, audit, pipeline: { stages }, now: () => clock,
      config: {
        maxConcurrentScans: 4, queueCapacity: 50, scanDeadlineMs: 5_000, heartbeatMs: 1_000, stuckAfterMs: 60_000,
        staleHeartbeatMs: 30_000, ...cfg,
      },
    });
    return { scans, lifecycle, runner };
  };
  const { scans, lifecycle, runner } = makeRunner();
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const newScan = (hasAuth = false) => scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: randomUUID(), idempotencyKey: null, hasAuth,
  }).id;
  return {
    db, scans, lifecycle, audit, runner, newScan, makeRunner,
    now: () => clock, advance: (ms: number) => { clock += ms; },
  };
}

describe('JobRunner — P7 caching hooks', () => {
  it('skips (and checkpoints) every remaining stage once a stage sets SKIP_REMAINING_STAGES', async () => {
    const later = vi.fn(async () => {});
    const { runner, newScan, states, scans } = setup([
      stage('RESOLVING', { run: async (ctx) => { ctx.checkpointData[SKIP_REMAINING_STAGES] = true; } }),
      stage('CLONING', { run: later }), stage('ANALYZING', { run: later }),
    ]);
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(later).not.toHaveBeenCalled();
    expect(states(id)).toEqual(['RESOLVING', 'COMPLETED']);
    expect(scans.getCheckpoint(id)?.completedStages).toEqual(['RESOLVING', 'CLONING', 'ANALYZING']);
  });

  it("does not degrade the outcome for 'info' warnings", async () => {
    const { runner, newScan, scans } = setup([
      stage('ANALYZING', { run: async (ctx) => { ctx.warn({ code: 'INCREMENTAL_DIFF_TOO_LARGE', message: 'full scan', level: 'info' }); } }),
    ]);
    const id = newScan();
    runner.enqueue(id, {});
    await runner.whenIdle();
    expect(scans.getDto(id)).toMatchObject({ state: 'COMPLETED', warnings: [{ code: 'INCREMENTAL_DIFF_TOO_LARGE', level: 'info' }] });
  });
});
