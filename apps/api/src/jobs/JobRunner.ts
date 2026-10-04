import { setTimeout as sleep } from 'node:timers/promises';
import type { AuditLogger } from '../audit/AuditLogger';
import type { Config } from '../config';
import type { Checkpoint, ScanRepo } from '../db/scanRepo';
import { AppError, toAppError } from '../errors/AppError';
import type { EventBus } from '../events/EventBus';
import type { Pipeline, PipelineContext, ScanSecrets } from '../pipeline/types';
import type { ScanLifecycle } from '../scans/ScanLifecycle';

export type CancelResult = 'aborted' | 'dequeued' | 'unknown';

export interface ScanQueue {
  enqueue(scanId: string, secrets: ScanSecrets): void;
  cancel(scanId: string): CancelResult;
  pendingCount(): number;
}

export type JobRunnerConfig = Pick<Config, 'maxConcurrentScans' | 'scanDeadlineMs' | 'heartbeatMs' | 'stuckAfterMs'>;

type AbortKind = 'user' | 'shutdown' | 'stuck';
type RunningJob = { controller: AbortController; abortKind: AbortKind | null; lastActivity: number; done: Promise<void> };

export type JobRunnerDeps = {
  scans: ScanRepo; lifecycle: ScanLifecycle; bus: EventBus; audit: AuditLogger;
  pipeline: Pipeline; config: JobRunnerConfig; now?: () => number;
};

export class JobRunner implements ScanQueue {
  private readonly queue: { scanId: string; secrets: ScanSecrets }[] = [];
  private readonly running = new Map<string, RunningJob>();
  private stopping = false;
  private watchdog: NodeJS.Timeout | undefined;

  constructor(private readonly deps: JobRunnerDeps) {}

  enqueue(scanId: string, secrets: ScanSecrets): void {
    if (this.stopping) throw new AppError('QUEUE_FULL', 'transient', 'Server is shutting down; try again shortly');
    this.queue.push({ scanId, secrets });
    this.pump();
  }

  pendingCount(): number {
    return this.queue.length + this.running.size;
  }

  isActive(scanId: string): boolean {
    return this.running.has(scanId) || this.queue.some((j) => j.scanId === scanId);
  }

  cancel(scanId: string): CancelResult {
    const idx = this.queue.findIndex((j) => j.scanId === scanId);
    if (idx >= 0) {
      this.queue.splice(idx, 1);
      return 'dequeued';
    }
    const job = this.running.get(scanId);
    if (!job) return 'unknown';
    job.abortKind ??= 'user';
    job.controller.abort();
    return 'aborted';
  }

  recover(): { resumed: string[]; failed: string[] } {
    const resumed: string[] = [];
    const failed: string[] = [];
    for (const row of this.deps.scans.listNonTerminal()) {
      if (this.isActive(row.id)) continue;
      if (row.has_auth === 1) {
        this.deps.lifecycle.transition(row.id, 'FAILED', {
          code: 'AUTH_REQUIRED',
          message: 'The server restarted. Re-enter your token to resume this private-repo scan.',
        });
        failed.push(row.id);
        continue;
      }
      this.deps.audit.append({ action: 'scan.resumed', targetType: 'scan', targetId: row.id, scanId: row.id });
      this.enqueue(row.id, {});
      resumed.push(row.id);
    }
    return { resumed, failed };
  }

  startWatchdog(intervalMs = 5_000): void {
    this.watchdog = setInterval(() => this.checkStuck(), intervalMs);
    this.watchdog.unref();
  }

  checkStuck(): void {
    const now = this.now();
    for (const job of this.running.values()) {
      if (job.abortKind === null && now - job.lastActivity > this.deps.config.stuckAfterMs) {
        job.abortKind = 'stuck';
        job.controller.abort();
      }
    }
  }

  async whenIdle(): Promise<void> {
    while (this.running.size > 0) {
      await Promise.all([...this.running.values()].map((j) => j.done));
    }
  }

  /** Stop taking work, let running scans finish for up to graceMs, then abort them (they stay resumable). */
  async shutdown(graceMs: number): Promise<void> {
    this.stopping = true;
    clearInterval(this.watchdog);
    this.queue.length = 0; // still QUEUED in the DB; recover() picks them up on next boot
    const allDone = this.whenIdle().then(() => true);
    const finished = await Promise.race([allDone, sleep(graceMs, false, { ref: false })]);
    if (!finished) {
      for (const job of this.running.values()) {
        job.abortKind = 'shutdown';
        job.controller.abort();
      }
      await this.whenIdle();
    }
  }

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  private pump(): void {
    while (!this.stopping && this.running.size < this.deps.config.maxConcurrentScans && this.queue.length > 0) {
      const { scanId, secrets } = this.queue.shift()!;
      const job: RunningJob = { controller: new AbortController(), abortKind: null, lastActivity: this.now(), done: Promise.resolve() };
      this.running.set(scanId, job);
      job.done = this.execute(scanId, secrets, job).finally(() => {
        this.running.delete(scanId);
        this.pump();
      });
    }
  }

  private async execute(scanId: string, secrets: ScanSecrets, job: RunningJob): Promise<void> {
    const { scans, lifecycle, pipeline, config, bus } = this.deps;
    const deadline = AbortSignal.timeout(config.scanDeadlineMs);
    const signal = AbortSignal.any([job.controller.signal, deadline]);
    const touch = () => { job.lastActivity = this.now(); };

    scans.heartbeat(scanId);
    const heartbeat = setInterval(() => scans.heartbeat(scanId), config.heartbeatMs);
    heartbeat.unref();

    const checkpoint: Checkpoint = scans.getCheckpoint(scanId) ?? { completedStages: [], data: {} };
    let warned = (scans.getDto(scanId)?.warnings.length ?? 0) > 0;
    const ctx: PipelineContext = {
      scanId,
      scan: scans.getDto(scanId)!,
      secrets,
      signal,
      checkpointData: checkpoint.data,
      emit: (event) => { touch(); bus.publish(scanId, event); },
      warn: (w) => { touch(); warned = true; lifecycle.warn(scanId, w); },
    };

    try {
      for (const stage of pipeline.stages) {
        if (checkpoint.completedStages.includes(stage.name)) continue;
        if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Scan aborted');
        touch();
        lifecycle.transition(scanId, stage.name);
        try {
          await stage.run(ctx);
        } catch (raw) {
          const err = toAppError(raw);
          if (signal.aborted || stage.fatal || err.kind === 'cancelled') throw raw;
          ctx.warn({ code: err.code, message: err.userMessage, stage: stage.name });
        }
        checkpoint.completedStages.push(stage.name);
        scans.setCheckpoint(scanId, checkpoint);
      }
      this.complete(scanId, warned);
    } catch (raw) {
      this.finishWithError(scanId, raw, job, deadline, checkpoint);
    } finally {
      clearInterval(heartbeat);
    }
  }

  private complete(scanId: string, warned: boolean): void {
    const state = warned ? 'COMPLETED_WITH_WARNINGS' : 'COMPLETED';
    this.deps.lifecycle.transition(scanId, state);
    this.deps.audit.append({ action: 'scan.completed', targetType: 'scan', targetId: scanId, scanId, details: { state } });
  }

  private finishWithError(scanId: string, raw: unknown, job: RunningJob, deadline: AbortSignal, checkpoint: Checkpoint): void {
    const { lifecycle, audit } = this.deps;
    if (job.abortKind === 'shutdown') return;
    if (job.abortKind === 'user') {
      lifecycle.transition(scanId, 'CANCELLED');
      return;
    }
    let err: AppError;
    if (job.abortKind === 'stuck') {
      err = new AppError('INTERNAL', 'permanent', 'The scan stopped making progress and was stopped');
    } else if (deadline.aborted) {
      if (checkpoint.completedStages.includes('ANALYZING')) {
        lifecycle.warn(scanId, { code: 'SCAN_DEADLINE', message: 'Time limit reached; results are partial' });
        this.complete(scanId, true);
        return;
      }
      err = new AppError('SCAN_DEADLINE', 'budget', 'The scan exceeded its time limit before analysis finished');
    } else {
      err = toAppError(raw);
    }
    lifecycle.transition(scanId, 'FAILED', { code: err.code, message: err.userMessage });
    audit.append({ action: 'scan.failed', targetType: 'scan', targetId: scanId, scanId, details: { code: err.code } });
  }
}
