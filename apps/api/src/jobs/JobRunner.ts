import { setTimeout as sleep } from 'node:timers/promises';
import { isTerminalState } from '@vibesec/shared';
import type { AuditInput, AuditLogger } from '../audit/AuditLogger';
import type { Config } from '../config';
import type { Checkpoint, ScanRepo } from '../db/scanRepo';
import { AppError, toAppError } from '../errors/AppError';
import type { EventBus } from '../events/EventBus';
import { SKIP_REMAINING_STAGES, type Pipeline, type PipelineContext, type ScanSecrets, type StageName } from '../pipeline/types';
import { classifyWarningLevel } from '../pipeline/warningLevels';
import type { ScanLifecycle } from '../scans/ScanLifecycle';
import { scrubSecrets } from '../security/scrub';

export type CancelResult = 'aborted' | 'dequeued' | 'unknown';

export interface ScanQueue {
  enqueue(scanId: string, secrets: ScanSecrets): void;
  /**
   * Dequeues or aborts the scan. `audit` is the `scan.cancelled` entry to record if an aborted running scan
   * ends CANCELLED (it is written in that transition); for 'dequeued'/'unknown' the caller transitions.
   */
  cancel(scanId: string, audit?: AuditInput): CancelResult;
  pendingCount(): number;
  /** False once the queue stops taking work (shutdown): callers must reject before writing anything. */
  accepting(): boolean;
}

export type JobRunnerConfig = Pick<
  Config, 'maxConcurrentScans' | 'queueCapacity' | 'scanDeadlineMs' | 'heartbeatMs' | 'stuckAfterMs' | 'staleHeartbeatMs'
>;

/** A resumed scan gets whatever is left of its whole-scan deadline (spec §14.2), but never less than this. */
const MIN_RESUME_DEADLINE_MS = 60_000;
/** A scan that keeps dying outside any stage (e.g. finalization fails) is failed instead of resumed forever. */
export const MAX_RESUMES = 3;
export const AUTH_REQUIRED_MESSAGE =
  'The server restarted and private-repo tokens are never stored. Start a new scan with your token.';

type AbortKind = 'user' | 'shutdown' | 'stuck';
type RunningJob = {
  controller: AbortController; abortKind: AbortKind | null; lastActivity: number; done: Promise<void>;
  cancelAudit: AuditInput | null;
};
type Outcome = { ok: true } | { ok: false; raw: unknown };

export type JobRunnerDeps = {
  scans: ScanRepo; lifecycle: ScanLifecycle; bus: EventBus; audit: AuditLogger;
  pipeline: Pipeline; config: JobRunnerConfig; now?: () => number;
};

/** Last-resort logging for failures that have no scan to report to. Scrubbed: errors may echo secrets. */
function logInternal(message: string, scanId: string | null, err: unknown): void {
  const detail = err instanceof Error ? `${err.name}: ${err.message}\n${err.stack ?? ''}` : String(err);
  const where = scanId ? ` (scan ${scanId})` : '';
  console.error(scrubSecrets(`[JobRunner] ${message}${where}: ${detail}`));
}

const scanAudit = (action: AuditInput['action'], scanId: string, details?: Record<string, unknown>): AuditInput => ({
  action, targetType: 'scan', targetId: scanId, scanId, ...(details ? { details } : {}),
});

export class JobRunner implements ScanQueue {
  private readonly queue: { scanId: string; secrets: ScanSecrets }[] = [];
  private readonly running = new Map<string, RunningJob>();
  private stopping = false;
  private watchdog: NodeJS.Timeout | undefined;

  constructor(private readonly deps: JobRunnerDeps) {}

  enqueue(scanId: string, secrets: ScanSecrets): void {
    if (this.isActive(scanId)) return; // already queued or running: never run a scan twice
    if (this.stopping) throw new AppError('QUEUE_FULL', 'transient', 'Server is shutting down; try again shortly');
    // Claim the scan now, not when it starts: another process's recover() must not adopt a scan that is
    // merely waiting in this queue. sweep() keeps queued claims fresh.
    this.deps.scans.heartbeat(scanId);
    this.queue.push({ scanId, secrets });
    this.pump();
  }

  pendingCount(): number {
    return this.queue.length + this.running.size;
  }

  accepting(): boolean {
    return !this.stopping;
  }

  isActive(scanId: string): boolean {
    return this.running.has(scanId) || this.queue.some((j) => j.scanId === scanId);
  }

  cancel(scanId: string, audit?: AuditInput): CancelResult {
    const idx = this.queue.findIndex((j) => j.scanId === scanId);
    if (idx >= 0) {
      this.queue.splice(idx, 1);
      return 'dequeued';
    }
    const job = this.running.get(scanId);
    if (!job) return 'unknown';
    job.abortKind ??= 'user';
    job.cancelAudit ??= audit ?? null;
    job.controller.abort();
    return 'aborted';
  }

  recover(): { resumed: string[]; failed: string[] } {
    const { scans, lifecycle, audit, config } = this.deps;
    const resumed: string[] = [];
    const failed: string[] = [];
    const now = this.now();
    for (const row of scans.listNonTerminal()) {
      if (this.isActive(row.id)) continue;
      // A recent heartbeat means another live process may still own this scan: leave it alone.
      const beat = row.heartbeat_at ? Date.parse(row.heartbeat_at) : NaN;
      if (!Number.isNaN(beat) && now - beat < config.staleHeartbeatMs) continue;
      if (row.has_auth === 1) {
        if (lifecycle.transition(row.id, 'FAILED', { code: 'AUTH_REQUIRED', message: AUTH_REQUIRED_MESSAGE },
          scanAudit('scan.failed', row.id, { code: 'AUTH_REQUIRED' }))) failed.push(row.id);
        continue;
      }
      if (this.stopping) continue; // still non-terminal in the DB; the next boot picks it up

      const checkpoint: Checkpoint = scans.getCheckpoint(row.id) ?? { completedStages: [], data: {} };
      const prior = checkpoint.data.resumeCount;
      const resumeCount = typeof prior === 'number' && Number.isFinite(prior) ? prior : 0;
      if (resumeCount >= MAX_RESUMES) {
        const message = 'The scan could not be resumed after repeated failures';
        if (lifecycle.transition(row.id, 'FAILED', { code: 'INTERNAL', message },
          scanAudit('scan.failed', row.id, { code: 'INTERNAL', resumeCount }))) failed.push(row.id);
        continue;
      }
      // Leave the rest for a later sweep rather than overfilling the queue.
      if (this.pendingCount() >= config.queueCapacity) continue;

      // Counter + audit + enqueue in one transaction. enqueue starts the scan synchronously, so the audit
      // entry is appended first; the scan's own events are notified once this commits.
      lifecycle.atomically(() => {
        scans.setCheckpoint(row.id, { ...checkpoint, data: { ...checkpoint.data, resumeCount: resumeCount + 1 } });
        audit.append(scanAudit('scan.resumed', row.id, { resumeCount: resumeCount + 1 }));
        this.enqueue(row.id, {});
      });
      resumed.push(row.id);
    }
    return { resumed, failed };
  }

  startWatchdog(intervalMs = 5_000): void {
    this.watchdog = setInterval(() => this.sweep(), intervalMs);
    this.watchdog.unref();
  }

  /**
   * Periodic maintenance: stop stuck scans, keep this process's claim on its queued scans fresh, and adopt
   * orphans whose heartbeat has gone stale (e.g. this process crashed and restarted within
   * staleHeartbeatMs, so boot-time recover() skipped them). Never throws: it runs from a timer.
   */
  sweep(): void {
    try {
      this.checkStuck();
      for (const { scanId } of this.queue) this.deps.scans.heartbeat(scanId);
      if (!this.stopping) this.recover();
    } catch (err) {
      logInternal('watchdog sweep failed', null, err);
    }
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
        job.abortKind ??= 'shutdown'; // a user cancel / stuck verdict already in flight wins
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
      const job: RunningJob = {
        controller: new AbortController(), abortKind: null, lastActivity: this.now(), done: Promise.resolve(), cancelAudit: null,
      };
      this.running.set(scanId, job);
      // `done` must never reject: an unhandled rejection would take the whole process down.
      job.done = this.execute(scanId, secrets, job)
        .catch((err: unknown) => logInternal('scan execution crashed', scanId, err))
        .finally(() => {
          this.running.delete(scanId);
          this.pump();
        });
    }
  }

  private async execute(scanId: string, secrets: ScanSecrets, job: RunningJob): Promise<void> {
    const { scans, lifecycle, pipeline, config } = this.deps;
    const touch = () => { job.lastActivity = this.now(); };

    const checkpoint: Checkpoint = scans.getCheckpoint(scanId) ?? { completedStages: [], data: {} };

    // Whole-scan deadline (spec §14.2): fixed on the first run and persisted, so a resume continues the
    // same budget instead of starting a fresh one.
    let deadlineMs: number;
    const storedDeadline = checkpoint.data.deadlineAt;
    if (typeof storedDeadline === 'number' && Number.isFinite(storedDeadline)) {
      deadlineMs = Math.max(storedDeadline - this.now(), MIN_RESUME_DEADLINE_MS);
    } else {
      deadlineMs = config.scanDeadlineMs;
      checkpoint.data.deadlineAt = this.now() + config.scanDeadlineMs;
      scans.setCheckpoint(scanId, checkpoint);
    }
    const deadline = new AbortController();
    const deadlineTimer = setTimeout(() => deadline.abort(), deadlineMs);
    deadlineTimer.unref();
    const signal = AbortSignal.any([job.controller.signal, deadline.signal]);

    const heartbeat = setInterval(() => {
      try {
        scans.heartbeat(scanId);
      } catch (err) {
        logInternal('heartbeat write failed', scanId, err); // a timer callback must never throw
      }
    }, config.heartbeatMs);
    heartbeat.unref();

    try {
      scans.heartbeat(scanId);
      // Stages that did not complete will re-run: drop their persisted warnings so they are not duplicated.
      // Note: their `progress`/`finding` events are re-published on resume; that is acceptable for now
      // because the UI dedupes findings by id and progress is idempotent.
      const pending = pipeline.stages.map((s) => s.name).filter((n) => !checkpoint.completedStages.includes(n));
      scans.removeWarningsForStages(scanId, pending);

      // Only real warnings degrade the outcome; 'info' notes (e.g. a rescan that fell back to a full scan) do not.
      let warned = (scans.getDto(scanId)?.warnings ?? []).some((w) => w.level !== 'info');
      let currentStage: StageName | undefined;
      const ctx: PipelineContext = {
        scanId,
        scan: scans.getDto(scanId)!,
        secrets,
        signal,
        checkpointData: checkpoint.data,
        emit: (event) => { touch(); lifecycle.emit(scanId, event); },
        // The level is ALWAYS taken from the central table (pipeline/warningLevels.ts), never from `w`:
        // one place decides what's expected-and-clean vs. real degradation, so a call site never has to.
        warn: (w) => {
          touch();
          const level = classifyWarningLevel(w.code);
          if (level !== 'info') warned = true;
          lifecycle.warn(scanId, { ...w, level });
        },
        touch,
      };

      // Phase 1: run stages. This only decides the outcome; nothing here writes a terminal state.
      let outcome: Outcome;
      try {
        for (const stage of pipeline.stages) {
          if (checkpoint.completedStages.includes(stage.name)) continue;
          if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Scan aborted');
          touch();
          currentStage = stage.name;
          if (!lifecycle.transition(scanId, stage.name)) {
            // Already terminal (e.g. finalized elsewhere): nothing left to do; finalization will no-op.
            throw new AppError('CANCELLED', 'cancelled', 'Scan is already finished');
          }
          try {
            await stage.run(ctx);
          } catch (raw) {
            const err = toAppError(raw);
            if (signal.aborted || stage.fatal || err.kind === 'cancelled') throw raw;
            ctx.warn({ code: err.code, message: err.userMessage, stage: stage.name });
          }
          // A stage that swallowed the abort did not really finish: never checkpoint it as complete.
          if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Scan aborted');
          checkpoint.completedStages.push(stage.name);
          // A stage may finish the whole scan early (the full-scan cache served every result): the
          // remaining stages are checkpointed as done, so a resume never runs them either.
          if (checkpoint.data[SKIP_REMAINING_STAGES] === true) {
            for (const rest of pipeline.stages) {
              if (!checkpoint.completedStages.includes(rest.name)) checkpoint.completedStages.push(rest.name);
            }
          }
          scans.setCheckpoint(scanId, checkpoint);
        }
        outcome = { ok: true };
      } catch (raw) {
        outcome = { ok: false, raw };
      }

      // Phase 2: finalize exactly once. If finalizing itself fails, log it and leave the scan
      // non-terminal so recover() can resume it; the lifecycle is terminal-once either way.
      try {
        if (outcome.ok) this.complete(scanId, warned);
        else this.finishWithError(scanId, outcome.raw, job, deadline.signal, checkpoint, currentStage);
      } catch (err) {
        logInternal('failed to finalize scan; it stays resumable', scanId, err);
      }

      // Best-effort cleanup once the scan is terminal (e.g. delete the checkout). Never affects the outcome.
      const finalState = scans.getDto(scanId)?.state;
      if (pipeline.onScanFinished && finalState && isTerminalState(finalState)) {
        try {
          await pipeline.onScanFinished(scanId);
        } catch (err) {
          logInternal('scan cleanup failed', scanId, err);
        }
      }
    } finally {
      clearInterval(heartbeat);
      clearTimeout(deadlineTimer);
    }
  }

  private complete(scanId: string, warned: boolean): void {
    const state = warned ? 'COMPLETED_WITH_WARNINGS' : 'COMPLETED';
    this.deps.lifecycle.transition(scanId, state, undefined, scanAudit('scan.completed', scanId, { state }));
  }

  private finishWithError(
    scanId: string, raw: unknown, job: RunningJob, deadline: AbortSignal, checkpoint: Checkpoint, currentStage: StageName | undefined,
  ): void {
    const { lifecycle } = this.deps;
    if (job.abortKind === 'shutdown') return;
    if (job.abortKind === 'user') {
      lifecycle.transition(scanId, 'CANCELLED', undefined, job.cancelAudit ?? scanAudit('scan.cancelled', scanId));
      return;
    }
    let err: AppError;
    if (job.abortKind === 'stuck') {
      err = new AppError('INTERNAL', 'permanent', 'The scan stopped making progress and was stopped');
    } else if (deadline.aborted) {
      if (checkpoint.completedStages.includes('ANALYZING')) {
        lifecycle.warn(scanId, {
          code: 'SCAN_DEADLINE', message: 'Time limit reached; results are partial', ...(currentStage ? { stage: currentStage } : {}),
        });
        this.complete(scanId, true);
        return;
      }
      err = new AppError('SCAN_DEADLINE', 'budget', 'The scan exceeded its time limit before analysis finished');
    } else {
      err = toAppError(raw);
    }
    lifecycle.transition(scanId, 'FAILED', { code: err.code, message: err.userMessage }, scanAudit('scan.failed', scanId, { code: err.code }));
  }
}
