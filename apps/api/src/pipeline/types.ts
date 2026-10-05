import type { ScanDto, ScanEvent, ScanState } from '@vibesec/shared';
import type { ScanWarning } from '../db/scanRepo';

export type StageName = Exclude<ScanState, 'QUEUED' | 'COMPLETED' | 'COMPLETED_WITH_WARNINGS' | 'FAILED' | 'CANCELLED'>;

/** Held in memory only for the lifetime of a scan; never persisted or logged. */
export type ScanSecrets = { token?: string };

export type PipelineContext = {
  scanId: string;
  scan: ScanDto;
  secrets: ScanSecrets;
  signal: AbortSignal;
  /** Mutable; persisted with the checkpoint after each completed stage. */
  checkpointData: Record<string, unknown>;
  emit(event: ScanEvent): void;
  warn(warning: ScanWarning & { file?: string }): void;
  /**
   * Reports liveness to the stuck-scan watchdog without emitting an event (`emit`/`warn` also count).
   * Any long, quiet operation (LLM calls, git clone/fetch, sandboxed analyzers…) MUST call `ctx.touch()`
   * at least every `stuckAfterMs / 2`, or the watchdog will abort the scan as stuck.
   */
  touch(): void;
};

export type StageSpec = {
  name: StageName;
  /**
   * Fatal stages fail the scan; degradable stages turn errors into warnings (spec §14.6).
   * Note: ANALYZING is degradable per analyzer, but when EVERY analyzer fails the real ANALYZING stage
   * must throw a fatal AppError so the scan ends FAILED — "all analyzers failed ⇒ FAILED". TODO (later milestone):
   * today the runner downgrades every degradable-stage error to a warning, so it must learn to honour that signal.
   * A stage must honour `ctx.signal`: if it resolves after an abort, the runner treats it as aborted (not completed).
   */
  fatal: boolean;
  run(ctx: PipelineContext): Promise<void>;
};

export type Pipeline = {
  stages: StageSpec[];
  /** Best-effort cleanup, called once after the scan reaches a terminal state (never for a resumable scan). */
  onScanFinished?(scanId: string): Promise<void>;
};
