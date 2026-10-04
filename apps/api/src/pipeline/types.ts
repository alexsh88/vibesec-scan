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
};

export type StageSpec = {
  name: StageName;
  /** Fatal stages fail the scan; degradable stages turn errors into warnings (spec §14.6). */
  fatal: boolean;
  run(ctx: PipelineContext): Promise<void>;
};

export type Pipeline = { stages: StageSpec[] };
