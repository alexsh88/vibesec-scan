import { isTerminalState, type ScanState } from '@vibesec/shared';

export { isTerminalState };

/** Pipeline stages in order, for the live view stepper and progress labels. */
export const PIPELINE_STAGES = [
  { state: 'QUEUED', label: 'Queued' },
  { state: 'RESOLVING', label: 'Resolving ref' },
  { state: 'CLONING', label: 'Cloning' },
  { state: 'INDEXING', label: 'Indexing' },
  { state: 'ANALYZING', label: 'Analyzing' },
  { state: 'VERIFYING', label: 'Verifying' },
  { state: 'SCORING', label: 'Scoring' },
  { state: 'SYNTHESIZING', label: 'Summarizing' },
] as const satisfies ReadonlyArray<{ state: ScanState; label: string }>;

export const STATE_LABEL: Record<ScanState, string> = {
  QUEUED: 'Queued',
  RESOLVING: 'Resolving',
  CLONING: 'Cloning',
  INDEXING: 'Indexing',
  ANALYZING: 'Analyzing',
  VERIFYING: 'Verifying',
  SCORING: 'Scoring',
  SYNTHESIZING: 'Summarizing',
  COMPLETED: 'Completed',
  COMPLETED_WITH_WARNINGS: 'Completed with warnings',
  FAILED: 'Failed',
  CANCELLED: 'Cancelled',
};

export type StateTone = 'running' | 'success' | 'warning' | 'danger' | 'neutral';

export function stateTone(s: ScanState): StateTone {
  if (s === 'COMPLETED') return 'success';
  if (s === 'COMPLETED_WITH_WARNINGS') return 'warning';
  if (s === 'FAILED') return 'danger';
  if (s === 'CANCELLED') return 'neutral';
  return 'running';
}

/** Has results worth showing (overview/findings). */
export const hasResults = (s: ScanState): boolean => s === 'COMPLETED' || s === 'COMPLETED_WITH_WARNINGS';
