import type { GitService } from '../git/GitService';
import { cloneStage } from './stages/cloneStage';
import { indexStage, type IndexDeps } from './stages/indexStage';
import { resolveStage, type ResolveDeps } from './stages/resolveStage';
import { createStubPipeline } from './stubPipeline';
import type { Pipeline, StageName } from './types';

export type ScanPipelineDeps = Omit<ResolveDeps, 'git'> & Omit<IndexDeps, 'git'> & {
  git: Pick<GitService, 'remoteUrl' | 'resolveRef' | 'ensureCheckout' | 'removeScanDir'>;
  /** Stages after INDEXING still come from the stub until P3–P7 replace them. */
  stub?: Pipeline;
  /** Called after cleanup, once the scan reaches a terminal state (e.g. budget-tracker cleanup). */
  onFinished?: (scanId: string) => void;
};

const REAL_STAGES = new Set<StageName>(['RESOLVING', 'CLONING', 'INDEXING']);

export function createScanPipeline(deps: ScanPipelineDeps): Pipeline {
  const rest = (deps.stub ?? createStubPipeline()).stages.filter((s) => !REAL_STAGES.has(s.name));
  return {
    stages: [resolveStage(deps), cloneStage(deps), indexStage(deps), ...rest],
    onScanFinished: async (scanId) => {
      await deps.git.removeScanDir(scanId);
      deps.onFinished?.(scanId);
    },
  };
}
