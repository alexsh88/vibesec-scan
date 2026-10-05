import type { Analyzer } from '../analyzers/types';
import type { FindingRepo } from '../db/findingRepo';
import type { IndexRepo } from '../db/indexRepo';
import type { GitService } from '../git/GitService';
import { analyzeStage } from './stages/analyzeStage';
import { cloneStage } from './stages/cloneStage';
import { indexStage, type IndexDeps } from './stages/indexStage';
import { resolveStage, type ResolveDeps } from './stages/resolveStage';
import { createStubPipeline } from './stubPipeline';
import type { Pipeline, StageName, StageSpec } from './types';

export type ScanPipelineDeps = Omit<ResolveDeps, 'git'> & Omit<IndexDeps, 'git' | 'indexRepo'> & {
  git: Pick<GitService, 'remoteUrl' | 'resolveRef' | 'ensureCheckout' | 'removeScanDir' | 'repoDir'>;
  /** Widened past IndexDeps's write-only `Pick<..,'replace'>` so the real ANALYZING stage can also read it. */
  indexRepo: Pick<IndexRepo, 'replace' | 'files'>;
  /** Stages after INDEXING still come from the stub until P3–P7 replace them. */
  stub?: Pipeline;
  /** Called after cleanup, once the scan reaches a terminal state (e.g. budget-tracker cleanup). */
  onFinished?: (scanId: string) => void;
  /** When both `analyzers` and `findings` are given, the real ANALYZING stage replaces the stub's. */
  analyzers?: readonly Analyzer[];
  findings?: FindingRepo;
};

const REAL_STAGES = new Set<StageName>(['RESOLVING', 'CLONING', 'INDEXING']);

export function createScanPipeline(deps: ScanPipelineDeps): Pipeline {
  const { analyzers, findings } = deps;
  const hasRealAnalyzing = analyzers !== undefined && findings !== undefined;
  const excluded = hasRealAnalyzing ? new Set<StageName>([...REAL_STAGES, 'ANALYZING']) : REAL_STAGES;
  const rest = (deps.stub ?? createStubPipeline()).stages.filter((s) => !excluded.has(s.name));
  const analyzing: StageSpec[] = (analyzers !== undefined && findings !== undefined)
    ? [analyzeStage({ analyzers, findings, indexRepo: deps.indexRepo, git: deps.git })]
    : [];
  return {
    stages: [resolveStage(deps), cloneStage(deps), indexStage(deps), ...analyzing, ...rest],
    onScanFinished: async (scanId) => {
      await deps.git.removeScanDir(scanId);
      deps.onFinished?.(scanId);
    },
  };
}
