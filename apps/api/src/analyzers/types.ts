import type { Category, Finding, ScanDto } from '@vibesec/shared';
import type { IndexedFile } from '../index/types';

/** Everything an analyzer needs to inspect the checked-out repo and report results; never persisted itself. */
export type AnalyzerContext = {
  scanId: string;
  scan: ScanDto;
  repoDir: string;
  commitSha: string;
  /** For building permalinks into the scanned repo. */
  repo: { owner: string; name: string };
  /** PAT for private repos (from ctx.secrets); never log this. */
  token?: string;
  files: readonly IndexedFile[];
  signal: AbortSignal;
  /** Liveness ping for the stuck-scan watchdog; call at least every stuckAfterMs / 2 during long work. */
  touch: () => void;
  warn: (code: string, message: string) => void;
  /** Throttled progress/log line; a no-op if the pipeline has nowhere to send it. */
  progress: (message: string) => void;
};

export interface Analyzer {
  /** Also the FindingRepo analyzer key, e.g. 'credentials'. */
  readonly id: string;
  readonly version: string;
  /** Gated against scan.options.categories: the analyzer only runs when its category is enabled. */
  readonly category: Category;
  run(ctx: AnalyzerContext): Promise<Finding[]>;
}
