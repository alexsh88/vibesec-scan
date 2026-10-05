import type { Category, Finding, ScanDto } from '@vibesec/shared';
import type { IndexedFile } from '../index/types';

/**
 * Per-file outcome of an analyzer's AI review (persisted per scan, see db/coverageRepo.ts):
 * reviewed (main model), reviewed-fast (cheaper model pass), not-relevant (judged out of scope, e.g.
 * triage relevance 0), budget-skipped (the scan's dollar budget ran out first), failed, cached.
 */
export type CoverageStatus = 'reviewed' | 'reviewed-fast' | 'not-relevant' | 'budget-skipped' | 'failed' | 'cached';
export const COVERAGE_STATUSES: readonly CoverageStatus[] = ['reviewed', 'reviewed-fast', 'cached', 'not-relevant', 'budget-skipped', 'failed'];
export type CoverageEntry = { analyzer: string; path: string; status: CoverageStatus };

/**
 * Incremental rescan (spec §11): the scan's diff against an earlier completed scan of the same repo and
 * result configuration (pipeline/incremental.ts). Analyzers use it to re-run only the changed/affected
 * part and re-attach the base scan's results for the rest (analyzers/reuse.ts):
 *   - triage / SAST: content-hash result caches — unchanged files hit them ('cached', $0) by themselves;
 *   - quality / credential hunter: only files in `changed` are reviewed again;
 *   - taint: only entrypoints in `affected` are re-traced; the others' flows are re-validated step by step;
 *   - credentials (regex + history), dependencies, config: deterministic or cheap — always run in full.
 */
export type IncrementalContext = {
  baseScanId: string;
  baseCommitSha: string;
  /** Added, modified, renamed (new path) or copied files since the base commit. */
  changed: ReadonlySet<string>;
  /** `changed` ∪ files importing them (reverse imports, depth 2) ∪ entrypoints whose import closure reaches them. */
  affected: ReadonlySet<string>;
  /** Deleted files and the old path of renamed ones. */
  deleted: ReadonlySet<string>;
  /** The base scan's own output of `analyzer`, as the analyzer returned it (before VERIFYING/SCORING). */
  baseFindings(analyzer: string): Finding[];
  /** The base scan's per-path coverage status for `analyzer` (coverage analyzer key, e.g. 'credential-hunter'). */
  baseCoverage(analyzer: string): ReadonlyMap<string, CoverageStatus>;
};

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
  /**
   * Structured per-unit progress (files reviewed / batches / entrypoints / lockfiles / steps),
   * wired to a `{type:'progress', analyzer, done, total}` ScanEvent (pipeline/stages/analyzeStage.ts).
   * Throttled to at most 4 events/s per `analyzerLabel` (always including the final `done === total`
   * call) — call it freely, every call after the first within the window is coalesced, not dropped.
   * `analyzerLabel` overrides the emitted `analyzer` field; omit it to report under this analyzer's own
   * id. Used by the shared triage pass (code/triage.ts) to always report as 'triage' regardless of
   * which analyzer's context triggered it. Absent in unit tests that build a bare AnalyzerContext.
   */
  reportProgress?: (done: number, total: number, analyzerLabel?: string) => void;
  /** Records a file's coverage outcome (last write per analyzer+path wins). Absent in unit tests. */
  recordCoverage?: (analyzer: string, path: string, status: CoverageStatus) => void;
  /** Present on an incremental rescan only (see IncrementalContext). */
  incremental?: IncrementalContext;
};

export interface Analyzer {
  /** Also the FindingRepo analyzer key, e.g. 'credentials'. */
  readonly id: string;
  readonly version: string;
  /** Gated against scan.options.categories: the analyzer only runs when its category is enabled. */
  readonly category: Category;
  run(ctx: AnalyzerContext): Promise<Finding[]>;
}
