// Single source of truth for whether a scan warning's `code` is an 'info' (expected, non-degrading
// condition) or a real 'warning' (degradation). This is the ONLY place that decides the level — every
// warning passes through classifyWarningLevel (JobRunner.ts's ctx.warn), so a call site never needs to
// (and never should) set `level` itself.
//
// Why this matters: ScanRepo.findFullCacheSource and JobRunner's `complete()` both treat a scan whose
// warnings are all 'info' as CLEAN — eligible for the full-scan cache and reported as COMPLETED rather
// than COMPLETED_WITH_WARNINGS. Before this table existed, every analyzer-level warning defaulted to
// 'warning' (AnalyzerContext.warn carries no level), so routine, expected conditions — a mock-mode scan
// with no Docker sandbox images built, a repo with no JS/TS/Python source, a cache miss that fell back
// to a full scan — permanently marked the scan COMPLETED_WITH_WARNINGS and blocked it from ever being a
// full-cache source, even though nothing was actually degraded.
//
// 'info'    — the scan still covered everything it set out to cover; the condition is either expected
//             in normal operation (no Docker available in dev/mock/CI, no source files in this repo) or
//             a fallback that costs time, not completeness (a cache miss re-running the full scan, an
//             incremental rescan with no usable base analyzing every file, a sandbox/lockfile version
//             note where the lockfile is authoritative anyway).
// 'warning' — real degradation: an analyzer failed outright, the dollar budget cut a review short, an
//             AI call was unavailable, an external service (OSV, the package registry) could not be
//             reached, or a result had to be dropped/left unverified.
//
// A code absent from this table defaults to 'warning' (fail safe: an unrecognised condition is never
// silently treated as clean).
export type WarningLevel = 'info' | 'warning';

export const WARNING_LEVELS: Readonly<Record<string, WarningLevel>> = {
  // --- info: expected, non-degrading ---------------------------------------------------------
  /** RESOLVING: the full-scan cache entry couldn't be reused; this scan just ran in full instead. */
  CACHE_UNAVAILABLE: 'info',
  /** ANALYZING (pipeline/incremental.ts): no usable incremental base — this rescan analyzed every file. */
  INCREMENTAL_BASE_UNAVAILABLE: 'info',
  /** ANALYZING (pipeline/incremental.ts): the diff was too large to bother; every file was analyzed. */
  INCREMENTAL_DIFF_TOO_LARGE: 'info',
  /** INDEXING: no JS/TS/Python source in this repo — not a failure, just nothing for code analyzers to do. */
  NO_SOURCE_FILES: 'info',
  /** ANALYZING (dependencies): Docker unavailable / sandbox images not built — expected outside a full
   *  deploy (dev, mock mode, most CI); usage falls back to the import index, not a degraded result. */
  SANDBOX_UNAVAILABLE: 'info',
  /** ANALYZING (dependencies): sandbox-resolved versions differ from the lockfile; findings still use
   *  the lockfile version (the authoritative source), so nothing about the result is actually degraded. */
  SANDBOX_VERSION_MISMATCH: 'info',

  // --- warning: real degradation --------------------------------------------------------------
  /** ANALYZING: one analyzer threw and produced no findings. */
  ANALYZER_FAILED: 'warning',
  /** ANALYZING: the dollar budget ran out before every file got its AI review. */
  BUDGET_COVERAGE_PARTIAL: 'warning',
  /** RESOLVING: the cached result's new/existing/fixed triage could not be recomputed. */
  CACHE_STATUS_PARTIAL: 'warning',
  /** ANALYZING (config): AI config review was unavailable for one or more files. */
  CONFIG_AI_UNAVAILABLE: 'warning',
  /** ANALYZING (credentials): scanning commit history for credentials failed outright. */
  CREDENTIALS_HISTORY_FAILED: 'warning',
  /** ANALYZING (credentials): oversized diff chunks were skipped while scanning commit history. */
  CREDENTIALS_HISTORY_PARTIAL: 'warning',
  /** ANALYZING (credentials): the commit history scan was truncated before reaching the requested depth. */
  CREDENTIALS_HISTORY_TRUNCATED: 'warning',
  /** ANALYZING (credentials): liveness verification failed for one or more candidates. */
  CREDENTIALS_VERIFICATION_FAILED: 'warning',
  /** ANALYZING (credential-hunter): AI credential hunting failed for one or more file batches. */
  CREDENTIAL_HUNTER_PARTIAL: 'warning',
  /** ANALYZING (dependencies): OSV advisories could not be retrieved for some dependencies. */
  DEPENDENCY_ADVISORIES_PARTIAL: 'warning',
  /** ANALYZING (dependencies): OSV advisories were unreachable entirely. */
  DEPENDENCY_ADVISORIES_UNAVAILABLE: 'warning',
  /** ANALYZING (dependencies): the dependency fix plan is partial or could not be built. */
  DEPENDENCY_FIX_PLAN_PARTIAL: 'warning',
  /** ANALYZING (quality): AI code-quality review failed for one or more files. */
  QUALITY_PARTIAL: 'warning',
  /** INDEXING: the repo exceeds the file-count safety limit; some files were never analyzed. */
  REPO_TOO_LARGE: 'warning',
  /** ANALYZING (dependencies): the opt-in sandbox install failed for one or more lockfiles. */
  SANDBOX_INSTALL_PARTIAL: 'warning',
  /** ANALYZING (dependencies): sandbox usage analysis failed for SOME (not all) targets. */
  SANDBOX_PARTIAL: 'warning',
  /** ANALYZING (sast): AI code review failed for one or more files. */
  SAST_PARTIAL: 'warning',
  /** ANALYZING (sast): an AI-reported issue was dropped because the cited code could not be verified. */
  SAST_UNVERIFIED_DROPPED: 'warning',
  /** SYNTHESIZING: the AI scan summary could not be generated; a deterministic one was used instead. */
  SYNTHESIS_FALLBACK: 'warning',
  /** ANALYZING (taint): taint tracing failed for one or more entrypoints. */
  TAINT_ENTRYPOINT_FAILED: 'warning',
  /** ANALYZING (taint): taint tracing of a file stopped early (max turns / timeout / budget). */
  TAINT_PARTIAL: 'warning',
  /** ANALYZING (taint): a reported taint flow was dropped because its source or sink could not be verified. */
  TAINT_UNVERIFIED_DROPPED: 'warning',
  /** ANALYZING (triage): the repo exceeds the file-count safety limit for AI triage. */
  TRIAGE_FILE_LIMIT: 'warning',
  /** ANALYZING (triage): AI triage failed for one or more file batches. */
  TRIAGE_PARTIAL: 'warning',
  /** VERIFYING: the AI skeptic review could not run; findings are reported unverified. */
  VERIFY_PARTIAL: 'warning',
};

/** The level for `code`, per WARNING_LEVELS above (default 'warning' for an unlisted code). */
export function classifyWarningLevel(code: string): WarningLevel {
  return WARNING_LEVELS[code] ?? 'warning';
}
