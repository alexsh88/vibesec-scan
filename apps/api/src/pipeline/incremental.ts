// Incremental rescans (spec §11). Before ANALYZING, a scan looks for its base: the latest completed scan
// of the same repo with the same result configuration (ScanOptions + analyzerVersionsHash) at a
// different commit. With a base, `git diff --name-status base..head` scopes the analysis:
//
//   changed  C = added ∪ modified ∪ renamed/copied (new path) ∪ type-changed files
//   deleted    = deleted files ∪ the old path of renamed ones
//   affected   = C ∪ files importing a file of C (reverse imports, depth 2)
//                  ∪ entrypoints whose (forward) import closure reaches C
//
// and analyzers re-run only that part (see IncrementalContext in analyzers/types.ts). Fallbacks to a
// full scan, each with an 'info' warning (never a degraded result): the base commit is not in the
// partial clone and cannot be fetched; or the diff touches more than 40% of the indexed files (an
// incremental scan would then save little and risk more).
//
// Reuse stats ("N files reused, $X saved", ScanDto.reuse + diagnostics + a `cache` event):
//   filesReused       = indexed files outside C
//   estimatedSavedUsd = Σ over analyzers a of  baseCost(a) × reused(a) / reviewed(a)
// where baseCost(a) is the base scan's LLM spend of analyzer a (llm_calls), reviewed(a) the files /
// entrypoints the base reviewed with it (coverage 'reviewed'/'reviewed-fast') and reused(a) those of them
// this scan served from cache (coverage 'cached'). An estimate: it assumes an even cost per reviewed file
// and leaves out what the base itself reused (its own 'cached' entries cost it $0).

import type { ReuseStats } from '@vibesec/shared';
import type { CoverageEntry, CoverageStatus, IncrementalContext } from '../analyzers/types';
import type { CoverageRepo } from '../db/coverageRepo';
import type { FindingRepo } from '../db/findingRepo';
import type { IndexRepo } from '../db/indexRepo';
import type { LlmCallRepo } from '../db/llmCallRepo';
import type { ScanRepo } from '../db/scanRepo';
import type { GitService } from '../git/GitService';
import type { Entrypoint, ImportEdge, IndexedFile } from '../index/types';
import type { PipelineContext } from './types';

/** Above this share of changed+deleted files (of the indexed files) a rescan runs in full. */
export const MAX_CHANGED_RATIO = 0.4;
const REVERSE_IMPORT_DEPTH = 2;

export type IncrementalDeps = {
  scans: Pick<ScanRepo, 'getRow' | 'findIncrementalBase'>;
  git: Pick<GitService, 'diffNameStatus' | 'fetchCommit'>;
  indexRepo: Pick<IndexRepo, 'imports' | 'entrypoints'>;
  findings: Pick<FindingRepo, 'analyzerResult'>;
  coverage: Pick<CoverageRepo, 'list'>;
  llmCalls: Pick<LlmCallRepo, 'byAnalyzer'>;
  maxChangedRatio?: number;
};

/**
 * The affected set: C ∪ reverse-import closure of C ∪ deleted (depth 2) ∪ entrypoints whose forward
 * import closure intersects C ∪ deleted. Pure (exported for tests).
 */
export function computeAffected(input: {
  changed: ReadonlySet<string>; deleted: ReadonlySet<string>; imports: readonly ImportEdge[]; entrypoints: readonly Entrypoint[];
  depth?: number;
}): Set<string> {
  const seeds = new Set([...input.changed, ...input.deleted]);
  const importers = new Map<string, Set<string>>();
  const importsOf = new Map<string, Set<string>>();
  for (const e of input.imports) {
    if (e.kind !== 'local' || !e.to) continue;
    (importers.get(e.to) ?? importers.set(e.to, new Set()).get(e.to)!).add(e.from);
    (importsOf.get(e.from) ?? importsOf.set(e.from, new Set()).get(e.from)!).add(e.to);
  }

  const affected = new Set(input.changed);
  let frontier = [...seeds];
  for (let d = 0; d < (input.depth ?? REVERSE_IMPORT_DEPTH) && frontier.length > 0; d++) {
    const next: string[] = [];
    for (const path of frontier) {
      for (const from of importers.get(path) ?? []) {
        if (!affected.has(from)) { affected.add(from); next.push(from); }
      }
    }
    frontier = next;
  }

  for (const ep of new Set(input.entrypoints.map((e) => e.path))) {
    if (affected.has(ep)) continue;
    const seen = new Set([ep]);
    const queue = [ep];
    while (queue.length > 0) {
      const path = queue.shift()!;
      if (seeds.has(path)) { affected.add(ep); break; }
      for (const to of importsOf.get(path) ?? []) if (!seen.has(to)) { seen.add(to); queue.push(to); }
    }
  }
  return affected;
}

function coverageMap(entries: readonly CoverageEntry[]): Map<string, Map<string, CoverageStatus>> {
  const byAnalyzer = new Map<string, Map<string, CoverageStatus>>();
  for (const e of entries) (byAnalyzer.get(e.analyzer) ?? byAnalyzer.set(e.analyzer, new Map()).get(e.analyzer)!).set(e.path, e.status);
  return byAnalyzer;
}

/**
 * Plans an incremental rescan, or returns undefined for a full scan (no base, or a fallback — then
 * an 'info' warning says why). Deterministic: a resumed ANALYZING stage plans the same thing again.
 */
export async function planIncremental(
  deps: IncrementalDeps, ctx: PipelineContext, input: { repoDir: string; commitSha: string; files: readonly IndexedFile[] },
): Promise<IncrementalContext | undefined> {
  const row = deps.scans.getRow(ctx.scanId);
  if (!row?.result_options_hash || !row.analyzer_versions_hash) return undefined;
  const keys = { resultOptionsHash: row.result_options_hash, analyzerVersionsHash: row.analyzer_versions_hash };
  const base = deps.scans.findIncrementalBase(row.repo_id, input.commitSha, keys, ctx.scanId);
  if (!base?.commit_sha) return undefined;

  const info = (code: string, message: string) => ctx.warn({ code, message, stage: 'ANALYZING', level: 'info' });
  const call = { token: ctx.secrets.token, signal: ctx.signal, onActivity: ctx.touch };
  let diff = await deps.git.diffNameStatus(input.repoDir, base.commit_sha, input.commitSha, call);
  if (diff === null && await deps.git.fetchCommit(input.repoDir, base.commit_sha, call)) {
    diff = await deps.git.diffNameStatus(input.repoDir, base.commit_sha, input.commitSha, call);
  }
  if (diff === null) {
    info('INCREMENTAL_BASE_UNAVAILABLE',
      `The previous scan's commit ${base.commit_sha.slice(0, 12)} is no longer available in the repository (force-push or history rewrite?); this rescan analyzed every file.`);
    return undefined;
  }

  const changed = new Set<string>();
  const deleted = new Set<string>();
  for (const d of diff) {
    if (d.status === 'D') deleted.add(d.path);
    else changed.add(d.path);
    if (d.status === 'R' && d.oldPath) deleted.add(d.oldPath);
  }
  const indexed = input.files.filter((f) => f.skipReason === null).length;
  const ratio = (changed.size + deleted.size) / Math.max(1, indexed);
  if (ratio > (deps.maxChangedRatio ?? MAX_CHANGED_RATIO)) {
    info('INCREMENTAL_DIFF_TOO_LARGE',
      `${changed.size + deleted.size} files changed since the previous scan (${Math.round(ratio * 100)}% of ${indexed}); this rescan analyzed every file.`);
    return undefined;
  }

  const affected = computeAffected({
    changed, deleted, imports: deps.indexRepo.imports(ctx.scanId), entrypoints: deps.indexRepo.entrypoints(ctx.scanId),
  });
  const baseCoverage = coverageMap(deps.coverage.list(base.id));
  const empty = new Map<string, CoverageStatus>();
  return {
    baseScanId: base.id,
    baseCommitSha: base.commit_sha,
    changed, affected, deleted,
    baseFindings: (analyzer) => deps.findings.analyzerResult(base.id, analyzer),
    baseCoverage: (analyzer) => baseCoverage.get(analyzer) ?? empty,
  };
}

const REVIEWED: ReadonlySet<CoverageStatus> = new Set(['reviewed', 'reviewed-fast']);

/** "N files reused, $X saved" for an incremental scan (formula in the header). */
export function reuseStats(
  deps: Pick<IncrementalDeps, 'coverage' | 'llmCalls'>, plan: IncrementalContext,
  input: { files: readonly IndexedFile[]; coverage: readonly CoverageEntry[] },
): ReuseStats {
  const base = coverageMap(deps.coverage.list(plan.baseScanId));
  const now = coverageMap(input.coverage);
  let saved = 0;
  for (const { analyzer, costUsd } of deps.llmCalls.byAnalyzer(plan.baseScanId)) {
    const baseCov = base.get(analyzer);
    if (!baseCov || costUsd <= 0) continue;
    const reviewed = [...baseCov.entries()].filter(([, s]) => REVIEWED.has(s)).map(([p]) => p);
    if (reviewed.length === 0) continue;
    const nowCov = now.get(analyzer);
    const reused = reviewed.filter((p) => nowCov?.get(p) === 'cached').length;
    saved += (costUsd * reused) / reviewed.length;
  }
  return {
    baseScanId: plan.baseScanId,
    filesChanged: plan.changed.size,
    filesDeleted: plan.deleted.size,
    filesReused: input.files.filter((f) => f.skipReason === null && !plan.changed.has(f.path)).length,
    estimatedSavedUsd: Math.round(saved * 1e6) / 1e6,
  };
}
