// Incremental-rescan reuse helpers (spec §11): which files an analyzer may skip on an incremental rescan
// and how a base-scan finding is re-attached to the new scan.

import type { Finding } from '@vibesec/shared';
import { fingerprint, githubPermalink } from '../findings/helpers';
import type { AnalyzerContext, CoverageStatus } from './types';

/** Base outcomes worth reusing: a real review (or a cache hit of one) or a "not relevant" verdict. */
const REUSABLE_STATUSES: ReadonlySet<CoverageStatus> = new Set(['reviewed', 'reviewed-fast', 'cached', 'not-relevant']);

/**
 * The subset of `paths` an analyzer may re-attach from the base scan instead of reviewing again: the
 * file is outside `scope` (default: the changed files) and the base scan really covered it (a file the
 * base skipped for budget, or failed on, deserves another attempt). Empty on a full scan.
 */
export function reusablePaths(
  ctx: Pick<AnalyzerContext, 'incremental'>, coverageKey: string, paths: Iterable<string>, scope: 'changed' | 'affected' = 'changed',
): Set<string> {
  const inc = ctx.incremental;
  const out = new Set<string>();
  if (!inc) return out;
  const coverage = inc.baseCoverage(coverageKey);
  const excluded = scope === 'changed' ? inc.changed : inc.affected;
  for (const path of paths) {
    const status = coverage.get(path);
    if (!excluded.has(path) && status !== undefined && REUSABLE_STATUSES.has(status)) out.add(path);
  }
  return out;
}

/**
 * A base-scan finding re-attached to this scan: same fingerprint (so new/existing/fixed matching and
 * triage suppressions carry over), this scan's id/scanId, a permalink at the new commit. Location is
 * kept as is unless `location` overrides it (e.g. after re-validation moved it).
 */
export function rebaseFinding(
  ctx: Pick<AnalyzerContext, 'scanId' | 'repo' | 'commitSha'>, f: Finding,
  patch: Partial<Pick<Finding, 'taintTrace'>> & { location?: Pick<Finding['location'], 'startLine' | 'endLine' | 'snippet'> } = {},
): Finding {
  const loc = { ...f.location, ...patch.location };
  const rebased: Finding = {
    ...f,
    id: fingerprint([ctx.scanId, f.fingerprint]).slice(0, 32),
    scanId: ctx.scanId,
    scanStatus: 'new',
    location: { ...loc, permalink: githubPermalink(ctx.repo, ctx.commitSha, loc.file, loc.startLine, loc.endLine) },
  };
  if (patch.taintTrace) rebased.taintTrace = patch.taintTrace;
  return rebased;
}

/** The base scan's findings of `analyzer` located in `paths`, re-attached to this scan (files unchanged ⇒ identical content). */
export function reusedFindings(
  ctx: Pick<AnalyzerContext, 'scanId' | 'repo' | 'commitSha' | 'incremental'>, analyzer: string, paths: ReadonlySet<string>,
): Finding[] {
  if (!ctx.incremental || paths.size === 0) return [];
  return ctx.incremental.baseFindings(analyzer)
    .filter((f) => paths.has(f.location.file))
    .map((f) => rebaseFinding(ctx, f));
}
