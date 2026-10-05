// new / existing / fixed (spec §11), computed at the end of SCORING (and on a full-scan cache hit) by
// comparing fingerprints with this scan's BASELINE:
//   the latest completed scan of the same repo with the same result options and the same requested ref
//   (ScanRepo.findBaselineCandidates), requested no later than this one, whose commit is this scan's
//   commit or one of its ancestors (`git merge-base --is-ancestor`, best-effort). A candidate whose
//   ancestry cannot be established is skipped; with no baseline every finding is 'new' and nothing is
//   'fixed' — "unknown" never produces a false "fixed".
//   present in both  → 'existing'
//   only in this one → 'new'
//   only in the baseline → copied into THIS scan as a `fixed` row (severity unchanged). Fixed rows are
//     left out of FindingRepo.all/list/counts by default (so of the grade, synthesis and exports too);
//     GET /api/scans/:id/findings?scanStatus=fixed lists them.
// A baseline finding only counts as fixed when this scan could have found it again:
//   - its category is enabled here and the analyzer that produced it completed in this scan, and
//   - it is repo-level (dependency / config), or its file was really looked at in this scan: deleted
//     from the repo, or indexed and — for an analyzer that records AI-review coverage — reviewed, served
//     from cache or judged not relevant (a budget-skipped or failed file never reads as fixed).
// Idempotent: statuses are recomputed and the fixed rows replaced on every run.

import type { Finding } from '@vibesec/shared';
import type { CoverageStatus } from '../../analyzers/types';
import type { CoverageRepo } from '../../db/coverageRepo';
import type { FindingRepo, FindingRow } from '../../db/findingRepo';
import type { IndexRepo } from '../../db/indexRepo';
import type { ScanRepo, ScanRow } from '../../db/scanRepo';
import type { GitCallOptions, GitService } from '../../git/GitService';
import { copiedFindingId } from './fullCache';

export type ScanStatusDeps = {
  scans: Pick<ScanRepo, 'getRow' | 'getDto' | 'findBaselineCandidates'>;
  findings: Pick<FindingRepo, 'all' | 'update' | 'replaceFixed' | 'analyzersWithResults'>;
  coverage: Pick<CoverageRepo, 'list'>;
  indexRepo: Pick<IndexRepo, 'files'>;
  /** Commit ancestry of a baseline candidate; absent → only a candidate at the same commit qualifies. */
  git?: Pick<GitService, 'isAncestor' | 'repoDir'>;
};

export type ScanStatusCounts = { previousScanId: string | null; new: number; existing: number; fixed: number };

const COVERED: ReadonlySet<CoverageStatus> = new Set(['reviewed', 'reviewed-fast', 'cached', 'not-relevant']);
const REPO_LEVEL: ReadonlySet<Finding['category']> = new Set(['dependency', 'config']);

/** Every fingerprint a finding stands for: its own plus those of findings merged into it (crossDedupe). */
export function fingerprintsOf(f: Pick<Finding, 'fingerprint' | 'mergedFingerprints'>): string[] {
  return [f.fingerprint, ...(f.mergedFingerprints ?? [])];
}

async function findBaseline(deps: ScanStatusDeps, row: ScanRow, call: GitCallOptions): Promise<ScanRow | undefined> {
  for (const candidate of deps.scans.findBaselineCandidates(row.id)) {
    if (!row.commit_sha || !candidate.commit_sha) continue;
    if (candidate.commit_sha === row.commit_sha) return candidate;
    if (!deps.git) continue;
    const ancestor = await deps.git.isAncestor(deps.git.repoDir(row.id), candidate.commit_sha, row.commit_sha, call);
    if (ancestor === true) return candidate;
  }
  return undefined;
}

export async function applyScanStatus(
  deps: ScanStatusDeps, scanId: string, call: Pick<GitCallOptions, 'signal'> & { touch?: () => void } = {},
): Promise<ScanStatusCounts> {
  const row = deps.scans.getRow(scanId);
  const categories = new Set(deps.scans.getDto(scanId)?.options.categories ?? []);
  if (!row) return { previousScanId: null, new: 0, existing: 0, fixed: 0 };
  const previous = await findBaseline(deps, row, { ...(call.signal ? { signal: call.signal } : {}), ...(call.touch ? { onActivity: call.touch } : {}) });
  const previousRows = previous ? deps.findings.all(previous.id) : [];
  const previousFps = new Set(previousRows.flatMap((r) => fingerprintsOf(r.finding)));

  const current = deps.findings.all(scanId);
  const changed: Finding[] = [];
  let existing = 0;
  for (const { finding } of current) {
    const status = fingerprintsOf(finding).some((fp) => previousFps.has(fp)) ? 'existing' : 'new';
    if (status === 'existing') existing++;
    if (finding.scanStatus !== status) changed.push({ ...finding, scanStatus: status });
  }
  if (changed.length > 0) deps.findings.update(scanId, changed);

  const currentFps = new Set(current.flatMap((r) => fingerprintsOf(r.finding)));
  const ran = deps.findings.analyzersWithResults(scanId);
  const looked = lookedAt(deps, scanId);
  const fixed: FindingRow[] = previousRows
    .filter((r) => !fingerprintsOf(r.finding).some((fp) => currentFps.has(fp))
      && categories.has(r.finding.category) && ran.has(r.analyzer) && looked(r.analyzer, r.finding))
    .map((r) => ({ analyzer: r.analyzer, finding: { ...r.finding, id: copiedFindingId(scanId, r.finding.id), scanId, scanStatus: 'fixed' } }));
  deps.findings.replaceFixed(scanId, fixed);
  return { previousScanId: previous?.id ?? null, new: current.length - existing, existing, fixed: fixed.length };
}

/** Whether this scan really looked at where `f` was (see the header). */
function lookedAt(deps: ScanStatusDeps, scanId: string): (analyzer: string, f: Finding) => boolean {
  const indexed = new Map(deps.indexRepo.files(scanId, { includeSkipped: true }).map((x) => [x.path, x.skipReason === null]));
  const coverage = new Map<string, Map<string, CoverageStatus>>();
  for (const e of deps.coverage.list(scanId)) {
    (coverage.get(e.analyzer) ?? coverage.set(e.analyzer, new Map()).get(e.analyzer)!).set(e.path, e.status);
  }
  return (analyzer, f) => {
    if (REPO_LEVEL.has(f.category)) return true;
    const paths = [...new Set([f.location.file, ...(f.taintTrace ?? []).map((s) => s.file)])];
    const file = f.location.file;
    if (!indexed.has(file)) return true; // deleted (or history-only): gone from the code
    if (indexed.get(file) === false) return false; // indexed but skipped (size/limits): never analyzed
    const cov = coverage.get(analyzer);
    if (!cov) return true; // deterministic analyzer (no AI-review coverage): every indexed file is scanned
    return paths.some((p) => {
      const status = cov.get(p);
      return status !== undefined && COVERED.has(status);
    });
  };
}
