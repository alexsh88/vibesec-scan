// new / existing / fixed (spec §11), computed at the end of SCORING by comparing fingerprints with the
// previous completed scan of the same repo (any options or commit, requested no later than this one):
//   present in both  → 'existing'
//   only in this one → 'new'
//   only in the previous one → copied into THIS scan as a `fixed` row (severity unchanged). Fixed rows are
//     left out of FindingRepo.all/list/counts by default (so of the grade, synthesis and exports too);
//     GET /api/scans/:id/findings?scanStatus=fixed lists them.
// A previous finding only counts as fixed when this scan could have found it again: its category is
// enabled here and the analyzer that produced it completed in this scan (a failed analyzer must not
// "fix" everything it found last time). A file the budget skipped this time can still read as fixed —
// the BUDGET_COVERAGE_PARTIAL warning says the coverage is partial.
// Idempotent: statuses are recomputed and the fixed rows replaced on every run.

import type { Finding } from '@vibesec/shared';
import type { FindingRepo, FindingRow } from '../../db/findingRepo';
import type { ScanRepo } from '../../db/scanRepo';
import { copiedFindingId } from './fullCache';

export type ScanStatusDeps = {
  scans: Pick<ScanRepo, 'getRow' | 'getDto' | 'findPreviousCompleted'>;
  findings: Pick<FindingRepo, 'all' | 'update' | 'replaceFixed' | 'analyzersWithResults'>;
};

export type ScanStatusCounts = { previousScanId: string | null; new: number; existing: number; fixed: number };

export function applyScanStatus(deps: ScanStatusDeps, scanId: string): ScanStatusCounts {
  const row = deps.scans.getRow(scanId);
  const categories = new Set(deps.scans.getDto(scanId)?.options.categories ?? []);
  if (!row) return { previousScanId: null, new: 0, existing: 0, fixed: 0 };
  const previous = deps.scans.findPreviousCompleted(row.repo_id, scanId);
  const previousRows = previous ? deps.findings.all(previous.id) : [];
  const previousFps = new Set(previousRows.map((r) => r.finding.fingerprint));

  const current = deps.findings.all(scanId);
  const changed: Finding[] = [];
  let existing = 0;
  for (const { finding } of current) {
    const status = previousFps.has(finding.fingerprint) ? 'existing' : 'new';
    if (status === 'existing') existing++;
    if (finding.scanStatus !== status) changed.push({ ...finding, scanStatus: status });
  }
  if (changed.length > 0) deps.findings.update(scanId, changed);

  const currentFps = new Set(current.map((r) => r.finding.fingerprint));
  const ran = deps.findings.analyzersWithResults(scanId);
  const fixed: FindingRow[] = previousRows
    .filter((r) => !currentFps.has(r.finding.fingerprint) && categories.has(r.finding.category) && ran.has(r.analyzer))
    .map((r) => ({ analyzer: r.analyzer, finding: { ...r.finding, id: copiedFindingId(scanId, r.finding.id), scanId, scanStatus: 'fixed' } }));
  deps.findings.replaceFixed(scanId, fixed);
  return { previousScanId: previous?.id ?? null, new: current.length - existing, existing, fixed: fixed.length };
}
