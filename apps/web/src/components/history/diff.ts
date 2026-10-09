import { matchFindings, type Finding } from '@vibesec/shared';

export type FindingDiff = {
  /** In head (B) but not in base (A). */
  added: Finding[];
  /** In base (A) but gone from head (B): fixed, or (same commit) not reproduced by B's AI review. */
  fixed: Finding[];
  /** Present in both; the head (B) copy. */
  unchanged: Finding[];
};

const byRisk = (a: Finding, b: Finding) => b.riskScore - a.riskScore || a.title.localeCompare(b.title);

/**
 * Diff two scans' current findings with the shared `matchFindings`: the same identity the API uses for
 * new/existing/fixed (exact fingerprint, plus re-worded AI findings at the same place), so the compare
 * view and a scan's own new/existing/fixed counts agree.
 */
export function diffFindings(base: Finding[], head: Finding[]): FindingDiff {
  const m = matchFindings(base, head, (f) => f);
  return {
    added: [...m.unmatchedHead].sort(byRisk),
    fixed: [...m.unmatchedBase].sort(byRisk),
    unchanged: head.filter((f) => m.pairs.has(f)).sort(byRisk),
  };
}
