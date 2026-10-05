import type { Finding } from '@vibesec/shared';

export type FindingDiff = {
  /** In head (B) but not in base (A). */
  added: Finding[];
  /** In base (A) but gone from head (B). */
  fixed: Finding[];
  /** Present in both; the head (B) copy. */
  unchanged: Finding[];
};

/** A finding's identity keys: its fingerprint plus any fingerprints cross-analyzer dedupe merged into it. */
const keysOf = (f: Finding): string[] => [f.fingerprint, ...(f.mergedFingerprints ?? [])];

const byRisk = (a: Finding, b: Finding) => b.riskScore - a.riskScore || a.title.localeCompare(b.title);

/**
 * Diff two scans' current findings by fingerprint — the same identity the API uses for
 * new/existing/fixed, so two scans of the same repo line up even when the analyzer that "won" a
 * dedupe merge differs.
 */
export function diffFindings(base: Finding[], head: Finding[]): FindingDiff {
  const baseByKey = new Map<string, Finding>();
  for (const f of base) for (const k of keysOf(f)) if (!baseByKey.has(k)) baseByKey.set(k, f);

  const matchedBase = new Set<Finding>();
  const added: Finding[] = [];
  const unchanged: Finding[] = [];
  for (const f of head) {
    let match: Finding | undefined;
    for (const k of keysOf(f)) {
      const m = baseByKey.get(k);
      if (m) {
        match = m;
        break;
      }
    }
    if (match) {
      matchedBase.add(match);
      unchanged.push(f);
    } else {
      added.push(f);
    }
  }
  const fixed = base.filter((f) => !matchedBase.has(f));
  return { added: added.sort(byRisk), fixed: fixed.sort(byRisk), unchanged: unchanged.sort(byRisk) };
}
