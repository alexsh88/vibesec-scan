import type { Category } from './enums';
import type { Finding } from './finding';

/**
 * Lines a re-reported issue may drift between runs and still count as the same issue (a model may
 * quote line 11 instead of line 10 for the same statement).
 */
export const SAME_ISSUE_LINE_SLACK = 3;
/** Minimum title similarity (0..1, token Jaccard) for two re-named rule ids to be the same issue. */
export const SAME_ISSUE_TITLE_SIMILARITY = 0.6;
/** Minimum word overlap of two rule-id tails for a re-named rule (with a matching title) to count. */
export const SAME_ISSUE_RULE_SIMILARITY = 0.5;
/** With a generic rule id, the title alone must be this close to count as the same issue. */
export const SAME_ISSUE_GENERIC_TITLE_SIMILARITY = 0.8;

/**
 * Categories whose rule id, title and snippet are written by a model and can be worded differently on
 * every run, so an exact fingerprint isn't stable for them. Credentials and dependencies come from
 * deterministic rules and keep exact matching only.
 */
const AI_WRITTEN: ReadonlySet<Category> = new Set<Category>(['sast', 'taint', 'config', 'quality']);
/** Rule-id tails too generic to identify an issue on their own. */
const GENERIC_TAILS: ReadonlySet<string> = new Set(['', 'other', 'tainted-flow']);

/** A finding's identity keys: its fingerprint plus those of findings cross-analyzer dedupe merged into it. */
export function findingKeys(f: Pick<Finding, 'fingerprint' | 'mergedFingerprints'>): string[] {
  return [f.fingerprint, ...(f.mergedFingerprints ?? [])];
}

const ruleTail = (ruleId: string): string => (ruleId.split('/').pop() ?? '').trim().toLowerCase().replace(/[_\s]+/g, '-');

const words = (s: string): Set<string> => new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 1));

/** Token Jaccard similarity of two titles (1 = same words, order-insensitive). */
export function titleSimilarity(a: string, b: string): number {
  const wa = words(a);
  const wb = words(b);
  if (wa.size === 0 || wb.size === 0) return 0;
  let shared = 0;
  for (const w of wa) if (wb.has(w)) shared++;
  return shared / (wa.size + wb.size - shared);
}

/** Word overlap of two rule-id tails, so `supabase-table-rls-disabled` ~ `supabase-table-without-rls`. */
const tailSimilarity = (a: string, b: string): number => titleSimilarity(a.replace(/-/g, ' '), b.replace(/-/g, ' '));

/**
 * Whether two AI-written findings with different fingerprints describe the same issue. Requires the same
 * category and file and line ranges within SAME_ISSUE_LINE_SLACK, and then agreement on the KIND of issue:
 * - different CWE ids: never the same issue;
 * - the same specific rule family (rule-id tail): the same issue (e.g. line 10 vs line 11);
 * - rule ids sharing most of their words AND near-identical titles: the same issue re-named;
 * - only when a rule id is generic ('other'…) can a near-identical title alone decide.
 * Titles never override clearly different rule families: a fixed path traversal and a new command
 * injection at the same spot share most title words but must stay "fixed" + "new".
 * Always false for deterministic categories.
 */
export function isSameIssue(a: Finding, b: Finding): boolean {
  if (a.category !== b.category || !AI_WRITTEN.has(a.category)) return false;
  if (a.location.file !== b.location.file) return false;
  const near = a.location.startLine <= b.location.endLine + SAME_ISSUE_LINE_SLACK
    && b.location.startLine <= a.location.endLine + SAME_ISSUE_LINE_SLACK;
  if (!near) return false;
  if (a.cwe && b.cwe && a.cwe.trim().toUpperCase() !== b.cwe.trim().toUpperCase()) return false;
  const ta = ruleTail(a.ruleId);
  const tb = ruleTail(b.ruleId);
  const titles = titleSimilarity(a.title, b.title);
  if (GENERIC_TAILS.has(ta) || GENERIC_TAILS.has(tb)) return titles >= SAME_ISSUE_GENERIC_TITLE_SIMILARITY;
  if (ta === tb) return true;
  return tailSimilarity(ta, tb) >= SAME_ISSUE_RULE_SIMILARITY && titles >= SAME_ISSUE_TITLE_SIMILARITY;
}

export type FindingMatch<B, H> = {
  /** head item → the base item it continues. */
  pairs: Map<H, B>;
  /** Base items with no counterpart in head. */
  unmatchedBase: B[];
  /** Head items with no counterpart in base. */
  unmatchedHead: H[];
};

/**
 * Pairs the findings of two scans: first by exact identity keys, then, one-to-one among what is left,
 * by `isSameIssue`, closest line distance first. `get` extracts the Finding from each item, so callers can
 * match their own row types. The single definition of "the same finding" across scans: the API's
 * new/existing/fixed and the UI's scan comparison both use it.
 */
export function matchFindings<B, H>(base: readonly B[], head: readonly H[], get: (x: B | H) => Finding): FindingMatch<B, H> {
  const pairs = new Map<H, B>();
  const usedBase = new Set<B>();
  const baseByKey = new Map<string, B>();
  for (const b of base) for (const k of findingKeys(get(b))) if (!baseByKey.has(k)) baseByKey.set(k, b);

  const rest: H[] = [];
  for (const h of head) {
    // Exact identity may be shared (several head findings can carry one base key), as before.
    const match = findingKeys(get(h)).map((k) => baseByKey.get(k)).find((b) => b !== undefined);
    if (match !== undefined) {
      pairs.set(h, match);
      usedBase.add(match);
    } else {
      rest.push(h);
    }
  }

  const candidates: Array<{ h: H; b: B; distance: number }> = [];
  for (const h of rest) {
    const fh = get(h);
    for (const b of base) {
      if (usedBase.has(b)) continue;
      const fb = get(b);
      if (isSameIssue(fh, fb)) candidates.push({ h, b, distance: Math.abs(fh.location.startLine - fb.location.startLine) });
    }
  }
  candidates.sort((x, y) => x.distance - y.distance);
  for (const { h, b } of candidates) {
    if (pairs.has(h) || usedBase.has(b)) continue;
    pairs.set(h, b);
    usedBase.add(b);
  }

  return { pairs, unmatchedBase: base.filter((b) => !usedBase.has(b)), unmatchedHead: head.filter((h) => !pairs.has(h)) };
}
