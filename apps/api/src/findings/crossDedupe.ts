/**
 * Cross-analyzer dedupe (VERIFYING stage). Different analyzers often report the same bug: the SAST
 * deep pass flags `exec(cmd)`, the taint agent traces `req.query.cmd → exec(cmd)` to the same line.
 * Over ALL findings of a scan, two findings MATCH when they are in the same file, their line ranges
 * overlap (for a taint finding: ANY step of its trace may be the overlapping location), and they are
 * the same vulnerability family (equal CWE, or equal normalized last ruleId segment via ALIASES).
 * Two findings that BOTH carry a taint trace only match when their sinks overlap: two flows into
 * different sinks are two bugs even if they share a source line.
 *
 * Winner order: taint (carries a trace) > SAST deep > SAST fast > config/quality/others, then higher
 * severity, then higher confidence, then lowest FINGERPRINT (stable across scans — ids are per scan).
 * Clustering is greedy and direct, never transitive: findings are visited best-first; each one not yet
 * absorbed becomes a winner and absorbs every not-yet-absorbed finding that matches IT directly. So a
 * wide-range finding can be absorbed by one winner but never chains two unrelated findings together.
 * Losers are removed; the winner's `producedBy` becomes the union of the cluster, its explanation gets an
 * "Also reported by: …" note, and `mergedFingerprints` lists every loser's fingerprint (and theirs), so
 * new/existing/fixed and triage suppressions still recognize a finding when another analyzer wins.
 *
 * Never merged: secret and dependency findings (they have their own dedupe and are never "the same"
 * as a code finding), and different families on the same line (command-injection and missing-authn on
 * one route are two separate problems).
 */

import type { Category, Finding } from '@vibesec/shared';
import { SEVERITY_RANK } from './helpers';

export type ScanFindingRow = { analyzer: string; finding: Finding };
export type CrossDedupeResult = {
  /** Every surviving finding (winners already merged). */
  kept: Finding[];
  /** Winners whose producedBy/explanation changed (to persist). */
  changed: Finding[];
  removedIds: string[];
};

const MERGEABLE: ReadonlySet<Category> = new Set(['sast', 'taint', 'config', 'quality']);
const CONFIDENCE_RANK: Record<Finding['confidence'], number> = { high: 0, medium: 1, low: 2 };

/** Normalized rule tail aliases (taint rule ids are derived from the model's free-text flow names). */
const ALIASES: Readonly<Record<string, string>> = {
  sqli: 'sql-injection',
  'sql-i': 'sql-injection',
  nosqli: 'nosql-injection',
  'os-command-injection': 'command-injection',
  'shell-injection': 'command-injection',
  'cross-site-scripting': 'xss',
  'reflected-xss': 'xss',
  'stored-xss': 'xss',
  'directory-traversal': 'path-traversal',
  'server-side-request-forgery': 'ssrf',
  'unvalidated-redirect': 'open-redirect',
  'insecure-deserialization': 'unsafe-deserialization',
  deserialization: 'unsafe-deserialization',
  'eval-injection': 'code-injection',
  'missing-authentication': 'missing-authn',
  'missing-authorization': 'missing-authz',
};
/** Catch-all tails never establish a family on their own. */
const GENERIC_TAILS: ReadonlySet<string> = new Set(['other', 'tainted-flow', '']);

export function familyTail(ruleId: string): string {
  const tail = (ruleId.split('/').pop() ?? '').trim().toLowerCase().replace(/[_\s]+/g, '-');
  return ALIASES[tail] ?? tail;
}

/** A finding's family keys, computed once per finding (familyTail is called per pair otherwise). */
type Family = { cwe: string | null; tail: string };

function familyOf(f: Finding): Family {
  return { cwe: f.cwe ? f.cwe.trim().toUpperCase() : null, tail: familyTail(f.ruleId) };
}

function familiesMatch(a: Family, b: Family): boolean {
  if (a.cwe && b.cwe && a.cwe === b.cwe) return true;
  return !GENERIC_TAILS.has(a.tail) && a.tail === b.tail;
}

export function sameFamily(a: Finding, b: Finding): boolean {
  return familiesMatch(familyOf(a), familyOf(b));
}

function rangeOverlaps(a: Finding, b: Finding): boolean {
  return a.location.file === b.location.file
    && a.location.startLine <= b.location.endLine && b.location.startLine <= a.location.endLine;
}

/** A step of `t`'s taint trace lies inside `other`'s reported range. */
function traceTouches(t: Finding, other: Finding): boolean {
  return (t.taintTrace ?? []).some((s) => s.file === other.location.file
    && s.line >= other.location.startLine && s.line <= other.location.endLine);
}

export function sameLocation(a: Finding, b: Finding): boolean {
  return rangeOverlaps(a, b) || traceTouches(a, b) || traceTouches(b, a);
}

/** The flow's sink (last 'sink' step, else the last step), or null without a trace. */
function sinkOf(f: Finding): { file: string; line: number } | null {
  const trace = f.taintTrace ?? [];
  if (trace.length === 0) return null;
  const sinks = trace.filter((s) => s.kind === 'sink');
  const s = sinks[sinks.length - 1] ?? trace[trace.length - 1]!;
  return { file: s.file, line: s.line };
}

/** Two traced flows are one bug only when their sinks overlap (same line, or inside the other's range). */
function sinksCompatible(a: Finding, b: Finding): boolean {
  const sa = sinkOf(a);
  const sb = sinkOf(b);
  if (!sa || !sb) return true;
  if (sa.file !== sb.file) return false;
  const within = (s: { file: string; line: number }, f: Finding) => s.file === f.location.file && s.line >= f.location.startLine && s.line <= f.location.endLine;
  return sa.line === sb.line || within(sa, b) || within(sb, a);
}

function sourceRank(f: Finding): number {
  if (f.category === 'taint' || (f.taintTrace?.length ?? 0) > 0) return 0;
  if (f.category === 'sast') {
    const by = f.producedBy ?? [];
    if (by.includes('sast:llm') || by.length === 0) return 1;
    if (by.includes('sast:llm-fast')) return 2;
    return 1;
  }
  return 3;
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** < 0 when `a` should win over `b`. Deterministic across scans (fingerprint before the per-scan id). */
function compareWinner(a: Finding, b: Finding): number {
  return sourceRank(a) - sourceRank(b)
    || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    || CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence]
    || cmp(a.fingerprint, b.fingerprint)
    || cmp(a.id, b.id);
}

const ALSO_NOTE_RE = /\n\nAlso reported by: [^\n]*$/;

/** Files a finding can match in: its own location file plus every file its trace steps touch. */
function touchedFiles(f: Finding): Set<string> {
  return new Set([f.location.file, ...(f.taintTrace ?? []).map((s) => s.file)]);
}

export function crossDedupe(rows: readonly ScanFindingRow[]): CrossDedupeResult {
  const mergeable: number[] = [];
  const kept: Finding[] = [];
  rows.forEach((r, i) => {
    if (MERGEABLE.has(r.finding.category)) mergeable.push(i);
  });

  // Precomputed per finding: family keys, and a file → findings index (only same-file pairs can match).
  const families = new Map<number, Family>(mergeable.map((i) => [i, familyOf(rows[i]!.finding)]));
  const byFile = new Map<string, number[]>();
  for (const i of mergeable) {
    for (const file of touchedFiles(rows[i]!.finding)) (byFile.get(file) ?? byFile.set(file, []).get(file)!).push(i);
  }
  const matches = (i: number, j: number): boolean => {
    const a = rows[i]!.finding;
    const b = rows[j]!.finding;
    return familiesMatch(families.get(i)!, families.get(j)!) && sameLocation(a, b) && sinksCompatible(a, b);
  };

  const order = [...mergeable].sort((x, y) => compareWinner(rows[x]!.finding, rows[y]!.finding));
  const pos = new Map(order.map((i, k) => [i, k]));
  const absorbed = new Set<number>();
  const changed: Finding[] = [];
  const removedIds: string[] = [];
  const keptMergeable = new Map<number, Finding>();
  for (const w of order) {
    if (absorbed.has(w)) continue;
    absorbed.add(w);
    const candidates = new Set<number>();
    for (const file of touchedFiles(rows[w]!.finding)) for (const j of byFile.get(file) ?? []) candidates.add(j);
    const losers = [...candidates].filter((j) => !absorbed.has(j) && matches(w, j)).sort((x, y) => pos.get(x)! - pos.get(y)!).map((j) => {
      absorbed.add(j);
      return rows[j]!;
    });
    const winnerRow = rows[w]!;
    if (losers.length === 0) { keptMergeable.set(w, winnerRow.finding); continue; }

    const producedBy = [...new Set([
      ...(winnerRow.finding.producedBy ?? [winnerRow.analyzer]),
      ...losers.flatMap((l) => l.finding.producedBy ?? [l.analyzer]),
    ])];
    const mergedFingerprints = [...new Set([
      ...(winnerRow.finding.mergedFingerprints ?? []),
      ...losers.flatMap((l) => [l.finding.fingerprint, ...(l.finding.mergedFingerprints ?? [])]),
    ])].filter((fp) => fp !== winnerRow.finding.fingerprint);
    const note = `Also reported by: ${losers.map((l) => `${l.analyzer} (${l.finding.ruleId} at ${l.finding.location.file}:${l.finding.location.startLine})`).join('; ')}.`;
    const winner: Finding = {
      ...winnerRow.finding,
      producedBy,
      mergedFingerprints,
      explanation: `${winnerRow.finding.explanation.replace(ALSO_NOTE_RE, '')}\n\n${note}`,
    };
    keptMergeable.set(w, winner);
    changed.push(winner);
    removedIds.push(...losers.map((l) => l.finding.id));
  }

  // Input order is preserved for the kept findings.
  rows.forEach((r, i) => {
    if (!MERGEABLE.has(r.finding.category)) kept.push(r.finding);
    else if (keptMergeable.has(i)) kept.push(keptMergeable.get(i)!);
  });
  return { kept, changed, removedIds };
}
