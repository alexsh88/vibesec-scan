/**
 * Cross-analyzer dedupe (VERIFYING stage). Different analyzers often report the same bug: the SAST
 * deep pass flags `exec(cmd)`, the taint agent traces `req.query.cmd → exec(cmd)` to the same line.
 * Over ALL findings of a scan, findings are merged when they are in the same file, their line ranges
 * overlap (for a taint finding: ANY step of its trace may be the overlapping location), and they are
 * the same vulnerability family (equal CWE, or equal normalized last ruleId segment via ALIASES).
 *
 * Winner: taint (carries a trace) > SAST deep > SAST fast > config/quality/others, then higher
 * severity, then higher confidence, then lowest id (stable). Losers are removed; the winner's
 * `producedBy` becomes the union of the cluster and its explanation gets an "Also reported by: …" note.
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

export function sameFamily(a: Finding, b: Finding): boolean {
  if (a.cwe && b.cwe && a.cwe.trim().toUpperCase() === b.cwe.trim().toUpperCase()) return true;
  const ta = familyTail(a.ruleId);
  return !GENERIC_TAILS.has(ta) && ta === familyTail(b.ruleId);
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

/** < 0 when `a` should win over `b`. */
function compareWinner(a: Finding, b: Finding): number {
  return sourceRank(a) - sourceRank(b)
    || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    || CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence]
    || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

const ALSO_NOTE_RE = /\n\nAlso reported by: [^\n]*$/;

export function crossDedupe(rows: readonly ScanFindingRow[]): CrossDedupeResult {
  const n = rows.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => {
    let r = x;
    while (parent[r] !== r) r = parent[r]!;
    parent[x] = r;
    return r;
  };
  for (let i = 0; i < n; i++) {
    const a = rows[i]!.finding;
    if (!MERGEABLE.has(a.category)) continue;
    for (let j = i + 1; j < n; j++) {
      const b = rows[j]!.finding;
      if (!MERGEABLE.has(b.category)) continue;
      if (sameLocation(a, b) && sameFamily(a, b)) {
        const ra = find(i);
        const rb = find(j);
        if (ra !== rb) parent[ra] = rb;
      }
    }
  }

  const clusters = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const root = find(i);
    const list = clusters.get(root);
    if (list) list.push(i);
    else clusters.set(root, [i]);
  }

  const kept: Finding[] = [];
  const changed: Finding[] = [];
  const removedIds: string[] = [];
  for (const indices of clusters.values()) {
    const members = indices.map((i) => rows[i]!);
    if (members.length === 1) { kept.push(members[0]!.finding); continue; }
    const sorted = [...members].sort((x, y) => compareWinner(x.finding, y.finding));
    const winnerRow = sorted[0]!;
    const losers = sorted.slice(1);
    const producedBy = [...new Set([
      ...(winnerRow.finding.producedBy ?? [winnerRow.analyzer]),
      ...losers.flatMap((l) => l.finding.producedBy ?? [l.analyzer]),
    ])];
    const note = `Also reported by: ${losers.map((l) => `${l.analyzer} (${l.finding.ruleId} at ${l.finding.location.file}:${l.finding.location.startLine})`).join('; ')}.`;
    const winner: Finding = {
      ...winnerRow.finding,
      producedBy,
      explanation: `${winnerRow.finding.explanation.replace(ALSO_NOTE_RE, '')}\n\n${note}`,
    };
    kept.push(winner);
    changed.push(winner);
    removedIds.push(...losers.map((l) => l.finding.id));
  }
  return { kept, changed, removedIds };
}
