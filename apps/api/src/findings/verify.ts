/**
 * Finding verification (P6): a Claude analyzer reports a `RawCodeIssue` at a file/line it *claims*
 * to have seen. Before that issue becomes a `Finding`, we re-read the real file and confirm the
 * reported snippet actually lives there — the model can mis-count lines, work off a stale copy, or
 * (worst case) be steered by a prompt-injected comment into reporting something that was never in
 * the file. We never trust the reported location blindly:
 *
 *   - exact-ish match at the reported lines (±2 slack for off-by-a-few line counting) → verified
 *   - match found elsewhere in the file (same line count) → relocated (location corrected)
 *   - no match anywhere → dropped (likely hallucination or prompt injection)
 *
 * `verifyTrace` applies the same logic to every step of a taint trace, against each step's own
 * file; losing the source or sink step invalidates the whole trace (and therefore the issue).
 *
 * `dedupeIssues` then collapses issues that multiple analyzers independently found at the same
 * location into one, preferring the richer (taint) report and recording who else flagged it.
 */

import type { RawCodeIssue, TraceStep } from '../analyzers/code/types';
import { SEVERITY_RANK } from './helpers';

export type VerifyOutcome =
  | { status: 'verified'; issue: RawCodeIssue }
  | { status: 'relocated'; issue: RawCodeIssue; from: { startLine: number; endLine: number } }
  | { status: 'dropped'; reason: string };

export type TraceVerifyResult = { ok: true; trace: TraceStep[] } | { ok: false; reason: string };

export type DedupedIssue = RawCodeIssue & { analyzer: string; alsoReportedBy?: string[] };

const SIMILARITY_THRESHOLD = 0.8;
const SLACK_LINES = 2;
const MAX_WINDOW_LINES = 20;
const MAX_SEARCH_FILE_BYTES = 1024 * 1024; // 1 MiB
const MAX_SNIPPET_LINE_CHARS = 300;
const MAX_SNIPPET_LINES = 10;
const HALLUCINATION_REASON = 'snippet not found — possible hallucination or prompt injection';

// --- similarity ----------------------------------------------------------------------------

/** Strips a leading "12: " / "12| " line-number prefix the model may have copied from a numbered listing. */
const LINE_NUMBER_PREFIX_RE = /^\s*\d+\s*[:|]\s?/;

function normalizeLine(line: string): string {
  return line.replace(LINE_NUMBER_PREFIX_RE, '').trim().replace(/[ \t]+/g, ' ');
}

function normalizeSnippet(s: string): string {
  return s.split(/\r\n|\r|\n/).map(normalizeLine).join('\n').trim();
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  let curr = new Array<number>(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= b.length; j++) {
      const cost = ca === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length]!;
}

function charSimilarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - levenshtein(a, b) / maxLen;
}

function tokenize(s: string): string[] {
  return s.split(/\s+/).filter((t) => t.length > 0);
}

function tokenSimilarity(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  if (ta.length === 0 && tb.length === 0) return 1;
  if (ta.length === 0 || tb.length === 0) return 0;
  const countA = new Map<string, number>();
  for (const t of ta) countA.set(t, (countA.get(t) ?? 0) + 1);
  let intersect = 0;
  for (const t of tb) {
    const remaining = countA.get(t) ?? 0;
    if (remaining > 0) {
      intersect++;
      countA.set(t, remaining - 1);
    }
  }
  const union = ta.length + tb.length - intersect;
  return union === 0 ? 1 : intersect / union;
}

/**
 * Normalized similarity of two code snippets, 0..1. Normalization trims each line, collapses
 * internal whitespace runs, and strips a copied-over "12: " / "12|" line-number prefix. Combines a
 * character-level (Levenshtein) ratio with a token-level (multiset Jaccard) ratio and takes the
 * higher of the two, so re-wrapped whitespace or reordered tokens don't tank an otherwise-identical
 * match, while still rewarding exact character matches most of the time.
 */
export function similarity(a: string, b: string): number {
  const na = normalizeSnippet(a);
  const nb = normalizeSnippet(b);
  if (na === nb) return 1;
  if (na.length === 0 || nb.length === 0) return 0;
  return Math.max(charSimilarity(na, nb), tokenSimilarity(na, nb));
}

// --- line/window helpers ---------------------------------------------------------------------

function toLines(fileText: string): string[] {
  const trimmed = fileText.endsWith('\n') ? fileText.slice(0, -1) : fileText;
  return trimmed.split(/\r\n|\r|\n/);
}

/** Raw (unclipped) text of lines [start, end] (1-indexed, inclusive); assumes a valid range. */
function windowText(lines: readonly string[], start: number, end: number): string {
  const out: string[] = [];
  for (let ln = start; ln <= end; ln++) out.push(lines[ln - 1] ?? '');
  return out.join('\n');
}

/** The real text to report back: at most MAX_SNIPPET_LINES lines, each clipped to MAX_SNIPPET_LINE_CHARS. */
function clipSnippet(lines: readonly string[], start: number, end: number): string {
  const cappedEnd = Math.min(end, start + MAX_SNIPPET_LINES - 1);
  const out: string[] = [];
  for (let ln = start; ln <= cappedEnd; ln++) {
    const text = lines[ln - 1] ?? '';
    out.push(text.length > MAX_SNIPPET_LINE_CHARS ? text.slice(0, MAX_SNIPPET_LINE_CHARS) : text);
  }
  return out.join('\n');
}

type LocateResult =
  | { status: 'verified'; start: number; end: number }
  | { status: 'relocated'; start: number; end: number }
  | { status: 'dropped' };

/**
 * Core location search shared by `verifyIssueLocation` (multi-line snippet) and `verifyTrace`
 * (single-line step): first try the reported range itself, allowing ±SLACK_LINES of drift: if
 * out of bounds, skip straight to the full-file search. Capped to files <= 1 MiB and search
 * windows <= 20 lines so a hostile/huge file can't make this quadratic-ish.
 */
function locateSnippet(
  snippet: string, reportedStart: number, reportedEnd: number, lines: readonly string[], fileText: string,
): LocateResult {
  const total = lines.length;
  const requestedCount = Math.max(1, reportedEnd - reportedStart + 1);
  const inBounds = reportedStart >= 1 && reportedEnd >= reportedStart && reportedEnd <= total;

  if (inBounds) {
    let best = -1;
    let bestStart = reportedStart;
    for (let offset = -SLACK_LINES; offset <= SLACK_LINES; offset++) {
      const s = reportedStart + offset;
      const e = reportedEnd + offset;
      if (s < 1 || e > total) continue;
      const sim = similarity(snippet, windowText(lines, s, e));
      if (sim > best) {
        best = sim;
        bestStart = s;
      }
    }
    if (best >= SIMILARITY_THRESHOLD) {
      return { status: 'verified', start: bestStart, end: bestStart + (reportedEnd - reportedStart) };
    }
  }

  if (Buffer.byteLength(fileText, 'utf8') > MAX_SEARCH_FILE_BYTES) return { status: 'dropped' };
  const windowSize = Math.min(requestedCount, MAX_WINDOW_LINES);
  if (windowSize > total) return { status: 'dropped' };

  let bestSim = -1;
  let bestStart = -1;
  for (let s = 1; s + windowSize - 1 <= total; s++) {
    const e = s + windowSize - 1;
    const sim = similarity(snippet, windowText(lines, s, e));
    if (sim > bestSim) {
      bestSim = sim;
      bestStart = s;
    }
  }
  if (bestStart !== -1 && bestSim >= SIMILARITY_THRESHOLD) {
    return { status: 'relocated', start: bestStart, end: bestStart + windowSize - 1 };
  }
  return { status: 'dropped' };
}

// --- issue verification ----------------------------------------------------------------------

/**
 * Re-checks `issue`'s reported location against the real file. `fileText` is `null` when the file
 * no longer exists (renamed/deleted since the model saw it) — always dropped. An empty snippet is
 * never trusted either (nothing to verify against).
 */
export function verifyIssueLocation(issue: RawCodeIssue, fileText: string | null): VerifyOutcome {
  if (fileText === null) return { status: 'dropped', reason: 'file not found' };
  if (issue.snippet.trim() === '') return { status: 'dropped', reason: 'empty snippet' };

  const lines = toLines(fileText);
  const result = locateSnippet(issue.snippet, issue.startLine, issue.endLine, lines, fileText);

  if (result.status === 'dropped') return { status: 'dropped', reason: HALLUCINATION_REASON };

  const verifiedIssue: RawCodeIssue = {
    ...issue,
    startLine: result.start,
    endLine: result.end,
    snippet: clipSnippet(lines, result.start, result.end),
  };

  if (result.status === 'verified') return { status: 'verified', issue: verifiedIssue };
  return { status: 'relocated', issue: verifiedIssue, from: { startLine: issue.startLine, endLine: issue.endLine } };
}

// --- trace verification ----------------------------------------------------------------------

/**
 * Verifies/relocates every step of a taint trace against its own file (via `readFile`, since a
 * trace can span multiple files). Steps that can't be confirmed anywhere are dropped from the
 * trace; if a dropped step was the `source` or `sink`, the trace (and therefore the issue it
 * supports) is no longer trustworthy, so the whole thing is rejected.
 */
export function verifyTrace(trace: readonly TraceStep[], readFile: (path: string) => string | null): TraceVerifyResult {
  const kept: TraceStep[] = [];
  let lostSourceOrSink = false;

  for (const step of trace) {
    const fileText = step.code.trim() === '' ? null : readFile(step.file);
    const lines = fileText === null ? null : toLines(fileText);
    const result = lines === null ? { status: 'dropped' as const }
      : locateSnippet(step.code, step.line, step.line, lines, fileText!);

    if (result.status === 'dropped') {
      if (step.kind === 'source' || step.kind === 'sink') lostSourceOrSink = true;
      continue;
    }
    kept.push({ ...step, line: result.start, code: clipSnippet(lines!, result.start, result.end) });
  }

  if (lostSourceOrSink) return { ok: false, reason: 'taint trace lost its source or sink step during verification' };
  return { ok: true, trace: kept };
}

// --- cross-analyzer dedupe --------------------------------------------------------------------

function isTaintIssue(issue: RawCodeIssue): boolean {
  return issue.ruleId.startsWith('taint/') || (issue.taintTrace !== undefined && issue.taintTrace.length > 0);
}

const CONFIDENCE_RANK: Record<RawCodeIssue['confidence'], number> = { high: 0, medium: 1, low: 2 };

function lastRuleSegment(ruleId: string): string {
  const segs = ruleId.split('/');
  return segs[segs.length - 1] ?? ruleId;
}

/** Same vulnerability family: both carry the same CWE, or (lacking that) the same ruleId tail
 *  ('sast/sql-injection' and 'taint/sql-injection' both end in 'sql-injection'). */
function sameFamily(a: RawCodeIssue, b: RawCodeIssue): boolean {
  if (a.cwe && b.cwe) return a.cwe === b.cwe;
  return lastRuleSegment(a.ruleId) === lastRuleSegment(b.ruleId);
}

function overlaps(a: RawCodeIssue, b: RawCodeIssue): boolean {
  return a.file === b.file && a.startLine <= b.endLine && b.startLine <= a.endLine;
}

/** -1 if `a` should be kept over `b`, 1 if `b` should be kept, 0 if tied (keep whichever is first). */
function compareIssues(a: RawCodeIssue, b: RawCodeIssue): number {
  const aTaint = isTaintIssue(a);
  const bTaint = isTaintIssue(b);
  if (aTaint !== bTaint) return aTaint ? -1 : 1;
  const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (sevDiff !== 0) return sevDiff;
  return CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
}

/**
 * Collapses issues that different analyzers raised for the same underlying vulnerability — same
 * file, overlapping line ranges, same CWE/rule family — into one. Keeps the taint report over a
 * plain SAST one (it carries the trace), then the higher severity, then the higher confidence;
 * every analyzer that also reported it is recorded in `alsoReportedBy` on the survivor.
 */
export function dedupeIssues(
  issues: readonly (RawCodeIssue & { analyzer: string })[],
): DedupedIssue[] {
  const n = issues.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => {
    let root = x;
    while (parent[root] !== root) root = parent[root]!;
    parent[x] = root;
    return root;
  };
  const union = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[ra] = rb;
  };

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const a = issues[i]!;
      const b = issues[j]!;
      if (overlaps(a, b) && sameFamily(a, b)) union(i, j);
    }
  }

  const clusters = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const root = find(i);
    const list = clusters.get(root);
    if (list) list.push(i);
    else clusters.set(root, [i]);
  }

  const result: DedupedIssue[] = [];
  for (const indices of clusters.values()) {
    const members = indices.map((i) => issues[i]!);
    let winner = members[0]!;
    for (const cur of members.slice(1)) {
      if (compareIssues(cur, winner) < 0) winner = cur;
    }
    const alsoReportedBy = Array.from(new Set(members.filter((m) => m !== winner).map((m) => m.analyzer)));
    const out: DedupedIssue = { ...winner };
    if (alsoReportedBy.length > 0) out.alsoReportedBy = alsoReportedBy;
    result.push(out);
  }
  return result;
}
