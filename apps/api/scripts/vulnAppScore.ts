// Scores a scan's findings against fixtures/vuln-app/expected.json (pure; used by the eval script and
// the e2e test).
//
// An expected issue is FOUND when some finding is in the same file, its line range lies within
// `lineTolerance` of the expected line, and it is compatible: same category, or same CWE, or the
// expected `ruleHint` (or one of its `alsoAccept` hints) matches the finding's ruleId (kebab-normalized,
// either contains the other).
// A safe look-alike is a FALSE POSITIVE only when a finding of the SAME CONCERN covers its line — same
// CWE family or matching rule hint (the look-alike's `concern`). Any other finding covering a safe line
// (e.g. missing-authn on the route a safe path-join sits in) is reported separately as "other findings on
// safe lines", for review: it may be legitimate and is not what the look-alike tests.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Category, Finding } from '@vibesec/shared';
import { VULN_APP_ROOT } from './vulnApp';

export type ExpectedIssue = {
  id: string; category: Category; cwe?: string; ruleHint: string; alsoAccept?: string[]; file: string; line: number;
  lineContains: string; lineTolerance: number; severityAtLeast: string; description: string;
};
/** The vulnerability family a safe look-alike resembles. */
export type SafeConcern = { ruleHints: string[]; cwes: string[] };
export type SafeEntry = { file: string; line: number; lineContains: string; description: string; concern: SafeConcern };
export type SafeLineFindings = { safe: SafeEntry; findings: Array<{ ruleId: string; category: Category; line: number }> };
export type Expected = { version: 1; issues: ExpectedIssue[]; safe: SafeEntry[] };

export type IssueVerdict = {
  issue: ExpectedIssue;
  found: boolean;
  /** Matching findings' analyzers (producedBy) and rule ids. */
  matchedBy: Array<{ analyzer: string; ruleId: string; category: Category; producedBy: string[]; line: number }>;
};

export type ScoreReport = {
  verdicts: IssueVerdict[];
  recall: number;
  recallByCategory: Record<string, { found: number; total: number; recall: number }>;
  /** Same-concern findings on safe look-alike lines — the meaningful false-positive count. */
  falsePositives: SafeLineFindings[];
  /** Any other findings covering a safe line (different concern), listed for review. */
  otherFindingsOnSafeLines: SafeLineFindings[];
  totalFindings: number;
};

export function loadExpected(root = VULN_APP_ROOT): Expected {
  return JSON.parse(readFileSync(join(root, 'expected.json'), 'utf8')) as Expected;
}

const kebab = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

function ruleHintMatches(hint: string, ruleId: string): boolean {
  const h = kebab(hint);
  const tail = kebab(ruleId.split('/').pop() ?? ruleId);
  return h.length > 0 && tail.length > 0 && (tail.includes(h) || h.includes(tail));
}

function nearLine(f: Finding, line: number, tolerance: number): boolean {
  return f.location.startLine - tolerance <= line && line <= f.location.endLine + tolerance;
}

/** Taint findings are code findings with a proven trace: VERIFYING's dedupe keeps them in place of SAST. */
const CODE_CATEGORIES: ReadonlySet<Category> = new Set(['sast', 'taint']);

export function compatible(issue: ExpectedIssue, f: Finding): boolean {
  const sameFamily = f.category === issue.category || (CODE_CATEGORIES.has(f.category) && CODE_CATEGORIES.has(issue.category));
  return sameFamily || (issue.cwe !== undefined && f.cwe === issue.cwe)
    || [issue.ruleHint, ...(issue.alsoAccept ?? [])].some((h) => ruleHintMatches(h, f.ruleId));
}

/** Does finding `f` raise the concern a safe look-alike is there to test? */
export function sameConcern(concern: SafeConcern, f: Finding): boolean {
  return (f.cwe !== undefined && concern.cwes.includes(f.cwe)) || concern.ruleHints.some((h) => ruleHintMatches(h, f.ruleId));
}

/** A finding plus the analyzer that persisted it (findings.analyzer). */
export type ScoredFinding = Finding & { analyzer?: string };

export function scoreFindings(findings: readonly ScoredFinding[], expected: Expected): ScoreReport {
  const verdicts: IssueVerdict[] = expected.issues.map((issue) => {
    const matches = findings.filter((f) => f.location.file === issue.file && nearLine(f, issue.line, issue.lineTolerance) && compatible(issue, f));
    return {
      issue, found: matches.length > 0,
      matchedBy: matches.map((f) => ({ analyzer: f.analyzer ?? '?', ruleId: f.ruleId, category: f.category, producedBy: f.producedBy ?? [], line: f.location.startLine })),
    };
  });
  const recallByCategory: ScoreReport['recallByCategory'] = {};
  for (const v of verdicts) {
    const c = (recallByCategory[v.issue.category] ??= { found: 0, total: 0, recall: 0 });
    c.total++;
    if (v.found) c.found++;
  }
  for (const c of Object.values(recallByCategory)) c.recall = c.total ? c.found / c.total : 0;
  const onSafeLine = (same: boolean): SafeLineFindings[] => expected.safe
    .map((safe) => ({
      safe,
      findings: findings
        .filter((f) => f.location.file === safe.file && nearLine(f, safe.line, 0) && sameConcern(safe.concern, f) === same)
        .map((f) => ({ ruleId: f.ruleId, category: f.category, line: f.location.startLine })),
    }))
    .filter((fp) => fp.findings.length > 0);
  const found = verdicts.filter((v) => v.found).length;
  return {
    verdicts, recall: verdicts.length ? found / verdicts.length : 0, recallByCategory,
    falsePositives: onSafeLine(true), otherFindingsOnSafeLines: onSafeLine(false), totalFindings: findings.length,
  };
}
