import type { Category, Finding } from '@vibesec/shared';
import { fingerprint, githubPermalink, provisionalScore } from '../../findings/helpers';
import type { AnalyzerContext } from '../types';
import type { RawCodeIssue } from './types';

const MAX_SNIPPET_CHARS = 2_000;

/** Whitespace-insensitive snippet identity, so reformatting doesn't change a finding's fingerprint. */
function normalizeSnippet(snippet: string): string {
  return snippet.replace(/\s+/g, ' ').trim();
}

/**
 * Converts a VERIFIED raw issue (see findings/verify.ts) into a shared Finding.
 * Scoring is provisional until P7's risk scoring replaces it.
 */
export function issueToFinding(
  ctx: Pick<AnalyzerContext, 'scanId' | 'repo' | 'commitSha'>,
  category: Category,
  issue: RawCodeIssue,
  producedBy: string[],
): Finding {
  const fp = fingerprint([issue.ruleId, issue.file, normalizeSnippet(issue.snippet)]);
  const finding: Finding = {
    id: fingerprint([ctx.scanId, fp]).slice(0, 32),
    scanId: ctx.scanId,
    fingerprint: fp,
    category,
    ruleId: issue.ruleId,
    title: issue.title,
    baseSeverity: issue.severity,
    riskScore: provisionalScore(issue.severity),
    severity: issue.severity,
    riskFactors: [],
    confidence: issue.confidence,
    location: {
      file: issue.file,
      startLine: issue.startLine,
      endLine: Math.max(issue.startLine, issue.endLine),
      snippet: issue.snippet.slice(0, MAX_SNIPPET_CHARS),
      permalink: githubPermalink(ctx.repo, ctx.commitSha, issue.file, issue.startLine, Math.max(issue.startLine, issue.endLine)),
    },
    explanation: issue.explanation,
    impact: issue.impact,
    remediation: issue.patch ? { summary: issue.remediation, patch: issue.patch } : { summary: issue.remediation },
    scanStatus: 'new',
    producedBy,
  };
  if (issue.cwe) finding.cwe = issue.cwe;
  if (issue.taintTrace?.length) finding.taintTrace = issue.taintTrace;
  return finding;
}
