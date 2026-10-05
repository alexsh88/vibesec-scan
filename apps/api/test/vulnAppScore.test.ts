import { describe, expect, it } from 'vitest';
import { loadExpected, scoreFindings, type Expected, type ScoredFinding } from '../scripts/vulnAppScore';

function finding(file: string, line: number, ruleId: string, category: string, cwe?: string, endLine = line): ScoredFinding {
  return {
    ruleId, category, ...(cwe ? { cwe } : {}), producedBy: ['test'], analyzer: category,
    location: { file, startLine: line, endLine },
  } as unknown as ScoredFinding;
}

const EXPECTED: Expected = {
  version: 1,
  issues: [
    {
      id: 'V1', category: 'secret', cwe: 'CWE-200', ruleHint: 'client-exposed-credential', alsoAccept: ['supabase-service-role-in-client'],
      file: 'web/admin.ts', line: 5, lineContains: 'x', lineTolerance: 2, severityAtLeast: 'critical', description: 'd',
    },
  ],
  safe: [
    { file: 'api/redirect.ts', line: 12, lineContains: 'x', description: 'd', concern: { ruleHints: ['open-redirect'], cwes: ['CWE-601'] } },
    { file: 'api/files.ts', line: 19, lineContains: 'x', description: 'd', concern: { ruleHints: ['path-traversal'], cwes: ['CWE-22'] } },
  ],
};

describe('scoreFindings — concern-aware false positives', () => {
  it('counts only same-concern findings on a safe line as false positives; lists the others separately', () => {
    const report = scoreFindings([
      finding('api/redirect.ts', 10, 'sast/open-redirect', 'sast', 'CWE-601', 12), // same concern (rule + CWE)
      finding('api/redirect.ts', 12, 'quality/null-dereference', 'quality'), // other finding on the safe line
      finding('api/files.ts', 9, 'vibesec/missing-authn', 'sast', 'CWE-306', 20), // other concern covering the line
      finding('api/files.ts', 19, 'sast/other', 'sast', 'CWE-22'), // same concern by CWE only
    ], EXPECTED);
    expect(report.falsePositives.map((fp) => [fp.safe.file, fp.findings.map((f) => f.ruleId)])).toEqual([
      ['api/redirect.ts', ['sast/open-redirect']],
      ['api/files.ts', ['sast/other']],
    ]);
    expect(report.otherFindingsOnSafeLines.map((fp) => [fp.safe.file, fp.findings.map((f) => f.ruleId)])).toEqual([
      ['api/redirect.ts', ['quality/null-dereference']],
      ['api/files.ts', ['vibesec/missing-authn']],
    ]);
  });

  it('accepts an issue matched by one of its alsoAccept rule hints', () => {
    const report = scoreFindings([finding('web/admin.ts', 3, 'vibesec/supabase-service-role-in-client', 'sast', 'CWE-284')], EXPECTED);
    expect(report.verdicts[0]!.found).toBe(true);
  });

  it('still requires compatibility: an unrelated finding near the issue line does not count', () => {
    const report = scoreFindings([finding('web/admin.ts', 5, 'quality/dead-code', 'quality')], EXPECTED);
    expect(report.verdicts[0]!.found).toBe(false);
  });

  it('every safe look-alike in the real fixture declares a concern', () => {
    for (const s of loadExpected().safe) {
      expect(s.concern.ruleHints.length + s.concern.cwes.length, `${s.file}:${s.line}`).toBeGreaterThan(0);
    }
  });
});
