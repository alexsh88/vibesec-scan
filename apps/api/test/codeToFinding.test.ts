import { describe, expect, it } from 'vitest';
import { FindingSchema } from '@vibesec/shared';
import { issueToFinding } from '../src/analyzers/code/toFinding';
import type { RawCodeIssue } from '../src/analyzers/code/types';

const ctx = { scanId: 'scan-1', repo: { owner: 'acme', name: 'app' }, commitSha: 'c'.repeat(40) };
const URL_LINE = "const FALLBACK = 'postgres://admin:N0tAR3alPassw0rd@db.internal:5432/app';";

function issue(over: Partial<RawCodeIssue> = {}): RawCodeIssue {
  return {
    ruleId: 'sast/hardcoded-credential', title: 'Hardcoded DB URL', severity: 'high', confidence: 'medium',
    file: 'src/db.ts', startLine: 3, endLine: 3, snippet: URL_LINE, explanation: 'x', impact: 'y', remediation: 'z', ...over,
  };
}

describe('issueToFinding', () => {
  it('builds a schema-valid finding', () => {
    expect(() => FindingSchema.parse(issueToFinding(ctx, 'sast', issue({ snippet: 'eval(code);' }), ['sast:llm']))).not.toThrow();
  });

  it('masks credentials the regex rules recognize in the snippet and in taint-trace code', () => {
    const f = issueToFinding(ctx, 'taint', issue({
      taintTrace: [
        { kind: 'source', file: 'src/a.ts', line: 1, code: 'const id = req.query.id;', note: 'n' },
        { kind: 'sink', file: 'src/db.ts', line: 3, code: URL_LINE, note: 'n' },
      ],
    }), ['taint:agent']);
    const json = JSON.stringify(f);
    expect(json).not.toContain('N0tAR3alPassw0rd');
    expect(f.location.snippet).toContain('postgres://');
    expect(f.taintTrace![0]!.code).toBe('const id = req.query.id;');
  });
});
