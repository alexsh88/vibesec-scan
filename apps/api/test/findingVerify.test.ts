import { describe, expect, it } from 'vitest';
import type { RawCodeIssue, TraceStep } from '../src/analyzers/code/types';
import { dedupeIssues, similarity, verifyIssueLocation, verifyTrace } from '../src/findings/verify';

function issue(overrides: Partial<RawCodeIssue> = {}): RawCodeIssue {
  return {
    ruleId: 'sast/sql-injection',
    title: 'SQL Injection',
    severity: 'high',
    confidence: 'high',
    file: 'src/db.ts',
    startLine: 1,
    endLine: 1,
    snippet: 'db.query(sql)',
    explanation: 'tainted input reaches db.query',
    impact: 'data exfiltration',
    remediation: 'use a parameterized query',
    ...overrides,
  };
}

const HALLUCINATION_REASON = 'snippet not found — possible hallucination or prompt injection';

describe('similarity', () => {
  it('is 1 for identical text', () => {
    expect(similarity('const x = 1;', 'const x = 1;')).toBe(1);
  });

  it('is 1 for two empty strings', () => {
    expect(similarity('', '')).toBe(1);
  });

  it('is 0 when one side is empty', () => {
    expect(similarity('abc', '')).toBe(0);
  });

  it('ignores surrounding whitespace and collapses internal runs', () => {
    expect(similarity('  const x   =   1;  ', 'const x = 1;')).toBe(1);
  });

  it('strips a copied line-number prefix like "12: " or "12|"', () => {
    expect(similarity('12: const x = 1;', 'const x = 1;')).toBe(1);
    expect(similarity('12|const x = 1;', 'const x = 1;')).toBe(1);
  });

  it('is low for unrelated text', () => {
    expect(similarity('const x = 1;', 'completely unrelated prose about cats and dogs')).toBeLessThan(0.5);
  });

  it('is high but not necessarily 1 for a near match', () => {
    const s = similarity('db.query(`SELECT * FROM users WHERE id = ${id}`)', 'db.query(`SELECT * FROM users WHERE id = ${userId}`)');
    expect(s).toBeGreaterThanOrEqual(0.8);
    expect(s).toBeLessThan(1);
  });
});

describe('verifyIssueLocation', () => {
  it('drops when the file no longer exists', () => {
    const outcome = verifyIssueLocation(issue(), null);
    expect(outcome).toEqual({ status: 'dropped', reason: 'file not found' });
  });

  it('drops an empty snippet without reading the file', () => {
    const outcome = verifyIssueLocation(issue({ snippet: '   ' }), 'anything\nat all');
    expect(outcome).toEqual({ status: 'dropped', reason: 'empty snippet' });
  });

  it('verifies an exact match at the reported line', () => {
    const file = ['const a = 1;', 'db.query(`SELECT * FROM users WHERE id = ${id}`);', 'const b = 2;'].join('\n');
    const outcome = verifyIssueLocation(
      issue({ startLine: 2, endLine: 2, snippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`);' }),
      file,
    );
    expect(outcome.status).toBe('verified');
    if (outcome.status === 'verified') {
      expect(outcome.issue.startLine).toBe(2);
      expect(outcome.issue.endLine).toBe(2);
      expect(outcome.issue.snippet).toBe('db.query(`SELECT * FROM users WHERE id = ${id}`);');
    }
  });

  it('verifies (not relocates) when the real content is within +/-2 lines of the reported line', () => {
    const file = ['const a = 1;', 'db.query(`SELECT * FROM users WHERE id = ${id}`);', 'const b = 2;'].join('\n');
    const outcome = verifyIssueLocation(
      issue({ startLine: 3, endLine: 3, snippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`);' }),
      file,
    );
    expect(outcome.status).toBe('verified');
    if (outcome.status === 'verified') {
      expect(outcome.issue.startLine).toBe(2);
      expect(outcome.issue.endLine).toBe(2);
    }
  });

  it('relocates when the reported range is out of bounds but the content exists elsewhere', () => {
    const file = ['line one', 'line two', 'line three', 'const target = findMe();', 'line five'].join('\n');
    const outcome = verifyIssueLocation(issue({ startLine: 50, endLine: 50, snippet: 'const target = findMe();' }), file);
    expect(outcome.status).toBe('relocated');
    if (outcome.status === 'relocated') {
      expect(outcome.issue.startLine).toBe(4);
      expect(outcome.issue.endLine).toBe(4);
      expect(outcome.from).toEqual({ startLine: 50, endLine: 50 });
      expect(outcome.issue.snippet).toBe('const target = findMe();');
    }
  });

  it('relocates when the reported line is in bounds but wrong, and the content is found far away', () => {
    const lines = Array.from({ length: 10 }, (_, i) => `const filler${i} = ${i};`);
    lines[8] = 'const target = findMe();';
    const file = lines.join('\n');
    const outcome = verifyIssueLocation(issue({ startLine: 1, endLine: 1, snippet: 'const target = findMe();' }), file);
    expect(outcome.status).toBe('relocated');
    if (outcome.status === 'relocated') {
      expect(outcome.issue.startLine).toBe(9);
      expect(outcome.from).toEqual({ startLine: 1, endLine: 1 });
    }
  });

  it('drops when the snippet cannot be found anywhere in the file', () => {
    const file = ['one', 'two', 'three', 'four', 'five'].join('\n');
    const outcome = verifyIssueLocation(issue({ startLine: 1, endLine: 1, snippet: 'this code was never in this file at all' }), file);
    expect(outcome).toEqual({ status: 'dropped', reason: HALLUCINATION_REASON });
  });

  it('drops rather than hangs when the requested window is far larger than the file', () => {
    const file = ['a', 'b', 'c'].join('\n');
    const outcome = verifyIssueLocation(issue({ startLine: 1, endLine: 100, snippet: 'a\nb\nc' }), file);
    expect(outcome.status).toBe('dropped');
  });

  it('caps the replaced snippet to <=10 lines and <=300 chars per line', () => {
    const lines = Array.from({ length: 15 }, (_, i) => `const line${i} = ${i};`);
    const longLineIndex = 2;
    lines[longLineIndex] = `const long = "${'x'.repeat(400)}";`;
    const file = lines.join('\n');
    const snippet = lines.join('\n');
    const outcome = verifyIssueLocation(issue({ startLine: 1, endLine: 15, snippet }), file);
    expect(outcome.status).toBe('verified');
    if (outcome.status === 'verified') {
      const outLines = outcome.issue.snippet.split('\n');
      expect(outLines.length).toBeLessThanOrEqual(10);
      for (const l of outLines) expect(l.length).toBeLessThanOrEqual(300);
    }
  });

  it('drops rather than relocates within a file larger than 1 MiB', () => {
    const paddingLine = 'x'.repeat(200);
    const padding = Array.from({ length: 6000 }, () => paddingLine);
    padding[3000] = 'const target = findMe();';
    const file = padding.join('\n');
    expect(Buffer.byteLength(file, 'utf8')).toBeGreaterThan(1024 * 1024);
    // reported location is out of bounds, so this can only succeed via the (size-capped) full-file search
    const outcome = verifyIssueLocation(issue({ startLine: 999999, endLine: 999999, snippet: 'const target = findMe();' }), file);
    expect(outcome.status).toBe('dropped');
  });
});

describe('verifyTrace', () => {
  const routeFile = ['import { db } from "./db";', 'export function handler(req) {', '  const id = req.query.id;', '  return db.query(id);', '}'].join('\n');
  const dbFile = ['export const db = {', '  query(sql) {', '    return pool.query(sql);', '  },', '};'].join('\n');

  function readFileFrom(files: Record<string, string>): (path: string) => string | null {
    return (path: string) => files[path] ?? null;
  }

  function trace(overrides: Partial<TraceStep> = {}): TraceStep {
    return { kind: 'propagator', file: 'routes.ts', line: 3, code: 'const id = req.query.id;', note: '', ...overrides };
  }

  it('keeps a fully verified trace as-is', () => {
    const steps: TraceStep[] = [
      trace({ kind: 'source', file: 'routes.ts', line: 3, code: 'const id = req.query.id;' }),
      trace({ kind: 'sink', file: 'db.ts', line: 3, code: 'return pool.query(sql);' }),
    ];
    const result = verifyTrace(steps, readFileFrom({ 'routes.ts': routeFile, 'db.ts': dbFile }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.trace).toHaveLength(2);
      expect(result.trace[0]?.line).toBe(3);
      expect(result.trace[1]?.line).toBe(3);
    }
  });

  it('relocates a step whose line is wrong but whose code is found elsewhere in the file (outside slack)', () => {
    const steps: TraceStep[] = [
      // routeFile line 5 is "}" — more than +/-2 lines from the reported line 1, so this can only
      // be found via the full-file search, not the +/-2 slack check.
      trace({ kind: 'source', file: 'routes.ts', line: 1, code: '}' }),
    ];
    const result = verifyTrace(steps, readFileFrom({ 'routes.ts': routeFile }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.trace[0]?.line).toBe(5);
  });

  it('drops the whole trace when the source step file is missing', () => {
    const steps: TraceStep[] = [
      trace({ kind: 'source', file: 'missing.ts', line: 1, code: 'const id = req.query.id;' }),
      trace({ kind: 'sink', file: 'db.ts', line: 3, code: 'return pool.query(sql);' }),
    ];
    const result = verifyTrace(steps, readFileFrom({ 'db.ts': dbFile }));
    expect(result.ok).toBe(false);
  });

  it('drops the whole trace when the sink step cannot be matched anywhere', () => {
    const steps: TraceStep[] = [
      trace({ kind: 'source', file: 'routes.ts', line: 3, code: 'const id = req.query.id;' }),
      trace({ kind: 'sink', file: 'db.ts', line: 3, code: 'this line does not exist in db.ts at all' }),
    ];
    const result = verifyTrace(steps, readFileFrom({ 'routes.ts': routeFile, 'db.ts': dbFile }));
    expect(result.ok).toBe(false);
  });

  it('drops only the unmatched propagator and keeps a valid source/sink', () => {
    const steps: TraceStep[] = [
      trace({ kind: 'source', file: 'routes.ts', line: 3, code: 'const id = req.query.id;' }),
      trace({ kind: 'propagator', file: 'routes.ts', line: 1, code: 'this propagator line is made up' }),
      trace({ kind: 'sink', file: 'db.ts', line: 3, code: 'return pool.query(sql);' }),
    ];
    const result = verifyTrace(steps, readFileFrom({ 'routes.ts': routeFile, 'db.ts': dbFile }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.trace).toHaveLength(2);
      expect(result.trace.map((s) => s.kind)).toEqual(['source', 'sink']);
    }
  });
});

describe('dedupeIssues', () => {
  it('keeps the taint report over an overlapping SAST one for the same CWE, and records alsoReportedBy', () => {
    const traceStep: TraceStep = { kind: 'source', file: 'a.ts', line: 10, code: 'x', note: '' };
    const sast = { ...issue({ ruleId: 'sast/sql-injection', cwe: 'CWE-89', severity: 'high', confidence: 'high', startLine: 10, endLine: 12, file: 'a.ts' }), analyzer: 'sast-scanner' };
    const taint = { ...issue({ ruleId: 'taint/sql-injection', cwe: 'CWE-89', severity: 'medium', confidence: 'medium', startLine: 11, endLine: 11, file: 'a.ts', taintTrace: [traceStep] }), analyzer: 'taint-agent' };
    const result = dedupeIssues([sast, taint]);
    expect(result).toHaveLength(1);
    expect(result[0]?.ruleId).toBe('taint/sql-injection');
    expect(result[0]?.alsoReportedBy).toEqual(['sast-scanner']);
  });

  it('recognizes a taint issue by its trace even without a taint/ prefixed ruleId', () => {
    const sast = { ...issue({ ruleId: 'sast/sql-injection', cwe: 'CWE-89', startLine: 1, endLine: 1, file: 'a.ts' }), analyzer: 'sast' };
    const tainted = {
      ...issue({ ruleId: 'vibesec/tainted-flow', cwe: 'CWE-89', startLine: 1, endLine: 1, file: 'a.ts', taintTrace: [{ kind: 'source', file: 'a.ts', line: 1, code: 'x', note: '' } as TraceStep] }),
      analyzer: 'flow-agent',
    };
    const result = dedupeIssues([sast, tainted]);
    expect(result).toHaveLength(1);
    expect(result[0]?.ruleId).toBe('vibesec/tainted-flow');
  });

  it('keeps the higher-severity issue when neither is a taint report', () => {
    const low = { ...issue({ ruleId: 'sast/sql-injection', severity: 'high', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-a' };
    const high = { ...issue({ ruleId: 'sast/sql-injection', severity: 'critical', startLine: 5, endLine: 6, file: 'a.ts' }), analyzer: 'scanner-b' };
    const result = dedupeIssues([low, high]);
    expect(result).toHaveLength(1);
    expect(result[0]?.severity).toBe('critical');
    expect(result[0]?.alsoReportedBy).toEqual(['scanner-a']);
  });

  it('breaks a severity tie by confidence', () => {
    const lowConf = { ...issue({ ruleId: 'sast/sql-injection', severity: 'high', confidence: 'low', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-a' };
    const highConf = { ...issue({ ruleId: 'sast/sql-injection', severity: 'high', confidence: 'high', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-b' };
    const result = dedupeIssues([lowConf, highConf]);
    expect(result).toHaveLength(1);
    expect(result[0]?.confidence).toBe('high');
  });

  it('does not merge issues in different files', () => {
    const a = { ...issue({ ruleId: 'sast/sql-injection', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-a' };
    const b = { ...issue({ ruleId: 'sast/sql-injection', startLine: 5, endLine: 5, file: 'b.ts' }), analyzer: 'scanner-b' };
    const result = dedupeIssues([a, b]);
    expect(result).toHaveLength(2);
  });

  it('does not merge non-overlapping ranges in the same file', () => {
    const a = { ...issue({ ruleId: 'sast/sql-injection', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-a' };
    const b = { ...issue({ ruleId: 'sast/sql-injection', startLine: 50, endLine: 50, file: 'a.ts' }), analyzer: 'scanner-b' };
    const result = dedupeIssues([a, b]);
    expect(result).toHaveLength(2);
  });

  it('does not merge overlapping issues from a different vulnerability family', () => {
    const a = { ...issue({ ruleId: 'sast/sql-injection', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-a' };
    const b = { ...issue({ ruleId: 'sast/xss', startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-b' };
    const result = dedupeIssues([a, b]);
    expect(result).toHaveLength(2);
  });

  it('omits alsoReportedBy when nothing else reported the issue', () => {
    const a = { ...issue({ startLine: 5, endLine: 5, file: 'a.ts' }), analyzer: 'scanner-a' };
    const result = dedupeIssues([a]);
    expect(result[0]?.alsoReportedBy).toBeUndefined();
  });
});
