import { describe, expect, it } from 'vitest';
import { isSameIssue, matchFindings, titleSimilarity, type Finding } from '../src';

const f = (fp: string, over: Partial<Finding> = {}): Finding => ({
  id: fp, scanId: 's', fingerprint: fp, category: 'sast', ruleId: `sast/${fp}`, title: `title ${fp}`,
  baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [], confidence: 'high',
  location: { file: 'a.ts', startLine: 10, endLine: 10, snippet: 'x', permalink: '' },
  explanation: 'e', impact: 'i', remediation: { summary: 'r' }, scanStatus: 'new', ...over,
});
const at = (line: number, file = 'a.ts') => ({ location: { file, startLine: line, endLine: line, snippet: 'x', permalink: '' } });

describe('titleSimilarity', () => {
  it('is 1 for the same words regardless of case and order, low for different issues', () => {
    expect(titleSimilarity('Path traversal in GET /logs', 'path TRAVERSAL in get /logs')).toBe(1);
    expect(titleSimilarity('Missing null check before startsWith call', 'Missing null check on query parameter')).toBeLessThan(0.6);
  });
});

describe('isSameIssue', () => {
  it('matches the same rule family within 3 lines, or a near-identical title', () => {
    expect(isSameIssue(f('a', { ruleId: 'taint/path-traversal', ...at(10) }), f('b', { ruleId: 'taint/Path_Traversal', ...at(13) }))).toBe(true);
    // Re-named rule (shared words) + same title: the Supabase RLS case seen across two real scans.
    expect(isSameIssue(
      f('a', { category: 'config', ruleId: 'config/supabase-table-rls-disabled', title: 'Row level security explicitly disabled on invoices table' }),
      f('b', { category: 'config', ruleId: 'config/supabase-table-without-rls', title: 'Row level security explicitly disabled on invoices table' }),
    )).toBe(true);
  });

  it('never lets similar titles merge different kinds of issue (a fixed bug + a new one at the same spot)', () => {
    expect(isSameIssue(
      f('a', { category: 'taint', ruleId: 'taint/path-traversal', title: 'Path traversal in GET /logs via req.query.name' }),
      f('b', { category: 'taint', ruleId: 'taint/command-injection', title: 'Command injection in GET /logs via req.query.name' }),
    )).toBe(false);
    expect(isSameIssue(f('a', { ruleId: 'sast/xss', cwe: 'CWE-79' }), f('b', { ruleId: 'sast/xss', cwe: 'CWE-89' }))).toBe(false);
  });

  it('never matches across files, categories, beyond the line slack, deterministic categories or generic tails', () => {
    const base = { ruleId: 'sast/sql-injection' };
    expect(isSameIssue(f('a', base), f('b', { ...base, ...at(10, 'b.ts') }))).toBe(false);
    expect(isSameIssue(f('a', base), f('b', { ...base, category: 'taint' }))).toBe(false);
    expect(isSameIssue(f('a', base), f('b', { ...base, ...at(14) }))).toBe(false);
    expect(isSameIssue(f('a', { ...base, category: 'secret' }), f('b', { ...base, category: 'secret' }))).toBe(false);
    expect(isSameIssue(f('a', { ruleId: 'taint/other', title: 'Flow into eval' }), f('b', { ruleId: 'taint/other', title: 'Unsafe redirect target' }))).toBe(false);
  });
});

describe('matchFindings', () => {
  const get = (x: Finding) => x;

  it('matches exact keys (including mergedFingerprints) before fuzzy ones', () => {
    const base = [f('x'), f('y')];
    const head = [f('z', { mergedFingerprints: ['x'] })];
    const m = matchFindings(base, head, get);
    expect(m.pairs.get(head[0]!)).toBe(base[0]);
    expect(m.unmatchedBase).toEqual([base[1]]);
  });

  it('pairs re-worded findings one-to-one, closest line first', () => {
    const base = [f('far', { ruleId: 'sast/xss', ...at(13) }), f('near', { ruleId: 'sast/xss', ...at(10) })];
    const head = [f('h', { ruleId: 'sast/xss', ...at(11) })];
    const m = matchFindings(base, head, get);
    expect(m.pairs.get(head[0]!)?.fingerprint).toBe('near');
    expect(m.unmatchedBase.map((b) => b.fingerprint)).toEqual(['far']);
    expect(m.unmatchedHead).toEqual([]);
  });
});
