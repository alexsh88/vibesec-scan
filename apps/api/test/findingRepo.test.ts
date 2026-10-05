import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema, type Finding } from '@vibesec/shared';
import { FindingRepo } from '../src/db/findingRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { fingerprint, githubPermalink, provisionalScore, bumpSeverity } from '../src/findings/helpers';
import { memoryDb } from './helpers';

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  return { scanId, repo: new FindingRepo(db) };
}

let n = 0;
const finding = (scanId: string, over: Partial<Finding> = {}): Finding => ({
  id: `f-${++n}`, scanId, fingerprint: `fp-${n}`, category: 'secret', ruleId: 'secret/github-pat', title: 'Hardcoded GitHub token',
  baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [], confidence: 'high',
  location: { file: 'src/a.ts', startLine: 3, endLine: 3, snippet: 'const t = "ghp_…abcd"', permalink: 'https://github.com/acme/app/blob/sha/src/a.ts#L3' },
  explanation: 'e', impact: 'i', remediation: { summary: 'rotate' }, scanStatus: 'new', ...over,
});

describe('FindingRepo', () => {
  it('replaces findings per analyzer idempotently and reads them back', () => {
    const { repo, scanId } = setup();
    const a = finding(scanId);
    repo.replaceForAnalyzer(scanId, 'secrets', [a]);
    repo.replaceForAnalyzer(scanId, 'secrets', [a]);
    repo.replaceForAnalyzer(scanId, 'sast', [finding(scanId, { category: 'sast', ruleId: 'sast/sqli', severity: 'critical', riskScore: 90 })]);
    expect(repo.get(scanId, a.id)).toEqual(a);
    expect(repo.list(scanId, {}).items).toHaveLength(2);
  });
  it('rejects findings that do not match the shared schema', () => {
    const { repo, scanId } = setup();
    expect(() => repo.replaceForAnalyzer(scanId, 'secrets', [{ ...finding(scanId), severity: 'urgent' } as unknown as Finding])).toThrow();
  });
  it('sorts by severity then risk score, filters, searches and paginates', () => {
    const { repo, scanId } = setup();
    repo.replaceForAnalyzer(scanId, 'x', [
      finding(scanId, { severity: 'low', riskScore: 20, title: 'low one' }),
      finding(scanId, { severity: 'critical', riskScore: 95, title: 'critical one', location: { file: 'src/db.ts', startLine: 1, endLine: 1, snippet: '', permalink: '' } }),
      finding(scanId, { severity: 'high', riskScore: 75, title: 'high one' }),
      finding(scanId, { severity: 'high', riskScore: 80, title: 'higher one', category: 'config' }),
    ]);
    expect(repo.list(scanId, {}).items.map((f) => f.title)).toEqual(['critical one', 'higher one', 'high one', 'low one']);
    expect(repo.list(scanId, { severity: 'high' }).items).toHaveLength(2);
    expect(repo.list(scanId, { category: 'config' }).items.map((f) => f.title)).toEqual(['higher one']);
    expect(repo.list(scanId, { file: 'src/db.ts' }).items.map((f) => f.title)).toEqual(['critical one']);
    expect(repo.list(scanId, { q: 'LOW' }).items.map((f) => f.title)).toEqual(['low one']);
    expect(repo.list(scanId, { q: '100%_' }).items).toEqual([]);
    const page1 = repo.list(scanId, { limit: 2 });
    expect(page1.items).toHaveLength(2);
    const page2 = repo.list(scanId, { limit: 2, cursor: page1.nextCursor! });
    expect(page2.items.map((f) => f.title)).toEqual(['high one', 'low one']);
    expect(page2.nextCursor).toBeNull();
  });
  it('counts by severity and category', () => {
    const { repo, scanId } = setup();
    repo.replaceForAnalyzer(scanId, 'x', [finding(scanId, { severity: 'critical' }), finding(scanId), finding(scanId, { category: 'sast' })]);
    expect(repo.counts(scanId)).toEqual({ total: 3, bySeverity: { critical: 1, high: 2 }, byCategory: { secret: 2, sast: 1 } });
  });
  it('returns undefined for a finding of another scan', () => {
    const a = setup();
    const f = finding(a.scanId);
    a.repo.replaceForAnalyzer(a.scanId, 'x', [f]);
    expect(a.repo.get('other-scan', f.id)).toBeUndefined();
  });
});

describe('finding helpers', () => {
  it('fingerprints deterministically', () => {
    expect(fingerprint(['secret', 'rule', 'a.ts', 'hash'])).toBe(fingerprint(['secret', 'rule', 'a.ts', 'hash']));
    expect(fingerprint(['a', 'b'])).not.toBe(fingerprint(['a', 'c']));
    expect(fingerprint(['ab', 'c'])).not.toBe(fingerprint(['a', 'bc']));
    expect(fingerprint(['x'])).toMatch(/^[0-9a-f]{64}$/);
  });
  it('builds GitHub permalinks with encoded paths and line anchors', () => {
    expect(githubPermalink({ owner: 'acme', name: 'app' }, 'abc123', 'src/my file.ts', 3, 3)).toBe('https://github.com/acme/app/blob/abc123/src/my%20file.ts#L3');
    expect(githubPermalink({ owner: 'acme', name: 'app' }, 'abc123', 'a.ts', 3, 7)).toBe('https://github.com/acme/app/blob/abc123/a.ts#L3-L7');
  });

  it('I7: percent-encodes dots-only path segments so they cannot act as path traversal in a permalink', () => {
    expect(githubPermalink({ owner: 'acme', name: 'app' }, 'sha1', '../../evil.ts', 1, 1))
      .toBe('https://github.com/acme/app/blob/sha1/%2E%2E/%2E%2E/evil.ts#L1');
    expect(githubPermalink({ owner: 'acme', name: 'app' }, 'sha1', './weird.ts', 1, 1))
      .toBe('https://github.com/acme/app/blob/sha1/%2E/weird.ts#L1');
    // An ordinary filename containing dots is untouched.
    expect(githubPermalink({ owner: 'acme', name: 'app' }, 'sha1', 'a/file.name.ts', 1, 1))
      .toBe('https://github.com/acme/app/blob/sha1/a/file.name.ts#L1');
  });
  it('maps severities to provisional scores and bumps severities with clamping', () => {
    expect(['critical', 'high', 'medium', 'low', 'info'].map((s) => provisionalScore(s as never))).toEqual([90, 70, 50, 25, 5]);
    expect(bumpSeverity('high', 1)).toBe('critical');
    expect(bumpSeverity('critical', 1)).toBe('critical');
    expect(bumpSeverity('medium', -2)).toBe('info');
    expect(bumpSeverity('low', -5)).toBe('info');
  });
});
