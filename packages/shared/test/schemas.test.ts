import { describe, expect, it } from 'vitest';
import {
  CreateScanRequestSchema, FindingSchema, ScanEventSchema, isTerminalState, parseRepoUrl,
} from '../src/index';

describe('parseRepoUrl', () => {
  it.each([
    ['https://github.com/acme/app', { owner: 'acme', name: 'app' }],
    ['https://github.com/acme/app.git', { owner: 'acme', name: 'app' }],
    ['https://github.com/acme/my.app-2/', { owner: 'acme', name: 'my.app-2' }],
  ])('accepts %s', (url, expected) => {
    expect(parseRepoUrl(url)).toEqual(expected);
  });

  it.each([
    'http://github.com/acme/app',
    'https://github.com.evil.com/acme/app',
    'https://gitlab.com/acme/app',
    'https://github.com/acme',
    'https://github.com/acme/app/tree/main',
    'https://user:pass@github.com/acme/app',
    'file:///etc/passwd',
  ])('rejects %s', (url) => {
    expect(parseRepoUrl(url)).toBeNull();
  });
});

describe('CreateScanRequestSchema', () => {
  it('applies option defaults', () => {
    const r = CreateScanRequestSchema.parse({ repoUrl: 'https://github.com/acme/app' });
    expect(r.options).toEqual({
      verifySecrets: false,
      historyDepth: 50,
      categories: ['secret', 'sast', 'taint', 'quality', 'dependency', 'config'],
    });
  });

  it('rejects a non-GitHub url', () => {
    expect(CreateScanRequestSchema.safeParse({ repoUrl: 'https://evil.com/a/b' }).success).toBe(false);
  });

  it('accepts a PAT', () => {
    const r = CreateScanRequestSchema.parse({
      repoUrl: 'https://github.com/acme/app', auth: { type: 'pat', token: 'github_pat_abc' },
    });
    expect(r.auth?.token).toBe('github_pat_abc');
  });
});

describe('isTerminalState', () => {
  it('knows terminal states', () => {
    expect(isTerminalState('COMPLETED')).toBe(true);
    expect(isTerminalState('CANCELLED')).toBe(true);
    expect(isTerminalState('ANALYZING')).toBe(false);
  });
});

describe('FindingSchema', () => {
  it('parses a minimal sast finding', () => {
    const f = FindingSchema.parse({
      id: 'f1', scanId: 's1', fingerprint: 'abc', category: 'sast', ruleId: 'sqli', title: 'SQL injection',
      baseSeverity: 'high', riskScore: 80, severity: 'high', riskFactors: [], confidence: 'high',
      location: { file: 'a.ts', startLine: 1, endLine: 2, snippet: 'x', permalink: 'https://github.com/a/b/blob/sha/a.ts#L1-L2' },
      explanation: 'e', impact: 'i', remediation: { summary: 's' }, scanStatus: 'new',
    });
    expect(f.category).toBe('sast');
  });
});

describe('ScanEventSchema', () => {
  it('discriminates by type', () => {
    const e = ScanEventSchema.parse({ type: 'progress', analyzer: 'secrets', done: 1, total: 4 });
    expect(e.type).toBe('progress');
  });
});
