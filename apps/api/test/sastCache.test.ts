import { describe, expect, it } from 'vitest';
import type { CachedSastIssue } from '../src/analyzers/code/sast';
import { SastCacheRepo } from '../src/db/sastCacheRepo';
import { memoryDb } from './helpers';

const ISSUE: CachedSastIssue = {
  ruleId: 'sast/sql-injection', title: 'SQL injection', cwe: 'CWE-89', severity: 'high', confidence: 'high',
  file: 'src/a.ts', startLine: 3, endLine: 3, explanation: 'x', impact: 'y', remediation: 'z',
};

describe('SastCacheRepo', () => {
  it('round-trips verified issues by key and overwrites on set', () => {
    const repo = new SastCacheRepo(memoryDb());
    expect(repo.get('k1')).toBeUndefined();
    repo.set('k1', [ISSUE]);
    expect(repo.get('k1')).toEqual([ISSUE]);
    repo.set('k1', []);
    expect(repo.get('k1')).toEqual([]);
  });

  it('persists across repo instances on the same database', () => {
    const db = memoryDb();
    new SastCacheRepo(db).set('k2', [ISSUE]);
    expect(new SastCacheRepo(db).get('k2')).toEqual([ISSUE]);
  });
});
