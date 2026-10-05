import { describe, expect, it } from 'vitest';
import { FindingSchema, type Finding } from '@vibesec/shared';
import { crossDedupe, familyTail, type ScanFindingRow } from '../src/findings/crossDedupe';
import { mkFinding } from './findingFactory';

const row = (analyzer: string, finding: Finding): ScanFindingRow => ({ analyzer, finding });

describe('crossDedupe', () => {
  it('merges sast + taint for the same bug: taint wins, producedBy union, note, loser removed', () => {
    const sast = mkFinding({ ruleId: 'sast/command-injection', cwe: 'CWE-78', severity: 'critical', line: 12 });
    const taint = mkFinding({
      category: 'taint', ruleId: 'taint/command-injection', cwe: 'CWE-78', severity: 'high', line: 12, producedBy: ['taint:agent'],
      taintTrace: [{ kind: 'source', file: 'src/a.ts', line: 8, code: 'req.query.c', note: 'src' }, { kind: 'sink', file: 'src/a.ts', line: 12, code: 'exec(c)', note: 'sink' }],
    });
    const r = crossDedupe([row('sast', sast), row('taint', taint)]);
    expect(r.removedIds).toEqual([sast.id]);
    expect(r.kept).toHaveLength(1);
    const w = r.kept[0]!;
    expect(w.id).toBe(taint.id);
    expect(w.producedBy).toEqual(['taint:agent', 'sast:llm']);
    expect(w.explanation).toContain('Also reported by: sast (sast/command-injection at src/a.ts:12)');
    expect(r.changed).toEqual([w]);
    expect(() => FindingSchema.parse(w)).not.toThrow();
  });

  it('matches families through the alias table when CWEs are missing', () => {
    const pairs: Array<[string, string]> = [
      ['sast/sql-injection', 'taint/sqli'],
      ['sast/command-injection', 'taint/os-command-injection'],
      ['sast/xss', 'taint/cross-site-scripting'],
      ['sast/path-traversal', 'taint/directory-traversal'],
      ['vibesec/missing-authn', 'config/missing-authentication'],
    ];
    for (const [a, b] of pairs) {
      expect(familyTail(a)).toBe(familyTail(b));
      const r = crossDedupe([
        row('sast', mkFinding({ ruleId: a, cwe: undefined })),
        row('x', mkFinding({ ruleId: b, cwe: undefined, category: 'config', producedBy: undefined })),
      ]);
      expect(r.kept).toHaveLength(1);
    }
  });

  it('merges on CWE equality even when rule tails differ', () => {
    const r = crossDedupe([
      row('sast', mkFinding({ ruleId: 'sast/sql-injection', cwe: 'CWE-89' })),
      row('taint', mkFinding({ category: 'taint', ruleId: 'taint/db-query-from-input', cwe: 'cwe-89', producedBy: ['taint:agent'] })),
    ]);
    expect(r.kept).toHaveLength(1);
    expect(r.kept[0]!.category).toBe('taint');
  });

  it('keeps different families on the same line separate (command-injection vs missing-authn)', () => {
    const r = crossDedupe([
      row('sast', mkFinding({ ruleId: 'sast/command-injection', cwe: 'CWE-78', line: 5, endLine: 20 })),
      row('sast', mkFinding({ ruleId: 'vibesec/missing-authn', cwe: 'CWE-306', line: 5, endLine: 20 })),
    ]);
    expect(r.kept).toHaveLength(2);
    expect(r.removedIds).toEqual([]);
    expect(r.changed).toEqual([]);
  });

  it('does not merge non-overlapping ranges or different files', () => {
    const r = crossDedupe([
      row('sast', mkFinding({ line: 5 })),
      row('sast', mkFinding({ line: 6 })),
      row('sast', mkFinding({ line: 5, file: 'src/b.ts' })),
    ]);
    expect(r.kept).toHaveLength(3);
  });

  it('merges overlapping multi-line ranges', () => {
    const r = crossDedupe([
      row('sast', mkFinding({ line: 5, endLine: 9 })),
      row('sast', mkFinding({ line: 9, endLine: 12, producedBy: ['sast:llm-fast'] })),
    ]);
    expect(r.kept).toHaveLength(1);
  });

  it('never merges secret/dependency findings with code findings', () => {
    const r = crossDedupe([
      row('sast', mkFinding({ ruleId: 'sast/hardcoded-credential', cwe: 'CWE-798' })),
      row('credentials', mkFinding({ category: 'secret', ruleId: 'secret/hardcoded-credential', cwe: 'CWE-798', producedBy: undefined })),
      row('dependencies', mkFinding({ category: 'dependency', ruleId: 'dep/hardcoded-credential', cwe: 'CWE-798', producedBy: undefined })),
    ]);
    expect(r.kept).toHaveLength(3);
  });

  it('merges a SAST finding at any step of a taint trace (not just the sink)', () => {
    const sastAtSource = mkFinding({ ruleId: 'sast/sql-injection', file: 'src/routes.ts', line: 30 });
    const taint = mkFinding({
      category: 'taint', ruleId: 'taint/sql-injection', file: 'src/db.ts', line: 4, producedBy: ['taint:agent'],
      taintTrace: [
        { kind: 'source', file: 'src/routes.ts', line: 28, code: 'req.body.q', note: '' },
        { kind: 'propagator', file: 'src/routes.ts', line: 30, code: 'search(q)', note: '' },
        { kind: 'sink', file: 'src/db.ts', line: 4, code: 'db.query(sql)', note: '' },
      ],
    });
    const otherFamilyAtStep = mkFinding({ ruleId: 'vibesec/missing-authn', cwe: 'CWE-306', file: 'src/routes.ts', line: 30 });
    const r = crossDedupe([row('sast', sastAtSource), row('taint', taint), row('sast', otherFamilyAtStep)]);
    expect(r.removedIds).toEqual([sastAtSource.id]);
    expect(r.kept.map((f) => f.id).sort()).toEqual([taint.id, otherFamilyAtStep.id].sort());
  });

  it('ranks winners: sast deep > sast fast > config, then severity, then confidence', () => {
    const fast = mkFinding({ producedBy: ['sast:llm-fast'], severity: 'critical' });
    const deep = mkFinding({ producedBy: ['sast:llm'], severity: 'high' });
    const cfg = mkFinding({ category: 'config', producedBy: ['config:llm'], severity: 'critical' });
    expect(crossDedupe([row('sast', fast), row('config', cfg), row('sast', deep)]).kept[0]!.id).toBe(deep.id);

    const high = mkFinding({ severity: 'high', confidence: 'low' });
    const crit = mkFinding({ severity: 'critical', confidence: 'low' });
    expect(crossDedupe([row('sast', high), row('sast', crit)]).kept[0]!.id).toBe(crit.id);

    const lowConf = mkFinding({ confidence: 'low' });
    const highConf = mkFinding({ confidence: 'high' });
    expect(crossDedupe([row('sast', lowConf), row('sast', highConf)]).kept[0]!.id).toBe(highConf.id);
  });

  it('uses the analyzer id for producedBy when a loser has none, and does not stack notes on re-merge', () => {
    const w = mkFinding({ explanation: 'Base.\n\nAlso reported by: old (x at y:1).' });
    const l = mkFinding({ category: 'config', producedBy: undefined });
    const r = crossDedupe([row('sast', w), row('config', l)]);
    expect(r.kept[0]!.producedBy).toEqual(['sast:llm', 'config']);
    expect(r.kept[0]!.explanation.match(/Also reported by/g)).toHaveLength(1);
    expect(r.kept[0]!.explanation.startsWith('Base.')).toBe(true);
  });

  it('never merges on generic tails without a matching CWE', () => {
    const r = crossDedupe([
      row('sast', mkFinding({ ruleId: 'sast/other', cwe: undefined })),
      row('sast', mkFinding({ ruleId: 'sast/other', cwe: undefined })),
    ]);
    expect(r.kept).toHaveLength(2);
  });
});

describe('crossDedupe: stable identity, no over-merging', () => {
  const sink = (file: string, line: number) => [
    { kind: 'source' as const, file: 'src/routes.ts', line: 3, code: 'req.query.q', note: '' },
    { kind: 'sink' as const, file, line, code: 'db.query(q)', note: '' },
  ];

  it('records every loser fingerprint on the winner (mergedFingerprints, transitively from earlier merges)', () => {
    const w = mkFinding({ category: 'taint', producedBy: ['taint:agent'], fingerprint: 'w', taintTrace: sink('src/a.ts', 10) });
    const l = mkFinding({ fingerprint: 'l', mergedFingerprints: ['older'] });
    const r = crossDedupe([row('taint', w), row('sast', l)]);
    expect(r.kept[0]!.mergedFingerprints).toEqual(['l', 'older']);
  });

  it('picks the same winner whatever the per-scan ids are (ties broken by fingerprint, not id)', () => {
    const a = mkFinding({ fingerprint: 'aaa' });
    const b = mkFinding({ fingerprint: 'bbb' });
    const swapped = [{ ...a, id: 'z-1' }, { ...b, id: 'a-1' }];
    expect(crossDedupe([row('sast', a), row('sast', b)]).kept[0]!.fingerprint).toBe('aaa');
    expect(crossDedupe(swapped.map((f) => row('sast', f))).kept[0]!.fingerprint).toBe('aaa');
  });

  it('assigns each finding to one direct winner: no transitive chain through a wide-range finding', () => {
    const top = mkFinding({ category: 'taint', producedBy: ['taint:agent'], line: 10, taintTrace: sink('src/a.ts', 10) });
    const wide = mkFinding({ producedBy: ['sast:llm-fast'], line: 1, endLine: 100 });
    const far = mkFinding({ producedBy: ['sast:llm'], line: 90 });
    const r = crossDedupe([row('sast', wide), row('sast', far), row('taint', top)]);
    expect(r.kept.map((f) => f.id).sort()).toEqual([far.id, top.id].sort());
    expect(r.removedIds).toEqual([wide.id]);
  });

  it('never merges two traced flows with different sinks; merges them when the sinks overlap', () => {
    const t1 = mkFinding({ category: 'taint', producedBy: ['taint:agent'], file: 'src/routes.ts', line: 3, taintTrace: sink('src/db.ts', 4) });
    const t2 = mkFinding({ category: 'taint', producedBy: ['taint:agent'], file: 'src/routes.ts', line: 3, taintTrace: sink('src/db.ts', 40) });
    expect(crossDedupe([row('taint', t1), row('taint', t2)]).kept).toHaveLength(2);
    const t3 = mkFinding({ category: 'taint', producedBy: ['taint:agent'], file: 'src/routes.ts', line: 3, taintTrace: sink('src/db.ts', 4) });
    expect(crossDedupe([row('taint', t1), row('taint', t3)]).kept).toHaveLength(1);
  });
});
