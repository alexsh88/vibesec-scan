import { describe, expect, it } from 'vitest';
import {
  computeFileMetrics,
  findDuplicateBlocks,
  rankFilesForQualityReview,
  LONG_FILE_LINES,
} from '../src/analyzers/code/quality/metrics';

describe('computeFileMetrics — TypeScript/JavaScript', () => {
  it('extracts a simple function with its length and name', () => {
    const text = ['function add(a, b) {', '  return a + b;', '}', ''].join('\n');
    const m = computeFileMetrics('a.ts', text, 'ts');
    expect(m.functions).toHaveLength(1);
    expect(m.functions[0]!.name).toBe('add');
    expect(m.functions[0]!.startLine).toBe(1);
    expect(m.functions[0]!.endLine).toBe(3);
    expect(m.functions[0]!.length).toBe(3);
    expect(m.functions[0]!.maxNesting).toBe(0);
  });

  it('names arrow functions and method shorthand from their binding', () => {
    const text = [
      'const handler = (req, res) => {',
      '  res.send("ok");',
      '};',
      '',
      'const obj = {',
      '  method() {',
      '    return 1;',
      '  },',
      '};',
    ].join('\n');
    const m = computeFileMetrics('b.js', text, 'js');
    const names = m.functions.map((f) => f.name).sort();
    expect(names).toEqual(['handler', 'method']);
  });

  it('computes nesting depth relative to the enclosing function and flags deep nesting', () => {
    const text = [
      'function deep() {',
      '  if (a) {',
      '    if (b) {',
      '      if (c) {',
      '        if (d) {',
      '          if (e) {',
      '            return 1;',
      '          }',
      '        }',
      '      }',
      '    }',
      '  }',
      '  return 0;',
      '}',
    ].join('\n');
    const m = computeFileMetrics('deep.ts', text, 'ts');
    expect(m.functions).toHaveLength(1);
    expect(m.functions[0]!.maxNesting).toBe(5);
    expect(m.deepNesting).toBe(1);
    expect(m.maxNesting).toBe(5);
  });

  it('flags long functions over the threshold', () => {
    const body = Array.from({ length: 90 }, (_, i) => `  const x${i} = ${i};`).join('\n');
    const text = `function longFn() {\n${body}\n  return 1;\n}\n`;
    const m = computeFileMetrics('long.ts', text, 'ts');
    expect(m.functions).toHaveLength(1);
    expect(m.functions[0]!.length).toBeGreaterThan(80);
    expect(m.longFunctions).toBe(1);
  });

  it('computes TODO density per 100 code lines', () => {
    const codeLines = Array.from({ length: 10 }, (_, i) => `const x${i} = ${i};`);
    const text = [...codeLines, '// TODO: revisit this'].join('\n');
    const m = computeFileMetrics('todo.ts', text, 'ts');
    expect(m.codeLines).toBe(10);
    expect(m.todoCount).toBe(1);
    expect(m.todoDensity).toBe(10);
  });

  it('counts total lines including blanks and comments', () => {
    const text = ['// header comment', '', 'const a = 1;', ''].join('\n');
    const m = computeFileMetrics('c.ts', text, 'ts');
    expect(m.lines).toBe(4);
    expect(m.codeLines).toBe(1);
  });
});

describe('computeFileMetrics — Python heuristic', () => {
  it('extracts def blocks with nesting from if/for/while/with/try', () => {
    const text = [
      'def outer():',
      '    if True:',
      '        for i in range(10):',
      '            if True:',
      '                if True:',
      '                    if True:',
      '                        print(i)',
      '    return 1',
    ].join('\n');
    const m = computeFileMetrics('a.py', text, 'py');
    expect(m.functions).toHaveLength(1);
    const fn = m.functions[0]!;
    expect(fn.name).toBe('outer');
    expect(fn.startLine).toBe(1);
    expect(fn.endLine).toBe(8);
    expect(fn.maxNesting).toBe(5);
    expect(m.deepNesting).toBe(1);
  });

  it('scopes nested methods inside a class independently', () => {
    const text = [
      'class Thing:',
      '    def method_a(self):',
      '        if True:',
      '            return 1',
      '',
      '    def method_b(self):',
      '        return 2',
    ].join('\n');
    const m = computeFileMetrics('b.py', text, 'py');
    expect(m.functions.map((f) => f.name).sort()).toEqual(['method_a', 'method_b']);
    const a = m.functions.find((f) => f.name === 'method_a')!;
    const b = m.functions.find((f) => f.name === 'method_b')!;
    expect(a.maxNesting).toBe(1);
    expect(b.maxNesting).toBe(0);
  });

  it('async def is recognized as a function', () => {
    const text = ['async def fetch():', '    return await get()'].join('\n');
    const m = computeFileMetrics('c.py', text, 'py');
    expect(m.functions).toHaveLength(1);
    expect(m.functions[0]!.name).toBe('fetch');
  });
});

describe('long-file metric', () => {
  it('counts lines past the long-file threshold (evidence for the AI review, never a finding)', () => {
    const text = Array.from({ length: LONG_FILE_LINES + 5 }, (_, i) => `const x${i} = ${i};`).join('\n');
    const m = computeFileMetrics('huge.ts', text, 'ts');
    expect(m.lines).toBeGreaterThan(LONG_FILE_LINES);
  });
});

describe('findDuplicateBlocks', () => {
  it('finds an identical 6+ line block shared across two files', () => {
    const fileA = {
      path: 'a.ts',
      text: [
        'function helperA() {',
        '  const value = 1;',
        '  const result = value * 2;',
        '  const total = result + value;',
        '  console.log(total);',
        '  return total;',
        '}',
      ].join('\n'),
    };
    const fileB = {
      path: 'b.ts',
      text: [
        'function helperB() {',
        '  const value = 1;',
        '  const result = value * 2;',
        '  const total = result + value;',
        '  console.log(total);',
        '  return total;',
        '}',
      ].join('\n'),
    };
    const dups = findDuplicateBlocks([fileA, fileB]);
    expect(dups.length).toBeGreaterThanOrEqual(1);
    const group = dups.find((d) => d.occurrences.length === 2)!;
    expect(group).toBeDefined();
    const paths = group.occurrences.map((o) => o.path).sort();
    expect(paths).toEqual(['a.ts', 'b.ts']);
    for (const occ of group.occurrences) expect(occ.startLine).toBe(2);
  });

  it('finds a duplicate repeated twice within the same file', () => {
    const block = ['  const value = 1;', '  const result = value * 2;', '  const total = result + value;', '  console.log(total);', '  return total;', '  // end'];
    const text = ['function one() {', ...block, '}', '', 'function two() {', ...block, '}'].join('\n');
    const dups = findDuplicateBlocks([{ path: 'one.ts', text }]);
    expect(dups.length).toBeGreaterThanOrEqual(1);
    const group = dups[0]!;
    expect(group.occurrences).toHaveLength(2);
    expect(group.occurrences[0]!.path).toBe('one.ts');
    expect(group.occurrences[1]!.path).toBe('one.ts');
    expect(group.occurrences[0]!.startLine).not.toBe(group.occurrences[1]!.startLine);
  });

  it('ignores trivial windows made mostly of imports/braces', () => {
    const imports = [
      "import a from 'a';",
      "import b from 'b';",
      "import c from 'c';",
      "import d from 'd';",
      "import e from 'e';",
      "import f from 'f';",
    ];
    const fileA = { path: 'x.ts', text: imports.join('\n') };
    const fileB = { path: 'y.ts', text: imports.join('\n') };
    const dups = findDuplicateBlocks([fileA, fileB]);
    expect(dups).toHaveLength(0);
  });

  it('does not report unique files as duplicates', () => {
    const fileA = { path: 'a.ts', text: 'function uniqueA() {\n  return 1;\n}\n' };
    const fileB = { path: 'b.ts', text: 'function uniqueB() {\n  return 2;\n}\n' };
    const dups = findDuplicateBlocks([fileA, fileB]);
    expect(dups).toHaveLength(0);
  });

  it('reports each duplicate occurrence with its real start line', () => {
    const shared = ['  const value = 1;', '  const result = value * 2;', '  const total = result + value;', '  console.log(total);', '  return total;', '  doStuff();'];
    const fileA = { path: 'a.ts', text: ['function helperA() {', ...shared, '}'].join('\n') };
    const fileB = { path: 'b.ts', text: ['function helperB() {', ...shared, '}'].join('\n') };
    const dups = findDuplicateBlocks([fileA, fileB]);
    expect(dups).toHaveLength(1);
    expect(dups[0]!.occurrences).toEqual([{ path: 'a.ts', startLine: 2 }, { path: 'b.ts', startLine: 2 }]);
  });
});

describe('rankFilesForQualityReview', () => {
  it('ranks worst files first', () => {
    const clean = computeFileMetrics('clean.ts', 'function ok() {\n  return 1;\n}\n', 'ts');
    const bodyLines = Array.from({ length: 90 }, (_, i) => `  const x${i} = ${i};`).join('\n');
    const badText = `function longFn() {\n${bodyLines}\n  if(a){if(b){if(c){if(d){if(e){return 1;}}}}}\n}\n`;
    const bad = computeFileMetrics('bad.ts', badText, 'ts');
    const ranked = rankFilesForQualityReview([clean, bad]);
    expect(ranked[0]).toBe('bad.ts');
    expect(ranked[1]).toBe('clean.ts');
  });
});
