import { describe, expect, it } from 'vitest';
import { depKey, EDGE_CAP, GraphBuilder } from '../src/analyzers/dependencies/lockfiles/graph';
import { parseNpmLockfile } from '../src/analyzers/dependencies/lockfiles/npm';
import { parsePnpmLock } from '../src/analyzers/dependencies/lockfiles/pnpm';
import { parseYarnLock } from '../src/analyzers/dependencies/lockfiles/yarn';
import { parsePoetryLock } from '../src/analyzers/dependencies/lockfiles/python';

/** N leaf packages, each depended on by all P parent packages (N×P edges). */
function npmLock(n: number, p: number): string {
  const packages: Record<string, unknown> = {
    '': { dependencies: Object.fromEntries(Array.from({ length: p }, (_, i) => [`par${i}`, '1.0.0'])) },
  };
  const deps: Record<string, string> = {};
  for (let i = 0; i < n; i++) {
    packages[`node_modules/c${i}`] = { version: '1.0.0' };
    deps[`c${i}`] = '1';
  }
  for (let i = 0; i < p; i++) packages[`node_modules/par${i}`] = { version: '1.0.0', dependencies: deps };
  return JSON.stringify({ lockfileVersion: 3, packages });
}

function time<T>(fn: () => T): { value: T; ms: number } {
  const t = performance.now();
  const value = fn();
  return { value, ms: performance.now() - t };
}

describe('YAML lockfiles: duplicate-key check is not quadratic', () => {
  it('pnpm: 20k flat packages parse in < 3 s', () => {
    const lines = ['lockfileVersion: "9.0"', 'importers:', '  .: {}', 'packages:'];
    for (let i = 0; i < 20_000; i++) lines.push(`  c${i}@1.0.0: {}`);
    const { value: g, ms } = time(() => parsePnpmLock({ path: 'pnpm-lock.yaml', kind: 'pnpm-lock', manifestDir: '' }, lines.join('
')));
    expect(g.nodes.size).toBe(20_000);
    expect(ms).toBeLessThan(3000);
  });
});

describe('lockfile parsing is (near-)linear in edges (event-loop DoS guard)', () => {
  it('npm: 10k packages x 10 parents parses in < 3 s', () => {
    const content = npmLock(10_000, 10);
    const { value: g, ms } = time(() => parseNpmLockfile({ path: 'package-lock.json', kind: 'package-lock', manifestDir: '' }, content));
    expect(g.nodes.size).toBe(10_010);
    expect(g.nodes.get(depKey('npm', 'c5', '1.0.0'))!.parents).toHaveLength(10);
    expect(ms).toBeLessThan(3000);
  });

  it('npm: 30k packages x 30 parents (900k edges, over the edge cap) parses in < 3 s', () => {
    const content = npmLock(30_000, 30);
    const { value: g, ms } = time(() => parseNpmLockfile({ path: 'package-lock.json', kind: 'package-lock', manifestDir: '' }, content));
    expect(g.nodes.size).toBe(30_030);
    expect(g.nodes.get(depKey('npm', 'c7', '1.0.0'))!.parents.length).toBeGreaterThan(0);
    expect(g.nodes.get(depKey('npm', 'c7', '1.0.0'))!.scope).toBe('prod');
    expect(g.warnings.some((w) => /edge cap/.test(w))).toBe(true);
    expect(ms).toBeLessThan(3000);
  });

  it('pnpm v9: 10k x 10 parses in < 3 s', () => {
    const lines = ['lockfileVersion: "9.0"', 'importers:', '  .:', '    dependencies:'];
    for (let i = 0; i < 10; i++) lines.push(`      par${i}:`, `        specifier: 1.0.0`, `        version: 1.0.0`);
    lines.push('packages:');
    for (let i = 0; i < 10_000; i++) lines.push(`  c${i}@1.0.0: {}`);
    for (let i = 0; i < 10; i++) lines.push(`  par${i}@1.0.0: {}`);
    lines.push('snapshots:');
    for (let i = 0; i < 10_000; i++) lines.push(`  c${i}@1.0.0: {}`);
    for (let i = 0; i < 10; i++) {
      lines.push(`  par${i}@1.0.0:`, '    dependencies:');
      for (let j = 0; j < 10_000; j++) lines.push(`      c${j}: 1.0.0`);
    }
    const content = lines.join('\n');
    const { value: g, ms } = time(() => parsePnpmLock({ path: 'pnpm-lock.yaml', kind: 'pnpm-lock', manifestDir: '' }, content));
    expect(g.nodes.get(depKey('npm', 'c1', '1.0.0'))!.parents).toHaveLength(10);
    expect(ms).toBeLessThan(3000);
  });

  it('yarn v1: 10k x 10 parses in < 3 s', () => {
    const lines: string[] = [];
    for (let i = 0; i < 10_000; i++) lines.push(`c${i}@^1.0.0:`, '  version "1.0.0"', '');
    for (let i = 0; i < 10; i++) {
      lines.push(`par${i}@^1.0.0:`, '  version "1.0.0"', '  dependencies:');
      for (let j = 0; j < 10_000; j++) lines.push(`    c${j} "^1.0.0"`);
      lines.push('');
    }
    const content = lines.join('\n');
    const { value: g, ms } = time(() => parseYarnLock({ path: 'yarn.lock', kind: 'yarn-lock', manifestDir: '' }, content));
    expect(g.nodes.get(depKey('npm', 'c1', '1.0.0'))!.parents).toHaveLength(10);
    expect(ms).toBeLessThan(3000);
  });

  it('poetry: 10k x 10 parses in < 3 s', () => {
    const lines: string[] = [];
    for (let i = 0; i < 10_000; i++) lines.push('[[package]]', `name = "c${i}"`, 'version = "1.0.0"', '');
    for (let i = 0; i < 10; i++) {
      lines.push('[[package]]', `name = "par${i}"`, 'version = "1.0.0"', '[package.dependencies]');
      for (let j = 0; j < 10_000; j++) lines.push(`c${j} = "*"`);
      lines.push('');
    }
    const content = lines.join('\n');
    const { value: g, ms } = time(() => parsePoetryLock({ path: 'poetry.lock', kind: 'poetry-lock', manifestDir: '' }, content));
    expect(g.nodes.get(depKey('PyPI', 'c1', '1.0.0'))!.parents).toHaveLength(10);
    expect(ms).toBeLessThan(3000);
  });

  it('caps total edges per graph with a warning', () => {
    const b = new GraphBuilder('npm');
    const n = 1000;
    for (let i = 0; i < n; i++) b.node(`p${i}`, '1');
    const per = Math.ceil(EDGE_CAP / n) + 1;
    for (let i = 0; i < n; i++) for (let j = 0; j < per; j++) b.edge(depKey('npm', `p${i}`, '1'), depKey('npm', `p${(i + j + 1) % n}`, '1'));
    const g = b.build('x', '', 'lockfile');
    let edges = 0;
    for (const node of g.nodes.values()) edges += node.children.length;
    expect(edges).toBeLessThanOrEqual(EDGE_CAP);
    expect(g.warnings.some((w) => /edge cap/.test(w))).toBe(true);
  });
});
