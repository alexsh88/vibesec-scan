import { describe, expect, it } from 'vitest';
import { GraphBuilder, depKey, normalizePypiName, pathsTo } from '../src/analyzers/dependencies/lockfiles/graph';

function buildDiamond() {
  const b = new GraphBuilder('npm');
  for (const name of ['a', 'b', 'c', 'd']) b.node(name, '1.0.0');
  b.edge(depKey('npm', 'a', '1.0.0'), depKey('npm', 'b', '1.0.0'));
  b.edge(depKey('npm', 'b', '1.0.0'), depKey('npm', 'c', '1.0.0'));
  b.edge(depKey('npm', 'd', '1.0.0'), depKey('npm', 'c', '1.0.0'));
  b.markDirect(depKey('npm', 'a', '1.0.0'), 'prod', '^1.0.0');
  b.markDirect(depKey('npm', 'd', '1.0.0'), 'prod', '^1.0.0');
  return b.build('pkg/package-lock.json', 'pkg', 'lockfile');
}

describe('pathsTo', () => {
  it('returns the shortest chain first, then longer ones', () => {
    const g = buildDiamond();
    const paths = pathsTo(g, depKey('npm', 'c', '1.0.0'));
    expect(paths[0]).toEqual(['d@1.0.0', 'c@1.0.0']);
    expect(paths).toContainEqual(['a@1.0.0', 'b@1.0.0', 'c@1.0.0']);
    expect(paths).toHaveLength(2);
  });

  it('is cycle-safe', () => {
    const b = new GraphBuilder('npm');
    for (const name of ['a', 'b', 'c']) b.node(name, '1.0.0');
    b.edge(depKey('npm', 'a', '1.0.0'), depKey('npm', 'b', '1.0.0'));
    b.edge(depKey('npm', 'b', '1.0.0'), depKey('npm', 'c', '1.0.0'));
    b.edge(depKey('npm', 'c', '1.0.0'), depKey('npm', 'b', '1.0.0')); // b <-> c cycle
    b.markDirect(depKey('npm', 'a', '1.0.0'), 'prod');
    const g = b.build('x', '', 'lockfile');
    const paths = pathsTo(g, depKey('npm', 'c', '1.0.0'));
    expect(paths).toEqual([['a@1.0.0', 'b@1.0.0', 'c@1.0.0']]);
  });

  it('respects maxDepth and limit', () => {
    const b = new GraphBuilder('npm');
    b.node('root', '1.0.0');
    b.markDirect(depKey('npm', 'root', '1.0.0'), 'prod');
    let prevKey = depKey('npm', 'root', '1.0.0');
    for (let i = 0; i < 5; i++) {
      b.node(`n${i}`, '1.0.0');
      const k = depKey('npm', `n${i}`, '1.0.0');
      b.edge(prevKey, k);
      prevKey = k;
    }
    const g = b.build('x', '', 'lockfile');
    const target = depKey('npm', 'n4', '1.0.0');
    expect(pathsTo(g, target, 5, 3)).toEqual([]); // too shallow to reach the root
    const found = pathsTo(g, target, 5, 12);
    expect(found).toHaveLength(1);
    expect(found[0]).toEqual(['root@1.0.0', 'n0@1.0.0', 'n1@1.0.0', 'n2@1.0.0', 'n3@1.0.0', 'n4@1.0.0']);
  });

  it('a direct dependency that is itself the target returns a single-element chain', () => {
    const g = buildDiamond();
    expect(pathsTo(g, depKey('npm', 'a', '1.0.0'))).toEqual([['a@1.0.0']]);
  });

  it('returns [] for a key not present in the graph', () => {
    const g = buildDiamond();
    expect(pathsTo(g, 'npm:nope@1.0.0')).toEqual([]);
  });

  it('caps the number of returned paths at `limit`', () => {
    // Fan-in: five independent direct deps all depending on the same target.
    const b = new GraphBuilder('npm');
    b.node('target', '1.0.0');
    for (let i = 0; i < 5; i++) {
      b.node(`root${i}`, '1.0.0');
      const rk = depKey('npm', `root${i}`, '1.0.0');
      b.edge(rk, depKey('npm', 'target', '1.0.0'));
      b.markDirect(rk, 'prod');
    }
    const g = b.build('x', '', 'lockfile');
    expect(pathsTo(g, depKey('npm', 'target', '1.0.0'), 3)).toHaveLength(3);
  });
});

describe('normalizePypiName (PEP 503)', () => {
  it('lowercases and collapses runs of -_. into a single -', () => {
    expect(normalizePypiName('Django_Rest.Framework')).toBe('django-rest-framework');
    expect(normalizePypiName('zope.interface')).toBe('zope-interface');
    expect(normalizePypiName('  Foo--Bar__Baz..Qux  ')).toBe('foo-bar-baz-qux');
  });
});

describe('GraphBuilder robustness', () => {
  it('enforces the node cap and emits exactly one warning', () => {
    const b = new GraphBuilder('npm');
    for (let i = 0; i < 50_005; i++) b.node(`pkg${i}`, '1.0.0');
    const g = b.build('x', '', 'lockfile');
    expect(g.nodes.size).toBe(50_000);
    expect(g.warnings.filter((w) => w.includes('node cap'))).toHaveLength(1);
  });

  it('markDirect is a no-op for a key that was never created', () => {
    const b = new GraphBuilder('npm');
    b.markDirect(depKey('npm', 'ghost', '1.0.0'), 'prod');
    const g = b.build('x', '', 'lockfile');
    expect(g.roots).toEqual([]);
  });

  it('prod scope is sticky across repeated markDirect calls', () => {
    const b = new GraphBuilder('npm');
    b.node('a', '1.0.0');
    const key = depKey('npm', 'a', '1.0.0');
    b.markDirect(key, 'dev');
    b.markDirect(key, 'prod');
    const g = b.build('x', '', 'lockfile');
    expect(g.nodes.get(key)!.scope).toBe('prod');
  });
});
