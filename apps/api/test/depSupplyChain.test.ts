import { describe, expect, it } from 'vitest';
import { findTyposquatTarget, sourceHost, supplyChainSignals } from '../src/analyzers/dependencies/supplyChain';
import type { DepGraph, DepNode, Ecosystem, OsvAdvisory } from '../src/analyzers/dependencies/types';

function node(eco: Ecosystem, name: string, over: Partial<DepNode> = {}): DepNode {
  return { key: `${eco}:${name}@1.0.0`, ecosystem: eco, name, version: '1.0.0', direct: false, scope: 'prod', parents: [], children: [], ...over };
}

function graph(eco: Ecosystem, nodes: DepNode[]): DepGraph {
  return { ecosystem: eco, lockfile: 'x', manifestDir: '', nodes: new Map(nodes.map((n) => [n.key, n])), roots: nodes.filter((n) => n.direct).map((n) => n.key), warnings: [], source: 'lockfile' };
}

function adv(id: string, malicious = false): OsvAdvisory {
  return { id, aliases: [], summary: 's', details: '', severity: 'critical', cvss: null, cvssVector: null, fixedVersions: [], affectedRanges: [], affectedSymbols: [], cwes: [], url: null, published: null, malicious };
}

describe('supplyChainSignals', () => {
  it('malicious-package: MAL- advisory → critical', () => {
    const n = node('npm', 'evil-pkg-xyz', { direct: true });
    const sigs = supplyChainSignals(graph('npm', [n]), new Map([[n.key, [adv('GHSA-1'), adv('MAL-2025-123', true)]]]));
    expect(sigs).toHaveLength(1);
    expect(sigs[0]).toMatchObject({ key: n.key, ruleId: 'supply-chain/malicious-package', severity: 'critical' });
    expect(sigs[0]!.reason).toContain('MAL-2025-123');
  });

  it('install-script: medium direct, low transitive, skipped for allowlisted packages', () => {
    const a = node('npm', 'weird-native-thing', { direct: true, hasInstallScript: true });
    const b = node('npm', 'other-native-thing', { hasInstallScript: true });
    const c = node('npm', 'esbuild', { direct: true, hasInstallScript: true });
    const d = node('npm', '@swc/core', { hasInstallScript: true });
    const sigs = supplyChainSignals(graph('npm', [a, b, c, d]), new Map());
    expect(sigs.map((s) => [s.key, s.ruleId, s.severity])).toEqual([
      [b.key, 'supply-chain/install-script', 'low'],
      [a.key, 'supply-chain/install-script', 'medium'],
    ]);
  });

  it('typosquat: flags look-alikes (high direct / medium transitive) and names the target', () => {
    const nodes = [node('npm', 'expresss', { direct: true }), node('npm', 'lodahs'), node('npm', 'l0dash'), node('npm', 'expres', { direct: true }), node('npm', 'lodash-')];
    const sigs = supplyChainSignals(graph('npm', nodes), new Map());
    const byName = new Map(sigs.map((s) => [s.key.replace(/^npm:|@1\.0\.0$/g, ''), s]));
    expect(byName.get('expresss')).toMatchObject({ ruleId: 'supply-chain/typosquat', severity: 'high', similarTo: 'express' });
    expect(byName.get('lodahs')).toMatchObject({ severity: 'medium', similarTo: 'lodash' });
    expect(byName.get('l0dash')).toMatchObject({ similarTo: 'lodash' });
    expect(byName.get('expres')).toMatchObject({ severity: 'high', similarTo: 'express' });
    expect(byName.get('lodash-')).toMatchObject({ similarTo: 'lodash' });
  });

  it('typosquat: PyPI transposition and separator confusion', () => {
    const sigs = supplyChainSignals(graph('PyPI', [node('PyPI', 'reqeusts', { direct: true }), node('PyPI', 'pythondateutil'), node('PyPI', 'beautiful-soup4')]), new Map());
    expect(sigs.map((s) => [s.key, s.similarTo])).toEqual([
      ['PyPI:beautiful-soup4@1.0.0', 'beautifulsoup4'],
      ['PyPI:pythondateutil@1.0.0', 'python-dateutil'],
      ['PyPI:reqeusts@1.0.0', 'requests'],
    ]);
  });

  it('typosquat: no false positives for popular, known-distinct, unrelated or short names', () => {
    const names = ['react-dom', 'express-session', 'express-rate-limit', 'lodash', 'inherit', 'abc', 'my-internal-lib', '@types/node'];
    const sigs = supplyChainSignals(graph('npm', names.map((n) => node('npm', n, { direct: true }))), new Map());
    expect(sigs).toEqual([]);
    expect(findTyposquatTarget('PyPI', 'requests')).toBeNull();
    expect(findTyposquatTarget('PyPI', 'Requests')).toBeNull();
  });

  it('non-registry-source: low direct / info transitive; reason carries the host only', () => {
    const a = node('npm', 'my-fork-of-something', { direct: true, nonRegistrySource: 'https://user:tok3n@git.example.com/a/b.tgz?token=abc' });
    const b = node('npm', 'another-git-dep', { nonRegistrySource: 'git' });
    const sigs = supplyChainSignals(graph('npm', [a, b]), new Map());
    expect(sigs.map((s) => [s.key, s.severity])).toEqual([[b.key, 'info'], [a.key, 'low']]);
    const ra = sigs.find((s) => s.key === a.key)!;
    expect(ra.reason).toContain('git.example.com');
    expect(ra.reason).not.toMatch(/tok3n|token=|user:/);
    expect(ra.title).not.toMatch(/tok3n/);
  });

  it('sourceHost strips credentials, paths and queries', () => {
    expect(sourceHost('git+https://user:pw@github.com/x/y.git#abc')).toBe('github.com');
    expect(sourceHost('git+ssh://git@gitlab.com/x/y.git')).toBe('gitlab.com');
    expect(sourceHost('git@github.com:x/y.git')).toBe('github.com');
    expect(sourceHost('https://cdn.example.org/pkg.tgz?sig=1')).toBe('cdn.example.org');
    expect(sourceHost('file:../local')).toBe('file');
    expect(sourceHost('github:user/repo')).toBe('github.com');
    expect(sourceHost('registry.internal.corp')).toBe('registry.internal.corp');
    expect(sourceHost('git')).toBe('git');
    expect(sourceHost('???weird thing with spaces')).toBe('unknown source');
  });

  it('deterministic order and one graph may yield several signals for a node', () => {
    const n = node('npm', 'expresss', { direct: true, hasInstallScript: true, nonRegistrySource: 'git' });
    const sigs = supplyChainSignals(graph('npm', [n]), new Map([[n.key, [adv('MAL-1', true)]]]));
    expect(sigs.map((s) => s.ruleId)).toEqual([
      'supply-chain/install-script', 'supply-chain/malicious-package', 'supply-chain/non-registry-source', 'supply-chain/typosquat',
    ]);
  });

  it('performance: 5k-node graph in < 500 ms', () => {
    const nodes: DepNode[] = [];
    for (let i = 0; i < 5000; i++) nodes.push(node('npm', `pkg-${i.toString(36)}-${'x'.repeat(i % 12)}`, { direct: i % 50 === 0, hasInstallScript: i % 97 === 0 }));
    const g = graph('npm', nodes);
    const t0 = performance.now();
    supplyChainSignals(g, new Map());
    expect(performance.now() - t0).toBeLessThan(500);
  });
});
