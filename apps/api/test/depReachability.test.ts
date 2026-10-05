import { describe, expect, it } from 'vitest';
import { assessReachability } from '../src/analyzers/dependencies/reachability';
import type { DepGraph, DepNode, Ecosystem, OsvAdvisory, PackageUsage } from '../src/analyzers/dependencies/types';

function node(eco: Ecosystem, name: string, version: string, over: Partial<DepNode> = {}): DepNode {
  return { key: `${eco}:${name}@${version}`, ecosystem: eco, name, version, direct: false, scope: 'prod', parents: [], children: [], ...over };
}

/** edges: [parentKey, childKey]; roots are the direct nodes. */
function graph(eco: Ecosystem, nodes: DepNode[], edges: [string, string][] = []): DepGraph {
  const map = new Map(nodes.map((n) => [n.key, { ...n, parents: [...n.parents], children: [...n.children] }]));
  for (const [p, c] of edges) {
    map.get(p)!.children.push(c);
    map.get(c)!.parents.push(p);
  }
  return { ecosystem: eco, lockfile: 'package-lock.json', manifestDir: '', nodes: map, roots: nodes.filter((n) => n.direct).map((n) => n.key), warnings: [], source: 'lockfile' };
}

function adv(over: Partial<OsvAdvisory> = {}): OsvAdvisory {
  return {
    id: 'GHSA-1', aliases: [], summary: 'Prototype pollution', details: '', severity: 'high', cvss: 7.5, cvssVector: null,
    fixedVersions: ['4.17.21'], affectedSymbols: [], cwes: [], url: null, published: null, malicious: false, ...over,
  };
}

function use(pkg: string, file: string, line: number, symbol: string | null, kind: PackageUsage['kind'] = 'call', eco: Ecosystem = 'npm'): PackageUsage {
  return { ecosystem: eco, package: pkg, file, line, symbol, kind };
}

const app = node('npm', 'app-lib', '1.0.0', { direct: true });
const lodash = node('npm', 'lodash', '4.17.20', { direct: true });
const unused = node('npm', 'left-pad', '1.0.0', { direct: true });
const express = node('npm', 'express', '4.0.0', { direct: true });
const qs = node('npm', 'qs', '6.0.0');
const deep = node('npm', 'deep-thing', '1.0.0');
const g = graph('npm', [app, lodash, unused, express, qs, deep], [[express.key, qs.key], [unused.key, deep.key]]);

describe('assessReachability', () => {
  it('null usages → unknown (no usage data at all)', () => {
    const v = assessReachability({ graph: g, node: g.nodes.get(lodash.key)!, advisories: [adv()], usages: null, usageSource: 'index' });
    expect(v.reachability).toBe('unknown');
    expect(v.via).toBe('none');
    expect(v.evidence).toEqual([]);
  });

  it('direct dep imported + vulnerable symbol called → reachable with matching evidence', () => {
    const usages = [use('lodash', 'src/b.ts', 9, 'map'), use('lodash', 'src/a.ts', 3, 'merge'), use('lodash', 'src/a.ts', 1, 'default', 'import')];
    const v = assessReachability({ graph: g, node: g.nodes.get(lodash.key)!, advisories: [adv({ affectedSymbols: ['lodash.merge', 'zipObjectDeep'] })], usages, usageSource: 'sandbox' });
    expect(v.reachability).toBe('reachable');
    expect(v.via).toBe('sandbox');
    expect(v.matchedSymbols).toEqual(['lodash.merge']);
    expect(v.evidence).toEqual([{ file: 'src/a.ts', line: 3, symbol: 'merge' }]);
  });

  it('symbol matching is case-sensitive', () => {
    const v = assessReachability({ graph: g, node: g.nodes.get(lodash.key)!, advisories: [adv({ affectedSymbols: ['Merge'] })], usages: [use('lodash', 'a.ts', 1, 'merge')], usageSource: 'sandbox' });
    expect(v.reachability).toBe('imported');
  });

  it('imported but no affected symbol used → imported, evidence capped at 10 in deterministic order', () => {
    const usages = Array.from({ length: 15 }, (_, i) => use('lodash/fp', `src/f${String(14 - i).padStart(2, '0')}.ts`, i + 1, 'map'));
    const v = assessReachability({ graph: g, node: g.nodes.get(lodash.key)!, advisories: [adv({ affectedSymbols: ['merge'] })], usages, usageSource: 'sandbox' });
    expect(v.reachability).toBe('imported');
    expect(v.evidence).toHaveLength(10);
    expect(v.evidence[0]).toEqual({ file: 'src/f00.ts', line: 15, symbol: 'map' });
    expect(v.matchedSymbols).toEqual([]);
  });

  it('index source (imports only) → imported, never reachable even when names coincide', () => {
    const usages = [use('lodash', 'src/a.ts', 1, 'merge', 'import')];
    const v = assessReachability({ graph: g, node: g.nodes.get(lodash.key)!, advisories: [adv({ affectedSymbols: ['merge'] })], usages, usageSource: 'index' });
    expect(v.reachability).toBe('imported');
    expect(v.via).toBe('index');
  });

  it('direct dep never imported → unreachable', () => {
    const v = assessReachability({ graph: g, node: g.nodes.get(unused.key)!, advisories: [adv()], usages: [use('lodash', 'a.ts', 1, null)], usageSource: 'index' });
    expect(v.reachability).toBe('unreachable');
    expect(v.reason).toMatch(/never imported|not imported/);
  });

  it('transitive dep whose ancestors are not imported → unreachable, reason names the chain', () => {
    const v = assessReachability({ graph: g, node: g.nodes.get(deep.key)!, advisories: [adv()], usages: [use('lodash', 'a.ts', 1, null)], usageSource: 'index' });
    expect(v.reachability).toBe('unreachable');
    expect(v.reason).toContain('left-pad');
  });

  it('transitive dep with an imported ancestor → unknown "reachable only through <ancestor> internals"', () => {
    const usages = [use('express', 'src/server.ts', 2, null, 'import'), use('express', 'src/server.ts', 5, 'default')];
    const v = assessReachability({ graph: g, node: g.nodes.get(qs.key)!, advisories: [adv()], usages, usageSource: 'sandbox' });
    expect(v.reachability).toBe('unknown');
    expect(v.reason).toContain('reachable only through express internals');
    expect(v.evidence).toEqual([{ file: 'src/server.ts', line: 2, symbol: null }, { file: 'src/server.ts', line: 5, symbol: 'default' }]);
  });

  it('phantom import: transitive dep imported directly by app code → treated as imported/reachable', () => {
    const usages = [use('qs', 'src/q.ts', 4, 'parse')];
    const v1 = assessReachability({ graph: g, node: g.nodes.get(qs.key)!, advisories: [adv()], usages, usageSource: 'sandbox' });
    expect(v1.reachability).toBe('imported');
    expect(v1.reason).toMatch(/phantom|transitive/i);
    const v2 = assessReachability({ graph: g, node: g.nodes.get(qs.key)!, advisories: [adv({ affectedSymbols: ['parse'] })], usages, usageSource: 'sandbox' });
    expect(v2.reachability).toBe('reachable');
  });

  it('malicious package that is imported → reachable regardless of symbols', () => {
    const v = assessReachability({ graph: g, node: g.nodes.get(lodash.key)!, advisories: [adv({ id: 'MAL-2024-1', malicious: true })], usages: [use('lodash', 'a.ts', 1, null, 'import')], usageSource: 'index' });
    expect(v.reachability).toBe('reachable');
  });

  it('scoped npm packages and subpaths match; look-alike names do not', () => {
    const babel = node('npm', '@babel/core', '7.0.0', { direct: true });
    const gb = graph('npm', [babel]);
    const yes = assessReachability({ graph: gb, node: gb.nodes.get(babel.key)!, advisories: [adv()], usages: [use('@babel/core/lib/x', 'a.ts', 1, null)], usageSource: 'index' });
    expect(yes.reachability).toBe('imported');
    const no = assessReachability({ graph: gb, node: gb.nodes.get(babel.key)!, advisories: [adv()], usages: [use('@babel/core-js', 'a.ts', 1, null)], usageSource: 'index' });
    expect(no.reachability).toBe('unreachable');
  });

  it('PyPI: usages reported under the distribution or the import name both match', () => {
    const pyyaml = node('PyPI', 'pyyaml', '5.3', { direct: true });
    const gp = graph('PyPI', [pyyaml]);
    const a = assessReachability({ graph: gp, node: gp.nodes.get(pyyaml.key)!, advisories: [adv({ affectedSymbols: ['yaml.load'] })], usages: [use('PyYAML', 'app.py', 3, 'load', 'call', 'PyPI')], usageSource: 'sandbox' });
    expect(a.reachability).toBe('reachable');
    const b = assessReachability({ graph: gp, node: gp.nodes.get(pyyaml.key)!, advisories: [adv({ affectedSymbols: ['load'] })], usages: [use('yaml', 'app.py', 3, 'safe_load', 'call', 'PyPI')], usageSource: 'sandbox' });
    expect(b.reachability).toBe('imported');
  });
});
