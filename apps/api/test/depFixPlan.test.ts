import { describe, expect, it } from 'vitest';
import { FixPlanSchema } from '@vibesec/shared';
import { buildFixPlan, type VulnerablePackage } from '../src/analyzers/dependencies/fixPlan';
import type { DepGraph, DepNode, Ecosystem, OsvAdvisory } from '../src/analyzers/dependencies/types';
import { AppError } from '../src/errors/AppError';

// ---------- graph helpers ----------

type NodeSpec = { name: string; version: string; direct?: boolean; dev?: boolean; parents?: string[] };

function graph(eco: Ecosystem, lockfile: string, specs: NodeSpec[], manifestDir = ''): DepGraph {
  const key = (s: string) => `${eco}:${s}`;
  const nodes = new Map<string, DepNode>();
  for (const s of specs) {
    const k = key(`${s.name}@${s.version}`);
    nodes.set(k, {
      key: k, ecosystem: eco, name: s.name, version: s.version, direct: s.direct ?? false, scope: s.dev ? 'dev' : 'prod',
      parents: (s.parents ?? []).map(key), children: [],
    });
  }
  for (const n of nodes.values()) for (const p of n.parents) nodes.get(p)?.children.push(n.key);
  return {
    ecosystem: eco, lockfile, manifestDir, nodes, roots: [...nodes.values()].filter((n) => n.direct).map((n) => n.key), warnings: [], source: 'lockfile',
  };
}

function adv(id: string, fixedVersions: string[], severity: OsvAdvisory['severity'] = 'high'): OsvAdvisory {
  return {
    id, aliases: [], summary: id, details: '', severity, cvss: null, cvssVector: null, fixedVersions, affectedRanges: [], affectedSymbols: [], cwes: [], url: null,
    published: null, malicious: false,
  };
}

let fid = 0;
function vuln(g: DepGraph, nameAtVersion: string, advisories: OsvAdvisory[], riskScore = 50): VulnerablePackage {
  const node = g.nodes.get(`${g.ecosystem}:${nameAtVersion}`);
  if (!node) throw new Error(`no node ${nameAtVersion}`);
  return { findingId: `f${++fid}`, graph: g, node, advisories, riskScore };
}

// ---------- fake registry ----------

class FakeRegistry {
  calls = 0;
  failing = new Set<string>();
  constructor(
    private readonly vers: Record<string, string[]> = {},
    private readonly deps: Record<string, Record<string, string>> = {},
  ) {}
  async versions(_eco: Ecosystem, name: string): Promise<string[]> {
    this.calls++;
    if (this.failing.has(name)) throw new AppError('INTERNAL', 'transient', 'registry down');
    const v = this.vers[name];
    if (!v) throw new AppError('NOT_FOUND', 'permanent', 'Package not found in registry');
    return v;
  }
  async dependencyRange(_eco: Ecosystem, name: string, version: string, child: string): Promise<string | null> {
    this.calls++;
    if (this.failing.has(name)) throw new AppError('INTERNAL', 'transient', 'registry down');
    return this.deps[`${name}@${version}`]?.[child] ?? null;
  }
}

const signal = new AbortController().signal;

async function plan(vulnerable: VulnerablePackage[], registry = new FakeRegistry(), extra: { maxRegistryLookups?: number } = {}) {
  const out = await buildFixPlan({ scanId: 's1', vulnerable, registry, signal, ...extra });
  expect(FixPlanSchema.parse(out.plan)).toEqual(out.plan);
  return out;
}

// ---------- tests ----------

describe('buildFixPlan — direct upgrades', () => {
  it.each([
    ['patch', '4.17.20', ['4.17.20', '4.17.21', '4.18.0'], '4.17.21', 1, false],
    ['minor', '4.17.20', ['4.17.20', '4.18.0', '4.18.1'], '4.18.0', 2, false],
    ['major', '4.17.20', ['4.17.20', '5.0.0'], '5.0.0', 5, true],
  ] as const)('%s jump', async (jump, current, published, fix, effort, breaking) => {
    const g = graph('npm', 'package-lock.json', [{ name: 'lodash', version: current, direct: true }]);
    const reg = new FakeRegistry({ lodash: [...published] });
    const { plan: p, warnings } = await plan([vuln(g, `lodash@${current}`, [adv('GHSA-1', [fix])], 80)], reg);
    expect(warnings).toEqual([]);
    expect(p.actions).toHaveLength(1);
    const a = p.actions[0]!;
    expect(a).toMatchObject({
      kind: 'upgrade-direct', package: 'lodash', from: current, to: fix, semverJump: jump, breakingRisk: breaking, effort,
      riskReduced: 80, priority: 80 / effort, resolvedCount: 1, command: `npm install lodash@${fix}`, lockfile: 'package-lock.json', ecosystem: 'npm',
    });
    expect(a.resolves).toEqual([{ findingId: expect.any(String), advisoryId: 'GHSA-1', severity: 'high', package: 'lodash', version: current }]);
  });

  it('treats a 0.x minor bump as breaking on npm', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'tiny', version: '0.3.1', direct: true }]);
    const { plan: p } = await plan([vuln(g, 'tiny@0.3.1', [adv('A', ['0.4.0'])])], new FakeRegistry({ tiny: ['0.3.1', '0.4.0'] }));
    expect(p.actions[0]).toMatchObject({ semverJump: 'major', breakingRisk: true, effort: 5 });
  });

  it('aggregates several advisories on one package into one action with the max fix', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'lodash', version: '4.17.10', direct: true }]);
    const reg = new FakeRegistry({ lodash: ['4.17.10', '4.17.12', '4.17.19', '4.17.21'] });
    const { plan: p } = await plan([vuln(g, 'lodash@4.17.10', [
      adv('A', ['4.17.12']), adv('B', ['4.17.19']), adv('C', ['3.10.0', '4.17.21']), adv('D', ['4.17.11'], 'critical'),
    ], 90)], reg);
    expect(p.actions).toHaveLength(1);
    expect(p.actions[0]).toMatchObject({ to: '4.17.21', resolvedCount: 4, riskReduced: 90 });
    expect(p.actions[0]!.resolves.map((r) => r.advisoryId).sort()).toEqual(['A', 'B', 'C', 'D']);
  });

  it('picks the smallest published version >= target and skips prereleases', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }]);
    const reg = new FakeRegistry({ x: ['1.0.0', '1.0.1-beta.1', '1.0.2-rc.0', '1.0.3', '1.0.4'] });
    const { plan: p } = await plan([vuln(g, 'x@1.0.0', [adv('A', ['1.0.1-beta.1'])])], reg);
    expect(p.actions[0]!.to).toBe('1.0.3');
  });

  it('falls back to the advisory version with a warning when the registry fails', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }]);
    const reg = new FakeRegistry({});
    reg.failing.add('x');
    const { plan: p, warnings } = await plan([vuln(g, 'x@1.0.0', [adv('A', ['1.0.5'])])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'upgrade-direct', to: '1.0.5' });
    expect(p.actions[0]!.notes.join(' ')).toMatch(/advisory/i);
    expect(warnings.join(' ')).toMatch(/x/);
  });

  it('propagates cancellation', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }]);
    const ctrl = new AbortController();
    const reg = {
      versions: async () => { ctrl.abort(); throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled'); },
      dependencyRange: async () => null,
    };
    await expect(buildFixPlan({ scanId: 's', vulnerable: [vuln(g, 'x@1.0.0', [adv('A', ['1.0.5'])])], registry: reg, signal: ctrl.signal }))
      .rejects.toMatchObject({ code: 'CANCELLED' });
  });
});

describe('buildFixPlan — transitive', () => {
  it('two vulnerable children under the same direct dep → one upgrade-parent resolving both', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'express', version: '4.17.0', direct: true },
      { name: 'qs', version: '6.7.0', parents: ['express@4.17.0'] },
      { name: 'send', version: '0.17.1', parents: ['express@4.17.0'] },
    ]);
    const reg = new FakeRegistry(
      { express: ['4.17.0', '4.17.1', '4.18.0', '4.19.0', '5.0.0-beta.1'], qs: ['6.7.0', '6.7.3', '6.11.0'], send: ['0.17.1', '0.18.0', '0.19.0'] },
      {
        'express@4.17.0': { qs: '6.7.0', send: '0.17.1' },
        'express@4.17.1': { qs: '6.7.0', send: '0.17.1' },
        'express@4.18.0': { qs: '6.11.0', send: '0.17.2' },
        'express@4.19.0': { qs: '6.11.0', send: '0.18.0' },
      },
    );
    const { plan: p, warnings } = await plan([
      vuln(g, 'qs@6.7.0', [adv('QS-1', ['6.7.3'])], 60),
      vuln(g, 'send@0.17.1', [adv('SEND-1', ['0.18.0'])], 40),
    ], reg);
    expect(warnings).toEqual([]);
    expect(p.actions).toHaveLength(1);
    const a = p.actions[0]!;
    expect(a).toMatchObject({
      kind: 'upgrade-parent', package: 'express', from: '4.17.0', to: '4.19.0', semverJump: 'minor', effort: 2, riskReduced: 100, resolvedCount: 2,
      command: 'npm install express@4.19.0',
    });
    expect(a.resolves.map((r) => `${r.package}@${r.version}:${r.advisoryId}`).sort()).toEqual(['qs@6.7.0:QS-1', 'send@0.17.1:SEND-1']);
    expect(a.notes.join('\n')).toMatch(/qs ≥ 6\.7\.3/);
    expect(a.notes.join('\n')).toMatch(/send ≥ 0\.18\.0/);
  });

  it('direct parent whose current range already admits the fix → lockfile refresh', async () => {
    const g = graph('npm', 'yarn.lock', [
      { name: 'a', version: '1.0.0', direct: true },
      { name: 'b', version: '2.0.0', parents: ['a@1.0.0'] },
    ]);
    const reg = new FakeRegistry({ a: ['1.0.0'], b: ['2.0.0', '2.0.1'] }, { 'a@1.0.0': { b: '^2.0.0' } });
    const { plan: p } = await plan([vuln(g, 'b@2.0.0', [adv('B-1', ['2.0.1'])])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'override', package: 'b', to: '2.0.1', command: 'yarn upgrade b' });
    expect(p.actions[0]!.notes.join(' ')).toMatch(/refresh lockfile: `yarn upgrade b`/);
  });

  it('deeper chain with a satisfiable intermediate range → lockfile-refresh override', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'top', version: '1.0.0', direct: true },
      { name: 'mid', version: '3.0.0', parents: ['top@1.0.0'] },
      { name: 'leaf', version: '1.2.0', parents: ['mid@3.0.0'] },
    ]);
    const reg = new FakeRegistry({ leaf: ['1.2.0', '1.2.5', '1.3.0'] }, { 'mid@3.0.0': { leaf: '^1.2.0' } });
    const { plan: p } = await plan([vuln(g, 'leaf@1.2.0', [adv('L-1', ['1.2.5'])])], reg);
    expect(p.actions).toHaveLength(1);
    expect(p.actions[0]).toMatchObject({ kind: 'override', package: 'leaf', from: '1.2.0', to: '1.2.5', command: 'npm update leaf', effort: 3 });
    expect(p.actions[0]!.notes.join(' ')).toMatch(/refresh lockfile: `npm update leaf`/);
    expect(p.actions[0]!.notes.join(' ')).toMatch(/top@1\.0\.0 > mid@3\.0\.0 > leaf@1\.2\.0/);
  });

  it.each([
    ['package-lock.json', '"overrides": { "leaf": "2.0.0" }'],
    ['yarn.lock', '"resolutions": { "leaf": "2.0.0" }'],
    ['pnpm-lock.yaml', '"pnpm": { "overrides": { "leaf": "2.0.0" } }'],
  ])('unsatisfiable range → override snippet for %s', async (lockfile, snippet) => {
    const g = graph('npm', lockfile, [
      { name: 'top', version: '1.0.0', direct: true },
      { name: 'mid', version: '3.0.0', parents: ['top@1.0.0'] },
      { name: 'leaf', version: '1.2.0', parents: ['mid@3.0.0'] },
    ]);
    const reg = new FakeRegistry({ leaf: ['1.2.0', '2.0.0'] }, { 'mid@3.0.0': { leaf: '^1.2.0' } });
    const { plan: p } = await plan([vuln(g, 'leaf@1.2.0', [adv('L-1', ['2.0.0'])])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'override', package: 'leaf', to: '2.0.0', semverJump: 'major', breakingRisk: true, effort: 3 });
    expect(p.actions[0]!.command).toContain(snippet);
  });

  it.each([
    ['poetry.lock', 'poetry add "leaf>=2.0.0"'],
    ['uv.lock', 'constraint-dependencies = ["leaf>=2.0.0"]'],
    ['Pipfile.lock', 'pipenv install "leaf>=2.0.0"'],
    ['requirements.txt', 'leaf>=2.0.0'],
  ])('unsatisfiable range → PyPI constraint pin for %s', async (lockfile, snippet) => {
    const g = graph('PyPI', lockfile, [
      { name: 'top', version: '1.0.0', direct: true },
      { name: 'mid', version: '3.0.0', parents: ['top@1.0.0'] },
      { name: 'leaf', version: '1.2.0', parents: ['mid@3.0.0'] },
    ]);
    const reg = new FakeRegistry({ leaf: ['1.2.0', '2.0.0'] }, { 'mid@3.0.0': { leaf: '<2,>=1.2' } });
    const { plan: p } = await plan([vuln(g, 'leaf@1.2.0', [adv('L-1', ['2.0.0'])])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'override', ecosystem: 'PyPI' });
    expect(p.actions[0]!.command).toContain(snippet);
  });

  it('no parent version admits the fix → override; parent registry failure → override + warning', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'a', version: '1.0.0', direct: true },
      { name: 'b', version: '2.0.0', parents: ['a@1.0.0'] },
      { name: 'c', version: '1.0.0', direct: true },
      { name: 'd', version: '1.0.0', parents: ['c@1.0.0'] },
    ]);
    const reg = new FakeRegistry(
      { a: ['1.0.0', '1.1.0'], b: ['2.0.0', '3.0.0'], d: ['1.0.0', '1.1.0'] },
      { 'a@1.0.0': { b: '^2.0.0' }, 'a@1.1.0': { b: '^2.0.0' } },
    );
    reg.failing.add('c');
    const { plan: p, warnings } = await plan([vuln(g, 'b@2.0.0', [adv('B', ['3.0.0'])]), vuln(g, 'd@1.0.0', [adv('D', ['1.1.0'])])], reg);
    expect(p.actions.map((a) => `${a.kind}:${a.package}`).sort()).toEqual(['override:b', 'override:d']);
    expect(warnings.some((w) => w.includes('c'))).toBe(true);
  });

  it('a newer parent that drops the child also resolves it', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'a', version: '1.0.0', direct: true },
      { name: 'b', version: '2.0.0', parents: ['a@1.0.0'] },
    ]);
    const reg = new FakeRegistry({ a: ['1.0.0', '1.1.0'], b: ['2.0.0', '3.0.0'] }, { 'a@1.0.0': { b: '^2.0.0' } });
    const { plan: p } = await plan([vuln(g, 'b@2.0.0', [adv('B', ['3.0.0'])])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'upgrade-parent', package: 'a', to: '1.1.0' });
    expect(p.actions[0]!.notes.join(' ')).toMatch(/no longer depends on b/);
  });
});

describe('buildFixPlan — unfixable', () => {
  it('no fix for a direct dep → unfixable + remove suggestion', async () => {
    const g = graph('npm', 'pnpm-lock.yaml', [{ name: 'evil', version: '1.0.0', direct: true }]);
    const { plan: p } = await plan([vuln(g, 'evil@1.0.0', [adv('MAL-1', [], 'critical')], 100)], new FakeRegistry({ evil: ['1.0.0'] }));
    expect(p.unfixable).toEqual([{ package: 'evil', version: '1.0.0', advisoryIds: ['MAL-1'], reason: expect.stringMatching(/no fixed version/i) }]);
    expect(p.actions).toHaveLength(1);
    expect(p.actions[0]).toMatchObject({
      kind: 'remove', package: 'evil', to: null, semverJump: null, effort: 5, riskReduced: 100, command: 'pnpm remove evil',
    });
    expect(p.actions[0]!.notes.join(' ')).toMatch(/replace or remove/i);
  });

  it('no fix for a transitive dep → unfixable only', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'a', version: '1.0.0', direct: true },
      { name: 'b', version: '2.0.0', parents: ['a@1.0.0'] },
    ]);
    const { plan: p } = await plan([vuln(g, 'b@2.0.0', [adv('B', [])])]);
    expect(p.actions).toEqual([]);
    expect(p.unfixable).toHaveLength(1);
  });

  it('partly fixable → upgrade resolves only the fixable advisories', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }]);
    const { plan: p } = await plan([vuln(g, 'x@1.0.0', [adv('A', ['1.0.1']), adv('B', [])])], new FakeRegistry({ x: ['1.0.0', '1.0.1'] }));
    expect(p.actions).toHaveLength(1);
    expect(p.actions[0]!.resolves.map((r) => r.advisoryId)).toEqual(['A']);
    expect(p.unfixable.map((u) => u.advisoryIds)).toEqual([['B']]);
  });
});

describe('buildFixPlan — commands', () => {
  it.each([
    ['npm', 'package-lock.json', false, 'npm install x@1.0.1'],
    ['npm', 'package-lock.json', true, 'npm install -D x@1.0.1'],
    ['npm', 'pnpm-lock.yaml', false, 'pnpm add x@1.0.1'],
    ['npm', 'pnpm-lock.yaml', true, 'pnpm add -D x@1.0.1'],
    ['npm', 'yarn.lock', false, 'yarn add x@1.0.1'],
    ['npm', 'yarn.lock', true, 'yarn add -D x@1.0.1'],
    ['PyPI', 'poetry.lock', false, 'poetry add "x>=1.0.1"'],
    ['PyPI', 'poetry.lock', true, 'poetry add --group dev "x>=1.0.1"'],
    ['PyPI', 'uv.lock', false, 'uv add "x>=1.0.1"'],
    ['PyPI', 'uv.lock', true, 'uv add --dev "x>=1.0.1"'],
    ['PyPI', 'Pipfile.lock', false, 'pipenv install "x>=1.0.1"'],
    ['PyPI', 'Pipfile.lock', true, 'pipenv install --dev "x>=1.0.1"'],
    ['PyPI', 'requirements-dev.txt', false, 'set `x==1.0.1` in requirements-dev.txt'],
  ] as const)('%s %s dev=%s', async (eco, lockfile, dev, command) => {
    const g = graph(eco, `svc/${lockfile}`, [{ name: 'x', version: '1.0.0', direct: true, dev }], 'svc');
    const { plan: p } = await plan([vuln(g, 'x@1.0.0', [adv('A', ['1.0.1'])])], new FakeRegistry({ x: ['1.0.0', '1.0.1'] }));
    expect(p.actions[0]).toMatchObject({ command, manifestDir: 'svc', lockfile: `svc/${lockfile}` });
  });
});

describe('buildFixPlan — ranking, ids, caps', () => {
  it('ranks by priority, then resolvedCount, then name; ids are deterministic', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'big', version: '1.0.0', direct: true },
      { name: 'small', version: '1.0.0', direct: true },
      { name: 'zeta', version: '1.0.0', direct: true },
      { name: 'alpha', version: '1.0.0', direct: true },
    ]);
    const reg = new FakeRegistry({ big: ['1.0.0', '2.0.0'], small: ['1.0.0', '1.0.1'], zeta: ['1.0.0', '1.0.1'], alpha: ['1.0.0', '1.0.1'] });
    const vs = [
      vuln(g, 'big@1.0.0', [adv('B', ['2.0.0'])], 90), // 90 / 5 = 18
      vuln(g, 'small@1.0.0', [adv('S', ['1.0.1'])], 30), // 30
      vuln(g, 'zeta@1.0.0', [adv('Z', ['1.0.1'])], 18), // 18, tie with big, same count → name
      vuln(g, 'alpha@1.0.0', [adv('A1', ['1.0.1']), adv('A2', ['1.0.1'])], 18), // 18, count 2
    ];
    const { plan: p1 } = await plan(vs, reg);
    expect(p1.actions.map((a) => a.package)).toEqual(['small', 'alpha', 'big', 'zeta']);
    const { plan: p2 } = await plan([...vs].reverse(), reg);
    expect(p2.actions.map((a) => a.id)).toEqual(p1.actions.map((a) => a.id));
    expect(new Set(p1.actions.map((a) => a.id)).size).toBe(4);
  });

  it('stops registry lookups at the cap and warns', async () => {
    const specs: NodeSpec[] = Array.from({ length: 5 }, (_, i) => ({ name: `p${i}`, version: '1.0.0', direct: true }));
    const g = graph('npm', 'package-lock.json', specs);
    const reg = new FakeRegistry(Object.fromEntries(specs.map((s) => [s.name, ['1.0.0', '1.0.1', '1.0.2']])));
    const { plan: p, warnings } = await plan(specs.map((s) => vuln(g, `${s.name}@1.0.0`, [adv(`A-${s.name}`, ['1.0.1'])])), reg, { maxRegistryLookups: 2 });
    expect(reg.calls).toBe(2);
    expect(p.actions).toHaveLength(5);
    expect(p.actions.every((a) => a.to === '1.0.1')).toBe(true);
    expect(warnings.filter((w) => /lookup/i.test(w))).toHaveLength(1);
  });

  it('counts a finding once per action even when several of its advisories resolve', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }]);
    const { plan: p } = await plan([vuln(g, 'x@1.0.0', [adv('A', ['1.0.1']), adv('B', ['1.0.1'])], 70)], new FakeRegistry({ x: ['1.0.0', '1.0.1'] }));
    expect(p.actions[0]).toMatchObject({ riskReduced: 70, resolvedCount: 2 });
  });
});

// ---------- affected-range-aware targets (regressions / multi-range advisories) ----------

function advR(id: string, ranges: OsvAdvisory['affectedRanges'], severity: OsvAdvisory['severity'] = 'high'): OsvAdvisory {
  const fixed = ranges.map((r) => r.fixed).filter((f): f is string => f !== undefined);
  return { ...adv(id, fixed, severity), affectedRanges: ranges };
}

describe('buildFixPlan — never recommends a still-affected version', () => {
  // A: fixed in 1.2.0 but regressed in 1.3.0 (fixed again in 1.3.2). B: fixed in 1.3.0.
  const A = () => advR('A', [{ introduced: '0', fixed: '1.2.0' }, { introduced: '1.3.0', fixed: '1.3.2' }]);
  const B = () => advR('B', [{ introduced: '0', fixed: '1.3.0' }]);

  it('skips published versions inside any affected range (registry data)', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.1.0', direct: true }]);
    const reg = new FakeRegistry({ x: ['1.1.0', '1.2.0', '1.3.0', '1.3.1', '1.3.2', '1.4.0'] });
    const { plan: p } = await plan([vuln(g, 'x@1.1.0', [A(), B()])], reg);
    expect(p.actions).toHaveLength(1);
    expect(p.actions[0]).toMatchObject({ kind: 'upgrade-direct', to: '1.3.2' });
    expect(p.actions[0]!.resolves.map((r) => r.advisoryId).sort()).toEqual(['A', 'B']);
  });

  it('without registry data verifies advisory candidates against the intervals and says so', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.1.0', direct: true }]);
    const reg = new FakeRegistry({});
    reg.failing.add('x');
    const { plan: p } = await plan([vuln(g, 'x@1.1.0', [A(), B()])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'upgrade-direct', to: '1.3.2' });
    expect(p.actions[0]!.notes.join(' ')).toMatch(/unverified against registry/);
  });

  it('honours last_affected intervals (first published version after it)', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }]);
    const reg = new FakeRegistry({ x: ['1.0.0', '1.0.1', '1.0.2'] });
    const { plan: p } = await plan([vuln(g, 'x@1.0.0', [advR('A', [{ introduced: '0', lastAffected: '1.0.1' }])])], reg);
    expect(p.actions[0]).toMatchObject({ kind: 'upgrade-direct', to: '1.0.2' });
  });

  it('no published version outside every affected range → unfixable (+ remove for a direct dep)', async () => {
    const g = graph('npm', 'package-lock.json', [{ name: 'x', version: '1.1.0', direct: true }]);
    // A is fixed in 1.2.0 but everything from 1.3.0 on is affected again; B needs >= 1.3.0.
    const a = advR('A', [{ introduced: '0', fixed: '1.2.0' }, { introduced: '1.3.0' }]);
    const reg = new FakeRegistry({ x: ['1.1.0', '1.2.0', '1.3.0', '1.4.0'] });
    const { plan: p } = await plan([vuln(g, 'x@1.1.0', [a, B()])], reg);
    expect(p.actions.map((x) => x.kind)).toEqual(['remove']);
    expect(p.unfixable).toHaveLength(1);
    expect(p.unfixable[0]!.advisoryIds).toEqual(['A', 'B']);
  });

  it('upgrade-parent: a parent release whose resolved child is still affected is skipped', async () => {
    const g = graph('npm', 'package-lock.json', [
      { name: 'p', version: '1.0.0', direct: true },
      { name: 'c', version: '1.1.0', parents: ['p@1.0.0'] },
    ]);
    const versions = { p: ['1.0.0', '1.1.0', '1.2.0'], c: ['1.1.0', '1.2.0', '1.3.0', '1.3.1', '1.3.2'] };
    // ~1.3.0 resolves to 1.3.2 (clean).
    const reg = new FakeRegistry(versions, { 'p@1.0.0': { c: '~1.1.0' }, 'p@1.1.0': { c: '~1.3.0' }, 'p@1.2.0': { c: '^1.3.2' } });
    // >=1.3.0 <1.3.2 resolves to 1.3.1 (regression-affected by A) although it is >= B's fix.
    const reg2 = new FakeRegistry(versions, { 'p@1.0.0': { c: '~1.1.0' }, 'p@1.1.0': { c: '>=1.3.0 <1.3.2' }, 'p@1.2.0': { c: '^1.3.2' } });
    const r1 = await plan([vuln(g, 'c@1.1.0', [A(), B()])], reg);
    expect(r1.plan.actions[0]).toMatchObject({ kind: 'upgrade-parent', package: 'p', to: '1.1.0' });
    const r2 = await plan([vuln(g, 'c@1.1.0', [A(), B()])], reg2);
    expect(r2.plan.actions[0]).toMatchObject({ kind: 'upgrade-parent', package: 'p', to: '1.2.0' });
  });
});

describe('safeUpgradeVersion / isAffected', () => {
  it('isAffected follows intervals, explicit versions, and reports unknown without data', async () => {
    const { isAffected } = await import('../src/analyzers/dependencies/osv/normalize');
    const a = { affectedRanges: [{ introduced: '1.0.0', fixed: '1.2.0' }, { introduced: '2.0.0', lastAffected: '2.0.3' }] };
    expect(isAffected('npm', '0.9.0', a)).toBe(false);
    expect(isAffected('npm', '1.1.9', a)).toBe(true);
    expect(isAffected('npm', '1.2.0', a)).toBe(false);
    expect(isAffected('npm', '2.0.3', a)).toBe(true);
    expect(isAffected('npm', '2.0.4', a)).toBe(false);
    expect(isAffected('npm', '3.0.0', { affectedRanges: [], affectedVersions: ['3.0.0'] })).toBe(true);
    expect(isAffected('npm', '3.0.1', { affectedRanges: [], affectedVersions: ['3.0.0'] })).toBe(false);
    expect(isAffected('npm', '3.0.1', { affectedRanges: [] })).toBeNull();
  });

  it('dependency.fixedIn helper (no registry) picks the smallest candidate clean for every advisory', async () => {
    const { safeUpgradeVersion } = await import('../src/analyzers/dependencies/fixPlan');
    const A = advR('A', [{ introduced: '0', fixed: '1.2.0' }, { introduced: '1.3.0', fixed: '1.3.2' }]);
    const B = advR('B', [{ introduced: '0', fixed: '1.3.0' }]);
    expect(safeUpgradeVersion('npm', '1.1.0', [A, B])).toEqual({ version: '1.3.2', verified: false });
    expect(safeUpgradeVersion('npm', '1.1.0', [A])).toEqual({ version: '1.2.0', verified: false });
    expect(safeUpgradeVersion('npm', '1.1.0', [A, B], ['1.1.0', '1.3.1', '1.3.5'])).toEqual({ version: '1.3.5', verified: true });
    expect(safeUpgradeVersion('npm', '1.1.0', [advR('C', [{ introduced: '0' }])])).toBeNull();
  });
});

describe('buildFixPlan — per-file Python manifests', () => {
  it('requirements files in the same dir get one action each (the command names the file to edit)', async () => {
    const prod = graph('PyPI', 'svc/requirements.txt', [{ name: 'x', version: '1.0.0', direct: true }], 'svc');
    const dev = graph('PyPI', 'svc/requirements-dev.txt', [{ name: 'x', version: '1.0.0', direct: true, dev: true }], 'svc');
    const reg = new FakeRegistry({ x: ['1.0.0', '1.0.1'] });
    const { plan: p } = await plan([vuln(prod, 'x@1.0.0', [adv('A', ['1.0.1'])]), vuln(dev, 'x@1.0.0', [adv('A', ['1.0.1'])])], reg);
    expect(p.actions.map((a) => a.command).sort()).toEqual(['set `x==1.0.1` in requirements-dev.txt', 'set `x==1.0.1` in requirements.txt']);
    expect(new Set(p.actions.map((a) => a.id)).size).toBe(2);
  });

  it('npm lockfiles in one dir still merge into one action', async () => {
    const a = graph('npm', 'web/package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }], 'web');
    const b = graph('npm', 'web/package-lock.json', [{ name: 'x', version: '1.0.0', direct: true }], 'web');
    const { plan: p } = await plan([vuln(a, 'x@1.0.0', [adv('A', ['1.0.1'])]), vuln(b, 'x@1.0.0', [adv('B', ['1.0.1'])])], new FakeRegistry({ x: ['1.0.0', '1.0.1'] }));
    expect(p.actions).toHaveLength(1);
  });
});
