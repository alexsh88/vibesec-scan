/**
 * Fix planner ("Next actions"): turns vulnerable packages + their advisories into a ranked list of
 * concrete changes. Advisories are aggregated per action, so one upgrade lists everything it fixes
 * ("fixing X also fixes Y and Z") with the total risk it removes.
 *
 * Per vulnerable node: target = max over advisories of the smallest fixed version above the
 * installed one, snapped to the smallest published stable release >= target. Direct deps get an
 * 'upgrade-direct'; transitive deps with a single direct parent get an 'upgrade-parent' when some
 * newer parent release pulls in a fixed child; otherwise an 'override' (a lockfile refresh when the
 * intermediate parents' current ranges already admit the fix, else a pin/override snippet).
 * Registry failures degrade to advisory versions / overrides with a warning; cancellation propagates.
 */
import { createHash } from 'node:crypto';
import type { FixAction, FixPlan, FixResolves, Unfixable } from '@vibesec/shared';
import { AppError } from '../../errors/AppError';
import { pathsTo } from './lockfiles';
import type { RegistryClient } from './registry';
import type { DepGraph, DepNode, Ecosystem, FixActionKind, OsvAdvisory } from './types';
import { compareVersions, isValidVersion, minVersionAtLeast, satisfies, semverJump } from './versions';

export type VulnerablePackage = {
  findingId: string;
  graph: DepGraph;
  node: DepNode;
  advisories: OsvAdvisory[];
  /** Finding risk score 0–100. */
  riskScore: number;
};

export type BuildFixPlanInput = {
  scanId: string;
  vulnerable: readonly VulnerablePackage[];
  registry: Pick<RegistryClient, 'versions' | 'dependencyRange'>;
  signal: AbortSignal;
  /** @default 200 */
  maxRegistryLookups?: number;
};

const DEFAULT_MAX_LOOKUPS = 200;
/** Upper bound on parent releases inspected per (parent, child) walk. */
const MAX_PARENT_VERSIONS = 50;

type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'poetry' | 'uv' | 'pipenv' | 'requirements' | 'pyproject' | 'pip';

/** Internal action before merging/ranking. */
type Draft = {
  ecosystem: Ecosystem;
  manifestDir: string;
  lockfile: string;
  kind: FixActionKind;
  package: string;
  from: string;
  to: string | null;
  dev: boolean;
  /** override only: a lockfile refresh suffices (no pin needed). */
  refreshOnly: boolean;
  resolves: FixResolves[];
  notes: string[];
};

// ---------- small helpers ----------

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

function packageManager(eco: Ecosystem, lockfile: string): PackageManager {
  const base = basename(lockfile).toLowerCase();
  if (eco === 'npm') {
    if (base === 'pnpm-lock.yaml') return 'pnpm';
    if (base === 'yarn.lock') return 'yarn';
    return 'npm';
  }
  if (base === 'poetry.lock') return 'poetry';
  if (base === 'uv.lock') return 'uv';
  if (base === 'pipfile.lock' || base === 'pipfile') return 'pipenv';
  if (/^requirements.*\.txt$/.test(base)) return 'requirements';
  if (base === 'pyproject.toml') return 'pyproject';
  return 'pip';
}

function cmp(eco: Ecosystem, a: string, b: string): number {
  const va = isValidVersion(eco, a);
  const vb = isValidVersion(eco, b);
  if (va && vb) return compareVersions(eco, a, b);
  if (va !== vb) return va ? 1 : -1; // valid versions sort above junk
  return a.localeCompare(b);
}

function maxVersion(eco: Ecosystem, a: string, b: string): string {
  return cmp(eco, a, b) >= 0 ? a : b;
}

function isStable(eco: Ecosystem, v: string): boolean {
  return minVersionAtLeast(eco, [v], v) === v;
}

function safeJump(eco: Ecosystem, from: string, to: string | null): 'patch' | 'minor' | 'major' | null {
  if (to === null || !isValidVersion(eco, from) || !isValidVersion(eco, to)) return null;
  try {
    return semverJump(eco, from, to);
  } catch {
    return null;
  }
}

function isCancellation(err: unknown, signal: AbortSignal): boolean {
  return signal.aborted || (err instanceof AppError && err.code === 'CANCELLED');
}

function checkAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function actionId(scanId: string, d: Pick<Draft, 'ecosystem' | 'manifestDir' | 'kind' | 'package'>): string {
  const h = createHash('sha256').update(`${scanId}|${d.ecosystem}|${d.manifestDir}|${d.kind}|${d.package}`).digest('hex');
  return `fx_${h.slice(0, 20)}`;
}

// ---------- commands ----------

function upgradeCommand(pm: PackageManager, name: string, to: string, dev: boolean, lockfile: string): string {
  const d = dev ? '-D ' : '';
  switch (pm) {
    case 'npm': return `npm install ${d}${name}@${to}`;
    case 'pnpm': return `pnpm add ${d}${name}@${to}`;
    case 'yarn': return `yarn add ${d}${name}@${to}`;
    case 'poetry': return `poetry add ${dev ? '--group dev ' : ''}"${name}>=${to}"`;
    case 'uv': return `uv add ${dev ? '--dev ' : ''}"${name}>=${to}"`;
    case 'pipenv': return `pipenv install ${dev ? '--dev ' : ''}"${name}>=${to}"`;
    case 'requirements': return `set \`${name}==${to}\` in ${basename(lockfile)}`;
    case 'pyproject': return `set \`${name}>=${to}\` in ${basename(lockfile)}`;
    case 'pip': return `pip install "${name}>=${to}"`;
  }
}

function removeCommand(pm: PackageManager, name: string, lockfile: string): string {
  switch (pm) {
    case 'npm': return `npm uninstall ${name}`;
    case 'pnpm': return `pnpm remove ${name}`;
    case 'yarn': return `yarn remove ${name}`;
    case 'poetry': return `poetry remove ${name}`;
    case 'uv': return `uv remove ${name}`;
    case 'pipenv': return `pipenv uninstall ${name}`;
    case 'requirements':
    case 'pyproject': return `remove \`${name}\` from ${basename(lockfile)}`;
    case 'pip': return `pip uninstall ${name}`;
  }
}

function refreshCommand(pm: PackageManager, name: string, to: string, lockfile: string): string {
  switch (pm) {
    case 'npm': return `npm update ${name}`;
    case 'pnpm': return `pnpm update ${name}`;
    case 'yarn': return `yarn upgrade ${name}`;
    case 'poetry': return `poetry update ${name}`;
    case 'uv': return `uv lock --upgrade-package ${name}`;
    case 'pipenv': return `pipenv update ${name}`;
    case 'requirements': return `set \`${name}==${to}\` in ${basename(lockfile)}`;
    case 'pyproject':
    case 'pip': return `pip install --upgrade "${name}>=${to}"`;
  }
}

function overrideCommand(pm: PackageManager, name: string, to: string, lockfile: string): string {
  const n = JSON.stringify(name);
  const v = JSON.stringify(to);
  switch (pm) {
    case 'npm': return `add to package.json: "overrides": { ${n}: ${v} } — then run \`npm install\``;
    case 'yarn': return `add to package.json: "resolutions": { ${n}: ${v} } — then run \`yarn install\``;
    case 'pnpm': return `add to package.json: "pnpm": { "overrides": { ${n}: ${v} } } — then run \`pnpm install\``;
    case 'poetry': return `poetry add "${name}>=${to}"`;
    case 'uv': return `add to pyproject.toml: [tool.uv] constraint-dependencies = ["${name}>=${to}"] — then run \`uv lock\``;
    case 'pipenv': return `pipenv install "${name}>=${to}"`;
    case 'requirements': return `add \`${name}>=${to}\` to ${basename(lockfile)} (or a constraints file used with \`pip install -c\`)`;
    case 'pyproject': return `add \`${name}>=${to}\` to the dependencies in ${basename(lockfile)}`;
    case 'pip': return `add \`${name}>=${to}\` to a constraints file and install with \`pip install -c constraints.txt\``;
  }
}

// ---------- planner ----------

export async function buildFixPlan(input: BuildFixPlanInput): Promise<{ plan: FixPlan; warnings: string[] }> {
  const { scanId, registry, signal } = input;
  const maxLookups = input.maxRegistryLookups ?? DEFAULT_MAX_LOOKUPS;
  const warnings: string[] = [];
  const warn = (w: string) => { if (!warnings.includes(w)) warnings.push(w); };

  // ---- budgeted, memoized registry access; `undefined` = unavailable (failed or capped) ----
  let lookups = 0;
  const memo = new Map<string, Promise<unknown>>();
  async function lookup<T>(key: string, what: string, fn: () => Promise<T>): Promise<T | undefined> {
    checkAborted(signal);
    const hit = memo.get(key);
    if (hit) return (await hit) as T | undefined;
    if (lookups >= maxLookups) {
      warn(`Registry lookup cap (${maxLookups}) reached; remaining fix suggestions use advisory versions and overrides`);
      return undefined;
    }
    lookups++;
    const p = fn().then(
      (v) => v as T | undefined,
      (err: unknown) => {
        if (isCancellation(err, signal)) throw err;
        warn(`Registry lookup failed for ${what}: ${errText(err)}`);
        return undefined;
      },
    );
    memo.set(key, p);
    return p;
  }
  const versionsOf = (eco: Ecosystem, name: string) =>
    lookup(`v|${eco}|${name}`, name, () => registry.versions(eco, name, signal));
  const rangeOf = (eco: Ecosystem, parent: string, version: string, child: string) =>
    lookup(`r|${eco}|${parent}|${version}|${child}`, `${parent}@${version}`, () => registry.dependencyRange(eco, parent, version, child, signal));

  const drafts: Draft[] = [];
  const unfixable = new Map<string, Unfixable & { reasons: Set<string> }>();

  for (const v of input.vulnerable) {
    checkAborted(signal);
    const { graph, node } = v;
    const eco = graph.ecosystem;
    const pm = packageManager(eco, graph.lockfile);
    const current = node.version;
    const currentValid = isValidVersion(eco, current);

    // 1. per-advisory minimal fix above the installed version
    let target: string | null = null;
    const fixable: OsvAdvisory[] = [];
    const notFixable: { adv: OsvAdvisory; reason: string }[] = [];
    for (const a of v.advisories) {
      const fixes = a.fixedVersions.filter((f) => isValidVersion(eco, f) && (!currentValid || compareVersions(eco, f, current) > 0));
      fixes.sort((x, y) => compareVersions(eco, x, y));
      const min = fixes[0];
      if (min === undefined) {
        notFixable.push({ adv: a, reason: a.fixedVersions.length === 0 ? 'no fixed version published' : 'no fixed version above the installed one' });
        continue;
      }
      fixable.push(a);
      target = target === null ? min : maxVersion(eco, target, min);
    }

    if (notFixable.length > 0) {
      const key = `${eco}|${node.name}@${current}`;
      const entry = unfixable.get(key) ?? { package: node.name, version: current, advisoryIds: [], reason: '', reasons: new Set<string>() };
      for (const { adv, reason } of notFixable) {
        if (!entry.advisoryIds.includes(adv.id)) entry.advisoryIds.push(adv.id);
        entry.reasons.add(reason);
      }
      unfixable.set(key, entry);
    }

    const resolvesOf = (advs: readonly OsvAdvisory[]): FixResolves[] =>
      advs.map((a) => ({ findingId: v.findingId, advisoryId: a.id, severity: a.severity, package: node.name, version: current }));
    const base = { ecosystem: eco, manifestDir: graph.manifestDir, lockfile: graph.lockfile, dev: node.scope === 'dev', refreshOnly: false };

    if (target === null) {
      if (node.direct && notFixable.length > 0) {
        drafts.push({
          ...base, kind: 'remove', package: node.name, from: current, to: null, resolves: resolvesOf(notFixable.map((n) => n.adv)),
          notes: [`No fixed version exists for ${notFixable.map((n) => n.adv.id).join(', ')}; replace or remove ${node.name}`],
        });
      }
      continue;
    }

    // Snap to the smallest published stable release >= target.
    const notes: string[] = [];
    const childVersions = await versionsOf(eco, node.name);
    let to = target;
    if (childVersions === undefined) {
      notes.push(`Target ${target} taken from the advisory (registry unavailable)`);
    } else {
      const published = minVersionAtLeast(eco, childVersions, target);
      if (published === null) notes.push(`No published stable release >= ${target} found; using the advisory version`);
      else to = published;
    }
    const resolves = resolvesOf(fixable);

    // 2. direct dependency
    if (node.direct) {
      drafts.push({ ...base, kind: 'upgrade-direct', package: node.name, from: current, to, resolves, notes });
      continue;
    }

    // 3. transitive
    const childAdmits = (range: string): boolean => {
      if (range.trim() === '' || range.trim() === '*') return true;
      if (childVersions === undefined) return satisfies(eco, to, range);
      return childVersions.some((cv) => isStable(eco, cv) && isValidVersion(eco, cv) && compareVersions(eco, cv, to) >= 0 && satisfies(eco, cv, range));
    };
    const labelMap = new Map<string, DepNode>();
    for (const n of graph.nodes.values()) labelMap.set(`${n.name}@${n.version}`, n);
    const chain = pathsTo(graph, node.key, 1)[0];
    if (chain && chain.length > 1) notes.push(`via ${chain.join(' > ')}`);

    const parents = node.parents.map((k) => graph.nodes.get(k)).filter((p): p is DepNode => p !== undefined);
    const rootSet = new Set(graph.roots);
    const single = parents.length === 1 ? parents[0] : undefined;

    if (single && rootSet.has(single.key)) {
      // Walk the direct parent's releases ascending from the installed one.
      const parentVersions = await versionsOf(eco, single.name);
      if (parentVersions !== undefined && isValidVersion(eco, single.version)) {
        const candidates = parentVersions
          .filter((pv) => isValidVersion(eco, pv) && isStable(eco, pv) && compareVersions(eco, pv, single.version) >= 0)
          .sort((x, y) => compareVersions(eco, x, y));
        if (!candidates.includes(single.version)) candidates.unshift(single.version);
        let found: { version: string; dropped: boolean } | null = null;
        let unavailable = false;
        for (const pv of candidates.slice(0, MAX_PARENT_VERSIONS)) {
          const range = await rangeOf(eco, single.name, pv, node.name);
          if (range === undefined) { unavailable = true; break; }
          if (range === null) { found = { version: pv, dropped: true }; break; }
          if (childAdmits(range)) { found = { version: pv, dropped: false }; break; }
        }
        if (found && found.version === single.version && !found.dropped) {
          drafts.push(refreshDraft());
          continue;
        }
        if (found && found.version !== single.version) {
          drafts.push({
            ...base, kind: 'upgrade-parent', package: single.name, from: single.version, to: found.version, dev: single.scope === 'dev', resolves,
            notes: [...notes, found.dropped ? `${single.name}@${found.version} no longer depends on ${node.name}` : `pulls in ${node.name} ≥ ${to}`],
          });
          continue;
        }
        if (!found && !unavailable && candidates.length > MAX_PARENT_VERSIONS) {
          notes.push(`Checked ${MAX_PARENT_VERSIONS} releases of ${single.name} without finding one that admits ${node.name} ${to}`);
        }
      }
      drafts.push(overrideDraft());
      continue;
    }

    // Deeper chain / several parents: is a lockfile refresh enough?
    let allAdmit = parents.length > 0;
    for (const p of parents) {
      const range = await rangeOf(eco, p.name, p.version, node.name);
      if (range === undefined || (range !== null && !childAdmits(range))) { allAdmit = false; break; }
    }
    drafts.push(allAdmit ? refreshDraft() : overrideDraft());

    function refreshDraft(): Draft {
      return {
        ...base, kind: 'override', refreshOnly: true, package: node.name, from: current, to, resolves,
        notes: [...notes, `refresh lockfile: \`${refreshCommand(pm, node.name, to, graph.lockfile)}\``],
      };
    }
    function overrideDraft(): Draft {
      return {
        ...base, kind: 'override', package: node.name, from: current, to, resolves,
        notes: [...notes, `pin ${node.name} to ≥ ${to}: ${overrideCommand(pm, node.name, to, graph.lockfile)}`],
      };
    }
  }

  // 5. merge per (ecosystem, manifestDir, kind, package)
  const merged = new Map<string, Draft>();
  for (const d of drafts) {
    const key = `${d.ecosystem}|${d.manifestDir}|${d.kind}|${d.package}`;
    const prev = merged.get(key);
    if (!prev) {
      merged.set(key, { ...d, resolves: [...d.resolves], notes: [...d.notes] });
      continue;
    }
    prev.from = cmp(d.ecosystem, d.from, prev.from) < 0 ? d.from : prev.from;
    prev.to = prev.to === null || d.to === null ? (prev.to ?? d.to) : maxVersion(d.ecosystem, prev.to, d.to);
    prev.dev = prev.dev && d.dev;
    prev.refreshOnly = prev.refreshOnly && d.refreshOnly;
    for (const r of d.resolves) {
      if (!prev.resolves.some((x) => x.findingId === r.findingId && x.advisoryId === r.advisoryId)) prev.resolves.push(r);
    }
    for (const n of d.notes) if (!prev.notes.includes(n)) prev.notes.push(n);
  }

  // 6. score & rank
  const riskOf = new Map(input.vulnerable.map((v) => [v.findingId, v.riskScore]));
  const actions: FixAction[] = [...merged.values()].map((d) => {
    const pm = packageManager(d.ecosystem, d.lockfile);
    const jump = safeJump(d.ecosystem, d.from, d.to);
    const effort = d.kind === 'remove' ? 5 : d.kind === 'override' ? 3 : jump === 'major' ? 5 : jump === 'minor' ? 2 : 1;
    const findingIds = new Set(d.resolves.map((r) => r.findingId));
    const riskReduced = [...findingIds].reduce((s, id) => s + (riskOf.get(id) ?? 0), 0);
    const resolvedCount = new Set(d.resolves.map((r) => r.advisoryId)).size;
    let command: string;
    if (d.kind === 'remove' || d.to === null) command = removeCommand(pm, d.package, d.lockfile);
    else if (d.kind === 'override') command = d.refreshOnly ? refreshCommand(pm, d.package, d.to, d.lockfile) : overrideCommand(pm, d.package, d.to, d.lockfile);
    else command = upgradeCommand(pm, d.package, d.to, d.dev, d.lockfile);
    const resolves = [...d.resolves].sort((a, b) =>
      a.package.localeCompare(b.package) || a.version.localeCompare(b.version) || a.advisoryId.localeCompare(b.advisoryId) || a.findingId.localeCompare(b.findingId));
    return {
      id: actionId(scanId, d), scanId, ecosystem: d.ecosystem, manifestDir: d.manifestDir, lockfile: d.lockfile, kind: d.kind,
      package: d.package, from: d.from, to: d.to, semverJump: jump, breakingRisk: d.kind === 'remove' || jump === 'major',
      resolves, resolvedCount, riskReduced, effort, priority: riskReduced / effort, command, notes: d.notes,
    };
  });
  actions.sort((a, b) =>
    b.priority - a.priority || b.resolvedCount - a.resolvedCount || a.package.localeCompare(b.package)
    || a.manifestDir.localeCompare(b.manifestDir) || a.kind.localeCompare(b.kind) || a.ecosystem.localeCompare(b.ecosystem));

  const unfixableList: Unfixable[] = [...unfixable.values()]
    .map(({ reasons, ...u }) => ({ ...u, advisoryIds: [...u.advisoryIds].sort(), reason: [...reasons].join('; ') }))
    .sort((a, b) => a.package.localeCompare(b.package) || a.version.localeCompare(b.version));

  return { plan: { scanId, actions, unfixable: unfixableList }, warnings };
}
