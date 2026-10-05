// Deterministic reachability of a vulnerable package from application code.
//
// Risk model (user requirement): a vulnerable ROOT/direct library that the app imports is far
// riskier than an INNER/transitive one that is only pulled in by another library's internals.
//
//   - no usage data at all (no sandbox AND no index)            → 'unknown'
//   - imported by app code (direct dep, or a transitive one imported directly = phantom dependency):
//       a used symbol matches an advisory affectedSymbol         → 'reachable'
//       otherwise                                                → 'imported'
//     (the index source carries imports only, no symbols, so it can never prove 'reachable')
//   - not imported by app code:
//       direct dep                                               → 'unreachable' (declared but unused)
//       transitive, no ancestor imported                         → 'unreachable'
//       transitive, some ancestor imported                       → 'unknown' ("reachable only through
//                                                                   <ancestor> internals")
//
// Malicious (MAL-) packages: never downgraded by symbol matching — an imported malicious package is
// 'reachable' (its install/import itself is the payload). When it is NOT imported the computed value
// is returned unchanged, but the CALLER must not lower the severity of a malicious finding based on
// it (install scripts run regardless of imports).

import { normalizePypiName, pathsTo } from './lockfiles/graph';
import { importNamesFor, npmPackageRoot } from './importNames';
import type { DepGraph, DepNode, Ecosystem, OsvAdvisory, PackageUsage } from './types';

export type Reachability = 'reachable' | 'imported' | 'unreachable' | 'unknown';

export type ReachabilityEvidence = { file: string; line: number; symbol: string | null };

export type ReachabilityVerdict = {
  reachability: Reachability;
  evidence: ReachabilityEvidence[];
  via: 'sandbox' | 'index' | 'none';
  reason: string;
  matchedSymbols: string[];
};

export type ReachabilityInput = {
  graph: DepGraph;
  node: DepNode;
  advisories: OsvAdvisory[];
  /** null = no usage data at all (no sandbox AND no index). */
  usages: readonly PackageUsage[] | null;
  /** 'index' = imports only, no symbols. */
  usageSource: 'sandbox' | 'index';
};

export const MAX_EVIDENCE = 10;
const MAX_ANCESTORS = 10_000;

// --- usage lookup (bucketed once per usages array) ---------------------------------------------

type UsageIndex = Map<string, PackageUsage[]>;
const indexCache = new WeakMap<readonly PackageUsage[], UsageIndex>();

/** Bucket keys a usage is filed under. npm: the package root of the specifier. PyPI: every dotted
 *  prefix of the module (normalized), so `google.protobuf.x` is found via `google.protobuf`. */
function usageKeys(u: PackageUsage): string[] {
  if (u.ecosystem === 'npm') return [`npm|${npmPackageRoot(u.package)}`];
  const parts = u.package.split('.');
  const keys: string[] = [];
  for (let n = 1; n <= parts.length; n++) keys.push(`PyPI|${normalizePypiName(parts.slice(0, n).join('.'))}`);
  return keys;
}

function usageIndex(usages: readonly PackageUsage[]): UsageIndex {
  let idx = indexCache.get(usages);
  if (idx) return idx;
  idx = new Map();
  for (const u of usages) {
    for (const k of usageKeys(u)) {
      const list = idx.get(k);
      if (list) list.push(u);
      else idx.set(k, [u]);
    }
  }
  indexCache.set(usages, idx);
  return idx;
}

function lookupKeys(ecosystem: Ecosystem, name: string): string[] {
  if (ecosystem === 'npm') return [`npm|${name}`];
  const keys = new Set([`PyPI|${normalizePypiName(name)}`]);
  for (const mod of importNamesFor('PyPI', name)) keys.add(`PyPI|${normalizePypiName(mod)}`);
  return [...keys];
}

/** All app-code usages of the package `name`, deterministic order. */
function usagesOf(idx: UsageIndex, ecosystem: Ecosystem, name: string): PackageUsage[] {
  const seen = new Set<PackageUsage>();
  for (const k of lookupKeys(ecosystem, name)) for (const u of idx.get(k) ?? []) seen.add(u);
  return [...seen].sort(compareUsage);
}

function compareUsage(a: PackageUsage, b: PackageUsage): number {
  return a.file < b.file ? -1 : a.file > b.file ? 1
    : a.line - b.line || (a.symbol ?? '').localeCompare(b.symbol ?? '') || a.kind.localeCompare(b.kind);
}

function toEvidence(usages: readonly PackageUsage[]): ReachabilityEvidence[] {
  const out: ReachabilityEvidence[] = [];
  const seen = new Set<string>();
  for (const u of usages) {
    const k = `${u.file}\0${u.line}\0${u.symbol ?? ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ file: u.file, line: u.line, symbol: u.symbol });
    if (out.length >= MAX_EVIDENCE) break;
  }
  return out;
}

// --- symbol matching ---------------------------------------------------------------------------

const lastSegment = (s: string): string => s.slice(s.lastIndexOf('.') + 1);

/** Case-sensitive: exact, or the last segment of a dotted symbol on either side. */
export function symbolMatches(usageSymbol: string, affected: string): boolean {
  if (usageSymbol === affected) return true;
  const u = lastSegment(usageSymbol);
  const a = lastSegment(affected);
  return u.length > 0 && u === a;
}

// --- graph helpers -----------------------------------------------------------------------------

/** Ancestors of `key` in BFS order (nearest first; ties by key), bounded. */
function ancestors(graph: DepGraph, key: string): string[] {
  const out: string[] = [];
  const seen = new Set([key]);
  let frontier = [key];
  while (frontier.length > 0 && out.length < MAX_ANCESTORS) {
    const next: string[] = [];
    for (const k of frontier) {
      for (const p of graph.nodes.get(k)?.parents ?? []) {
        if (seen.has(p)) continue;
        seen.add(p);
        next.push(p);
      }
    }
    next.sort();
    out.push(...next);
    frontier = next;
  }
  return out.slice(0, MAX_ANCESTORS);
}

// --- main --------------------------------------------------------------------------------------

export function assessReachability(input: ReachabilityInput): ReachabilityVerdict {
  const { graph, node, advisories, usages, usageSource } = input;
  if (usages === null) {
    return { reachability: 'unknown', evidence: [], via: 'none', reason: 'No usage data available (neither sandbox analysis nor import index)', matchedSymbols: [] };
  }
  const via = usageSource;
  const idx = usageIndex(usages);
  const own = usagesOf(idx, node.ecosystem, node.name);
  const malicious = advisories.some((a) => a.malicious);

  if (own.length > 0) {
    const phantom = !node.direct ? ' (transitive dependency imported directly — phantom dependency)' : '';
    if (malicious) {
      return { reachability: 'reachable', evidence: toEvidence(own), via, reason: `Known malicious package ${node.name} is imported by application code${phantom}`, matchedSymbols: [] };
    }
    if (usageSource === 'sandbox') {
      const affected = [...new Set(advisories.flatMap((a) => a.affectedSymbols))];
      const matched = new Set<string>();
      const hits: PackageUsage[] = [];
      for (const u of own) {
        if (u.symbol === null) continue;
        let hit = false;
        for (const a of affected) {
          if (symbolMatches(u.symbol, a)) {
            matched.add(a);
            hit = true;
          }
        }
        if (hit) hits.push(u);
      }
      if (hits.length > 0) {
        const matchedSymbols = [...matched].sort();
        return {
          reachability: 'reachable', evidence: toEvidence(hits), via, matchedSymbols,
          reason: `Application code uses the vulnerable ${matchedSymbols.join(', ')} of ${node.name}${phantom}`,
        };
      }
    }
    const what = usageSource === 'index' ? 'imported (import index has no symbol-level data)' : 'imported, but no advisory-affected symbol is used';
    return { reachability: 'imported', evidence: toEvidence(own), via, reason: `${node.name} is ${what}${phantom}`, matchedSymbols: [] };
  }

  if (node.direct) {
    return { reachability: 'unreachable', evidence: [], via, reason: `${node.name} is declared as a direct dependency but never imported by application code`, matchedSymbols: [] };
  }

  // Transitive and not imported: is any ancestor imported by the app?
  const importedAncestors: { name: string; usages: PackageUsage[] }[] = [];
  const seenNames = new Set<string>();
  for (const k of ancestors(graph, node.key)) {
    const anc = graph.nodes.get(k);
    if (!anc || seenNames.has(anc.name)) continue;
    seenNames.add(anc.name);
    const u = usagesOf(idx, anc.ecosystem, anc.name);
    if (u.length > 0) importedAncestors.push({ name: anc.name, usages: u });
  }

  if (importedAncestors.length === 0) {
    const chain = pathsTo(graph, node.key, 1)[0];
    const chainText = chain ? chain.join(' > ') : `${node.name}@${node.version} (no path from a direct dependency)`;
    return { reachability: 'unreachable', evidence: [], via, reason: `Transitive dependency not imported by application code, and none of its dependents are either: ${chainText}`, matchedSymbols: [] };
  }

  const shown = importedAncestors.slice(0, 3);
  const names = shown.map((a) => a.name).join(', ');
  const evidence = toEvidence(shown.flatMap((a) => a.usages).sort(compareUsage));
  return { reachability: 'unknown', evidence, via, reason: `Not imported directly; reachable only through ${names} internals`, matchedSymbols: [] };
}
