// Supply-chain signals over a dependency graph, independent of reachability:
//   - malicious-package: an OSV MAL- advisory (critical)
//   - install-script: npm `hasInstallScript`, minus a curated allowlist of well-known packages
//   - typosquat: name within Damerau-Levenshtein distance 1 (or a separator-only variant) of a popular
//     package that is not itself popular
//   - non-registry-source: git / tarball URL / file dependencies (host only — credentials, paths and
//     query strings are never echoed)
// Pure and deterministic (sorted by node key, then rule id).

import { normalizePypiName } from './lockfiles/graph';
import { INSTALL_SCRIPT_ALLOWLIST, KNOWN_DISTINCT, POPULAR_NPM, POPULAR_PYPI } from './popularPackages';
import type { DepGraph, DepNode, Ecosystem, OsvAdvisory, Severity } from './types';

export type SupplyChainRuleId =
  | 'supply-chain/malicious-package'
  | 'supply-chain/install-script'
  | 'supply-chain/typosquat'
  | 'supply-chain/non-registry-source';

export type SupplyChainSignal = {
  key: string;
  ruleId: SupplyChainRuleId;
  severity: Severity;
  title: string;
  reason: string;
  similarTo?: string;
};

const MIN_TYPOSQUAT_LENGTH = 4;

// --- typosquat lookup --------------------------------------------------------------------------

type PopularIndex = { all: Set<string>; byLength: Map<number, string[]>; byStripped: Map<string, string> };

const strip = (s: string): string => s.replace(/[-_.]/g, '');

function buildIndex(names: readonly string[], normalize: (s: string) => string): PopularIndex {
  const all = new Set<string>();
  const byLength = new Map<number, string[]>();
  const byStripped = new Map<string, string>();
  for (const raw of [...names].map(normalize).sort()) {
    if (all.has(raw)) continue;
    all.add(raw);
    const list = byLength.get(raw.length);
    if (list) list.push(raw);
    else byLength.set(raw.length, [raw]);
    const s = strip(raw);
    if (!byStripped.has(s)) byStripped.set(s, raw);
  }
  return { all, byLength, byStripped };
}

const npmNormalize = (s: string): string => s.toLowerCase();
const INDEX: Record<Ecosystem, PopularIndex> = {
  npm: buildIndex(POPULAR_NPM, npmNormalize),
  PyPI: buildIndex(POPULAR_PYPI, normalizePypiName),
};
const DISTINCT: Record<Ecosystem, Set<string>> = {
  npm: new Set([...KNOWN_DISTINCT].map(npmNormalize)),
  PyPI: new Set([...KNOWN_DISTINCT].map(normalizePypiName)),
};

/** Optimal-string-alignment distance ≤ 1 (one insert/delete/substitute/adjacent swap), a !== b. O(n). */
export function withinOneEdit(a: string, b: string): boolean {
  if (a === b) return false;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  let i = 0;
  while (i < la && i < lb && a[i] === b[i]) i++;
  if (la === lb) {
    if (a.slice(i + 1) === b.slice(i + 1)) return true; // substitution
    return i + 1 < la && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2); // transposition
  }
  return la > lb ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1); // deletion / insertion
}

/** The popular package `name` imitates, or null. Popular / known-distinct / short names → null. */
export function findTyposquatTarget(ecosystem: Ecosystem, name: string): string | null {
  const n = ecosystem === 'PyPI' ? normalizePypiName(name) : npmNormalize(name);
  const idx = INDEX[ecosystem];
  if (n.length < MIN_TYPOSQUAT_LENGTH || idx.all.has(n) || DISTINCT[ecosystem].has(n)) return null;
  for (const len of [n.length - 1, n.length, n.length + 1]) {
    for (const cand of idx.byLength.get(len) ?? []) {
      if (cand.length >= MIN_TYPOSQUAT_LENGTH && withinOneEdit(n, cand)) return cand;
    }
  }
  const viaSeparators = idx.byStripped.get(strip(n));
  if (viaSeparators !== undefined && viaSeparators !== n && strip(n).length >= MIN_TYPOSQUAT_LENGTH) return viaSeparators;
  return null;
}

// --- non-registry source -----------------------------------------------------------------------

const SHORTHAND_HOSTS: Record<string, string> = { github: 'github.com', gitlab: 'gitlab.com', bitbucket: 'bitbucket.org', gist: 'gist.github.com' };
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;

/** Host part of a dependency source (URL, scp-like git remote, shorthand, or a bare host); never
 *  returns credentials, paths or query strings. */
export function sourceHost(raw: string): string {
  const s = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      const host = new URL(s.replace(/^git\+/i, '')).hostname;
      return host && HOST_RE.test(host) ? host.toLowerCase() : 'unknown source';
    } catch {
      return 'unknown source';
    }
  }
  if (/^file:/i.test(s) || /^link:/i.test(s)) return 'file';
  const shorthand = /^(github|gitlab|bitbucket|gist):/i.exec(s);
  if (shorthand) return SHORTHAND_HOSTS[shorthand[1]!.toLowerCase()] ?? 'unknown source';
  const scp = /^[^@\s/]+@([^:\s/]+):/.exec(s);
  if (scp && HOST_RE.test(scp[1]!)) return scp[1]!.toLowerCase();
  if (HOST_RE.test(s)) return s.toLowerCase();
  return 'unknown source';
}

// --- main --------------------------------------------------------------------------------------

const label = (n: DepNode): string => `${n.name}@${n.version}`;

export function supplyChainSignals(graph: DepGraph, advisoriesByKey: Map<string, OsvAdvisory[]>): SupplyChainSignal[] {
  const out: SupplyChainSignal[] = [];
  for (const node of graph.nodes.values()) {
    const mal = (advisoriesByKey.get(node.key) ?? []).filter((a) => a.malicious || a.id.startsWith('MAL-'));
    if (mal.length > 0) {
      out.push({
        key: node.key, ruleId: 'supply-chain/malicious-package', severity: 'critical',
        title: `Known malicious package ${label(node)}`,
        reason: `${node.name} is listed as malicious by OSV (${mal.map((a) => a.id).sort().join(', ')}); remove it and rotate any credentials available to the environments that installed it`,
      });
    }

    if (node.ecosystem === 'npm' && node.hasInstallScript && !INSTALL_SCRIPT_ALLOWLIST.has(node.name)) {
      out.push({
        key: node.key, ruleId: 'supply-chain/install-script', severity: node.direct ? 'medium' : 'low',
        title: `${label(node)} runs an install script`,
        reason: `${node.name} declares install-time scripts (preinstall/install/postinstall) that execute arbitrary code on every install${node.direct ? '' : ' (pulled in transitively)'}`,
      });
    }

    const target = findTyposquatTarget(node.ecosystem, node.name);
    if (target !== null) {
      out.push({
        key: node.key, ruleId: 'supply-chain/typosquat', severity: node.direct ? 'high' : 'medium',
        title: `${node.name} looks like a typosquat of ${target}`,
        reason: `The name ${node.name} differs from the popular package ${target} by a single character or separator; verify this is the intended dependency`,
        similarTo: target,
      });
    }

    if (node.nonRegistrySource) {
      const host = sourceHost(node.nonRegistrySource);
      const where = host === 'git' ? 'a git repository' : host === 'file' ? 'a local file path' : host;
      out.push({
        key: node.key, ruleId: 'supply-chain/non-registry-source', severity: node.direct ? 'low' : 'info',
        title: `${label(node)} is installed from outside the public registry`,
        reason: `${node.name} is resolved from ${where} instead of the public ${node.ecosystem} registry, bypassing registry integrity and malware checks`,
      });
    }
  }
  return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
}
