// Shared graph-building helpers used by every per-ecosystem lockfile parser. Keeping the mutation
// logic here (node dedupe, edge wiring, direct/root bookkeeping, node cap, scope propagation) means
// npm.ts / pnpm.ts / yarn.ts / python.ts only need to know their own file format.

import type { DepGraph, DepNode, DepScope, Ecosystem } from '../types';

/** Hard safety cap: attacker-controlled lockfiles must never let a graph grow unbounded. */
export const NODE_CAP = 50_000;

/** Keys that must never be treated as data when walking attacker-controlled JSON/YAML/TOML. */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** `Object.entries`, but skipping `__proto__`/`constructor`/`prototype` (no prototype pollution). */
export function safeEntries(obj: unknown): [string, unknown][] {
  if (!isPlainObject(obj)) return [];
  return Object.entries(obj).filter(([k]) => !DANGEROUS_KEYS.has(k));
}

export function safeKeys(obj: unknown): string[] {
  if (!isPlainObject(obj)) return [];
  return Object.keys(obj).filter((k) => !DANGEROUS_KEYS.has(k));
}

export function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function depKey(ecosystem: Ecosystem, name: string, version: string): string {
  return `${ecosystem}:${name}@${version}`;
}

/** PEP 503: lowercase, runs of -_. collapsed to a single '-'. */
export function normalizePypiName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * Accumulates nodes/edges for one DepGraph. Never throws: callers are expected to catch per-file
 * parse errors themselves and fall back to `builder.build(...)` with whatever was accumulated plus
 * a warning.
 */
export class GraphBuilder {
  readonly nodes = new Map<string, DepNode>();
  readonly warnings: string[] = [];
  private readonly warnedOnce = new Set<string>();
  /** key -> most-generous declared scope seen for it as a direct/root dependency ('prod' wins). */
  private readonly rootDeclared = new Map<string, DepScope>();
  private capWarned = false;

  constructor(readonly ecosystem: Ecosystem) {}

  /** True once the node cap has been hit (and the one-time warning emitted). */
  atCap(): boolean {
    if (this.nodes.size < NODE_CAP) return false;
    if (!this.capWarned) {
      this.capWarned = true;
      this.warnings.push(`graph truncated at ${NODE_CAP} nodes (node cap reached)`);
    }
    return true;
  }

  /** Looks up an existing node by key without creating one. */
  get(key: string): DepNode | undefined {
    return this.nodes.get(key);
  }

  /**
   * Returns the node for (name, version), creating it if the cap allows. `patch` fields are merged
   * in every time (last write wins), which lets later-seen metadata (e.g. hasInstallScript) refine
   * a node created earlier purely to satisfy an edge.
   */
  node(name: string, version: string, patch?: Partial<DepNode>): DepNode {
    const key = depKey(this.ecosystem, name, version);
    let n = this.nodes.get(key);
    if (!n) {
      if (this.atCap()) {
        // Transient, not persisted: callers that only need .key (e.g. to skip wiring) still work.
        return { key, ecosystem: this.ecosystem, name, version, direct: false, scope: 'dev', parents: [], children: [] };
      }
      n = { key, ecosystem: this.ecosystem, name, version, direct: false, scope: 'dev', parents: [], children: [] };
      this.nodes.set(key, n);
    }
    if (patch) Object.assign(n, patch);
    return n;
  }

  /** Wires a child onto a parent. Silently a no-op if either side isn't a real (persisted) node. */
  edge(parentKey: string, childKey: string): void {
    if (parentKey === childKey) return;
    const parent = this.nodes.get(parentKey);
    const child = this.nodes.get(childKey);
    if (!parent || !child) return;
    if (!parent.children.includes(childKey)) parent.children.push(childKey);
    if (!child.parents.includes(parentKey)) child.parents.push(parentKey);
  }

  /** Marks a node as a direct/root dependency with the given declared scope ('prod' is sticky). */
  markDirect(key: string, scope: DepScope, declaredRange?: string): void {
    const n = this.nodes.get(key);
    if (!n) return;
    n.direct = true;
    if (declaredRange !== undefined) n.declaredRange = declaredRange;
    const prev = this.rootDeclared.get(key);
    this.rootDeclared.set(key, prev === 'prod' || scope === 'prod' ? 'prod' : scope);
  }

  warnOnce(id: string, message: string): void {
    if (this.warnedOnce.has(id)) return;
    this.warnedOnce.add(id);
    this.warnings.push(message);
  }

  warn(message: string): void {
    this.warnings.push(message);
  }

  /** Finalizes the graph: computes `roots` and propagates 'prod' scope by reachability. */
  build(lockfile: string, manifestDir: string, source: DepGraph['source']): DepGraph {
    const roots = [...this.rootDeclared.keys()];
    const prodRoots = roots.filter((k) => this.rootDeclared.get(k) === 'prod');

    const visited = new Set<string>();
    const queue: string[] = [...prodRoots];
    while (queue.length > 0) {
      const k = queue.shift()!;
      if (visited.has(k)) continue;
      visited.add(k);
      const n = this.nodes.get(k);
      if (!n) continue;
      n.scope = 'prod';
      for (const c of n.children) if (!visited.has(c)) queue.push(c);
    }
    for (const [k, n] of this.nodes) {
      if (!visited.has(k)) n.scope = 'dev';
    }

    return { ecosystem: this.ecosystem, lockfile, manifestDir, nodes: this.nodes, roots, warnings: this.warnings, source };
  }
}

/**
 * Chains of "name@version" from a direct dependency down to `key`, shortest first, cycle-safe.
 * Walks UP via `parents` (BFS, level by level) until a root is reached, since that's typically the
 * much smaller fan-in direction; a path is a sequence of node keys from `key` to a root, which is
 * then reversed to read root -> ... -> key.
 */
export function pathsTo(graph: DepGraph, key: string, limit = 5, maxDepth = 12): string[][] {
  if (!graph.nodes.has(key)) return [];
  const rootSet = new Set(graph.roots);
  const label = (k: string): string => {
    const n = graph.nodes.get(k);
    return n ? `${n.name}@${n.version}` : k;
  };

  const results: string[][] = [];
  // Each queue entry: a path of keys from `key` up to (and including) its last element, plus the
  // set of keys already used on that path (cycle guard local to the path, not global — different
  // branches may legitimately revisit a node that another branch already used).
  type Entry = { path: string[]; seen: Set<string> };
  let frontier: Entry[] = [{ path: [key], seen: new Set([key]) }];

  if (rootSet.has(key)) results.push([label(key)]);

  let depth = 0;
  // Bound total work so a pathological (near-complete) parents graph can't blow up runtime/memory.
  let explored = 0;
  const EXPLORE_BUDGET = 50_000;

  while (frontier.length > 0 && results.length < limit && depth < maxDepth && explored < EXPLORE_BUDGET) {
    const next: Entry[] = [];
    for (const entry of frontier) {
      const last = entry.path[entry.path.length - 1]!;
      const node = graph.nodes.get(last);
      if (!node) continue;
      for (const parentKey of node.parents) {
        explored++;
        if (explored > EXPLORE_BUDGET) break;
        if (entry.seen.has(parentKey)) continue; // cycle guard
        const path = [...entry.path, parentKey];
        const seen = new Set(entry.seen);
        seen.add(parentKey);
        if (rootSet.has(parentKey)) {
          results.push(path.slice().reverse().map(label));
          if (results.length >= limit) break;
        }
        next.push({ path, seen });
      }
      if (results.length >= limit) break;
    }
    frontier = next;
    depth++;
  }

  return results.slice(0, limit);
}
