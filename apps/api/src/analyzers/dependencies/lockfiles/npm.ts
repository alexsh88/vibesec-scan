// npm lockfile parsing: package-lock.json / npm-shrinkwrap.json (v1 nested, v2/v3 flat `packages`
// map), plus the package.json-only manifest fallback used when there's no lockfile at all.

import type { DepGraph, DepScope } from '../types';
import type { LockfileRef } from './discover';
import { depKey, errMsg, GraphBuilder, isPlainObject, safeEntries, safeKeys } from './graph';

type JsonRecord = Record<string, unknown>;

// --- shared helpers -----------------------------------------------------------------------------

/** Resolution host for a non-public-registry `resolved` field (git/url/file deps), else undefined. */
function nonRegistryHost(resolved: unknown): string | undefined {
  if (typeof resolved !== 'string' || resolved.length === 0) return undefined;
  if (resolved.startsWith('git+') || resolved.startsWith('git://')) return 'git';
  if (resolved.startsWith('file:')) return 'file';
  if (!/^https?:\/\//.test(resolved)) return undefined;
  try {
    const host = new URL(resolved).hostname;
    if (host === 'registry.npmjs.org' || host.endsWith('.registry.npmjs.org')) return undefined;
    return host;
  } catch {
    return undefined;
  }
}

/** Direct deps declared by a package.json-shaped object: dependencies/optionalDependencies/
 *  peerDependencies are 'prod', devDependencies is 'dev'. */
function directDepsOf(entry: JsonRecord): { name: string; range: string; scope: DepScope }[] {
  const out: { name: string; range: string; scope: DepScope }[] = [];
  for (const [name, range] of safeEntries(entry.dependencies)) out.push({ name, range: String(range), scope: 'prod' });
  for (const [name, range] of safeEntries(entry.optionalDependencies)) out.push({ name, range: String(range), scope: 'prod' });
  for (const [name, range] of safeEntries(entry.peerDependencies)) out.push({ name, range: String(range), scope: 'prod' });
  for (const [name, range] of safeEntries(entry.devDependencies)) out.push({ name, range: String(range), scope: 'dev' });
  return out;
}

/** Extracts direct deps (name -> declared range + scope) from a raw package.json string. */
export function extractManifestDirect(content: string): Map<string, { range: string; scope: DepScope }> | undefined {
  try {
    const raw = JSON.parse(content);
    if (!isPlainObject(raw)) return undefined;
    const out = new Map<string, { range: string; scope: DepScope }>();
    for (const { name, range, scope } of directDepsOf(raw)) {
      const prev = out.get(name);
      if (!prev || (prev.scope !== 'prod' && scope === 'prod')) out.set(name, { range, scope });
    }
    return out;
  } catch {
    return undefined;
  }
}

// --- v2 / v3 (`packages` map) --------------------------------------------------------------------

/** Ancestor "install context" prefixes, self first, root last — mirrors Node's module resolution
 *  walk up through nested `node_modules` directories (and, for workspace members, up to root). */
function ancestorPrefixes(pkgKey: string): string[] {
  const out: string[] = [pkgKey];
  let cur = pkgKey;
  for (;;) {
    const idx = cur.lastIndexOf('/node_modules/');
    if (idx === -1) {
      if (cur.startsWith('node_modules/')) out.push('');
      break;
    }
    cur = cur.slice(0, idx);
    out.push(cur);
  }
  if (out[out.length - 1] !== '') out.push('');
  return out;
}

function deriveNameFromPath(path: string): string {
  const idx = path.lastIndexOf('node_modules/');
  if (idx === -1) return path;
  return path.slice(idx + 'node_modules/'.length);
}

function nodeIdentity(path: string, entry: JsonRecord): { name: string; version: string } {
  const name = typeof entry.name === 'string' && entry.name.length > 0 ? entry.name : deriveNameFromPath(path);
  const version = typeof entry.version === 'string' && entry.version.length > 0 ? entry.version : 'unknown';
  return { name, version };
}

/** Follows `link: true` entries (workspace symlinks) to the real package entry, bounded hops. */
function resolvePackageEntry(packages: JsonRecord, startPath: string): { path: string; entry: JsonRecord } | null {
  let p = startPath;
  for (let hop = 0; hop < 5; hop++) {
    const entry = packages[p];
    if (!isPlainObject(entry)) return null;
    if (entry.link === true && typeof entry.resolved === 'string') {
      p = entry.resolved;
      continue;
    }
    return { path: p, entry };
  }
  return null;
}

function resolveTarget(packages: JsonRecord, fromKey: string, depName: string): { path: string; entry: JsonRecord } | null {
  for (const prefix of ancestorPrefixes(fromKey)) {
    const candidate = prefix === '' ? `node_modules/${depName}` : `${prefix}/node_modules/${depName}`;
    const found = resolvePackageEntry(packages, candidate);
    if (found) return found;
  }
  return null;
}

function wireDirect(builder: GraphBuilder, packages: JsonRecord, fromKey: string, dep: { name: string; range: string; scope: DepScope }): void {
  const target = resolveTarget(packages, fromKey, dep.name);
  if (!target) return;
  const { name, version } = nodeIdentity(target.path, target.entry);
  builder.node(name, version);
  builder.markDirect(depKey(builder.ecosystem, name, version), dep.scope, dep.range);
}

function parsePackagesMap(builder: GraphBuilder, raw: JsonRecord): void {
  const packages = isPlainObject(raw.packages) ? raw.packages : {};
  const keys = safeKeys(packages);

  // Pass 1: create a node for every real (non-link), non-root entry.
  for (const key of keys) {
    if (key === '' || builder.atCap()) continue;
    const entry = packages[key];
    if (!isPlainObject(entry) || entry.link === true) continue;
    const { name, version } = nodeIdentity(key, entry);
    const host = nonRegistryHost(entry.resolved);
    builder.node(name, version, {
      ...(entry.hasInstallScript === true ? { hasInstallScript: true } : {}),
      ...(host ? { nonRegistrySource: host } : {}),
    });
  }

  // Pass 2a: root direct deps.
  const root = packages[''];
  if (isPlainObject(root)) {
    for (const dep of directDepsOf(root)) wireDirect(builder, packages, '', dep);
  } else {
    builder.warn('package-lock: missing root ("") entry in packages map');
  }

  // Pass 2b: workspace members (keys with no node_modules segment) — their deps are direct too.
  for (const key of keys) {
    if (key === '' || key.includes('node_modules')) continue;
    const entry = packages[key];
    if (!isPlainObject(entry) || entry.link === true) continue;
    for (const dep of directDepsOf(entry)) wireDirect(builder, packages, key, dep);
  }

  // Pass 2c: transitive edges for every real installed/workspace package.
  for (const key of keys) {
    if (key === '') continue;
    const entry = packages[key];
    if (!isPlainObject(entry) || entry.link === true) continue;
    const { name, version } = nodeIdentity(key, entry);
    const parentKey = depKey(builder.ecosystem, name, version);
    const deps = [...safeEntries(entry.dependencies), ...safeEntries(entry.optionalDependencies), ...safeEntries(entry.peerDependencies)];
    for (const [depName] of deps) {
      const target = resolveTarget(packages, key, depName);
      if (!target) continue;
      const identity = nodeIdentity(target.path, target.entry);
      builder.edge(parentKey, depKey(builder.ecosystem, identity.name, identity.version));
    }
  }
}

// --- v1 (nested `dependencies`) ------------------------------------------------------------------

type V1Level = { deps: JsonRecord };

function resolveV1(chain: V1Level[], name: string): JsonRecord | undefined {
  for (let i = chain.length - 1; i >= 0; i--) {
    const level = chain[i]!.deps;
    if (Object.prototype.hasOwnProperty.call(level, name) && name !== '__proto__' && name !== 'constructor' && name !== 'prototype') {
      const v = level[name];
      return isPlainObject(v) ? v : undefined;
    }
  }
  return undefined;
}

/** Creates a node for every entry in the WHOLE nested tree (recursing into overrides) before any
 *  edge is wired — a nested override (e.g. mocha's own `dependencies.supports-color`) must already
 *  exist as a node before a sibling's `requires` edge can target it, regardless of visit order. */
function createNodesV1(builder: GraphBuilder, deps: unknown): void {
  if (!isPlainObject(deps)) return;
  for (const [name, entryRaw] of safeEntries(deps)) {
    if (!isPlainObject(entryRaw) || builder.atCap()) continue;
    const version = typeof entryRaw.version === 'string' ? entryRaw.version : 'unknown';
    const host = nonRegistryHost(entryRaw.resolved);
    builder.node(name, version, {
      ...(entryRaw.hasInstallScript === true ? { hasInstallScript: true } : {}),
      ...(host ? { nonRegistrySource: host } : {}),
    });
    createNodesV1(builder, entryRaw.dependencies);
  }
}

function wireEdgesV1(builder: GraphBuilder, deps: unknown, chain: V1Level[]): void {
  if (!isPlainObject(deps)) return;
  for (const [name, entryRaw] of safeEntries(deps)) {
    if (!isPlainObject(entryRaw)) continue;
    const version = typeof entryRaw.version === 'string' ? entryRaw.version : 'unknown';
    const parentKey = depKey(builder.ecosystem, name, version);
    const nested = isPlainObject(entryRaw.dependencies) ? entryRaw.dependencies : {};
    const myChain = [...chain, { deps: nested }];
    for (const [depName] of safeEntries(entryRaw.requires)) {
      const found = resolveV1(myChain, depName);
      if (!found) continue;
      const depVersion = typeof found.version === 'string' ? found.version : 'unknown';
      builder.edge(parentKey, depKey(builder.ecosystem, depName, depVersion));
    }
    wireEdgesV1(builder, entryRaw.dependencies, myChain);
  }
}

function parseNestedDependencies(builder: GraphBuilder, raw: JsonRecord, manifestDirect?: Map<string, { range: string; scope: DepScope }>): void {
  const topDeps = isPlainObject(raw.dependencies) ? raw.dependencies : {};
  createNodesV1(builder, topDeps);
  wireEdgesV1(builder, topDeps, [{ deps: topDeps }]);

  if (manifestDirect) {
    for (const [name, { range, scope }] of manifestDirect) {
      const entry = topDeps[name];
      if (!isPlainObject(entry)) continue;
      const version = typeof entry.version === 'string' ? entry.version : 'unknown';
      builder.markDirect(depKey(builder.ecosystem, name, version), scope, range);
    }
  } else {
    for (const [name, entry] of safeEntries(topDeps)) {
      if (!isPlainObject(entry)) continue;
      const version = typeof entry.version === 'string' ? entry.version : 'unknown';
      builder.markDirect(depKey(builder.ecosystem, name, version), entry.dev === true ? 'dev' : 'prod');
    }
    builder.warn('package-lock v1: no sibling package.json; direct/scope inferred from lockfile flags only');
  }
}

// --- public entry points --------------------------------------------------------------------------

/** Parses package-lock.json / npm-shrinkwrap.json (any version) into a DepGraph. Never throws. */
export function parseNpmLockfile(ref: LockfileRef, content: string, manifest?: string): DepGraph {
  const builder = new GraphBuilder('npm');
  try {
    const raw = JSON.parse(content);
    if (!isPlainObject(raw)) throw new Error('top-level value is not an object');
    if (isPlainObject(raw.packages)) {
      parsePackagesMap(builder, raw);
    } else if (isPlainObject(raw.dependencies)) {
      parseNestedDependencies(builder, raw, manifest ? extractManifestDirect(manifest) : undefined);
    } else {
      builder.warn(`${ref.kind}: no "packages" or "dependencies" map found; nothing resolved`);
    }
  } catch (err) {
    builder.warn(`failed to parse ${ref.kind} at ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'lockfile');
}

/** package.json with no lockfile: ranges recorded as unresolved versions, source 'manifest-only'. */
export function parsePackageJsonManifestOnly(ref: LockfileRef, content: string): DepGraph {
  const builder = new GraphBuilder('npm');
  try {
    const raw = JSON.parse(content);
    if (!isPlainObject(raw)) throw new Error('top-level value is not an object');
    for (const dep of directDepsOf(raw)) {
      const node = builder.node(dep.name, dep.range);
      builder.markDirect(node.key, dep.scope, dep.range);
    }
    builder.warn(`${ref.path}: no lockfile found; versions are unresolved manifest ranges`);
  } catch (err) {
    builder.warn(`failed to parse ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'manifest-only');
}
