// pnpm-lock.yaml parsing: v6-style (`packages` keyed by "/name@version" or "/name/version", direct
// deps at the document root) and v9-style (`importers` + `packages` + `snapshots`, peer-context
// suffixes like "(react@18.2.0)" on snapshot keys and resolved versions).

import { parse as parseYaml } from 'yaml';
import type { DepGraph, DepScope } from '../types';
import type { LockfileRef } from './discover';
import { depKey, errMsg, GraphBuilder, isPlainObject, safeEntries, safeKeys } from './graph';

type JsonRecord = Record<string, unknown>;

/** Parses a pnpm package spec ("/name@version", "/name/version", "name@version", with optional
 *  trailing peer-context suffixes) into a bare name + version. Returns null if unparseable. */
function parsePnpmPackageSpec(rawKey: string): { name: string; version: string } | null {
  let s = rawKey.trim();
  if (s.startsWith('/')) s = s.slice(1);
  s = s.replace(/(\([^()]*\))+$/, ''); // strip trailing peer-context suffix(es)
  if (s.length === 0) return null;

  const scoped = s.startsWith('@');
  let searchFrom = 0;
  if (scoped) {
    const slash = s.indexOf('/');
    if (slash === -1) return null;
    searchFrom = slash + 1;
  }
  const atIdx = s.indexOf('@', searchFrom);
  const slashIdx = s.indexOf('/', searchFrom);
  if (atIdx !== -1 && (slashIdx === -1 || atIdx < slashIdx)) {
    return { name: s.slice(0, atIdx), version: s.slice(atIdx + 1) };
  }
  if (slashIdx !== -1) {
    return { name: s.slice(0, slashIdx), version: s.slice(slashIdx + 1) };
  }
  return null;
}

function rootDepsOf(map: unknown, scope: DepScope): { name: string; version: string; range: string; scope: DepScope }[] {
  const out: { name: string; version: string; range: string; scope: DepScope }[] = [];
  for (const [name, val] of safeEntries(map)) {
    if (!isPlainObject(val) || typeof val.version !== 'string') continue;
    const spec = parsePnpmPackageSpec(`${name}@${val.version}`);
    if (!spec) continue;
    const range = typeof val.specifier === 'string' ? val.specifier : spec.version;
    out.push({ name: spec.name, version: spec.version, range, scope });
  }
  return out;
}

function wireEdgesFrom(builder: GraphBuilder, parentKey: string, entry: JsonRecord): void {
  for (const field of ['dependencies', 'optionalDependencies'] as const) {
    for (const [depName, depVersionRaw] of safeEntries(entry[field])) {
      if (typeof depVersionRaw !== 'string' && typeof depVersionRaw !== 'number') continue;
      const childSpec = parsePnpmPackageSpec(`${depName}@${String(depVersionRaw)}`);
      if (!childSpec) continue;
      builder.node(childSpec.name, childSpec.version);
      builder.edge(parentKey, depKey(builder.ecosystem, childSpec.name, childSpec.version));
    }
  }
}

function markRoots(builder: GraphBuilder, groups: [unknown, DepScope][]): void {
  for (const [map, scope] of groups) {
    for (const dep of rootDepsOf(map, scope)) {
      builder.node(dep.name, dep.version);
      builder.markDirect(depKey(builder.ecosystem, dep.name, dep.version), dep.scope, dep.range);
    }
  }
}

function parseV6(builder: GraphBuilder, raw: JsonRecord): void {
  const packages = isPlainObject(raw.packages) ? raw.packages : {};
  for (const rawKey of safeKeys(packages)) {
    if (builder.atCap()) break;
    const spec = parsePnpmPackageSpec(rawKey);
    if (spec) builder.node(spec.name, spec.version);
  }
  for (const rawKey of safeKeys(packages)) {
    const spec = parsePnpmPackageSpec(rawKey);
    const entry = packages[rawKey];
    if (!spec || !isPlainObject(entry)) continue;
    wireEdgesFrom(builder, depKey(builder.ecosystem, spec.name, spec.version), entry);
  }
  markRoots(builder, [
    [raw.dependencies, 'prod'],
    [raw.optionalDependencies, 'prod'],
    [raw.devDependencies, 'dev'],
  ]);
}

function parseV9(builder: GraphBuilder, raw: JsonRecord): void {
  const packages = isPlainObject(raw.packages) ? raw.packages : {};
  const snapshots = isPlainObject(raw.snapshots) ? raw.snapshots : {};

  for (const rawKey of safeKeys(packages)) {
    if (builder.atCap()) break;
    const spec = parsePnpmPackageSpec(rawKey);
    if (spec) builder.node(spec.name, spec.version);
  }
  for (const rawKey of safeKeys(snapshots)) {
    const spec = parsePnpmPackageSpec(rawKey);
    const entry = snapshots[rawKey];
    if (!spec || !isPlainObject(entry) || builder.atCap()) continue;
    builder.node(spec.name, spec.version);
    wireEdgesFrom(builder, depKey(builder.ecosystem, spec.name, spec.version), entry);
  }

  const importers = isPlainObject(raw.importers) ? raw.importers : {};
  for (const [, importerVal] of safeEntries(importers)) {
    if (!isPlainObject(importerVal)) continue;
    markRoots(builder, [
      [importerVal.dependencies, 'prod'],
      [importerVal.optionalDependencies, 'prod'],
      [importerVal.devDependencies, 'dev'],
    ]);
  }
}

/** Parses pnpm-lock.yaml (v6 or v9 shape) into a DepGraph. Never throws. */
export function parsePnpmLock(ref: LockfileRef, content: string): DepGraph {
  const builder = new GraphBuilder('npm');
  try {
    const raw = parseYaml(content, { maxAliasCount: 1000 });
    if (!isPlainObject(raw)) throw new Error('top-level YAML value is not a mapping');
    if (isPlainObject(raw.importers)) {
      parseV9(builder, raw);
    } else {
      parseV6(builder, raw);
    }
  } catch (err) {
    builder.warn(`failed to parse pnpm-lock.yaml at ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'lockfile');
}
