// yarn.lock parsing: classic v1 (custom line-oriented format, multi-spec header blocks) and Berry
// (YAML with a top-level `__metadata` key and `npm:`-protocol-prefixed ranges). Directness/scope
// come from the sibling package.json in both cases — yarn.lock itself doesn't record them.

import { parse as parseYaml } from 'yaml';
import type { DepGraph, DepScope } from '../types';
import type { LockfileRef } from './discover';
import { depKey, errMsg, GraphBuilder, isPlainObject, safeEntries } from './graph';
import { extractManifestDirect } from './npm';

type Spec = { name: string; range: string };
type YarnEntry = { specs: Spec[]; version: string; deps: Spec[] };

function unquote(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) return t.slice(1, -1);
  return t;
}

function splitHeaderSpecs(header: string): string[] {
  return header.split(',').map((s) => unquote(s.trim())).filter((s) => s.length > 0);
}

/** "name@range" (name may be scoped, e.g. "@scope/pkg@npm:^1.0.0"); assumes pre-unquoted input. */
function parseYarnSpec(raw: string): Spec | null {
  const s = raw.trim();
  if (s.length === 0) return null;
  const scoped = s.startsWith('@');
  const searchFrom = scoped ? s.indexOf('/') + 1 : 0;
  if (scoped && searchFrom === 0) return null;
  const at = s.indexOf('@', searchFrom);
  if (at === -1) return null;
  return { name: s.slice(0, at), range: s.slice(at + 1) };
}

function stripNpmProtocol(range: string): string {
  return range.startsWith('npm:') ? range.slice(4) : range;
}

// --- classic v1 -----------------------------------------------------------------------------------

function indentOf(line: string): number {
  let n = 0;
  while (n < line.length && line[n] === ' ') n++;
  return n;
}

function parseV1Entries(content: string): YarnEntry[] {
  const lines = content.split(/\r?\n/);
  const n = lines.length;
  const entries: YarnEntry[] = [];
  let i = 0;
  while (i < n) {
    const raw = lines[i]!;
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#') || indentOf(raw) > 0) {
      i++;
      continue;
    }
    if (!trimmed.endsWith(':')) {
      i++;
      continue;
    }
    const specs = splitHeaderSpecs(trimmed.slice(0, -1))
      .map(parseYarnSpec)
      .filter((s): s is Spec => s !== null);
    i++;
    let version = 'unknown';
    const deps: Spec[] = [];
    while (i < n) {
      const bodyRaw = lines[i]!;
      if (bodyRaw.trim() === '') {
        i++;
        continue;
      }
      const indent = indentOf(bodyRaw);
      if (indent === 0) break;
      const bodyTrim = bodyRaw.trim();
      if (bodyTrim.startsWith('version ')) {
        version = unquote(bodyTrim.slice('version '.length));
        i++;
      } else if (bodyTrim === 'dependencies:' || bodyTrim === 'optionalDependencies:') {
        const blockIndent = indent;
        i++;
        while (i < n && indentOf(lines[i]!) > blockIndent && lines[i]!.trim() !== '') {
          const depLine = lines[i]!.trim();
          const spaceIdx = depLine.indexOf(' ');
          if (spaceIdx > 0) deps.push({ name: unquote(depLine.slice(0, spaceIdx)), range: unquote(depLine.slice(spaceIdx + 1)) });
          i++;
        }
      } else {
        i++;
      }
    }
    if (specs.length > 0) entries.push({ specs, version, deps });
  }
  return entries;
}

// --- Berry (YAML) ----------------------------------------------------------------------------------

function parseBerryEntries(content: string): YarnEntry[] {
  const raw = parseYaml(content, { maxAliasCount: 1000, uniqueKeys: false });
  if (!isPlainObject(raw)) return [];
  const entries: YarnEntry[] = [];
  for (const [headerKey, val] of safeEntries(raw)) {
    if (headerKey === '__metadata' || !isPlainObject(val)) continue;
    const specs = splitHeaderSpecs(headerKey)
      .map(parseYarnSpec)
      .filter((s): s is Spec => s !== null);
    if (specs.length === 0) continue;
    const version = typeof val.version === 'string' ? val.version : 'unknown';
    const deps: Spec[] = [];
    for (const [depName, depRange] of safeEntries(val.dependencies)) if (typeof depRange === 'string') deps.push({ name: depName, range: depRange });
    for (const [depName, depRange] of safeEntries(val.optionalDependencies)) if (typeof depRange === 'string') deps.push({ name: depName, range: depRange });
    entries.push({ specs, version, deps });
  }
  return entries;
}

// --- shared graph construction -----------------------------------------------------------------

function buildYarnGraph(builder: GraphBuilder, entries: YarnEntry[], manifestDirect?: Map<string, { range: string; scope: DepScope }>): void {
  const key = (name: string, range: string) => `${name}@${stripNpmProtocol(range)}`;
  const specIndex = new Map<string, number>();
  entries.forEach((e, idx) => {
    for (const spec of e.specs) specIndex.set(key(spec.name, spec.range), idx);
  });

  for (const e of entries) {
    if (builder.atCap()) break;
    const name = e.specs[0]?.name;
    if (name) builder.node(name, e.version);
  }

  for (const e of entries) {
    const name = e.specs[0]?.name;
    if (!name) continue;
    const parentKey = depKey(builder.ecosystem, name, e.version);
    for (const dep of e.deps) {
      const targetIdx = specIndex.get(key(dep.name, dep.range));
      if (targetIdx === undefined) continue;
      const target = entries[targetIdx]!;
      const targetName = target.specs[0]?.name;
      if (!targetName) continue;
      builder.edge(parentKey, depKey(builder.ecosystem, targetName, target.version));
    }
  }

  if (manifestDirect) {
    for (const [name, { range, scope }] of manifestDirect) {
      const idx = specIndex.get(key(name, range));
      if (idx === undefined) continue;
      const target = entries[idx]!;
      const targetName = target.specs[0]?.name ?? name;
      builder.node(targetName, target.version);
      builder.markDirect(depKey(builder.ecosystem, targetName, target.version), scope, range);
    }
  } else {
    for (const e of entries) {
      const name = e.specs[0]?.name;
      if (name) builder.markDirect(depKey(builder.ecosystem, name, e.version), 'prod');
    }
    builder.warn('yarn.lock: no sibling package.json; all packages treated as direct prod deps');
  }
}

/** Parses yarn.lock (classic v1 or Berry) into a DepGraph. Never throws. */
export function parseYarnLock(ref: LockfileRef, content: string, manifest?: string): DepGraph {
  const builder = new GraphBuilder('npm');
  try {
    const isBerry = /^__metadata:/m.test(content);
    const entries = isBerry ? parseBerryEntries(content) : parseV1Entries(content);
    buildYarnGraph(builder, entries, manifest ? extractManifestDirect(manifest) : undefined);
  } catch (err) {
    builder.warn(`failed to parse yarn.lock at ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'lockfile');
}
