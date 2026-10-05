// Python ecosystem: poetry.lock / uv.lock (TOML, real dependency edges), Pipfile.lock (JSON, no
// edges — pipenv discards the tree), and requirements*.txt (flat, no tree either; only exact pins
// resolve to a version). Directness for the TOML-locked formats comes from pyproject.toml; for
// Pipfile.lock from the sibling Pipfile; requirements files ARE the direct declarations.

import { posix } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { DepGraph, DepScope } from '../types';
import type { LockfileRef } from './discover';
import { depKey, errMsg, GraphBuilder, isPlainObject, normalizePypiName, safeEntries, safeKeys } from './graph';

type JsonRecord = Record<string, unknown>;

function basenameOf(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] ?? p;
}

/** First PEP 508 token of a dependency spec, e.g. "requests>=2,<3; python_version>='3.8'" -> "requests". */
function pep508Name(spec: string): string {
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(spec);
  return m ? m[1]! : spec.trim();
}

/** Everything after the name (and optional `[extras]`) of a PEP 508 spec, e.g.
 *  "requests[security]>=2,<3" -> ">=2,<3"; "click" (no specifier at all) -> "*". */
function pep508Range(spec: string): string {
  const m = /^\s*[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*(.*)$/.exec(spec);
  const rest = (m?.[2] ?? '').trim();
  return rest.length > 0 ? rest : '*';
}

// --- pyproject.toml: direct-dependency extraction (shared by poetry.lock / uv.lock) ---------------

function addDirect(out: Map<string, { scope: DepScope }>, rawName: string, scope: DepScope): void {
  const name = rawName.trim();
  if (name.length === 0 || normalizePypiName(name) === 'python') return;
  const prev = out.get(name);
  if (!prev || (prev.scope !== 'prod' && scope === 'prod')) out.set(name, { scope });
}

export function extractPyprojectDirect(content: string): Map<string, { scope: DepScope }> | undefined {
  try {
    const raw = parseToml(content) as JsonRecord;
    if (!isPlainObject(raw)) return undefined;
    const out = new Map<string, { scope: DepScope }>();

    const tool = isPlainObject(raw.tool) ? raw.tool : undefined;
    const poetry = tool && isPlainObject(tool.poetry) ? tool.poetry : undefined;
    if (poetry) {
      for (const name of safeKeys(poetry.dependencies)) addDirect(out, name, 'prod');
      const group = isPlainObject(poetry.group) ? poetry.group : undefined;
      if (group) {
        for (const groupVal of Object.values(group)) {
          if (!isPlainObject(groupVal)) continue;
          for (const name of safeKeys(groupVal.dependencies)) addDirect(out, name, 'dev');
        }
      }
    }

    const project = isPlainObject(raw.project) ? raw.project : undefined;
    if (project) {
      if (Array.isArray(project.dependencies)) {
        for (const spec of project.dependencies) if (typeof spec === 'string') addDirect(out, pep508Name(spec), 'prod');
      }
      const optional = isPlainObject(project['optional-dependencies']) ? project['optional-dependencies'] : undefined;
      if (optional) {
        for (const specs of Object.values(optional)) {
          if (!Array.isArray(specs)) continue;
          for (const spec of specs) if (typeof spec === 'string') addDirect(out, pep508Name(spec), 'dev');
        }
      }
    }

    const depGroups = isPlainObject(raw['dependency-groups']) ? raw['dependency-groups'] : undefined;
    if (depGroups) {
      for (const specs of Object.values(depGroups)) {
        if (!Array.isArray(specs)) continue;
        for (const spec of specs) if (typeof spec === 'string') addDirect(out, pep508Name(spec), 'dev');
      }
    }

    return out.size > 0 ? out : undefined;
  } catch {
    return undefined;
  }
}

function applyPyDirect(
  builder: GraphBuilder,
  byNorm: Map<string, { name: string; version: string }>,
  pyprojectContent: string | undefined,
  label: string,
): void {
  const direct = pyprojectContent ? extractPyprojectDirect(pyprojectContent) : undefined;
  if (direct) {
    for (const [rawName, { scope }] of direct) {
      const target = byNorm.get(normalizePypiName(rawName));
      if (target) builder.markDirect(depKey('PyPI', target.name, target.version), scope);
    }
  } else {
    for (const { name, version } of byNorm.values()) builder.markDirect(depKey('PyPI', name, version), 'prod');
    builder.warn(`${label}: no sibling pyproject.toml; all packages treated as direct prod deps`);
  }
}

// --- poetry.lock -----------------------------------------------------------------------------------

export function parsePoetryLock(ref: LockfileRef, content: string, pyprojectContent?: string): DepGraph {
  const builder = new GraphBuilder('PyPI');
  try {
    const raw = parseToml(content) as JsonRecord;
    const packages = Array.isArray(raw.package) ? raw.package : [];
    const byNorm = new Map<string, { name: string; version: string }>();

    for (const p of packages) {
      if (!isPlainObject(p) || typeof p.name !== 'string') continue;
      const name = normalizePypiName(p.name);
      const version = typeof p.version === 'string' ? p.version : 'unknown';
      byNorm.set(name, { name, version });
      if (!builder.atCap()) builder.node(name, version);
    }
    for (const p of packages) {
      if (!isPlainObject(p) || typeof p.name !== 'string') continue;
      const name = normalizePypiName(p.name);
      const version = typeof p.version === 'string' ? p.version : 'unknown';
      const parentKey = depKey('PyPI', name, version);
      for (const depNameRaw of safeKeys(p.dependencies)) {
        const depNorm = normalizePypiName(depNameRaw);
        if (depNorm === 'python') continue;
        const target = byNorm.get(depNorm);
        if (target) builder.edge(parentKey, depKey('PyPI', target.name, target.version));
      }
    }

    applyPyDirect(builder, byNorm, pyprojectContent, 'poetry.lock');
  } catch (err) {
    builder.warn(`failed to parse poetry.lock at ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'lockfile');
}

// --- uv.lock ---------------------------------------------------------------------------------------

export function parseUvLock(ref: LockfileRef, content: string, pyprojectContent?: string): DepGraph {
  const builder = new GraphBuilder('PyPI');
  try {
    const raw = parseToml(content) as JsonRecord;
    const packages = Array.isArray(raw.package) ? raw.package : [];
    const byNorm = new Map<string, { name: string; version: string }>();

    for (const p of packages) {
      if (!isPlainObject(p) || typeof p.name !== 'string') continue;
      const name = normalizePypiName(p.name);
      const version = typeof p.version === 'string' ? p.version : 'unknown';
      byNorm.set(name, { name, version });
      if (!builder.atCap()) builder.node(name, version);
    }
    for (const p of packages) {
      if (!isPlainObject(p) || typeof p.name !== 'string') continue;
      const name = normalizePypiName(p.name);
      const version = typeof p.version === 'string' ? p.version : 'unknown';
      const parentKey = depKey('PyPI', name, version);
      const deps = Array.isArray(p.dependencies) ? p.dependencies : [];
      for (const d of deps) {
        if (!isPlainObject(d) || typeof d.name !== 'string') continue;
        const depNorm = normalizePypiName(d.name);
        if (depNorm === 'python') continue;
        const target = byNorm.get(depNorm);
        if (target) builder.edge(parentKey, depKey('PyPI', target.name, target.version));
      }
    }

    applyPyDirect(builder, byNorm, pyprojectContent, 'uv.lock');
  } catch (err) {
    builder.warn(`failed to parse uv.lock at ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'lockfile');
}

// --- Pipfile.lock ----------------------------------------------------------------------------------

function pipfileVersionOf(info: unknown): string {
  if (!isPlainObject(info)) return 'unknown';
  if (typeof info.version === 'string') return info.version.startsWith('==') ? info.version.slice(2) : info.version;
  if (typeof info.ref === 'string') return info.ref;
  return 'unknown';
}

function extractPipfileDirect(content: string): Set<string> | undefined {
  try {
    const raw = parseToml(content) as JsonRecord;
    if (!isPlainObject(raw)) return undefined;
    const out = new Set<string>();
    for (const name of safeKeys(raw.packages)) out.add(normalizePypiName(name));
    for (const name of safeKeys(raw['dev-packages'])) out.add(normalizePypiName(name));
    return out.size > 0 ? out : undefined;
  } catch {
    return undefined;
  }
}

/** Pipfile.lock has no dependency tree: every entry in `default`/`develop` is a flat, scope-tagged
 *  node. `direct` is narrowed to the sibling Pipfile's declared set when available (contract: "else
 *  all"), independent of the scope every node still needs (computed from its section, not reachability,
 *  since there are no edges to propagate through). */
export function parsePipfileLock(ref: LockfileRef, content: string, pipfileContent?: string): DepGraph {
  const builder = new GraphBuilder('PyPI');
  const trueDirect = new Set<string>();
  try {
    const raw = JSON.parse(content);
    if (!isPlainObject(raw)) throw new Error('top-level value is not an object');
    const sections: [unknown, DepScope][] = [
      [raw.default, 'prod'],
      [raw.develop, 'dev'],
    ];
    const pipfileDirect = pipfileContent ? extractPipfileDirect(pipfileContent) : undefined;

    for (const [sectionVal, scope] of sections) {
      for (const [rawName, info] of safeEntries(sectionVal)) {
        const name = normalizePypiName(rawName);
        const version = pipfileVersionOf(info);
        if (!builder.atCap()) builder.node(name, version);
        builder.markDirect(depKey('PyPI', name, version), scope);
        if (!pipfileDirect || pipfileDirect.has(name)) trueDirect.add(name);
      }
    }
    if (!pipfileContent) builder.warn('Pipfile.lock: no sibling Pipfile; every package treated as direct');
  } catch (err) {
    builder.warn(`failed to parse Pipfile.lock at ${ref.path}: ${errMsg(err)}`);
  }

  const graph = builder.build(ref.path, ref.manifestDir, 'lockfile');
  graph.roots = graph.roots.filter((k) => {
    const n = graph.nodes.get(k);
    return n !== undefined && trueDirect.has(n.name);
  });
  for (const n of graph.nodes.values()) n.direct = trueDirect.has(n.name);
  return graph;
}

// --- requirements*.txt -------------------------------------------------------------------------

type ReqEntry =
  | { kind: 'pin'; name: string; version: string }
  | { kind: 'unpinned'; name: string; specifier: string }
  | { kind: 'include'; target: string };

function stripComment(line: string): string {
  const idx = line.indexOf('#');
  return idx === -1 ? line : line.slice(0, idx);
}

/** Parses one requirement "name[extras]<specifier>" fragment (markers/hash options already removed
 *  by the caller). Returns null for anything that isn't a plain name-based requirement (direct URL
 *  refs, VCS specs, stray tokens). */
function parseRequirementSpec(specPart: string): { name: string; version: string } | { name: string; specifier: string } | null {
  const s = specPart.trim();
  if (s.length === 0 || /\s@\s/.test(s)) return null;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$/.exec(s);
  if (!m) return null;
  const name = m[1]!;
  const restFull = (m[3] ?? '').trim();
  if (restFull.length === 0) return { name, specifier: '' };
  const restToken = restFull.split(/\s+/)[0]!; // drop trailing --hash=... / other pip options
  if (!/^(==|>=|<=|~=|!=|===|>|<)/.test(restToken)) return null;
  if (restToken.startsWith('==')) {
    const version = restToken.slice(2).trim();
    return version.length > 0 ? { name, version } : { name, specifier: restToken };
  }
  return { name, specifier: restToken };
}

function parseRequirementsLines(content: string): ReqEntry[] {
  const rawLines = content.split(/\r?\n/);
  const joined: string[] = [];
  let buf = '';
  for (const line of rawLines) {
    const l = buf + line;
    if (l.endsWith('\\')) {
      buf = l.slice(0, -1);
      continue;
    }
    buf = '';
    joined.push(l);
  }
  if (buf.length > 0) joined.push(buf);

  const out: ReqEntry[] = [];
  for (const rawLine of joined) {
    const trimmed = stripComment(rawLine).trim();
    if (trimmed.length === 0) continue;
    const incMatch = /^(?:-r|--requirement)\s+(.+)$/.exec(trimmed);
    if (incMatch) {
      out.push({ kind: 'include', target: incMatch[1]!.trim() });
      continue;
    }
    if (trimmed.startsWith('-')) continue; // -e, --index-url, --no-binary, …
    const specPart = trimmed.split(';')[0]!;
    const parsed = parseRequirementSpec(specPart);
    if (!parsed) continue;
    out.push('version' in parsed ? { kind: 'pin', name: parsed.name, version: parsed.version } : { kind: 'unpinned', name: parsed.name, specifier: parsed.specifier });
  }
  return out;
}

/** Builds the flat graph for one requirements*.txt entry point, following same-directory `-r`
 *  includes (cycle-safe) against the full set of sibling requirements files read by the caller. */
export function buildRequirementsGraph(ref: LockfileRef, filesInDir: ReadonlyMap<string, string>): DepGraph {
  const builder = new GraphBuilder('PyPI');
  const scope: DepScope = /dev|test/i.test(posix.basename(ref.path)) ? 'dev' : 'prod';
  const visitedFiles = new Set<string>();

  const visit = (basename: string): void => {
    if (visitedFiles.has(basename)) return;
    visitedFiles.add(basename);
    const content = filesInDir.get(basename);
    if (content === undefined) {
      builder.warnOnce(`missing:${basename}`, `requirements include not found: ${basename}`);
      return;
    }
    let entries: ReqEntry[];
    try {
      entries = parseRequirementsLines(content);
    } catch (err) {
      builder.warn(`failed to parse ${basename}: ${errMsg(err)}`);
      return;
    }
    for (const entry of entries) {
      if (builder.atCap()) break;
      if (entry.kind === 'include') {
        visit(basenameOf(entry.target));
      } else if (entry.kind === 'pin') {
        const name = normalizePypiName(entry.name);
        const node = builder.node(name, entry.version);
        builder.markDirect(node.key, scope, entry.version);
      } else {
        const name = normalizePypiName(entry.name);
        const version = entry.specifier.length > 0 ? entry.specifier : 'unknown';
        const node = builder.node(name, version);
        builder.markDirect(node.key, scope, entry.specifier);
        builder.warn(`${basename}: unpinned requirement "${entry.name}${entry.specifier}" recorded with specifier as version`);
      }
    }
  };

  visit(posix.basename(ref.path));
  return builder.build(ref.path, ref.manifestDir, 'lockfile');
}

// --- pyproject.toml manifest-only (no lockfile at all) --------------------------------------------

function addManifestOnly(builder: GraphBuilder, rawName: string, range: string, scope: DepScope): void {
  const name = normalizePypiName(rawName);
  const node = builder.node(name, range);
  builder.markDirect(node.key, scope, range);
}

export function parsePyprojectManifestOnly(ref: LockfileRef, content: string): DepGraph {
  const builder = new GraphBuilder('PyPI');
  try {
    const raw = parseToml(content) as JsonRecord;
    let any = false;

    const tool = isPlainObject(raw.tool) ? raw.tool : undefined;
    const poetry = tool && isPlainObject(tool.poetry) ? tool.poetry : undefined;
    if (poetry) {
      for (const [name, rangeRaw] of safeEntries(poetry.dependencies)) {
        if (normalizePypiName(name) === 'python') continue;
        const range = typeof rangeRaw === 'string' ? rangeRaw : isPlainObject(rangeRaw) && typeof rangeRaw.version === 'string' ? rangeRaw.version : '*';
        addManifestOnly(builder, name, range, 'prod');
        any = true;
      }
      const group = isPlainObject(poetry.group) ? poetry.group : undefined;
      if (group) {
        for (const groupVal of Object.values(group)) {
          if (!isPlainObject(groupVal)) continue;
          for (const [name, rangeRaw] of safeEntries(groupVal.dependencies)) {
            addManifestOnly(builder, name, typeof rangeRaw === 'string' ? rangeRaw : '*', 'dev');
            any = true;
          }
        }
      }
    }

    const project = isPlainObject(raw.project) ? raw.project : undefined;
    if (project) {
      if (Array.isArray(project.dependencies)) {
        for (const spec of project.dependencies) {
          if (typeof spec !== 'string') continue;
          addManifestOnly(builder, pep508Name(spec), pep508Range(spec), 'prod');
          any = true;
        }
      }
      const optional = isPlainObject(project['optional-dependencies']) ? project['optional-dependencies'] : undefined;
      if (optional) {
        for (const specs of Object.values(optional)) {
          if (!Array.isArray(specs)) continue;
          for (const spec of specs) {
            if (typeof spec !== 'string') continue;
            addManifestOnly(builder, pep508Name(spec), pep508Range(spec), 'dev');
            any = true;
          }
        }
      }
    }

    const depGroups = isPlainObject(raw['dependency-groups']) ? raw['dependency-groups'] : undefined;
    if (depGroups) {
      for (const specs of Object.values(depGroups)) {
        if (!Array.isArray(specs)) continue;
        for (const spec of specs) {
          if (typeof spec !== 'string') continue;
          addManifestOnly(builder, pep508Name(spec), pep508Range(spec), 'dev');
          any = true;
        }
      }
    }

    if (!any) builder.warn('pyproject.toml: no recognizable dependency tables found');
    builder.warn(`${ref.path}: no lockfile found; versions are unresolved manifest ranges`);
  } catch (err) {
    builder.warn(`failed to parse ${ref.path}: ${errMsg(err)}`);
  }
  return builder.build(ref.path, ref.manifestDir, 'manifest-only');
}
