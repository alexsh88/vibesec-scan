// Public surface of the lockfile/manifest -> DepGraph pipeline: discovery, per-format parsing
// (dispatched by LockfileRef.kind), the full repo-scan orchestrator, and the shared graph utilities.

import { open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type { IndexedFile } from '../../../index/types';
import type { DepGraph } from '../types';
import { discoverLockfiles, type LockfileKind, type LockfileRef } from './discover';
import { errMsg } from './graph';
import { extractManifestDirect, parseNpmLockfile, parsePackageJsonManifestOnly } from './npm';
import { parsePnpmLock } from './pnpm';
import { buildRequirementsGraph, parsePipfileLock, parsePoetryLock, parsePyprojectManifestOnly, parseUvLock } from './python';
import { parseYarnLock } from './yarn';

export type { LockfileKind, LockfileRef } from './discover';
export { discoverLockfiles } from './discover';
export { normalizePypiName, pathsTo } from './graph';

/** Dispatches one already-read lockfile/manifest to its format parser. Never throws — each parser
 *  catches its own per-file errors and returns a DepGraph carrying a warning instead. */
export function parseLockfile(ref: LockfileRef, content: string, manifest?: string): DepGraph {
  switch (ref.kind) {
    case 'package-lock':
    case 'npm-shrinkwrap':
      return parseNpmLockfile(ref, content, manifest);
    case 'package-json':
      return parsePackageJsonManifestOnly(ref, content);
    case 'pnpm-lock':
      return parsePnpmLock(ref, content);
    case 'yarn-lock':
      return parseYarnLock(ref, content, manifest);
    case 'poetry-lock':
      return parsePoetryLock(ref, content, manifest);
    case 'uv-lock':
      return parseUvLock(ref, content, manifest);
    case 'pipfile-lock':
      return parsePipfileLock(ref, content, manifest);
    case 'pyproject':
      return parsePyprojectManifestOnly(ref, content);
    case 'requirements':
      return buildRequirementsGraph(ref, new Map([[basename(ref.path), content]]));
    /* c8 ignore next 3 */
    default: {
      const neverKind: never = ref.kind;
      throw new Error(`unsupported lockfile kind: ${String(neverKind)}`);
    }
  }
}

function basename(p: string): string {
  const parts = p.split('/');
  return parts[parts.length - 1] ?? p;
}

function joinRel(dir: string, base: string): string {
  return dir === '' ? base : `${dir}/${base}`;
}

const DEFAULT_MAX_BYTES = 20 * 1024 * 1024;

export type ParseDependencyGraphsOptions = {
  repoDir: string;
  files: readonly IndexedFile[];
  signal: AbortSignal;
  /** @default 20 MiB */
  maxBytes?: number;
};

/**
 * Discovers every lockfile/manifest in the repo and parses each into a DepGraph. Reads are bounded
 * by `maxBytes` and guarded against escaping `repoDir` (mirrors the approach in
 * credentials/scanText.ts: open + stat + bounded read, never trust the path alone). Never throws for
 * malformed file content — only for cancellation (`signal` aborted).
 */
export async function parseDependencyGraphs(opts: ParseDependencyGraphsOptions): Promise<{ graphs: DepGraph[]; warnings: string[] }> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const resolvedRepoDir = resolve(opts.repoDir);
  const repoDirPrefix = resolvedRepoDir + sep;
  const isWithinRepoDir = (absPath: string) => absPath === resolvedRepoDir || absPath.startsWith(repoDirPrefix);
  const warnings: string[] = [];

  const readSafe = async (repoRelPath: string): Promise<string | null> => {
    const abs = resolve(join(opts.repoDir, ...repoRelPath.split('/')));
    if (!isWithinRepoDir(abs)) return null;
    const handle = await open(abs, 'r').catch(() => null);
    if (!handle) return null;
    try {
      const { size } = await handle.stat();
      if (size > maxBytes) {
        warnings.push(`${repoRelPath}: skipped, exceeds max size (${size} > ${maxBytes} bytes)`);
        return null;
      }
      if (size === 0) return '';
      const buffer = Buffer.allocUnsafe(size);
      let bytesRead = 0;
      while (bytesRead < size) {
        const { bytesRead: n } = await handle.read(buffer, bytesRead, size - bytesRead, bytesRead);
        if (n === 0) break;
        bytesRead += n;
      }
      return buffer.subarray(0, bytesRead).toString('utf8');
    } catch {
      return null;
    } finally {
      await handle.close();
    }
  };

  const refs = discoverLockfiles(opts.files);
  const graphs: DepGraph[] = [];

  const requirementsByDir = new Map<string, LockfileRef[]>();
  for (const ref of refs) {
    if (ref.kind !== 'requirements') continue;
    const list = requirementsByDir.get(ref.manifestDir);
    if (list) list.push(ref);
    else requirementsByDir.set(ref.manifestDir, [ref]);
  }

  for (const ref of refs) {
    if (opts.signal.aborted) throw opts.signal.reason;
    if (ref.kind === 'requirements') continue; // handled per-directory below

    const content = await readSafe(ref.path);
    if (content === null) continue;

    let manifest: string | undefined;
    if (ref.kind === 'package-lock' || ref.kind === 'npm-shrinkwrap' || ref.kind === 'yarn-lock') {
      const pj = await readSafe(joinRel(ref.manifestDir, 'package.json'));
      if (pj !== null) manifest = pj;
    } else if (ref.kind === 'poetry-lock' || ref.kind === 'uv-lock') {
      const pp = await readSafe(joinRel(ref.manifestDir, 'pyproject.toml'));
      if (pp !== null) manifest = pp;
    } else if (ref.kind === 'pipfile-lock') {
      const pf = await readSafe(joinRel(ref.manifestDir, 'Pipfile'));
      if (pf !== null) manifest = pf;
    }

    try {
      graphs.push(parseLockfile(ref, content, manifest));
    } catch (err) {
      warnings.push(`${ref.path}: ${errMsg(err)}`);
    }
  }

  // requirements*.txt: read every sibling once per directory so `-r` includes resolve across them.
  for (const [, dirRefs] of requirementsByDir) {
    if (opts.signal.aborted) throw opts.signal.reason;
    const filesInDir = new Map<string, string>();
    for (const ref of dirRefs) {
      const content = await readSafe(ref.path);
      if (content !== null) filesInDir.set(basename(ref.path), content);
    }
    for (const ref of dirRefs) {
      if (!filesInDir.has(basename(ref.path))) continue;
      try {
        graphs.push(buildRequirementsGraph(ref, filesInDir));
      } catch (err) {
        warnings.push(`${ref.path}: ${errMsg(err)}`);
      }
    }
  }

  return { graphs, warnings };
}

// Re-exported for tests/consumers that need the manifest-direct extraction used by the npm/yarn
// parsers (e.g. to build a manifest string that behaves consistently with the parsers under test).
export { extractManifestDirect };
