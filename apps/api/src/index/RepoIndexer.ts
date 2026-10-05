import { lstat, open, readFile } from 'node:fs/promises';
import { join, posix, resolve, sep } from 'node:path';
import { AppError } from '../errors/AppError';
import type { GitService } from '../git/GitService';
import { categoryOf, isLockfile, languageOf, skipReasonForContent, skipReasonForPath, tagsOf } from './classify';
import { detectEntrypoints, packageJsonBins } from './entrypoints';
import { extractJsImports, parsePathConfig, resolveJsImport, type PathConfig } from './jsImports';
import { extractPyImports, pythonRoots, resolvePyImport } from './pyImports';
import type { Entrypoint, ImportEdge, IndexedFile, IndexStats, RepoIndex } from './types';

export type RepoIndexerOptions = { maxFiles: number; maxFileBytes: number };
export type IndexRunOptions = { signal?: AbortSignal; touch?: () => void; onProgress?: (done: number, total: number) => void };

const HEAD_BYTES = 8_192;
const CONCURRENCY = 32;
const MANIFEST_BASENAMES = new Set(['package.json', 'pyproject.toml', 'setup.py', 'composer.json', 'go.mod', 'Cargo.toml']);

/** Directories (repo-relative, '' for the root) that directly contain a project manifest file. */
function manifestDirsOf(tree: readonly { path: string }[]): Set<string> {
  const dirs = new Set<string>();
  for (const entry of tree) {
    if (!MANIFEST_BASENAMES.has(posix.basename(entry.path))) continue;
    const dir = posix.dirname(entry.path);
    dirs.add(dir === '.' ? '' : dir);
  }
  return dirs;
}

export class RepoIndexer {
  constructor(private readonly git: Pick<GitService, 'listTree'>, private readonly opts: RepoIndexerOptions) {}

  async index(dir: string, sha: string, run: IndexRunOptions = {}): Promise<RepoIndex> {
    const check = () => {
      if (run.signal?.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    };
    check();
    const tree = (await this.git.listTree(dir, sha, { signal: run.signal }))
      .filter((e) => e.type === 'blob' || e.type === 'commit')
      .sort((a, b) => (a.path < b.path ? -1 : 1));
    const abs = (p: string) => join(dir, ...p.split('/'));
    const resolvedDirPrefix = resolve(dir) + sep;
    /** Safety backstop: a tree path must resolve to somewhere strictly inside `dir`. */
    const isWithinDir = (p: string) => resolve(abs(p)).startsWith(resolvedDirPrefix);

    // 1. Path-level decisions, deterministically in path order (including the maxFiles cut-off).
    const manifestDirs = manifestDirsOf(tree);
    let considered = 0;
    let truncated = false;
    const pathSkips = tree.map((entry) => {
      const reason = skipReasonForPath(entry.path, entry.mode, entry.type, manifestDirs);
      if (reason || isLockfile(entry.path)) return reason;
      if (considered >= this.opts.maxFiles) {
        truncated = true;
        return 'file_limit' as const;
      }
      considered++;
      return null;
    });

    // 2. Content-level decisions (size, binary, minified, generated) with bounded concurrency.
    const files: IndexedFile[] = [];
    await forEachLimit(tree, CONCURRENCY, async (entry, i) => {
      check();
      const language = languageOf(entry.path);
      const category = categoryOf(entry.path, language);
      let skipReason = pathSkips[i] ?? null;
      let size = 0;
      if (skipReason === null) {
        if (!isWithinDir(entry.path)) {
          // Resolves outside the checkout dir (e.g. a path-traversal-like tree entry): treat as unsafe.
          skipReason = 'symlink';
        } else {
          const stat = await lstat(abs(entry.path)).catch(() => null);
          if (!stat) throw new AppError('INTERNAL', 'permanent', `The checkout is incomplete (missing ${entry.path})`);
          size = stat.size;
          skipReason = skipReasonForContent(entry.path, size, await readHead(abs(entry.path)), this.opts.maxFileBytes);
        }
      }
      files[i] = { path: entry.path, blobSha: entry.blobSha, size, language, category, tags: tagsOf(entry.path), skipReason };
      if (i % 200 === 0) {
        run.touch?.();
        run.onProgress?.(i, tree.length * 2);
      }
    });

    // 3. Resolution context from the non-skipped files.
    const kept = files.filter((f) => f.skipReason === null);
    const keptPaths = new Set(kept.map((f) => f.path));
    const pathConfigs: PathConfig[] = [];
    for (const f of kept) {
      const base = posix.basename(f.path);
      if (base !== 'tsconfig.json' && base !== 'jsconfig.json') continue;
      const cfg = parsePathConfig(posix.dirname(f.path) === '.' ? '' : posix.dirname(f.path), await readFile(abs(f.path), 'utf8'));
      if (cfg) pathConfigs.push(cfg);
    }
    const pyRoots = pythonRoots(new Set(files.map((f) => f.path)));

    // 4. Imports and entrypoints from source files.
    const imports: ImportEdge[][] = [];
    const entrypoints: Entrypoint[][] = [];
    const sources = kept.filter((f) => f.category === 'source');
    await forEachLimit(sources, CONCURRENCY, async (f, i) => {
      check();
      const content = await readFile(abs(f.path), 'utf8');
      const edges: ImportEdge[] = [];
      if (f.language === 'python') {
        for (const imp of extractPyImports(content)) {
          for (const r of resolvePyImport(f.path, imp, { files: keptPaths, roots: pyRoots })) {
            edges.push({ from: f.path, ...r, line: imp.line });
          }
        }
      } else {
        for (const raw of extractJsImports(content)) {
          edges.push({ from: f.path, specifier: raw.specifier, ...resolveJsImport(f.path, raw.specifier, { files: keptPaths, pathConfigs }), line: raw.line });
        }
      }
      imports[i] = edges;
      entrypoints[i] = detectEntrypoints(f.path, content);
      if (i % 100 === 0) {
        run.touch?.();
        run.onProgress?.(tree.length + Math.round((i / Math.max(sources.length, 1)) * tree.length), tree.length * 2);
      }
    });

    const allEntrypoints = entrypoints.flat();
    for (const f of kept) {
      if (posix.basename(f.path) === 'package.json') {
        allEntrypoints.push(...packageJsonBins(f.path, await readFile(abs(f.path), 'utf8')));
      }
    }
    const allImports = imports.flat();
    run.touch?.();
    run.onProgress?.(tree.length * 2, tree.length * 2);

    return { files, imports: allImports, entrypoints: allEntrypoints, stats: buildStats(files, allImports, allEntrypoints, truncated) };
  }
}

async function readHead(path: string): Promise<Buffer> {
  const handle = await open(path, 'r').catch(() => null);
  if (!handle) return Buffer.alloc(0);
  try {
    const buffer = Buffer.alloc(HEAD_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, HEAD_BYTES, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

/** Runs `fn` over `items` with at most `limit` in flight, preserving index positions. */
async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

function buildStats(files: IndexedFile[], imports: ImportEdge[], entrypoints: Entrypoint[], truncated: boolean): IndexStats {
  const skipped: IndexStats['skipped'] = {};
  const byLanguage: IndexStats['byLanguage'] = {};
  let indexed = 0;
  for (const f of files) {
    if (f.skipReason) {
      skipped[f.skipReason] = (skipped[f.skipReason] ?? 0) + 1;
    } else {
      indexed++;
      byLanguage[f.language] = (byLanguage[f.language] ?? 0) + 1;
    }
  }
  return { totalFiles: files.length, indexedFiles: indexed, skipped, byLanguage, imports: imports.length, entrypoints: entrypoints.length, truncated };
}
