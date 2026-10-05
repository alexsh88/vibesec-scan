import { readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { discoverLockfiles, parseDependencyGraphs } from '../src/analyzers/dependencies/lockfiles/index';
import type { IndexedFile } from '../src/index/types';

function fixtureDir(rel: string): string {
  return fileURLToPath(new URL(`./fixtures/lockfiles/${rel}`, import.meta.url));
}

async function listFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  const out: string[] = [];
  for (const e of entries) {
    if (!e.isFile()) continue;
    const abs = join(e.parentPath, e.name);
    out.push(relative(dir, abs).split(sep).join('/'));
  }
  return out.sort();
}

function idxFile(path: string, skipReason: IndexedFile['skipReason'] = null): IndexedFile {
  return { path, blobSha: 'x', size: 0, language: 'other', category: 'other', tags: [], skipReason };
}

describe('discoverLockfiles', () => {
  it('picks the right file per directory under npm/python precedence (shrinkwrap > lock > pnpm > yarn; lock-style python > requirements > manifest-only)', async () => {
    const dir = fixtureDir('precedence');
    const paths = await listFiles(dir);
    const refs = discoverLockfiles(paths.map((p) => idxFile(p)));
    const byDir = new Map(refs.map((r) => [r.manifestDir, r]));

    expect(byDir.get('npm-lock-and-yarn')).toEqual({ path: 'npm-lock-and-yarn/package-lock.json', kind: 'package-lock', manifestDir: 'npm-lock-and-yarn' });
    expect(byDir.get('npm-shrinkwrap-wins')).toEqual({ path: 'npm-shrinkwrap-wins/npm-shrinkwrap.json', kind: 'npm-shrinkwrap', manifestDir: 'npm-shrinkwrap-wins' });
    expect(byDir.get('python-poetry-wins')).toEqual({ path: 'python-poetry-wins/poetry.lock', kind: 'poetry-lock', manifestDir: 'python-poetry-wins' });
    expect(byDir.get('no-lockfile')).toEqual({ path: 'no-lockfile/package.json', kind: 'package-json', manifestDir: 'no-lockfile' });
    expect(byDir.get('no-lockfile-py')).toEqual({ path: 'no-lockfile-py/pyproject.toml', kind: 'pyproject', manifestDir: 'no-lockfile-py' });

    // yarn.lock / package-lock.json / requirements.txt that lost precedence must not also appear.
    expect(refs.filter((r) => r.manifestDir === 'npm-lock-and-yarn')).toHaveLength(1);
    expect(refs.filter((r) => r.manifestDir === 'npm-shrinkwrap-wins')).toHaveLength(1);
    expect(refs.filter((r) => r.manifestDir === 'python-poetry-wins')).toHaveLength(1);
  });

  it('discovers a monorepo with two independent package directories, and skips vendored dirs regardless of skipReason', async () => {
    const dir = fixtureDir('monorepo');
    const paths = await listFiles(dir);
    const refs = discoverLockfiles(paths.map((p) => idxFile(p)));

    expect(refs).toContainEqual({ path: 'apps/web/package-lock.json', kind: 'package-lock', manifestDir: 'apps/web' });
    expect(refs).toContainEqual({ path: 'services/worker/requirements.txt', kind: 'requirements', manifestDir: 'services/worker' });
    expect(refs).toContainEqual({ path: 'services/worker/requirements-dev.txt', kind: 'requirements', manifestDir: 'services/worker' });
    expect(refs.some((r) => r.path.includes('node_modules'))).toBe(false);
  });

  it('never discovers binary/symlink/submodule-skipped files, but does discover too_large/generated/lockfile-skipped ones', () => {
    const files: IndexedFile[] = [
      idxFile('a/package-lock.json', 'too_large'),
      idxFile('b/package-lock.json', 'generated'),
      idxFile('c/package-lock.json', null),
      idxFile('d/package-lock.json', 'binary'),
      idxFile('e/package-lock.json', 'symlink'),
      idxFile('f/package-lock.json', 'submodule'),
    ];
    const refs = discoverLockfiles(files);
    const dirs = refs.map((r) => r.manifestDir).sort();
    expect(dirs).toEqual(['a', 'b', 'c']);
  });

  it('ignores vendored directories by name even with skipReason null', () => {
    const files: IndexedFile[] = [
      idxFile('node_modules/pkg/package-lock.json'),
      idxFile('vendor/pkg/package-lock.json'),
      idxFile('third_party/pkg/package-lock.json'),
      idxFile('a/.venv/lib/requirements.txt'),
      idxFile('a/site-packages/requirements.txt'),
      idxFile('real/package-lock.json'),
    ];
    const refs = discoverLockfiles(files);
    expect(refs).toEqual([{ path: 'real/package-lock.json', kind: 'package-lock', manifestDir: 'real' }]);
  });
});

describe('parseDependencyGraphs', () => {
  it('resolves a monorepo (npm dir + python requirements dir) end to end, following -r includes', async () => {
    const dir = fixtureDir('monorepo');
    const paths = await listFiles(dir);
    const files = paths.map((p) => idxFile(p));
    const { graphs, warnings } = await parseDependencyGraphs({ repoDir: dir, files, signal: new AbortController().signal });

    const web = graphs.find((g) => g.lockfile === 'apps/web/package-lock.json')!;
    expect(web).toBeDefined();
    expect(web.nodes.get('npm:left-pad@1.3.0')?.direct).toBe(true);

    const reqMain = graphs.find((g) => g.lockfile === 'services/worker/requirements.txt')!;
    expect(reqMain).toBeDefined();
    expect([...reqMain.nodes.keys()].sort()).toEqual(['PyPI:click@8.1.7', 'PyPI:flask@2.3.3']);

    const reqDev = graphs.find((g) => g.lockfile === 'services/worker/requirements-dev.txt')!;
    expect(reqDev).toBeDefined();
    // follows "-r requirements.txt" into the sibling file, plus its own pin, all scope 'dev'.
    expect([...reqDev.nodes.keys()].sort()).toEqual(['PyPI:click@8.1.7', 'PyPI:flask@2.3.3', 'PyPI:pytest@7.4.0']);
    expect([...reqDev.nodes.values()].every((n) => n.scope === 'dev' && n.direct)).toBe(true);

    expect(graphs.some((g) => g.lockfile.includes('node_modules'))).toBe(false);
    expect(warnings).toEqual([]);
  });

  it('yields to the event loop and reports liveness between lockfiles', async () => {
    const dir = fixtureDir('monorepo');
    const files = (await listFiles(dir)).map((p) => idxFile(p));
    let touches = 0;
    let ticks = 0;
    const timer = setInterval(() => { ticks++; }, 0);
    const immediate = new Promise<void>((r) => setImmediate(() => { ticks++; r(); }));
    try {
      await parseDependencyGraphs({ repoDir: dir, files, signal: new AbortController().signal, touch: () => { touches++; } });
    } finally {
      clearInterval(timer);
    }
    await immediate;
    expect(touches).toBeGreaterThanOrEqual(2);
    expect(ticks).toBeGreaterThan(0);
  });
});
