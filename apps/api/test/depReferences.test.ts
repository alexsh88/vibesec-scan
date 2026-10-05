import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { findPackageReferences } from '../src/analyzers/dependencies/references';
import type { DepGraph, DepNode, Ecosystem } from '../src/analyzers/dependencies/types';
import type { IndexedFile } from '../src/index/types';

let dir: string;
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vibesec-refs-')); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

async function repo(files: Record<string, string>): Promise<IndexedFile[]> {
  const out: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    out.push({ path, blobSha: 'b', size: content.length, language: 'other', category: 'source', tags: [], skipReason: null });
  }
  return out;
}

const read = async (rel: string) => {
  try {
    return (await readFile(join(dir, ...rel.split('/')), 'utf8')).split(/\r?\n/);
  } catch {
    return null;
  }
};

function graph(eco: Ecosystem, names: string[], manifestDir = ''): DepGraph {
  const nodes = new Map<string, DepNode>();
  for (const name of names) {
    const key = `${eco}:${name}@1.0.0`;
    nodes.set(key, { key, ecosystem: eco, name, version: '1.0.0', direct: true, scope: 'prod', parents: [], children: [] });
  }
  return { ecosystem: eco, lockfile: manifestDir ? `${manifestDir}/package-lock.json` : 'package-lock.json', manifestDir, nodes, roots: [...nodes.keys()], warnings: [], source: 'lockfile' };
}

describe('findPackageReferences', () => {
  it('npm: package.json scripts (incl. bin aliases), config-file string references, eslint/babel shorthands', async () => {
    const files = await repo({
      'package.json': JSON.stringify({
        name: 'app',
        scripts: { build: 'tsc -p .', lint: 'eslint src && prettier --check .', start: 'node ./node_modules/.bin/pm2-runtime start x' },
        dependencies: { 'left-pad': '1' },
      }, null, 2),
      '.eslintrc.json': JSON.stringify({ extends: ['airbnb', 'plugin:react/recommended'], plugins: ['import'] }, null, 2),
      'babel.config.js': "module.exports = { presets: ['@babel/preset-env'] };\n",
      'src/index.ts': "export const x = 'left-pad';\n",
    });
    const g = graph('npm', ['typescript', 'eslint', 'prettier', 'pm2', 'eslint-config-airbnb', 'eslint-plugin-react', 'eslint-plugin-import', '@babel/preset-env', 'left-pad', 'unused-thing']);
    const refs = await findPackageReferences(read, files, g);
    const byPkg = new Map(refs.map((r) => [r.package, r]));
    expect([...byPkg.keys()].sort()).toEqual([
      '@babel/preset-env', 'eslint', 'eslint-config-airbnb', 'eslint-plugin-import', 'eslint-plugin-react', 'pm2', 'prettier', 'typescript',
    ]);
    expect(byPkg.get('typescript')).toMatchObject({ ecosystem: 'npm', file: 'package.json', kind: 'reference', symbol: null });
    expect(byPkg.get('typescript')!.line).toBeGreaterThan(1);
    expect(byPkg.get('@babel/preset-env')).toMatchObject({ file: 'babel.config.js', line: 1 });
  });

  it('PyPI: Procfile / Dockerfile CMD + ENTRYPOINT / compose command reference servers and workers', async () => {
    const files = await repo({
      Procfile: 'web: gunicorn app:app -k uvicorn.workers.UvicornWorker\n',
      Dockerfile: 'FROM python:3.12\nRUN pip install -r requirements.txt\nCMD ["celery", "-A", "proj", "worker"]\n',
      'docker-compose.yml': 'services:\n  api:\n    command: python -m hypercorn app:app\n',
      'requirements.txt': 'gunicorn==21.2.0\n',
    });
    const g = graph('PyPI', ['gunicorn', 'uvicorn', 'celery', 'hypercorn', 'requests']);
    const refs = await findPackageReferences(read, files, g);
    const pkgs = [...new Set(refs.map((r) => r.package))].sort();
    expect(pkgs).toEqual(['celery', 'gunicorn', 'hypercorn', 'uvicorn']);
    expect(refs.find((r) => r.package === 'celery')).toMatchObject({ file: 'Dockerfile', line: 3, kind: 'reference' });
  });

  it('only looks at files of the graph\'s manifest dir (plus root entrypoints)', async () => {
    const files = await repo({
      'svc/package.json': JSON.stringify({ scripts: { test: 'jest' } }),
      'other/package.json': JSON.stringify({ scripts: { test: 'mocha' } }),
    });
    const refs = await findPackageReferences(read, files, graph('npm', ['jest', 'mocha'], 'svc'));
    expect(refs.map((r) => r.package)).toEqual(['jest']);
  });
});
