import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProcess } from '../src/process/runProcess';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const nodeAnalyzer = join(repoRoot, 'sandbox', 'node', 'analyze.mjs');
const pyAnalyzer = join(repoRoot, 'sandbox', 'python', 'analyze.py');
const tsPath = join(repoRoot, 'node_modules', 'typescript');
const fixturesDir = join(here, 'fixtures', 'usage');
const pythonBin = process.env.VIBESEC_TEST_PYTHON ?? 'python';

type PackageInput = { name: string; importNames: string[] };
type PackagesJson = {
  ecosystem: 'npm' | 'PyPI';
  packages: PackageInput[];
  maxFiles?: number;
  maxFileBytes?: number;
};
type Usage = { package: string; file: string; line: number; symbol: string | null; kind: 'import' | 'call' | 'member' };
type Output = { version: number; usages: Usage[]; filesScanned: number; errors: string[] };

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'vibesec-usage-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

async function runAnalyzer(bin: string, scriptArgs: string[], srcDir: string, input: PackagesJson) {
  return withTempDir(async (work) => {
    const inPath = join(work, 'packages.json');
    const outPath = join(work, 'usages.json');
    await writeFile(inPath, JSON.stringify(input));
    const result = await runProcess(
      bin,
      [...scriptArgs, `--src=${srcDir}`, `--in=${inPath}`, `--out=${outPath}`],
      { env: { ...process.env, TS_PATH: tsPath }, timeoutMs: 30_000 },
    );
    let output: Output | null = null;
    try {
      output = JSON.parse(await readFile(outPath, 'utf8')) as Output;
    } catch {
      output = null;
    }
    return { result, output };
  });
}

const runNode = (srcDir: string, input: PackagesJson) => runAnalyzer(process.execPath, [nodeAnalyzer], srcDir, input);
const runPython = (srcDir: string, input: PackagesJson) => runAnalyzer(pythonBin, [pyAnalyzer], srcDir, input);

const lodashScoped: PackagesJson = {
  ecosystem: 'npm',
  packages: [
    { name: 'lodash', importNames: ['lodash', 'lodash/merge', 'lodash/fp'] },
    { name: '@scope/pkg', importNames: ['@scope/pkg', '@scope/pkg/sub'] },
  ],
  maxFiles: 1000,
  maxFileBytes: 1_048_576,
};
const lodashOnlyNpm: PackagesJson = { ecosystem: 'npm', packages: [{ name: 'lodash', importNames: ['lodash'] }], maxFiles: 1000, maxFileBytes: 1_048_576 };
const yamlOnlyPy: PackagesJson = { ecosystem: 'PyPI', packages: [{ name: 'pyyaml', importNames: ['yaml'] }], maxFiles: 1000, maxFileBytes: 1_048_576 };

describe('sandbox/node/analyze.mjs', () => {
  it('recognizes every import/require/export/dynamic-import form, aliasing, subpaths, scoped packages and dedupes same-line calls', async () => {
    const { result, output } = await runNode(join(fixturesDir, 'node-basic', 'src'), lodashScoped);
    expect(result.code).toBe(0);
    expect(output?.filesScanned).toBe(2);
    expect(output?.errors).toEqual([]);
    expect(output?.usages).toEqual([
      { package: 'lodash', file: 'index.ts', line: 2, symbol: 'default', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 4, symbol: 'debounce', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 4, symbol: 'merge', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 6, symbol: null, kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 8, symbol: 'merge', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 10, symbol: 'debounce', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 12, symbol: null, kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 14, symbol: null, kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 15, symbol: 'debounce', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 17, symbol: 'merge', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 18, symbol: 'debounce', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 20, symbol: null, kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 22, symbol: 'merge', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 24, symbol: null, kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 26, symbol: 'merge', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 28, symbol: 'default', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 29, symbol: 'pick', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 30, symbol: 'merge', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 31, symbol: 'debounce', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 32, symbol: 'merge', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 33, symbol: 'other', kind: 'member' },
      { package: 'lodash', file: 'index.ts', line: 34, symbol: 'merge', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 35, symbol: 'debounce', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 36, symbol: 'merge', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 37, symbol: 'debounce', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 38, symbol: 'default', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 39, symbol: 'pick', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 40, symbol: 'merge', kind: 'call' },
      { package: 'lodash', file: 'index.ts', line: 43, symbol: 'merge', kind: 'call' }, // two calls, same line -> deduped to one
      { package: '@scope/pkg', file: 'scoped.ts', line: 2, symbol: 'default', kind: 'import' },
      { package: '@scope/pkg', file: 'scoped.ts', line: 3, symbol: 'a', kind: 'import' },
      { package: '@scope/pkg', file: 'scoped.ts', line: 4, symbol: 'default', kind: 'import' },
      { package: '@scope/pkg', file: 'scoped.ts', line: 6, symbol: 'thing', kind: 'call' },
      { package: '@scope/pkg', file: 'scoped.ts', line: 7, symbol: 'a', kind: 'call' },
      { package: '@scope/pkg', file: 'scoped.ts', line: 8, symbol: 'default', kind: 'call' },
    ]);
  });

  it('produces identical output across repeated runs (deterministic order)', async () => {
    const { output: first } = await runNode(join(fixturesDir, 'node-basic', 'src'), lodashScoped);
    const { output: second } = await runNode(join(fixturesDir, 'node-basic', 'src'), lodashScoped);
    expect(second?.usages).toEqual(first?.usages);
  });

  it('documents the no-scope-analysis limitation: a shadowing local name is still reported', async () => {
    const { result, output } = await runNode(join(fixturesDir, 'node-shadow', 'src'), lodashOnlyNpm);
    expect(result.code).toBe(0);
    expect(output?.usages).toEqual([
      { package: 'lodash', file: 'index.ts', line: 3, symbol: 'default', kind: 'import' },
      { package: 'lodash', file: 'index.ts', line: 6, symbol: 'default', kind: 'call' },
    ]);
  });

  it('records syntax errors per file without aborting the scan', async () => {
    const { result, output } = await runNode(join(fixturesDir, 'node-syntax-error', 'src'), lodashOnlyNpm);
    expect(result.code).toBe(0);
    expect(output?.filesScanned).toBe(2);
    expect(output?.errors).toEqual(['bad.js: 3 syntax error(s), parsed best-effort']);
    expect(output?.usages).toEqual([
      { package: 'lodash', file: 'good.ts', line: 1, symbol: 'default', kind: 'import' },
      { package: 'lodash', file: 'good.ts', line: 2, symbol: 'default', kind: 'call' },
    ]);
  });

  it('skips node_modules/dist/build/.git/vendor/coverage directories and *.min.js files', async () => {
    const { output } = await runNode(join(fixturesDir, 'node-skip-dirs', 'src'), lodashOnlyNpm);
    expect(output?.filesScanned).toBe(1);
    expect(output?.usages).toEqual([
      { package: 'lodash', file: 'keep/index.ts', line: 1, symbol: 'default', kind: 'import' },
      { package: 'lodash', file: 'keep/index.ts', line: 2, symbol: 'default', kind: 'call' },
    ]);
  });

  it('skips a .git directory (built at runtime: git refuses to track fixtures under a literal .git path)', async () => {
    await withTempDir(async (src) => {
      await writeFile(join(src, 'keep.ts'), "import m from 'lodash';\nm();\n");
      await mkdir(join(src, '.git'), { recursive: true });
      await writeFile(join(src, '.git', 'decoy.ts'), "import m from 'lodash';\nm();\n");
      const { output } = await runNode(src, lodashOnlyNpm);
      expect(output?.filesScanned).toBe(1);
      expect(output?.usages.every((u) => u.file === 'keep.ts')).toBe(true);
    });
  });

  it('exits non-zero and writes nothing useful for invalid input JSON', async () => {
    await withTempDir(async (work) => {
      const inPath = join(work, 'packages.json');
      const outPath = join(work, 'usages.json');
      await writeFile(inPath, '{ not valid json');
      const result = await runProcess(
        process.execPath,
        [nodeAnalyzer, `--src=${join(fixturesDir, 'node-basic', 'src')}`, `--in=${inPath}`, `--out=${outPath}`],
        { env: { ...process.env, TS_PATH: tsPath }, timeoutMs: 15_000 },
      );
      expect(result.code).not.toBe(0);
      await expect(readFile(outPath, 'utf8')).rejects.toThrow();
    });
  });

  it('caps the file list at maxFiles, chosen deterministically by repo-relative path', async () => {
    await withTempDir(async (src) => {
      for (let i = 0; i < 8; i++) await writeFile(join(src, `f${i}.ts`), "import m from 'lodash';\nm();\n");
      const { output } = await runNode(src, { ...lodashOnlyNpm, maxFiles: 5 });
      expect(output?.filesScanned).toBe(5);
      expect(output?.errors).toEqual(['file list capped at 5 files']);
      const files = [...new Set(output?.usages.map((u) => u.file))].sort();
      expect(files).toEqual(['f0.ts', 'f1.ts', 'f2.ts', 'f3.ts', 'f4.ts']);
    });
  });

  it('skips files larger than maxFileBytes without recording an error', async () => {
    await withTempDir(async (src) => {
      await writeFile(join(src, 'small.ts'), "import m from 'lodash';\nm();\n");
      await writeFile(join(src, 'big.ts'), `import m from 'lodash';\nm();\n${'// padding\n'.repeat(50)}`);
      const { output } = await runNode(src, { ...lodashOnlyNpm, maxFileBytes: 60 });
      expect(output?.filesScanned).toBe(1);
      expect(output?.errors).toEqual([]);
      expect(output?.usages.every((u) => u.file === 'small.ts')).toBe(true);
    });
  });

  it('never follows a symlinked directory or file', async () => {
    await withTempDir(async (src) => {
      await mkdir(join(src, 'real'), { recursive: true });
      await writeFile(join(src, 'real', 'target.ts'), "import m from 'lodash';\nm();\n");
      let canSymlink = true;
      try {
        await symlink(join(src, 'real'), join(src, 'linked'), 'dir');
      } catch {
        canSymlink = false;
      }
      if (!canSymlink) return; // e.g. Windows without Developer Mode / elevated privileges
      const { output } = await runNode(src, lodashOnlyNpm);
      expect(output?.usages.some((u) => u.file.startsWith('linked/'))).toBe(false);
      expect(output?.usages.some((u) => u.file === 'real/target.ts')).toBe(true);
    });
  });

  it('caps total usages at 200000 and notes it in errors', async () => {
    await withTempDir(async (src) => {
      const extra = 5;
      const lines = ["import x from 'lodash';"];
      for (let i = 0; i < 200_000 + extra; i++) lines.push(`x.a${i}();`);
      await writeFile(join(src, 'many.ts'), `${lines.join('\n')}\n`);
      const { output } = await runNode(src, { ...lodashOnlyNpm, maxFileBytes: 50_000_000 });
      expect(output?.usages.length).toBe(200_000);
      expect(output?.errors).toEqual(['usages capped at 200000']);
    });
  }, 30_000);
});

describe('sandbox/python/analyze.py', () => {
  it('recognizes import/from-import forms, aliasing, dotted whole-module access and dedupes same-line calls', async () => {
    const { result, output } = await runPython(join(fixturesDir, 'py-basic', 'src'), yamlOnlyPy);
    expect(result.code).toBe(0);
    expect(output?.filesScanned).toBe(2);
    expect(output?.errors).toEqual([]);
    expect(output?.usages).toEqual([
      { package: 'pyyaml', file: 'dotted.py', line: 4, symbol: null, kind: 'import' },
      { package: 'pyyaml', file: 'dotted.py', line: 6, symbol: 'Loader', kind: 'call' },
      { package: 'pyyaml', file: 'dotted.py', line: 7, symbol: 'other', kind: 'member' },
      { package: 'pyyaml', file: 'main.py', line: 2, symbol: null, kind: 'import' },
      { package: 'pyyaml', file: 'main.py', line: 4, symbol: null, kind: 'import' },
      { package: 'pyyaml', file: 'main.py', line: 6, symbol: 'load', kind: 'import' },
      { package: 'pyyaml', file: 'main.py', line: 6, symbol: 'safe_load', kind: 'import' },
      { package: 'pyyaml', file: 'main.py', line: 8, symbol: 'Loader', kind: 'import' },
      { package: 'pyyaml', file: 'main.py', line: 17, symbol: 'load', kind: 'call' },
      { package: 'pyyaml', file: 'main.py', line: 18, symbol: 'FullLoader', kind: 'member' },
      { package: 'pyyaml', file: 'main.py', line: 19, symbol: 'safe_load', kind: 'call' },
      { package: 'pyyaml', file: 'main.py', line: 20, symbol: 'other', kind: 'member' },
      { package: 'pyyaml', file: 'main.py', line: 21, symbol: 'load', kind: 'call' },
      { package: 'pyyaml', file: 'main.py', line: 22, symbol: 'safe_load', kind: 'call' },
      { package: 'pyyaml', file: 'main.py', line: 27, symbol: 'load', kind: 'call' }, // two calls, same line -> deduped to one
    ]);
  });

  it('produces identical output across repeated runs (deterministic order)', async () => {
    const { output: first } = await runPython(join(fixturesDir, 'py-basic', 'src'), yamlOnlyPy);
    const { output: second } = await runPython(join(fixturesDir, 'py-basic', 'src'), yamlOnlyPy);
    expect(second?.usages).toEqual(first?.usages);
  });

  it('documents the no-scope-analysis limitation: a shadowing local name is still reported', async () => {
    const { result, output } = await runPython(join(fixturesDir, 'py-shadow', 'src'), yamlOnlyPy);
    expect(result.code).toBe(0);
    expect(output?.usages).toEqual([
      { package: 'pyyaml', file: 'main.py', line: 3, symbol: 'load', kind: 'import' },
      { package: 'pyyaml', file: 'main.py', line: 7, symbol: 'load', kind: 'call' },
    ]);
  });

  it('records syntax errors per file without aborting the scan', async () => {
    const { result, output } = await runPython(join(fixturesDir, 'py-syntax-error', 'src'), yamlOnlyPy);
    expect(result.code).toBe(0);
    expect(output?.filesScanned).toBe(1);
    expect(output?.errors).toEqual(['bad.py: syntax error: invalid syntax (line 1)']);
    expect(output?.usages).toEqual([
      { package: 'pyyaml', file: 'good.py', line: 1, symbol: null, kind: 'import' },
      { package: 'pyyaml', file: 'good.py', line: 2, symbol: 'load', kind: 'call' },
    ]);
  });

  it('catches a RecursionError from pathologically nested code without aborting the scan', async () => {
    await withTempDir(async (src) => {
      await writeFile(join(src, 'good.py'), 'import yaml\nyaml.load(1)\n');
      const deep = `x = a${'.b'.repeat(50_000)}\n`;
      await writeFile(join(src, 'deep.py'), deep);
      const { result, output } = await runPython(src, { ...yamlOnlyPy, maxFileBytes: 10_000_000 });
      expect(result.code).toBe(0);
      expect(output?.filesScanned).toBe(1);
      expect(output?.errors).toHaveLength(1);
      expect(output?.errors[0]).toMatch(/deep\.py: too deeply nested to parse/);
      expect(output?.usages).toEqual([
        { package: 'pyyaml', file: 'good.py', line: 1, symbol: null, kind: 'import' },
        { package: 'pyyaml', file: 'good.py', line: 2, symbol: 'load', kind: 'call' },
      ]);
    });
  });

  it('skips venv/.venv/site-packages/node_modules/build/dist/__pycache__ directories', async () => {
    const { output } = await runPython(join(fixturesDir, 'py-skip-dirs', 'src'), yamlOnlyPy);
    expect(output?.filesScanned).toBe(1);
    expect(output?.usages).toEqual([
      { package: 'pyyaml', file: 'keep/main.py', line: 1, symbol: null, kind: 'import' },
      { package: 'pyyaml', file: 'keep/main.py', line: 2, symbol: 'load', kind: 'call' },
    ]);
  });

  it('skips a .git directory (built at runtime: git refuses to track fixtures under a literal .git path)', async () => {
    await withTempDir(async (src) => {
      await writeFile(join(src, 'keep.py'), 'import yaml\nyaml.load(1)\n');
      await mkdir(join(src, '.git'), { recursive: true });
      await writeFile(join(src, '.git', 'decoy.py'), 'import yaml\nyaml.load(1)\n');
      const { output } = await runPython(src, yamlOnlyPy);
      expect(output?.filesScanned).toBe(1);
      expect(output?.usages.every((u) => u.file === 'keep.py')).toBe(true);
    });
  });

  it('exits non-zero for invalid input JSON', async () => {
    await withTempDir(async (work) => {
      const inPath = join(work, 'packages.json');
      const outPath = join(work, 'usages.json');
      await writeFile(inPath, '{ not valid json');
      const result = await runProcess(
        pythonBin,
        [pyAnalyzer, `--src=${join(fixturesDir, 'py-basic', 'src')}`, `--in=${inPath}`, `--out=${outPath}`],
        { timeoutMs: 15_000 },
      );
      expect(result.code).not.toBe(0);
      await expect(readFile(outPath, 'utf8')).rejects.toThrow();
    });
  });

  it('caps the file list at maxFiles, chosen deterministically by repo-relative path', async () => {
    await withTempDir(async (src) => {
      for (let i = 0; i < 8; i++) await writeFile(join(src, `f${i}.py`), 'import yaml\nyaml.load(1)\n');
      const { output } = await runPython(src, { ...yamlOnlyPy, maxFiles: 5 });
      expect(output?.filesScanned).toBe(5);
      expect(output?.errors).toEqual(['file list capped at 5 files']);
      const files = [...new Set(output?.usages.map((u) => u.file))].sort();
      expect(files).toEqual(['f0.py', 'f1.py', 'f2.py', 'f3.py', 'f4.py']);
    });
  });

  it('skips files larger than maxFileBytes without recording an error', async () => {
    await withTempDir(async (src) => {
      await writeFile(join(src, 'small.py'), 'import yaml\nyaml.load(1)\n');
      await writeFile(join(src, 'big.py'), `import yaml\nyaml.load(1)\n${'# padding\n'.repeat(50)}`);
      const { output } = await runPython(src, { ...yamlOnlyPy, maxFileBytes: 40 });
      expect(output?.filesScanned).toBe(1);
      expect(output?.errors).toEqual([]);
      expect(output?.usages.every((u) => u.file === 'small.py')).toBe(true);
    });
  });

  it('never follows a symlinked directory or file', async () => {
    await withTempDir(async (src) => {
      await mkdir(join(src, 'real'), { recursive: true });
      await writeFile(join(src, 'real', 'target.py'), 'import yaml\nyaml.load(1)\n');
      let canSymlink = true;
      try {
        await symlink(join(src, 'real'), join(src, 'linked'), 'dir');
      } catch {
        canSymlink = false;
      }
      if (!canSymlink) return; // e.g. Windows without Developer Mode / elevated privileges
      const { output } = await runPython(src, yamlOnlyPy);
      expect(output?.usages.some((u) => u.file.startsWith('linked/'))).toBe(false);
      expect(output?.usages.some((u) => u.file === 'real/target.py')).toBe(true);
    });
  });

  it('caps total usages at 200000 and notes it in errors', async () => {
    await withTempDir(async (src) => {
      const extra = 5;
      const lines = ['import yaml as x'];
      for (let i = 0; i < 200_000 + extra; i++) lines.push(`x.a${i}()`);
      await writeFile(join(src, 'many.py'), `${lines.join('\n')}\n`);
      const { output } = await runPython(src, { ...yamlOnlyPy, maxFileBytes: 50_000_000 });
      expect(output?.usages.length).toBe(200_000);
      expect(output?.errors).toEqual(['usages capped at 200000']);
    });
  }, 30_000);
});
