import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ImportEdge, IndexedFile } from '../src/index/types';
import type { AgentTool } from '../src/llm/LlmClient';
import {
  createRepoTools, GREP_MAX_HITS, LIST_DIR_MAX_ENTRIES, normalizeRepoPath, READ_FILE_MAX_LINES, regexProblem, ReportFlowInput,
} from '../src/analyzers/code/repoTools';

const file = (path: string, skipReason: IndexedFile['skipReason'] = null): IndexedFile => ({
  path, blobSha: 'x', size: 1, language: 'typescript', category: 'source', tags: [], skipReason,
});

let repo: string;
let outside: string;
const files: IndexedFile[] = [];
const imports: ImportEdge[] = [
  { from: 'src/app.ts', specifier: './db', kind: 'local', to: 'src/db.ts', pkg: null, line: 1 },
  { from: 'src/app.ts', specifier: 'express', kind: 'package', to: null, pkg: 'express', line: 2 },
  { from: 'src/app.ts', specifier: 'node:fs', kind: 'builtin', to: null, pkg: null, line: 3 },
  { from: 'src/app.ts', specifier: './missing', kind: 'unresolved', to: null, pkg: null, line: 4 },
  { from: 'src/routes.ts', specifier: './app', kind: 'local', to: 'src/app.ts', pkg: null, line: 7 },
];
let symlinkFileOk = false;
let junctionOk = false;

async function put(rel: string, content: string | Buffer, index: IndexedFile['skipReason'] | 'unindexed' = null) {
  const abs = join(repo, ...rel.split('/'));
  await mkdir(join(abs, '..'), { recursive: true });
  await writeFile(abs, content);
  if (index !== 'unindexed') files.push(file(rel, index));
}

beforeAll(async () => {
  repo = await mkdtemp(join(tmpdir(), 'vibesec-tools-'));
  outside = await mkdtemp(join(tmpdir(), 'vibesec-outside-'));
  await writeFile(join(outside, 'loot.txt'), 'outside content');
  await put('src/app.ts', [
    "import { query } from './db';",
    "import express from 'express';",
    "import fs from 'node:fs';",
    "import x from './missing';",
    'const app = express();',
    "app.get('/u', (req, res) => {",
    '  const userId = req.query.id;',
    '  const userIdentifier = 1;',
    '  query(`SELECT * FROM users WHERE id = ${userId}`);',
    '});',
  ].join('\n'));
  await put('src/db.ts', 'export function query(sql: string) { return db.run(sql); }\n');
  await put('src/routes.ts', "import './app';\n");
  await put('src/long.ts', Array.from({ length: 1_000 }, (_, i) => `line ${i + 1}`).join('\n'));
  await put('src/huge.ts', 'x'.repeat(300 * 1024));
  await put('src/blob.ts', Buffer.from([0x61, 0x00, 0x62]));
  await put('assets/logo.png', 'png', 'binary');
  await put('vendor/lib.js', 'const userId = 2;', 'vendor');
  await put('src/notindexed.ts', 'const userId = 3;', 'unindexed');
  await put('.git/config', '[core]', 'unindexed');
  await put('src/many.ts', Array.from({ length: 300 }, () => 'needle').join('\n'));
  await put('src/evil.ts', 'a'.repeat(1_990));
  await put('py/handler.py', 'user_id = request.args["id"]\n');
  for (let i = 0; i < LIST_DIR_MAX_ENTRIES + 20; i++) files.push(file(`gen/f${String(i).padStart(4, '0')}.ts`));
  // A symlinked file and a junction (directory link) pointing outside the repository, wrongly indexed as normal files.
  try {
    await symlink(join(outside, 'loot.txt'), join(repo, 'src', 'link.ts'), 'file');
    files.push(file('src/link.ts'));
    symlinkFileOk = true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EPERM') throw err;
  }
  try {
    await symlink(outside, join(repo, 'linkdir'), 'junction');
    files.push(file('linkdir/loot.txt'));
    junctionOk = true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EPERM') throw err;
  }
});

afterAll(async () => {
  await rm(repo, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
});

function tools(over: { grepTimeBudgetMs?: number; imports?: typeof imports | ((p: string) => ImportEdge[]) } = {}) {
  const list = createRepoTools({ repoDir: repo, files, imports: over.imports ?? imports, grepTimeBudgetMs: over.grepTimeBudgetMs });
  const byName = new Map(list.map((t) => [t.name, t]));
  const run = async (name: string, input: unknown): Promise<string> => {
    const tool = byName.get(name) as AgentTool;
    return tool.run(tool.input.parse(input), { signal: new AbortController().signal });
  };
  return { list, run };
}

describe('normalizeRepoPath', () => {
  it.each(['../x', 'src/../../x', '/etc/passwd', 'C:/Windows', 'c:x', 'src\\app.ts', 'a\0b', '.git/config', 'src/.GIT/x'])('rejects %j', (p) => {
    expect(() => normalizeRepoPath(p)).toThrow();
  });
  it('normalizes ./ and duplicate slashes', () => {
    expect(normalizeRepoPath('./src//app.ts')).toBe('src/app.ts');
    expect(normalizeRepoPath('.')).toBe('');
  });
});

describe('read_file', () => {
  it('returns numbered lines wrapped as untrusted content', async () => {
    const out = await tools().run('read_file', { path: 'src/app.ts', startLine: 7, endLine: 9 });
    expect(out).toContain('<untrusted_file path="src/app.ts">');
    expect(out).toContain('\n7    const userId = req.query.id;');
    expect(out).toContain('(lines 7-9 of 10; continue with startLine=10)');
    expect(out).not.toContain('express()');
  });

  it(`caps a window at ${READ_FILE_MAX_LINES} lines and tells how to continue`, async () => {
    const out = await tools().run('read_file', { path: 'src/long.ts' });
    expect(out).toContain('line 400');
    expect(out).not.toContain('line 401');
    expect(out).toContain('continue with startLine=401');
    const window = await tools().run('read_file', { path: 'src/long.ts', startLine: 990, endLine: 5_000 });
    expect(window).toContain('(lines 990-1000 of 1000)');
    await expect(tools().run('read_file', { path: 'src/long.ts', startLine: 2_000 })).rejects.toThrow(/only 1000 lines/);
  });

  it.each([
    ['../outside.txt', /\.\./],
    ['/etc/passwd', /relative/],
    ['.git/config', /\.git/],
    ['src/notindexed.ts', /not in the repository index/],
    ['assets/logo.png', /binary/],
    ['src/blob.ts', /binary/],
    ['src/huge.ts', /larger than 256 KiB/],
    ['src', /not in the repository index/],
  ])('refuses %s', async (path, message) => {
    await expect(tools().run('read_file', { path })).rejects.toThrow(message);
  });

  it('refuses a symlinked file pointing outside the repository', async (ctx) => {
    if (!symlinkFileOk) ctx.skip();
    await expect(tools().run('read_file', { path: 'src/link.ts' })).rejects.toThrow(/symbolic link/);
  });

  it('refuses a path through a linked directory (junction) pointing outside the repository', async (ctx) => {
    if (!junctionOk) ctx.skip();
    await expect(tools().run('read_file', { path: 'linkdir/loot.txt' })).rejects.toThrow(/symbolic link|outside/);
  });
});

describe('grep', () => {
  it('finds substrings in indexed, non-skipped files only', async () => {
    const out = await tools().run('grep', { pattern: 'userId' });
    expect(out).toContain('src/app.ts:7: const userId = req.query.id;');
    expect(out).toContain('<untrusted_text');
    expect(out).not.toContain('vendor/lib.js');
    expect(out).not.toContain('notindexed');
  });

  it('filters by glob (basename or path)', async () => {
    expect(await tools().run('grep', { pattern: 'request', glob: '*.py' })).toContain('py/handler.py:1:');
    expect(await tools().run('grep', { pattern: 'userId', glob: '*.py' })).toBe('No matches.');
    expect(await tools().run('grep', { pattern: 'query', glob: 'src/**/*.{ts,tsx}' })).toContain('src/db.ts:1:');
  });

  it('supports safe regexes, case-insensitive', async () => {
    const out = await tools().run('grep', { pattern: 'select \\*', regex: true, ignoreCase: true });
    expect(out).toContain('src/app.ts:9:');
  });

  it('rejects ReDoS-prone and invalid regexes', async () => {
    for (const pattern of ['(a+)+$', '(a|aa)*b', '(\\w+\\s?)*$', '(.*a){12}', '(a)\\1', '([a-z]+)+x', 'x'.repeat(201)]) {
      expect(regexProblem(pattern), pattern).not.toBeNull();
    }
    for (const pattern of ['req\\.(query|body)\\.\\w+', 'exec\\(', '[a-z]+_id', '(foo)?bar+']) {
      expect(regexProblem(pattern), pattern).toBeNull();
    }
    await expect(tools().run('grep', { pattern: '(a+)+$', regex: true })).rejects.toThrow(/Regex rejected/);
    await expect(tools().run('grep', { pattern: '(unclosed', regex: true })).rejects.toThrow(/invalid regular expression/);
  });

  it('stops a slow regex at the time budget and reports partial results', async () => {
    const started = Date.now();
    const out = await tools({ grepTimeBudgetMs: 200 }).run('grep', { pattern: 'a*a*a*a*a*a*a*c', regex: true, glob: 'src/evil.ts' });
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(out).toMatch(/time budget/);
  });

  it(`caps hits at ${GREP_MAX_HITS} and clips long lines`, async () => {
    const out = await tools().run('grep', { pattern: 'needle' });
    expect(out.match(/^src\/many\.ts:\d+:/gm)).toHaveLength(GREP_MAX_HITS);
    expect(out).toMatch(/stopped at 100 matches/);
    const long = await tools().run('grep', { pattern: 'aaaa', glob: 'src/evil.ts' });
    expect(long).toMatch(/src\/evil\.ts:1: a{200}…/);
  });
});

describe('find_references', () => {
  it('matches whole identifiers only', async () => {
    const out = await tools().run('find_references', { symbol: 'userId' });
    expect(out).toContain('src/app.ts:7:');
    expect(out).toContain('src/app.ts:9:');
    expect(out).not.toContain('src/app.ts:8:'); // userIdentifier
  });
  it('rejects non-identifiers', () => {
    const tool = tools().list.find((t) => t.name === 'find_references')!;
    expect(tool.input.safeParse({ symbol: 'a.b' }).success).toBe(false);
    expect(tool.input.safeParse({ symbol: '(a+)+' }).success).toBe(false);
  });
});

describe('get_imports', () => {
  it('lists resolved local imports, packages, builtins, unresolved specifiers and importers', async () => {
    const out = await tools().run('get_imports', { path: 'src/app.ts' });
    expect(out).toContain('src/db.ts (line 1, "./db")');
    expect(out).toContain('express (line 2');
    expect(out).toContain('builtins:');
    expect(out).toContain('./missing (line 4');
    expect(out).toContain('Imported by:\n  src/routes.ts (line 7)');
  });
  it('accepts a per-file lookup and refuses unindexed paths', async () => {
    const out = await tools({ imports: (p) => imports.filter((e) => e.from === p) }).run('get_imports', { path: 'src/app.ts' });
    expect(out).toContain('src/db.ts');
    expect(out).not.toContain('Imported by');
    await expect(tools().run('get_imports', { path: 'src/notindexed.ts' })).rejects.toThrow(/not in the repository index/);
  });
});

describe('list_dir', () => {
  it('lists indexed entries (dirs with /), marks skipped files, hides unindexed ones', async () => {
    const root = await tools().run('list_dir', { path: '' });
    expect(root).toMatch(/src\//);
    expect(root).toMatch(/vendor\//);
    expect(root).not.toContain('.git');
    const src = await tools().run('list_dir', { path: 'src' });
    expect(src).toContain('app.ts');
    expect(src).not.toContain('notindexed.ts');
    expect(await tools().run('list_dir', { path: 'assets' })).toContain('logo.png  [skipped: binary]');
  });
  it(`caps at ${LIST_DIR_MAX_ENTRIES} entries`, async () => {
    const out = await tools().run('list_dir', { path: 'gen' });
    expect(out).toContain('(20 more entries not shown)');
  });
  it('refuses traversal and unknown directories', async () => {
    await expect(tools().run('list_dir', { path: '..' })).rejects.toThrow();
    await expect(tools().run('list_dir', { path: 'nope' })).rejects.toThrow(/No indexed directory/);
  });
});

describe('ReportFlowInput', () => {
  const base = {
    title: 'SQL injection', ruleId: 'taint/sql-injection', cwe: 'CWE-89', severity: 'high', verdict: 'exploitable', confidence: 'high',
    trace: [
      { kind: 'source', file: 'src/app.ts', line: 7, code: 'req.query.id', note: 'user input' },
      { kind: 'sink', file: 'src/db.ts', line: 1, code: 'db.run(sql)', note: 'raw SQL' },
    ],
    sanitizersSeen: [], explanation: 'e', impact: 'i', remediation: 'r',
  };
  it('accepts a source → sink trace and rejects malformed traces', () => {
    expect(ReportFlowInput.safeParse(base).success).toBe(true);
    expect(ReportFlowInput.safeParse({ ...base, trace: base.trace.slice(0, 1) }).success).toBe(false);
    expect(ReportFlowInput.safeParse({ ...base, trace: [...base.trace].reverse() }).success).toBe(false);
    expect(ReportFlowInput.safeParse({ ...base, cwe: '89' }).success).toBe(false);
  });
});
