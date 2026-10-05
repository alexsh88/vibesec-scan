import { existsSync } from 'node:fs';
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GitService } from '../src/git/GitService';
import { createFixtureRepo, type FixtureRepo } from './fixtures/gitRepo';

let repo: FixtureRepo;
let workDir: string;
let git: GitService;

beforeAll(async () => {
  repo = await createFixtureRepo([
    { files: { 'README.md': '# demo\n', 'src/a.ts': 'export const a = 1;\n' } },
    { files: { 'src/a.ts': 'export const a = 2;\n', 'src/b.ts': 'export const b = 1;\n', 'README.md': null } },
    { symlinks: { escape: '../../../etc/passwd' } },
  ]);
  workDir = await mkdtemp(join(tmpdir(), 'vibesec-work-'));
  git = new GitService({ workDir, cloneTimeoutMs: 60_000, stallMs: 20_000, allowFileProtocol: true });
  await git.init();
}, 60_000);

afterAll(async () => {
  await repo.cleanup();
  await rm(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

describe('GitService', () => {
  it('init reports the git version and creates the empty global config', async () => {
    expect(await git.init()).toMatch(/^git version \d+\.\d+/);
    expect(existsSync(join(workDir, '.gitconfig-empty'))).toBe(true);
  });

  it('builds github remote URLs by default', () => {
    expect(new GitService({ workDir, cloneTimeoutMs: 1_000, stallMs: 500, allowFileProtocol: false }).remoteUrl('acme', 'app'))
      .toBe('https://github.com/acme/app.git');
  });

  it('resolves branches, nested branches, annotated tags, HEAD and full SHAs', async () => {
    expect(await git.resolveRef(repo.url, 'main')).toBe(repo.shas[2]);
    expect(await git.resolveRef(repo.url, 'feature/x')).toBe(repo.shas[0]);
    expect(await git.resolveRef(repo.url, 'v1.0.0')).toBe(repo.shas[2]);
    expect(await git.resolveRef(repo.url, 'HEAD')).toBe(repo.shas[2]);
    expect(await git.resolveRef(repo.url, repo.shas[1]!.toUpperCase())).toBe(repo.shas[1]);
  });

  it('fails with REF_NOT_FOUND for an unknown ref', async () => {
    await expect(git.resolveRef(repo.url, 'does-not-exist')).rejects.toMatchObject({ code: 'REF_NOT_FOUND' });
  });

  it('fails with REPO_NOT_FOUND for a missing repository', async () => {
    const missing = repo.url.replace('bare.git', 'nope.git');
    await expect(git.resolveRef(missing, 'main')).rejects.toMatchObject({ code: 'REPO_NOT_FOUND' });
  });

  it('checks out a commit, reports progress, and never writes the token to .git/config', async () => {
    const phases = new Set<string>();
    const dir = await git.ensureCheckout('scan-1', repo.url, repo.shas[1]!, {
      token: 'ghp_0123456789abcdefghijABCDEFGHIJ012345',
      onProgress: (phase) => phases.add(phase),
    });
    expect(await readFile(join(dir, 'src/a.ts'), 'utf8')).toBe('export const a = 2;\n');
    expect(existsSync(join(dir, 'README.md'))).toBe(false);
    const config = await readFile(join(dir, '.git', 'config'), 'utf8');
    expect(config).not.toContain('ghp_');
    expect(config.toLowerCase()).not.toContain('extraheader');
    expect(phases.size).toBeGreaterThan(0);
  }, 60_000);

  it('reuses an existing checkout at the same commit and replaces it for another commit', async () => {
    const dir = await git.ensureCheckout('scan-2', repo.url, repo.shas[0]!);
    const marker = join(dir, '.git', 'vibesec-marker');
    await writeFile(marker, 'x');
    await git.ensureCheckout('scan-2', repo.url, repo.shas[0]!);
    expect(existsSync(marker)).toBe(true);
    await git.ensureCheckout('scan-2', repo.url, repo.shas[1]!);
    expect(existsSync(marker)).toBe(false);
    expect(await git.headSha(dir)).toBe(repo.shas[1]);
  }, 60_000);

  it('checks out symlinks as plain files containing the target (no escape)', async () => {
    const dir = await git.ensureCheckout('scan-3', repo.url, repo.shas[2]!);
    const stat = await lstat(join(dir, 'escape'));
    expect(stat.isSymbolicLink()).toBe(false);
    expect(await readFile(join(dir, 'escape'), 'utf8')).toBe('../../../etc/passwd');
  }, 60_000);

  it('lists the tree with modes and blob SHAs', async () => {
    const dir = await git.ensureCheckout('scan-3', repo.url, repo.shas[2]!);
    const tree = await git.listTree(dir, repo.shas[2]!);
    const byPath = Object.fromEntries(tree.map((e) => [e.path, e]));
    expect(Object.keys(byPath).sort()).toEqual(['escape', 'src/a.ts', 'src/b.ts']);
    expect(byPath['escape']!.mode).toBe('120000');
    expect(byPath['src/a.ts']!.blobSha).toMatch(/^[0-9a-f]{40}$/);
  }, 60_000);

  it('diffs two commits and returns null when the base commit is unknown', async () => {
    const dir = await git.ensureCheckout('scan-3', repo.url, repo.shas[2]!);
    const diff = await git.diffNameStatus(dir, repo.shas[0]!, repo.shas[1]!);
    expect(diff).toEqual(expect.arrayContaining([
      { status: 'M', path: 'src/a.ts' },
      { status: 'A', path: 'src/b.ts' },
      { status: 'D', path: 'README.md' },
    ]));
    expect(await git.diffNameStatus(dir, 'f'.repeat(40), repo.shas[1]!)).toBeNull();
  }, 60_000);

  it('cancels when the signal is already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(git.ensureCheckout('scan-4', repo.url, repo.shas[0]!, { signal: ac.signal }))
      .rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('removes scan directories and sweeps the ones not kept', async () => {
    await git.ensureCheckout('keep-me', repo.url, repo.shas[0]!);
    await git.ensureCheckout('drop-me', repo.url, repo.shas[0]!);
    const removed = await git.sweep((id) => id === 'keep-me');
    expect(removed).toContain('drop-me');
    expect(existsSync(git.scanDir('keep-me'))).toBe(true);
    expect(existsSync(git.scanDir('drop-me'))).toBe(false);
    await git.removeScanDir('keep-me');
    expect(existsSync(git.scanDir('keep-me'))).toBe(false);
  }, 60_000);
});
