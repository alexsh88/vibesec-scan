import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GitService } from '../src/git/GitService';
import { runProcess } from '../src/process/runProcess';
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
    expect(existsSync(join(workDir, '.home'))).toBe(true);
  });

  it('runs git with HOME/USERPROFILE/XDG_CONFIG_HOME pointing at <workDir>/.home, never the host home (netrc)', async () => {
    const fakeHome = await mkdtemp(join(tmpdir(), 'vibesec-host-home-'));
    const netrc = 'machine github.com login netrcuser password netrcpass\nmachine localhost login netrcuser password netrcpass\n';
    await writeFile(join(fakeHome, '.netrc'), netrc);
    await writeFile(join(fakeHome, '_netrc'), netrc);
    const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    process.env.HOME = fakeHome;
    process.env.USERPROFILE = fakeHome;
    try {
      const script = 'console.log(JSON.stringify({h:process.env.HOME,u:process.env.USERPROFILE,x:process.env.XDG_CONFIG_HOME}))';
      const run = (git as unknown as { git(args: string[], o: object): Promise<string> }).git.bind(git);
      const out = await run(['-c', `alias.vsenv=!node -e '${script}'`, 'vsenv'], {});
      const seen = JSON.parse(out.trim()) as { h: string; u: string; x: string };
      const home = join(workDir, '.home');
      for (const v of [seen.h, seen.u, seen.x]) {
        expect(v).toBe(home);
        expect(v).not.toBe(fakeHome);
      }
      const origins = await run(['config', '--list', '--show-origin'], {});
      expect(origins).not.toContain(fakeHome);
      expect(origins).not.toContain('netrc');
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      await rm(fakeHome, { recursive: true, force: true });
    }
  }, 30_000);

  it('builds github remote URLs by default', () => {
    expect(new GitService({ workDir, cloneTimeoutMs: 1_000, stallMs: 500, allowFileProtocol: false }).remoteUrl('acme', 'app'))
      .toBe('https://github.com/acme/app.git');
  });

  it('resolves branches, nested branches, annotated tags, HEAD and full SHAs', async () => {
    expect(await git.resolveRef(repo.url, 'main')).toBe(repo.shas[2]);
    expect(await git.resolveRef(repo.url, 'feature/x')).toBe(repo.shas[0]);
    expect(await git.resolveRef(repo.url, 'v1.0.0')).toBe(repo.shas[2]);
    expect(await git.resolveRef(repo.url, 'refs/tags/v1.0.0')).toBe(repo.shas[2]);
    expect(await git.resolveRef(repo.url, 'refs/heads/main')).toBe(repo.shas[2]);
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

  it('re-clones a checkout left empty by a crash between clone --no-checkout and checkout', async () => {
    const id = randomUUID();
    await mkdir(git.scanDir(id), { recursive: true });
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: join(workDir, '.gitconfig-empty') };
    const r = await runProcess('git', ['clone', '--no-checkout', '-q', '--', repo.url, git.repoDir(id)], { env, timeoutMs: 30_000 });
    expect(r.code).toBe(0);
    expect(await git.headSha(git.repoDir(id))).toBe(repo.shas[2]); // HEAD already "equals" the tip
    const dir = await git.ensureCheckout(id, repo.url, repo.shas[2]!);
    expect(existsSync(join(dir, 'src', 'a.ts'))).toBe(true);
    expect((await readFile(join(dir, '.git', 'vibesec-checkout'), 'utf8')).trim()).toBe(repo.shas[2]);

    // A checkout whose completion marker is missing is never trusted either.
    await unlink(join(dir, '.git', 'vibesec-checkout'));
    await unlink(join(dir, 'src', 'a.ts'));
    await git.ensureCheckout(id, repo.url, repo.shas[2]!);
    expect(existsSync(join(dir, 'src', 'a.ts'))).toBe(true);
    await git.removeScanDir(id);
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

  it('rejects non-SHA diff arguments without running git (no option injection)', async () => {
    const dir = await git.ensureCheckout('scan-3', repo.url, repo.shas[2]!);
    const outFile = join(dir, 'x');
    expect(await git.diffNameStatus(dir, '--output=x', repo.shas[1]!)).toBeNull();
    expect(await git.diffNameStatus(dir, repo.shas[0]!, '--output=x')).toBeNull();
    expect(existsSync(outFile)).toBe(false);
  }, 60_000);

  it('cancels when the signal is already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(git.ensureCheckout('scan-4', repo.url, repo.shas[0]!, { signal: ac.signal }))
      .rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('keeps scan workspaces under <workDir>/scans', () => {
    const id = randomUUID();
    expect(git.scanDir(id)).toBe(join(workDir, 'scans', id));
  });

  it('removes scan directories and sweeps only UUID-named scan dirs that are not kept', async () => {
    const keep = randomUUID();
    const drop = randomUUID();
    await git.ensureCheckout(keep, repo.url, repo.shas[0]!);
    await git.ensureCheckout(drop, repo.url, repo.shas[0]!);
    const scans = join(workDir, 'scans');
    await mkdir(join(scans, 'not-a-scan'), { recursive: true });
    await writeFile(join(scans, randomUUID()), 'plain file');
    await mkdir(join(workDir, 'operator-data'), { recursive: true });

    const removed = await git.sweep((id) => id === keep);
    expect(removed).toEqual([drop]);
    expect(existsSync(git.scanDir(keep))).toBe(true);
    expect(existsSync(git.scanDir(drop))).toBe(false);
    expect(existsSync(join(scans, 'not-a-scan'))).toBe(true);
    expect(existsSync(join(workDir, 'operator-data'))).toBe(true);
    expect(existsSync(join(workDir, '.gitconfig-empty'))).toBe(true);
    expect(existsSync(join(workDir, '.home'))).toBe(true);
    await git.removeScanDir(keep);
    expect(existsSync(git.scanDir(keep))).toBe(false);
  }, 60_000);
});
