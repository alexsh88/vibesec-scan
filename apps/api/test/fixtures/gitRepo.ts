import { mkdir, mkdtemp, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runProcess } from '../../src/process/runProcess';

export type FixtureCommit = {
  /** path → content; null deletes the file. */
  files?: Record<string, string | null>;
  /** path → link target, stored as a git symlink (mode 120000) without needing OS symlink privileges. */
  symlinks?: Record<string, string>;
};

export type FixtureRepo = { url: string; root: string; shas: string[]; cleanup(): Promise<void> };

/**
 * Builds a bare repo with one commit per entry on `main`, a branch `feature/x` at the first commit
 * and an annotated tag `v1.0.0` at the last commit.
 */
export async function createFixtureRepo(commits: FixtureCommit[]): Promise<FixtureRepo> {
  const root = await mkdtemp(join(tmpdir(), 'vibesec-fixture-'));
  const work = join(root, 'work');
  const bare = join(root, 'bare.git');
  const emptyConfig = join(root, 'empty.gitconfig');
  await writeFile(emptyConfig, '');
  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: emptyConfig,
  };
  const git = async (args: string[], cwd = work): Promise<string> => {
    const r = await runProcess('git', args, { cwd, env, timeoutMs: 30_000 });
    if (r.code !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
    return r.stdout.trim();
  };

  await mkdir(work, { recursive: true });
  await git(['init', '-q', '-b', 'main']);
  const shas: string[] = [];
  for (const [i, commit] of commits.entries()) {
    for (const [path, content] of Object.entries(commit.files ?? {})) {
      const abs = join(work, path);
      if (content === null) {
        await unlink(abs).catch(() => undefined);
      } else {
        await mkdir(dirname(abs), { recursive: true });
        await writeFile(abs, content);
      }
    }
    await git(['add', '-A']);
    for (const [path, target] of Object.entries(commit.symlinks ?? {})) {
      const targetFile = join(root, `link-${i}.txt`);
      await writeFile(targetFile, target);
      const blob = await git(['hash-object', '-w', '--', targetFile]);
      await git(['update-index', '--add', '--cacheinfo', `120000,${blob},${path}`]);
    }
    await git(['commit', '-q', '--allow-empty', '-m', `commit ${i}`]);
    shas.push(await git(['rev-parse', 'HEAD']));
  }
  await git(['branch', 'feature/x', shas[0]!]);
  await git(['tag', '-a', 'v1.0.0', '-m', 'release']);
  await git(['clone', '-q', '--bare', work, bare], root);
  await git(['config', 'uploadpack.allowFilter', 'true'], bare);
  await git(['config', 'uploadpack.allowAnySHA1InWant', 'true'], bare);

  return {
    url: pathToFileURL(bare).href,
    root,
    shas,
    cleanup: () => rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }),
  };
}
