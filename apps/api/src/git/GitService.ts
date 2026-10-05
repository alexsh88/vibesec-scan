import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { AppError } from '../errors/AppError';
import { ProcessError, runProcess, type RunResult } from '../process/runProcess';
import { gitEnv, safeGitFlags } from './gitEnv';
import { classifyGitFailure, fromProcessError } from './gitErrors';

export type GitServiceOptions = {
  workDir: string;
  cloneTimeoutMs: number;
  stallMs: number;
  /** Only for local fixtures/tests (ALLOW_LOCAL_REPOS); production allows https only. */
  allowFileProtocol: boolean;
  remoteUrlFor?: (owner: string, name: string) => string;
  gitBinary?: string;
};

export type GitCallOptions = { token?: string; signal?: AbortSignal; onActivity?: () => void };
export type TreeEntry = { mode: string; type: 'blob' | 'commit' | 'tree'; blobSha: string; path: string };
export type DiffEntry = { status: 'A' | 'M' | 'D' | 'R' | 'C' | 'T'; path: string; oldPath?: string };

const SHA_RE = /^[0-9a-f]{40}$/i;
const PROGRESS_RE = /^(?:remote:\s*)?([A-Za-z][A-Za-z ]+):\s+\d+%\s+\((\d+)\/(\d+)\)/;
const SHORT_TIMEOUT_MS = 30_000;
const LS_REMOTE_TIMEOUT_MS = 20_000;
const MAX_TREE_BYTES = 64 * 1024 * 1024;
const MAX_LOG_PATCH_BYTES = 64 * 1024 * 1024;
const EMPTY_CONFIG = '.gitconfig-empty';
/** Private, empty HOME for git: the operator's ~/.netrc, _netrc and per-user config are never visible. */
const GIT_HOME = '.home';
const SCANS_DIR = 'scans';
/** Written into .git/ only after a successful checkout; its content is the checked-out SHA. */
const CHECKOUT_MARKER = 'vibesec-checkout';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RM_OPTS = { recursive: true, force: true, maxRetries: 5, retryDelay: 200 } as const;

export class GitService {
  private readonly gitBinary: string;

  constructor(private readonly opts: GitServiceOptions) {
    this.gitBinary = opts.gitBinary ?? 'git';
  }

  /** Creates the workspace and returns `git --version`; fails fast when git is missing. */
  async init(): Promise<string> {
    await mkdir(join(this.opts.workDir, GIT_HOME), { recursive: true });
    await mkdir(join(this.opts.workDir, SCANS_DIR), { recursive: true });
    await writeFile(join(this.opts.workDir, EMPTY_CONFIG), '');
    return (await this.git(['--version'], {})).trim();
  }

  remoteUrl(owner: string, name: string): string {
    return this.opts.remoteUrlFor?.(owner, name) ?? `https://github.com/${owner}/${name}.git`;
  }

  scanDir(scanId: string): string {
    return join(this.opts.workDir, SCANS_DIR, scanId);
  }

  repoDir(scanId: string): string {
    return join(this.scanDir(scanId), 'repo');
  }

  /** Resolves a branch, tag (annotated tags are peeled), `HEAD`, or full SHA to a commit SHA. */
  async resolveRef(remote: string, ref: string, call: GitCallOptions = {}): Promise<string> {
    if (SHA_RE.test(ref)) return ref.toLowerCase();
    // Pass the explicit peel pattern too: with an exact (non-glob) refname, modern git omits the
    // "refs/tags/<ref>^{}" advertisement unless it is itself requested, so an annotated tag would
    // otherwise resolve to the tag object's SHA instead of the commit it points at.
    const out = await this.git(['ls-remote', '--', remote, ref, `${ref}^{}`], { ...call, timeoutMs: LS_REMOTE_TIMEOUT_MS });
    const refs = new Map<string, string>();
    for (const line of out.split('\n')) {
      const [sha, name] = line.trim().split('\t');
      if (sha && name) refs.set(name, sha);
    }
    const sha = refs.get(`refs/heads/${ref}`)
      ?? refs.get(`refs/tags/${ref}^{}`)
      ?? refs.get(`refs/tags/${ref}`)
      ?? refs.get(`${ref}^{}`) // fully-qualified annotated tag (refs/tags/x): prefer the peeled commit
      ?? refs.get(ref);
    if (!sha) throw new AppError('REF_NOT_FOUND', 'permanent', 'Branch, tag or commit not found in this repository');
    return sha;
  }

  /**
   * Idempotent: reuses an existing checkout only when its completion marker records `sha` (a crash between
   * `clone --no-checkout` and `checkout` leaves HEAD at the tip with an empty worktree), otherwise (re)clones with --filter=blob:none and
   * checks out `sha` detached. A failed clone never leaves a half-populated directory behind.
   */
  async ensureCheckout(
    scanId: string, remote: string, sha: string,
    call: GitCallOptions & { onProgress?: (phase: string, done: number, total: number) => void } = {},
  ): Promise<string> {
    if (call.signal?.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    if (!SHA_RE.test(sha)) throw new AppError('VALIDATION', 'permanent', 'Invalid commit SHA');
    const dir = this.repoDir(scanId);

    const marker = join(dir, '.git', CHECKOUT_MARKER);
    if (existsSync(dir)) {
      const done = await readFile(marker, 'utf8').then((s) => s.trim().toLowerCase(), () => null);
      if (done === sha.toLowerCase()) return dir;
      await rm(dir, RM_OPTS);
    }

    await mkdir(this.scanDir(scanId), { recursive: true });
    const long = { ...call, timeoutMs: this.opts.cloneTimeoutMs };
    try {
      await this.git(['clone', '--filter=blob:none', '--no-checkout', '--progress', '--', remote, dir], {
        ...long,
        onStderrLine: (line) => {
          const m = line.match(PROGRESS_RE);
          if (m) call.onProgress?.(m[1]!.trim(), Number(m[2]), Number(m[3]));
        },
      });
      try {
        await this.git(['checkout', '--force', '--detach', sha], { ...long, cwd: dir });
      } catch (err) {
        if (!(err instanceof AppError) || err.code !== 'REF_NOT_FOUND') throw err;
        // The commit is not reachable from the advertised refs (e.g. a PR head): fetch it explicitly.
        await this.git(['fetch', '--filter=blob:none', '--', 'origin', sha], { ...long, cwd: dir });
        await this.git(['checkout', '--force', '--detach', sha], { ...long, cwd: dir });
      }
      await writeFile(marker, `${sha.toLowerCase()}
`);
      return dir;
    } catch (err) {
      await rm(dir, RM_OPTS).catch(() => undefined);
      throw err;
    }
  }

  async headSha(dir: string): Promise<string> {
    return (await this.git(['rev-parse', 'HEAD'], { cwd: dir })).trim().toLowerCase();
  }

  async listTree(dir: string, sha: string, call: GitCallOptions = {}): Promise<TreeEntry[]> {
    const out = await this.git(['ls-tree', '-r', '-z', '--full-tree', sha], { ...call, cwd: dir, maxStdoutBytes: MAX_TREE_BYTES });
    const entries: TreeEntry[] = [];
    for (const record of out.split('\0')) {
      if (!record) continue;
      const tab = record.indexOf('\t');
      const [mode, type, blobSha] = record.slice(0, tab).split(' ');
      entries.push({ mode: mode!, type: type as TreeEntry['type'], blobSha: blobSha!, path: record.slice(tab + 1) });
    }
    return entries;
  }

  /** Changed paths between two commits, or null when the base commit is not available locally. */
  async diffNameStatus(dir: string, baseSha: string, sha: string, call: GitCallOptions = {}): Promise<DiffEntry[] | null> {
    if (!SHA_RE.test(baseSha) || !SHA_RE.test(sha)) return null;
    let out: string;
    try {
      out = await this.git(['diff', '--name-status', '-z', '-M', baseSha, sha, '--'], { ...call, cwd: dir });
    } catch (err) {
      // An unknown base shows up as "bad object"/"unknown revision": no usable base → caller does a full scan.
      if (err instanceof AppError && err.kind === 'permanent') return null;
      throw err;
    }
    const parts = out.split('\0').filter((p) => p.length > 0);
    const entries: DiffEntry[] = [];
    for (let i = 0; i < parts.length;) {
      const status = parts[i]!.charAt(0) as DiffEntry['status'];
      if (status === 'R' || status === 'C') {
        entries.push({ status, oldPath: parts[i + 1]!, path: parts[i + 2]! });
        i += 3;
      } else {
        entries.push({ status, path: parts[i + 1]! });
        i += 2;
      }
    }
    return entries;
  }

  /**
   * Fetches one commit (trees only, blobs stay lazy) into an existing clone, e.g. an incremental
   * rescan's base commit that is no longer reachable from the advertised refs. False when the remote
   * does not have it (force-push / history rewrite) — the caller then runs a full scan.
   */
  async fetchCommit(dir: string, sha: string, call: GitCallOptions = {}): Promise<boolean> {
    if (!SHA_RE.test(sha)) return false;
    try {
      await this.git(['fetch', '--filter=blob:none', '--no-tags', '--', 'origin', sha], { ...call, cwd: dir, timeoutMs: this.opts.cloneTimeoutMs });
      return true;
    } catch (err) {
      if (err instanceof AppError && (err.kind === 'cancelled' || call.signal?.aborted)) throw err;
      return false;
    }
  }

  /**
   * Unified-0 patches of the last `depth` commits reachable from HEAD (newest first), with a NUL-prefixed
   * `\0COMMIT <sha>` marker line before each commit's patch so a parser can't be fooled by file content.
   * depth <= 0 returns `{ text: '', truncated: false }` without running git. `token` is only needed for a
   * partial clone's lazy blob fetch of a private repo and is applied the same way `ensureCheckout` applies it
   * (an `http.extraHeader` scoped to github.com, never argv/URL). Output is capped at MAX_LOG_PATCH_BYTES;
   * runProcess's output_limit failure discards whatever stdout it already buffered (ProcessError only carries
   * a stderr tail, not partial stdout), so there is nothing partial to salvage from a single attempt that hits
   * the cap. Instead, on that specific failure, this retries with a halved depth until the patch fits or depth
   * reaches 1, and reports `truncated: true` whenever a retry was needed.
   */
  async logPatch(
    repoDir: string, depth: number, signal?: AbortSignal, token?: string,
  ): Promise<{ text: string; truncated: boolean }> {
    if (!Number.isFinite(depth) || depth <= 0) return { text: '', truncated: false };
    const requested = Math.floor(depth);
    return this.logPatchAttempt(repoDir, requested, requested, signal, token);
  }

  private async logPatchAttempt(
    repoDir: string, depth: number, requested: number, signal?: AbortSignal, token?: string,
  ): Promise<{ text: string; truncated: boolean }> {
    const args = [
      'log', '-n', String(depth), '-p', '--unified=0', '--no-color', '--no-ext-diff', '--no-textconv',
      '--no-renames', '--diff-filter=AM', '--format=format:%x00COMMIT %H',
    ];
    try {
      const text = await this.git(args, {
        cwd: repoDir, signal, token, timeoutMs: this.opts.cloneTimeoutMs, maxStdoutBytes: MAX_LOG_PATCH_BYTES,
      });
      return { text, truncated: depth < requested };
    } catch (err) {
      if (err instanceof AppError && err.code === 'REPO_TOO_LARGE' && depth > 1) {
        return this.logPatchAttempt(repoDir, Math.max(1, Math.floor(depth / 2)), requested, signal, token);
      }
      if (err instanceof AppError && err.code === 'REPO_TOO_LARGE') return { text: '', truncated: true };
      throw err;
    }
  }

  async removeScanDir(scanId: string): Promise<void> {
    await rm(this.scanDir(scanId), RM_OPTS);
  }

  /**
   * Removes scan workspaces (UUID-named directories under <workDir>/scans) whose scan should not be kept;
   * returns the removed scan ids. Anything else in WORK_DIR is never touched.
   */
  async sweep(keep: (scanId: string) => boolean): Promise<string[]> {
    const scansDir = join(this.opts.workDir, SCANS_DIR);
    if (!existsSync(scansDir)) return [];
    const removed: string[] = [];
    for (const entry of await readdir(scansDir, { withFileTypes: true })) {
      if (!entry.isDirectory() || !UUID_RE.test(entry.name) || keep(entry.name)) continue;
      await this.removeScanDir(entry.name).catch(() => undefined);
      removed.push(entry.name);
    }
    return removed;
  }

  private async git(
    args: string[],
    o: GitCallOptions & { cwd?: string; timeoutMs?: number; maxStdoutBytes?: number; onStderrLine?: (line: string) => void },
  ): Promise<string> {
    const env = gitEnv({
      emptyConfigPath: join(this.opts.workDir, EMPTY_CONFIG),
      homeDir: join(this.opts.workDir, GIT_HOME),
      auth: { token: o.token },
    });
    let result: RunResult;
    try {
      result = await runProcess(this.gitBinary, [...safeGitFlags(this.opts.allowFileProtocol), ...args], {
        cwd: o.cwd, env, signal: o.signal, timeoutMs: o.timeoutMs ?? SHORT_TIMEOUT_MS, stallMs: this.opts.stallMs,
        maxStdoutBytes: o.maxStdoutBytes, onStderrLine: o.onStderrLine, onActivity: o.onActivity,
      });
    } catch (err) {
      if (err instanceof ProcessError) throw fromProcessError(err);
      throw err;
    }
    if (result.code !== 0) throw classifyGitFailure(result.stderr, { hasToken: Boolean(o.token) });
    return result.stdout;
  }
}
