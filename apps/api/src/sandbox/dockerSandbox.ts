import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { AppError } from '../errors/AppError';
import { ProcessError, runProcess, type RunResult } from '../process/runProcess';
import type {
  AnalyzeOptions, AnalyzeResult, DockerSandboxOptions, InstallOptions, InstallResult, RunFn, SandboxAvailability,
} from './types';

/** Must match TAG in scripts/sandbox-build.mjs. */
export const SANDBOX_IMAGE_TAG = 'v1';
export const SANDBOX_LABEL = 'vibesec.scan';
export const SANDBOX_UID = '10001';
const PROXY_PORT = 3128;

/** Must match the versions pinned in sandbox/node/Dockerfile (corepack has them cached; its network is disabled). */
export const PNPM_VERSION = '10.34.6';
export const YARN_CLASSIC_VERSION = '1.22.22';
export const YARN_BERRY_VERSION = '4.18.1';

const DEFAULT_INSTALL_TIMEOUT_MS = 180_000;
const DEFAULT_ANALYZE_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_DEPS_BYTES = 1.5 * 1024 * 1024 * 1024;
const AVAILABILITY_TTL_MS = 30_000;
const DOCKER_CMD_TIMEOUT_MS = 30_000;
const CLEANUP_TIMEOUT_MS = 20_000;
const MAX_MANIFEST_BYTES = 50 * 1024 * 1024;
const MAX_TREE_BYTES = 50 * 1024 * 1024;
const MAX_USAGES_BYTES = 50 * 1024 * 1024;
const MAX_CONTAINER_STDOUT = 4 * 1024 * 1024;
const MAX_PACKAGES = 10_000;
const MAX_REQUIREMENTS = 5_000;

type Limits = { memory: string; cpus: string; pids: number };
const SANDBOX_LIMITS: Limits = { memory: '2g', cpus: '2', pids: 512 };
const PROXY_LIMITS: Limits = { memory: '256m', cpus: '0.5', pids: 64 };
const HELPER_LIMITS: Limits = { memory: '256m', cpus: '1', pids: 64 };
const HELPER_TIMEOUT_MS = 120_000;

/**
 * Fixed maintenance scripts run in an offline helper container over a host dir mounted at /w. The host never
 * traverses or deletes container-written trees itself: they may hold symlinks to host paths, mode-000 dirs, files
 * the host user may not delete (uid 10001 on Linux), or — on Docker Desktop for Windows — Linux symlinks that
 * surface as reparse points on which Node's fs.rm hangs.
 */
const HELPER_CLEAN = 'chmod -R u+rwX /w 2>/dev/null; find /w -mindepth 1 -depth -exec rm -rf {} + 2>/dev/null; '
  + 'if [ -n "$(find /w -mindepth 1 ! -type d 2>/dev/null | head -n 1)" ]; then echo LEFTOVER; else echo CLEAN; fi';
const helperPostInstall = (depsRel: string) => 'chmod -R u+rwX /w 2>/dev/null; '
  + 'find /w/cache /w/tmp -mindepth 1 -depth -exec rm -rf {} + 2>/dev/null; '
  + `echo "SIZE_KB=$(du -sk /w/${depsRel} 2>/dev/null | cut -f1)"`;

/**
 * Host environment variables the docker CLI may see. Everything else (GITHUB_TOKEN, ANTHROPIC_API_KEY, cloud
 * credentials, proxies, ...) is dropped. Containers never inherit the CLI env anyway (only explicit --env); this
 * keeps the CLI process itself hermetic. Matched case-insensitively (Windows env names are).
 */
const DOCKER_ENV_ALLOW = [
  'PATH', 'SystemRoot', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY',
  'USERPROFILE', 'HOME', 'TEMP', 'TMP',
].map((k) => k.toLowerCase());

export function dockerCliEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of Object.keys(base)) {
    if (DOCKER_ENV_ALLOW.includes(key.toLowerCase()) && base[key] !== undefined) env[key] = base[key];
  }
  return env;
}

export type BindMount = { source: string; target: string; readonly: boolean };

export type ContainerSpec = {
  name: string;
  scanId: string;
  image: string;
  /** 'none' (phase B), 'bridge' (proxy only) or a per-scan --internal network name (phase A). */
  network: string;
  mounts: BindMount[];
  env: Record<string, string>;
  command: string[];
  workdir?: string;
  detach?: boolean;
  limits?: Limits;
};

/**
 * The single place that builds a `docker run` argv: every sandbox container (install, analyze, proxy) gets the
 * same hardening. Exported for unit tests and for the Docker integration test, which runs exactly these flags.
 */
export function hardenedRunArgs(spec: ContainerSpec): string[] {
  const l = spec.limits ?? SANDBOX_LIMITS;
  const args = ['run'];
  if (spec.detach) args.push('-d');
  args.push(
    '--rm', '--init', '--pull', 'never',
    '--name', spec.name,
    '--label', `${SANDBOX_LABEL}=${spec.scanId}`,
    '--hostname', 'sandbox',
    '--user', `${SANDBOX_UID}:${SANDBOX_UID}`,
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=256m',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', String(l.pids),
    '--memory', l.memory, '--memory-swap', l.memory,
    '--cpus', l.cpus,
    '--ulimit', 'core=0',
    '--network', spec.network,
  );
  for (const [k, v] of Object.entries(spec.env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || /[\r\n\0]/.test(v)) throw new Error(`invalid sandbox env ${k}`);
    args.push('--env', `${k}=${v}`);
  }
  for (const m of spec.mounts) {
    // --mount (unlike -v) never auto-creates a missing host path, and is unambiguous with Windows drive letters.
    if (/[,"\r\n\0]/.test(m.source) || !isAbsolute(m.source)) throw new Error(`unsupported bind mount source: ${m.source}`);
    args.push('--mount', `type=bind,source=${m.source},target=${m.target}${m.readonly ? ',readonly' : ''}`);
  }
  if (spec.workdir) args.push('--workdir', spec.workdir);
  args.push(spec.image, ...spec.command);
  return args;
}

const SCAN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const DOCKER_ID_RE = /^[0-9a-f]{12,64}$/;

function assertScanId(scanId: string): void {
  if (!SCAN_ID_RE.test(scanId)) throw new Error(`invalid scanId for sandbox: ${JSON.stringify(scanId).slice(0, 80)}`);
}

const cancelled = () => new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
const rand = () => randomBytes(3).toString('hex');
const shortId = (scanId: string) => scanId.replace(/[^A-Za-z0-9]/g, '').slice(0, 8).toLowerCase();
const RM_OPTS = { recursive: true, force: true, maxRetries: 5, retryDelay: 200 } as const;
const baseName = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** Container output is attacker-influenced: strip control chars and keep a short tail for messages. */
function tail(text: string, max = 600): string {
  // eslint-disable-next-line no-control-regex
  const clean = text.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '').trim();
  return clean.length > max ? `…${clean.slice(-max)}` : clean;
}

/** An expected, user-facing failure while staging inputs or reading outputs. */
class StageError extends Error {}

/** Reads a JSON file written by a container without ever following a symlink planted in the output dir. */
export async function readJsonCapped(path: string, maxBytes: number): Promise<unknown> {
  let st;
  try {
    st = await lstat(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') throw new StageError(`${baseName(path)} was not produced`);
    // e.g. EACCES: on Docker Desktop for Windows a Linux symlink written by the container is an unreadable reparse point.
    throw new StageError(`${baseName(path)} is not a regular file (unreadable: ${(err as NodeJS.ErrnoException).code ?? 'error'})`);
  }
  if (!st.isFile()) throw new StageError(`${baseName(path)} is not a regular file (symlink or special file refused)`);
  if (st.size > maxBytes) throw new StageError(`${baseName(path)} exceeds ${maxBytes} bytes`);
  // O_NOFOLLOW closes the lstat→open race on POSIX hosts (undefined on Windows, where lstat is the guard).
  const fh = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const st2 = await fh.stat();
    if (!st2.isFile() || st2.size > maxBytes) throw new StageError(`${baseName(path)} changed while reading`);
    const buf = await fh.readFile();
    if (buf.length > maxBytes) throw new StageError(`${baseName(path)} exceeds ${maxBytes} bytes`);
    try {
      return JSON.parse(buf.toString('utf8')) as unknown;
    } catch {
      throw new StageError(`${baseName(path)} is not valid JSON`);
    }
  } finally {
    await fh.close();
  }
}

/**
 * Every path component from `base` (exclusive) down to `target` must be a real directory, not a symlink: the
 * container could have replaced e.g. node_modules with a link to a host path that a later bind mount would follow.
 * A missing leaf is created when `createLeaf` (e.g. an install without dependencies has no node_modules).
 */
async function assertRealDirChain(base: string, target: string, createLeaf: boolean): Promise<void> {
  const rel = relative(base, target);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) throw new StageError('dependency dir is outside the sandbox dir');
  const parts = rel.split(/[\\/]/);
  let cur = base;
  for (const [i, part] of parts.entries()) {
    cur = join(cur, part);
    let st;
    try {
      st = await lstat(cur);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT' && createLeaf && i === parts.length - 1) {
        await mkdir(cur);
        return;
      }
      throw new StageError(`dependency dir is not a plain directory (${(err as NodeJS.ErrnoException).code ?? 'error'})`);
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw new StageError('dependency dir is not a plain directory (symlink refused)');
  }
}

/** Copies a repo file only if it is a regular file (never a symlink: a planted link could exfiltrate host files). */
async function copyRegular(from: string, to: string): Promise<boolean> {
  let st;
  try {
    st = await lstat(from);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw err;
  }
  if (!st.isFile()) throw new StageError(`${baseName(from)} is not a regular file`);
  if (st.size > MAX_MANIFEST_BYTES) throw new StageError(`${baseName(from)} is too large`);
  await copyFile(from, to);
  return true;
}

const within = (parent: string, child: string) => {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
};

/** PEP 508 subset: name[extras] specifiers ; marker. No URLs, paths, options (-r/--index-url), hashes or comments. */
const REQUIREMENT_RE = new RegExp(
  '^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?'
  + '(?:\\[[A-Za-z0-9._-]+(?:\\s*,\\s*[A-Za-z0-9._-]+)*\\])?'
  + '(?:\\s*(?:===|==|~=|!=|<=|>=|<|>)\\s*[A-Za-z0-9.*+!_-]+(?:\\s*,\\s*(?:===|==|~=|!=|<=|>=|<|>)\\s*[A-Za-z0-9.*+!_-]+)*)?'
  + '(?:\\s*;\\s*[A-Za-z0-9_.<>=!~"\' (),-]+)?$',
);

export function isSafeRequirement(line: string): boolean {
  return line.length <= 500 && REQUIREMENT_RE.test(line);
}

type NodePm = 'npm' | 'npm-nolock' | 'pnpm' | 'yarn' | 'yarn-berry';

const NPM_LS = '(npm ls --all --json --long=false > /out/tree.json 2>/dev/null; exit 0)';
const NPM_CI = 'npm ci --ignore-scripts --no-audit --no-fund --loglevel=error';
/** Fixed scripts: nothing attacker-controlled is ever interpolated into a shell command. */
export const NODE_SCRIPTS: Record<NodePm, string> = {
  npm: `${NPM_CI} && ${NPM_LS}`,
  'npm-nolock': `npm install --ignore-scripts --package-lock-only --no-audit --no-fund --loglevel=error && ${NPM_CI} && ${NPM_LS}`,
  pnpm: 'pnpm install --frozen-lockfile --ignore-scripts --reporter=silent && (pnpm ls --json --depth Infinity > /out/tree.json 2>/dev/null; exit 0)',
  yarn: `yarn install --frozen-lockfile --ignore-scripts --non-interactive --no-progress --silent && ${NPM_LS}`,
  'yarn-berry': `yarn install --immutable --mode=skip-build && ${NPM_LS}`,
};
const NODE_PM_FIELD: Record<NodePm, string | null> = {
  npm: null, 'npm-nolock': null,
  pnpm: `pnpm@${PNPM_VERSION}`, yarn: `yarn@${YARN_CLASSIC_VERSION}`, 'yarn-berry': `yarn@${YARN_BERRY_VERSION}`,
};

type ContainerOutcome =
  | { kind: 'exit'; result: RunResult }
  | { kind: 'timeout'; message: string }
  | { kind: 'unavailable'; message: string };

type Staged = { depsDir: string; treeFile: string; build: (proxyUrl: string, network: string) => ContainerSpec };

export class DockerSandbox {
  private readonly run: RunFn;
  private readonly dockerBin: string;
  private readonly env: NodeJS.ProcessEnv;
  private readonly installTimeoutMs: number;
  private readonly analyzeTimeoutMs: number;
  private readonly maxDepsBytes: number;
  private availabilityCache: { at: number; value: SandboxAvailability } | null = null;

  constructor(private readonly opts: DockerSandboxOptions) {
    this.run = opts.run ?? runProcess;
    this.dockerBin = opts.dockerBinary ?? 'docker';
    this.env = dockerCliEnv(opts.hostEnv);
    this.installTimeoutMs = opts.installTimeoutMs ?? DEFAULT_INSTALL_TIMEOUT_MS;
    this.analyzeTimeoutMs = opts.analyzeTimeoutMs ?? DEFAULT_ANALYZE_TIMEOUT_MS;
    this.maxDepsBytes = opts.maxDepsBytes ?? DEFAULT_MAX_DEPS_BYTES;
  }

  image(kind: 'node' | 'python' | 'proxy'): string {
    return `${this.opts.imagePrefix}/sandbox-${kind}:${SANDBOX_IMAGE_TAG}`;
  }

  /** Host dir holding everything the sandbox produced for one scan (removed by sweep). */
  scanRoot(scanId: string): string {
    return join(resolve(this.opts.workDir), 'sandbox', scanId);
  }

  private cli(args: string[], timeoutMs: number, signal?: AbortSignal, maxStdoutBytes = 1024 * 1024): Promise<RunResult> {
    return this.run(this.dockerBin, args, { env: this.env, timeoutMs, ...(signal ? { signal } : {}), maxStdoutBytes });
  }

  /** Best-effort docker command for cleanup paths: never throws, never uses the (possibly aborted) scan signal. */
  private async quiet(args: string[]): Promise<RunResult | null> {
    try {
      return await this.cli(args, CLEANUP_TIMEOUT_MS);
    } catch {
      return null;
    }
  }

  async availability(signal: AbortSignal): Promise<SandboxAvailability> {
    const cached = this.availabilityCache;
    if (cached && Date.now() - cached.at < AVAILABILITY_TTL_MS) return cached.value;
    let value: SandboxAvailability;
    try {
      const v = await this.cli(['version', '--format', '{{.Server.Version}}'], 15_000, signal);
      const serverVersion = v.stdout.trim();
      if (v.code !== 0 || !serverVersion) {
        value = { ok: false, reason: `docker daemon not reachable: ${tail(v.stderr, 300)}` };
      } else {
        const images = [this.image('node'), this.image('python'), this.image('proxy')];
        const i = await this.cli(['image', 'inspect', '--format', '{{.Id}}', ...images], 15_000, signal);
        value = i.code === 0
          ? { ok: true, serverVersion }
          : { ok: false, reason: `sandbox images missing (${images.join(', ')}); run \`npm run sandbox:build\`` };
      }
    } catch (err) {
      if (err instanceof ProcessError && err.reason === 'aborted') throw cancelled();
      value = { ok: false, reason: err instanceof Error ? `docker unavailable: ${err.message}` : 'docker unavailable' };
    }
    this.availabilityCache = { at: Date.now(), value };
    return value;
  }

  /** Runs one container to completion; on timeout/cancel the container itself is killed (killing the CLI is not enough). */
  private async runContainer(spec: ContainerSpec, timeoutMs: number, signal: AbortSignal): Promise<ContainerOutcome> {
    const args = hardenedRunArgs(spec);
    let result: RunResult;
    try {
      result = await this.cli(args, timeoutMs, signal, MAX_CONTAINER_STDOUT);
    } catch (err) {
      if (!(err instanceof ProcessError)) throw err;
      await this.killContainer(spec.name);
      switch (err.reason) {
        case 'aborted': throw cancelled();
        case 'timeout':
        case 'stall': return { kind: 'timeout', message: `sandbox container exceeded ${timeoutMs} ms and was killed` };
        case 'spawn': return { kind: 'unavailable', message: `docker CLI could not be started: ${err.message}` };
        case 'output_limit': return { kind: 'exit', result: { code: -1, stdout: '', stderr: 'container output exceeded the cap' } };
      }
    }
    if (signal.aborted) {
      await this.killContainer(spec.name);
      throw cancelled();
    }
    if (result.code === 125) return { kind: 'unavailable', message: `docker could not start the container: ${tail(result.stderr, 300)}` };
    return { kind: 'exit', result };
  }

  private async killContainer(name: string): Promise<void> {
    await this.quiet(['kill', name]);
    await this.quiet(['rm', '-f', name]);
  }

  /** Runs a fixed maintenance script (see HELPER_CLEAN) offline over `hostDir` (at /w). Null when docker failed. */
  private async helper(scanId: string, hostDir: string, script: string): Promise<RunResult | null> {
    const name = `vibesec-helper-${shortId(scanId)}-${rand()}`;
    const args = hardenedRunArgs({
      name, scanId, image: this.image('node'), network: 'none', limits: HELPER_LIMITS,
      mounts: [{ source: hostDir, target: '/w', readonly: false }], env: {}, command: ['sh', '-c', script],
    });
    try {
      const r = await this.cli(args, HELPER_TIMEOUT_MS);
      return r.code === 0 ? r : null;
    } catch {
      await this.killContainer(name);
      return null;
    }
  }

  /**
   * Deletes a dir holding container-written files: contents via the helper container, then the (now empty,
   * host-owned) directories on the host. If the helper cannot run or leaves non-directories behind, the dir is left
   * for a later sweep rather than risking a host-side traversal of attacker-controlled entries.
   */
  private async removeTree(scanId: string, dir: string): Promise<void> {
    if (!await lstat(dir).then(() => true, () => false)) return;
    const r = await this.helper(scanId, dir, HELPER_CLEAN);
    if (r?.stdout.includes('CLEAN')) await rm(dir, RM_OPTS);
  }

  /**
   * Phase-A egress: a per-scan --internal network whose only other member is the allowlist proxy, which is also on
   * the default bridge (its only way out). Both are torn down whatever happens inside `fn`.
   */
  private async withEgress<T>(
    scanId: string, signal: AbortSignal, fn: (proxyUrl: string, network: string) => Promise<T>,
  ): Promise<{ value: T; denied: string[] } | { unavailable: string }> {
    const suffix = `${shortId(scanId)}-${rand()}`;
    const network = `vibesec-net-${suffix}`;
    const proxyName = `vibesec-proxy-${suffix}`;
    let proxyStarted = false;
    let networkCreated = false;
    try {
      const n = await this.cli(
        ['network', 'create', '--internal', '--driver', 'bridge', '--label', `${SANDBOX_LABEL}=${scanId}`, network],
        DOCKER_CMD_TIMEOUT_MS, signal,
      );
      if (n.code !== 0) return { unavailable: `could not create sandbox network: ${tail(n.stderr, 300)}` };
      networkCreated = true;
      proxyStarted = true; // set before the call: a timed-out `run -d` may still have created the container
      const p = await this.cli(hardenedRunArgs({
        name: proxyName, scanId, image: this.image('proxy'), network: 'bridge', mounts: [], env: {},
        command: [], detach: true, limits: PROXY_LIMITS,
      }), DOCKER_CMD_TIMEOUT_MS, signal);
      if (p.code !== 0) return { unavailable: `could not start egress proxy: ${tail(p.stderr, 300)}` };
      const c = await this.cli(['network', 'connect', network, proxyName], DOCKER_CMD_TIMEOUT_MS, signal);
      if (c.code !== 0) return { unavailable: `could not attach egress proxy: ${tail(c.stderr, 300)}` };

      const value = await fn(`http://${proxyName}:${PROXY_PORT}`, network);
      const logs = await this.quiet(['logs', '--tail', '500', proxyName]);
      return { value, denied: deniedHosts(logs?.stdout ?? '') };
    } catch (err) {
      if (err instanceof ProcessError) {
        if (err.reason === 'aborted') throw cancelled();
        return { unavailable: `docker failed while preparing the sandbox: ${err.message}` };
      }
      throw err;
    } finally {
      if (proxyStarted) await this.killContainer(proxyName);
      if (networkCreated) await this.quiet(['network', 'rm', network]);
    }
  }

  async install(opts: InstallOptions): Promise<InstallResult> {
    assertScanId(opts.scanId);
    if (opts.signal.aborted) throw cancelled();
    const avail = await this.availability(opts.signal);
    if (!avail.ok) return { ok: false, code: 'SANDBOX_UNAVAILABLE', message: avail.reason };

    const runDir = join(this.scanRoot(opts.scanId), `install-${opts.ecosystem === 'npm' ? 'npm' : 'pypi'}-${rand()}`);
    const inDir = join(runDir, 'in');
    const outDir = join(runDir, 'out');
    let keep = false;
    let touched = false; // a container wrote into runDir: only the helper may delete it
    try {
      await makeDirs(inDir, outDir, join(outDir, 'tmp'), join(outDir, 'cache'));
      // Sticky: the container user may create entries in /out but not delete/replace the host-made work/cache/tmp.
      await chmod(outDir, 0o1777);
      const warnings: string[] = [];
      let stage: Staged;
      try {
        stage = opts.ecosystem === 'npm'
          ? await this.stageNpm(opts.scanId, opts.srcDir, opts.manifestDir, outDir)
          : await this.stagePython(opts.scanId, opts.requirements, inDir, outDir, warnings);
      } catch (err) {
        if (err instanceof StageError) return { ok: false, code: 'SANDBOX_INSTALL_FAILED', message: err.message };
        throw err;
      }

      touched = true;
      const egress = await this.withEgress(opts.scanId, opts.signal,
        (proxyUrl, network) => this.runContainer(stage.build(proxyUrl, network), this.installTimeoutMs, opts.signal));
      if ('unavailable' in egress) return { ok: false, code: 'SANDBOX_UNAVAILABLE', message: egress.unavailable };
      for (const host of egress.denied) warnings.push(`sandbox proxy denied egress to ${host}`);
      const outcome = egress.value;
      if (outcome.kind === 'unavailable') return { ok: false, code: 'SANDBOX_UNAVAILABLE', message: outcome.message };
      if (outcome.kind === 'timeout') return { ok: false, code: 'SANDBOX_TIMEOUT', message: `dependency install: ${outcome.message}` };
      if (outcome.result.code !== 0) {
        const oom = outcome.result.code === 137 ? ' (killed, out of memory?)' : '';
        return {
          ok: false, code: 'SANDBOX_INSTALL_FAILED',
          message: `dependency install exited with ${outcome.result.code}${oom}: ${tail(outcome.result.stderr || outcome.result.stdout)}`,
        };
      }

      // Drop caches and measure the install from inside a helper container (see HELPER_CLEAN for why not on the host).
      const post = await this.helper(opts.scanId, outDir, helperPostInstall(relative(outDir, stage.depsDir).split(sep).join('/')));
      const sizeKb = Number(/SIZE_KB=(\d*)/.exec(post?.stdout ?? '')?.[1] || 0);
      if (!post) return { ok: false, code: 'SANDBOX_UNAVAILABLE', message: 'sandbox helper container failed after install' };
      if (sizeKb * 1024 > this.maxDepsBytes) {
        return { ok: false, code: 'SANDBOX_INSTALL_FAILED', message: `installed dependencies exceed ${Math.round(this.maxDepsBytes / 1048576)} MB` };
      }
      try {
        await assertRealDirChain(runDir, stage.depsDir, true);
      } catch (err) {
        if (err instanceof StageError) return { ok: false, code: 'SANDBOX_INSTALL_FAILED', message: err.message };
        throw err;
      }
      let tree: unknown = null;
      try {
        tree = await readJsonCapped(stage.treeFile, MAX_TREE_BYTES);
      } catch (err) {
        if (!(err instanceof StageError)) throw err;
        warnings.push(`dependency tree unavailable: ${err.message}`);
      }
      keep = true;
      return { ok: true, ecosystem: opts.ecosystem, depsDir: stage.depsDir, tree, warnings };
    } finally {
      if (!keep) await (touched ? this.removeTree(opts.scanId, runDir) : rm(runDir, RM_OPTS));
    }
  }

  private async stageNpm(scanId: string, srcDir: string, manifestDir: string, outDir: string): Promise<Staged> {
    const root = await realpath(resolve(srcDir)).catch(() => { throw new StageError('repository checkout not found'); });
    const dir = resolve(root, manifestDir);
    if (!within(root, dir)) throw new StageError('manifest directory escapes the repository');
    const realDir = await realpath(dir).catch(() => { throw new StageError('manifest directory not found'); });
    if (!within(root, realDir)) throw new StageError('manifest directory escapes the repository');

    const work = join(outDir, 'work');
    await makeDirs(work);
    const has = async (f: string) => (await lstat(join(realDir, f)).catch(() => null)) !== null;
    let pm: NodePm;
    let lockfiles: string[];
    if (await has('package-lock.json') || await has('npm-shrinkwrap.json')) {
      pm = 'npm'; lockfiles = ['package-lock.json', 'npm-shrinkwrap.json'];
    } else if (await has('pnpm-lock.yaml')) {
      pm = 'pnpm'; lockfiles = ['pnpm-lock.yaml'];
    } else if (await has('yarn.lock')) {
      pm = 'yarn'; lockfiles = ['yarn.lock'];
    } else {
      pm = 'npm-nolock'; lockfiles = [];
    }

    // Only the manifest and the chosen lockfile: .npmrc / .yarnrc(.yml) / pnpm-workspace.yaml can carry registry
    // credentials, alternate registries, yarnPath (arbitrary JS) or plugins, and are never copied.
    if (!await copyRegular(join(realDir, 'package.json'), join(work, 'package.json'))) throw new StageError('package.json not found');
    for (const f of lockfiles) await copyRegular(join(realDir, f), join(work, f));
    if (pm === 'yarn' && (await readFile(join(work, 'yarn.lock'), 'utf8')).includes('__metadata:')) pm = 'yarn-berry';

    // The repo's `packageManager` field would make corepack fetch an arbitrary version: pin ours (cached in the image).
    let pkg: unknown;
    try {
      pkg = JSON.parse(await readFile(join(work, 'package.json'), 'utf8'));
    } catch {
      throw new StageError('package.json is not valid JSON');
    }
    if (typeof pkg !== 'object' || pkg === null || Array.isArray(pkg)) throw new StageError('package.json is not an object');
    const manifest = pkg as Record<string, unknown>;
    delete manifest.packageManager;
    const field = NODE_PM_FIELD[pm];
    if (field) manifest.packageManager = field;
    await writeFile(join(work, 'package.json'), JSON.stringify(manifest, null, 2));

    const script = NODE_SCRIPTS[pm];
    return {
      depsDir: join(work, 'node_modules'),
      treeFile: join(outDir, 'tree.json'),
      build: (proxyUrl, network) => ({
        name: `vibesec-install-${shortId(scanId)}-${rand()}`, scanId, image: this.image('node'), network,
        mounts: [{ source: outDir, target: '/out', readonly: false }],
        env: nodeInstallEnv(proxyUrl), workdir: '/out/work',
        command: ['sh', '-c', script],
      }),
    };
  }

  private async stagePython(scanId: string, requirements: string[], inDir: string, outDir: string, warnings: string[]): Promise<Staged> {
    const safe: string[] = [];
    for (const raw of requirements.slice(0, MAX_REQUIREMENTS)) {
      const line = raw.trim();
      if (!line) continue;
      if (isSafeRequirement(line)) safe.push(line);
      else warnings.push(`skipped unsupported requirement: ${tail(line, 120)}`);
    }
    if (requirements.length > MAX_REQUIREMENTS) warnings.push(`only the first ${MAX_REQUIREMENTS} requirements were installed`);
    if (safe.length === 0) throw new StageError('no installable pinned requirements');
    await writeFile(join(inDir, 'requirements.txt'), `${safe.join('\n')}\n`);
    return {
      depsDir: join(outDir, 'deps'),
      treeFile: join(outDir, 'report.json'),
      build: (proxyUrl, network) => ({
        name: `vibesec-install-${shortId(scanId)}-${rand()}`, scanId, image: this.image('python'), network,
        mounts: [{ source: inDir, target: '/in', readonly: true }, { source: outDir, target: '/out', readonly: false }],
        env: {
          HOME: '/tmp', TMPDIR: '/out/tmp', PYTHONDONTWRITEBYTECODE: '1',
          HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl,
        },
        workdir: '/tmp',
        // Wheels only (--only-binary=:all:): no sdist build, so no setup.py / build backend ever executes.
        // --isolated ignores PIP_* env and pip.conf; index and proxy are given explicitly.
        command: [
          'python', '-m', 'pip', 'install', '--isolated', '--only-binary=:all:', '--no-input', '--disable-pip-version-check',
          '--no-cache-dir', '--no-compile', '--no-warn-script-location', '--progress-bar', 'off',
          '--index-url', 'https://pypi.org/simple', '--proxy', proxyUrl,
          '--target', '/out/deps', '--report', '/out/report.json', '-r', '/in/requirements.txt',
        ],
      }),
    };
  }

  async analyze(opts: AnalyzeOptions): Promise<AnalyzeResult> {
    assertScanId(opts.scanId);
    if (opts.signal.aborted) throw cancelled();
    const scanRoot = this.scanRoot(opts.scanId);
    if (opts.depsDir !== undefined && !within(scanRoot, resolve(opts.depsDir))) {
      return { ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: 'depsDir is not a sandbox install of this scan' };
    }
    if (opts.packages.length > MAX_PACKAGES || opts.packages.some((p) => typeof p !== 'string' || p.length > 300)) {
      return { ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: 'invalid package list' };
    }
    if (opts.depsDir !== undefined) {
      try {
        await assertRealDirChain(scanRoot, resolve(opts.depsDir), false);
      } catch (err) {
        if (err instanceof StageError) return { ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: err.message };
        throw err;
      }
    }
    const avail = await this.availability(opts.signal);
    if (!avail.ok) return { ok: false, code: 'SANDBOX_UNAVAILABLE', message: avail.reason };

    const runDir = join(scanRoot, `analyze-${rand()}`);
    const inDir = join(runDir, 'in');
    const outDir = join(runDir, 'out');
    let touched = false;
    try {
      await makeDirs(inDir, outDir);
      await writeFile(join(inDir, 'packages.json'), JSON.stringify(opts.packages));
      const mounts: BindMount[] = [{ source: resolve(opts.srcDir), target: '/src', readonly: true }];
      if (opts.depsDir !== undefined) mounts.push({ source: resolve(opts.depsDir), target: '/deps', readonly: true });
      mounts.push({ source: inDir, target: '/in', readonly: true }, { source: outDir, target: '/out', readonly: false });
      const node = opts.ecosystem === 'npm';
      touched = true;
      const outcome = await this.runContainer({
        name: `vibesec-analyze-${shortId(opts.scanId)}-${rand()}`, scanId: opts.scanId,
        image: this.image(node ? 'node' : 'python'), network: 'none', mounts,
        env: { HOME: '/tmp', PYTHONDONTWRITEBYTECODE: '1' }, workdir: '/tmp',
        command: node ? ['node', '/opt/vibesec/analyze.mjs'] : ['python', '/opt/vibesec/analyze.py'],
      }, this.analyzeTimeoutMs, opts.signal);
      if (outcome.kind === 'unavailable') return { ok: false, code: 'SANDBOX_UNAVAILABLE', message: outcome.message };
      if (outcome.kind === 'timeout') return { ok: false, code: 'SANDBOX_TIMEOUT', message: `usage analysis: ${outcome.message}` };
      if (outcome.result.code !== 0) {
        return {
          ok: false, code: 'SANDBOX_ANALYZE_FAILED',
          message: `analyzer exited with ${outcome.result.code}: ${tail(outcome.result.stderr || outcome.result.stdout)}`,
        };
      }
      try {
        return { ok: true, usages: await readJsonCapped(join(outDir, 'usages.json'), MAX_USAGES_BYTES) };
      } catch (err) {
        if (err instanceof StageError) return { ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: err.message };
        throw err;
      }
    } finally {
      await (touched ? this.removeTree(opts.scanId, runDir) : rm(runDir, RM_OPTS));
    }
  }

  /**
   * Removes every container, network and volume labeled vibesec.scan(=scanId) plus the host staging dir.
   * Call on scan finish (with the id) and on startup (without: removes ALL sandbox leftovers of every scan).
   */
  async sweep(scanId?: string): Promise<void> {
    if (scanId !== undefined) assertScanId(scanId);
    const filter = scanId === undefined ? `label=${SANDBOX_LABEL}` : `label=${SANDBOX_LABEL}=${scanId}`;
    const ids = async (args: string[]) => {
      const r = await this.quiet([...args, '--filter', filter]);
      return r && r.code === 0 ? r.stdout.split(/\s+/).filter((s) => DOCKER_ID_RE.test(s)) : [];
    };
    const containers = await ids(['ps', '-aq']);
    if (containers.length) await this.quiet(['rm', '-f', ...containers]);
    const networks = await ids(['network', 'ls', '-q']);
    if (networks.length) await this.quiet(['network', 'rm', ...networks]);
    const volumes = await ids(['volume', 'ls', '-q']);
    if (volumes.length) await this.quiet(['volume', 'rm', '-f', ...volumes]);
    await this.removeTree(scanId ?? 'sweep', scanId === undefined ? join(resolve(this.opts.workDir), 'sandbox') : this.scanRoot(scanId));
  }
}

/** Fixed env for node installs: public registries only, proxy for every client, corepack strictly offline. */
function nodeInstallEnv(proxyUrl: string): Record<string, string> {
  return {
    HOME: '/tmp', TMPDIR: '/out/tmp',
    HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl,
    npm_config_https_proxy: proxyUrl, npm_config_proxy: proxyUrl,
    npm_config_registry: 'https://registry.npmjs.org/',
    npm_config_cache: '/out/cache/npm', npm_config_store_dir: '/out/cache/pnpm-store',
    npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false', npm_config_ignore_scripts: 'true',
    COREPACK_ENABLE_NETWORK: '0', COREPACK_ENABLE_DOWNLOAD_PROMPT: '0', COREPACK_ENABLE_AUTO_PIN: '0',
    YARN_CACHE_FOLDER: '/out/cache/yarn', YARN_GLOBAL_FOLDER: '/out/cache/yarn-global', YARN_ENABLE_GLOBAL_CACHE: 'false',
    YARN_NODE_LINKER: 'node-modules', YARN_ENABLE_SCRIPTS: 'false', YARN_ENABLE_TELEMETRY: 'false',
    YARN_ENABLE_PROGRESS_BARS: 'false', YARN_NPM_REGISTRY_SERVER: 'https://registry.yarnpkg.com',
    YARN_HTTPS_PROXY: proxyUrl, YARN_HTTP_PROXY: proxyUrl,
  };
}

/** Creates dirs writable by the container user (uid 10001): on Linux hosts a bind mount keeps host ownership. */
async function makeDirs(...dirs: string[]): Promise<void> {
  for (const d of dirs) {
    await mkdir(d, { recursive: true });
    await chmod(d, 0o777);
  }
}

/** Distinct targets the proxy refused, from its JSON-lines log (attacker-influenced: sanitized and capped). */
function deniedHosts(logs: string): string[] {
  const hosts = new Set<string>();
  for (const line of logs.split('\n')) {
    if (hosts.size >= 20) break;
    let entry: { decision?: unknown; host?: unknown; target?: unknown };
    try {
      entry = JSON.parse(line) as typeof entry;
    } catch {
      continue;
    }
    if (entry.decision !== 'deny') continue;
    const h = typeof entry.host === 'string' ? entry.host : typeof entry.target === 'string' ? entry.target : null;
    if (h) hosts.add(h.replace(/[^A-Za-z0-9.:\-[\]/_]/g, '').slice(0, 100));
  }
  return [...hosts];
}
