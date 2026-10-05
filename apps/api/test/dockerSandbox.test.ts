import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { AppError } from '../src/errors/AppError';
import { ProcessError, runProcess, type RunOptions, type RunResult } from '../src/process/runProcess';
import {
  type ContainerSpec, DockerSandbox, dockerCliEnv, hardenedRunArgs, isSafeRequirement, PNPM_VERSION, YARN_BERRY_VERSION,
} from '../src/sandbox/dockerSandbox';
import type { RunFn } from '../src/sandbox/types';

type Call = { cmd: string; args: string[]; opts: RunOptions };
type Handler = (args: string[], opts: RunOptions) => Promise<RunResult> | RunResult;

const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '' });
const SCAN = '3f2b9c1e-1111-4222-8333-444455556666';
const HARDENING = [
  '--rm', '--init', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
  '--pids-limit', '--memory', '--cpus', '--pull', 'never',
];

/** Value following a flag, e.g. flag(args, '--network'). */
const flag = (args: string[], name: string) => args[args.indexOf(name) + 1];
const flagValues = (args: string[], name: string) => args.flatMap((a, i) => (a === name ? [args[i + 1]!] : []));
const mountSource = (args: string[], target: string) => {
  const m = flagValues(args, '--mount').find((v) => v.includes(`target=${target}`));
  return m ? /source=([^,]+)/.exec(m)![1]! : undefined;
};
const isRun = (args: string[]) => args[0] === 'run';
const isDetachedRun = (args: string[]) => isRun(args) && args[1] === '-d';
const isHelperRun = (args: string[]) => isRun(args) && (flag(args, '--name') ?? '').startsWith('vibesec-helper-');
const isWorkloadRun = (args: string[]) => isRun(args) && !isDetachedRun(args) && !isHelperRun(args);

/** Host-side stand-in for the helper container's `du -sk` (test files are plain). */
function treeBytes(dir: string): number {
  if (!existsSync(dir)) return 0;
  let total = 0;
  for (const e of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (e.isFile()) total += statSync(join(e.parentPath, e.name)).size;
  }
  return total;
}

/** Simulates the helper container: post-install size report, or a successful cleanup. */
const helperResult = (args: string[]): RunResult => {
  const script = args.at(-1)!;
  const sizeMatch = /du -sk \/w\/(\S+)/.exec(script);
  if (sizeMatch) return ok(`SIZE_KB=${Math.ceil(treeBytes(join(mountSource(args, '/w')!, sizeMatch[1]!)) / 1024)}\n`);
  return ok('CLEAN\n');
};

function fake(workload: Handler = () => ok(), overrides: Record<string, Handler> = {}) {
  const calls: Call[] = [];
  const run = (async (cmd: string, args: readonly string[], opts: RunOptions) => {
    const a = [...args];
    calls.push({ cmd, args: a, opts });
    const key = a[0] === 'network' || a[0] === 'image' ? `${a[0]} ${a[1]}` : a[0]!;
    if (overrides[key]) return overrides[key]!(a, opts);
    if (key === 'version') return ok('28.5.1\n');
    if (isDetachedRun(a)) return ok('abc123\n');
    if (isHelperRun(a)) return overrides.helper ? overrides.helper(a, opts) : helperResult(a);
    if (isRun(a)) return workload(a, opts);
    if (key === 'logs') return ok(`${JSON.stringify({ decision: 'deny', host: 'evil.example', port: 443, reason: 'host-not-allowlisted' })}\n{"decision":"allow","host":"registry.npmjs.org"}\n`);
    return ok();
  }) as RunFn;
  return { run, calls };
}

/**
 * Plants a link at `at`: a file symlink where permitted, else (unprivileged Windows) a directory junction to the
 * target's parent dir. Either way it is not a regular file and must be refused. False if neither is possible.
 */
async function plantLink(target: string, at: string): Promise<boolean> {
  try {
    await symlink(target, at);
    return true;
  } catch {
    try {
      await symlink(join(target, '..'), at, 'junction');
      return true;
    } catch {
      return false;
    }
  }
}

let work: string;
let repo: string;
const signal = () => new AbortController().signal;

beforeEach(async () => {
  work = await mkdtemp(join(tmpdir(), 'vibesec-sbx-'));
  repo = join(work, 'repo');
  await mkdir(join(repo, 'web'), { recursive: true });
  await writeFile(join(repo, 'web', 'package.json'), JSON.stringify({ name: 'web', packageManager: 'yarn@0.0.0-evil', dependencies: { lodash: '^4.17.0' } }));
  await writeFile(join(repo, 'web', 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}');
  await writeFile(join(repo, 'web', '.npmrc'), '//registry.npmjs.org/:_authToken=npm_SHOULD_NOT_BE_COPIED');
});
afterEach(async () => {
  await rm(work, { recursive: true, force: true });
});

function sandbox(run: RunFn, extra: Partial<ConstructorParameters<typeof DockerSandbox>[0]> = {}) {
  return new DockerSandbox({
    workDir: join(work, 'wd'), imagePrefix: 'vibesec', run,
    hostEnv: { PATH: '/usr/bin', GITHUB_TOKEN: 'ghp_leak', ANTHROPIC_API_KEY: 'sk-ant-leak', DOCKER_HOST: 'npipe:////./pipe/docker_engine', AWS_SECRET_ACCESS_KEY: 'x' },
    ...extra,
  });
}

/** Simulates a successful npm install container: writes node_modules + tree.json into the /out mount. */
const npmInstallOk: Handler = async (args) => {
  const out = mountSource(args, '/out')!;
  await mkdir(join(out, 'work', 'node_modules', 'lodash'), { recursive: true });
  await writeFile(join(out, 'work', 'node_modules', 'lodash', 'package.json'), '{"name":"lodash","version":"4.17.21"}');
  await mkdir(join(out, 'cache', 'npm'), { recursive: true });
  await writeFile(join(out, 'tree.json'), JSON.stringify({ name: 'web', dependencies: { lodash: { version: '4.17.21' } } }));
  return ok();
};

describe('dockerCliEnv', () => {
  it('passes only the allowlisted host variables to the docker CLI', () => {
    const env = dockerCliEnv({
      Path: 'C:\\x', SystemRoot: 'C:\\Windows', USERPROFILE: 'C:\\u', TEMP: 't', DOCKER_CONTEXT: 'desktop-linux',
      GITHUB_TOKEN: 'ghp', ANTHROPIC_API_KEY: 'sk', HTTPS_PROXY: 'http://corp', NODE_OPTIONS: '--require x',
    });
    expect(Object.keys(env).sort()).toEqual(['DOCKER_CONTEXT', 'Path', 'SystemRoot', 'TEMP', 'USERPROFILE']);
  });
});

describe('hardenedRunArgs', () => {
  it('always applies the full hardening set and the scan label', () => {
    const args = hardenedRunArgs({
      name: 'vibesec-x', scanId: SCAN, image: 'vibesec/sandbox-node:v1', network: 'none', mounts: [], env: {}, command: ['true'],
    });
    for (const f of HARDENING) expect(args).toContain(f);
    expect(flag(args, '--user')).toBe('10001:10001');
    expect(flag(args, '--pids-limit')).toBe('512');
    expect(flag(args, '--memory')).toBe('2g');
    expect(flag(args, '--memory-swap')).toBe('2g');
    expect(flag(args, '--cpus')).toBe('2');
    expect(flag(args, '--tmpfs')).toMatch(/^\/tmp:/);
    expect(flag(args, '--label')).toBe(`vibesec.scan=${SCAN}`);
    expect(args).not.toContain('--privileged');
    expect(args.join(' ')).not.toMatch(/--cap-add|--device|docker\.sock|--pid |--ipc host|--network host|--userns host/);
  });

  it('refuses bind-mount sources that could smuggle extra --mount options', () => {
    expect(() => hardenedRunArgs({
      name: 'n', scanId: SCAN, image: 'i', network: 'none', env: {}, command: [],
      mounts: [{ source: '/tmp/a,target=/etc', target: '/out', readonly: false }],
    })).toThrow(/bind mount/);
  });
});

describe('DockerSandbox.availability', () => {
  it('reports ok with the server version when the daemon and all three images exist, and caches briefly', async () => {
    const { run, calls } = fake();
    const sb = sandbox(run);
    expect(await sb.availability(signal())).toEqual({ ok: true, serverVersion: '28.5.1' });
    const inspect = calls.find((c) => c.args[0] === 'image')!;
    expect(inspect.args).toEqual(expect.arrayContaining(['vibesec/sandbox-node:v1', 'vibesec/sandbox-python:v1', 'vibesec/sandbox-proxy:v1']));
    await sb.availability(signal());
    expect(calls.filter((c) => c.args[0] === 'version')).toHaveLength(1);
  });

  it('reports unavailable when the docker CLI cannot start', async () => {
    const { run } = fake(undefined, { version: () => { throw new ProcessError('spawn', 'failed to start docker: ENOENT', ''); } });
    const r = await sandbox(run).availability(signal());
    expect(r.ok).toBe(false);
  });

  it('reports unavailable with a build hint when images are missing', async () => {
    const { run } = fake(undefined, { 'image inspect': () => ({ code: 1, stdout: '', stderr: 'No such image' }) });
    const r = await sandbox(run).availability(signal());
    expect(r).toEqual({ ok: false, reason: expect.stringContaining('sandbox:build') });
  });

  it('install returns SANDBOX_UNAVAILABLE without touching anything when docker is down', async () => {
    const { run, calls } = fake(undefined, { version: () => ({ code: 1, stdout: '', stderr: 'pipe not found' }) });
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_UNAVAILABLE' });
    expect(calls.some((c) => c.args[0] === 'run' || c.args[0] === 'network')).toBe(false);
  });
});

describe('DockerSandbox.install (npm)', () => {
  it('runs the install on a per-scan internal network behind the proxy, hardened, with no host env', async () => {
    const { run, calls } = fake(npmInstallOk);
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r.ok).toBe(true);
    if (!r.ok) return;

    const create = calls.find((c) => c.args[0] === 'network' && c.args[1] === 'create')!;
    expect(create.args).toContain('--internal');
    expect(create.args).toContain(`vibesec.scan=${SCAN}`);
    const net = create.args.at(-1)!;

    const proxy = calls.find((c) => isDetachedRun(c.args))!;
    expect(flag(proxy.args, '--network')).toBe('bridge');
    expect(proxy.args).toContain('vibesec/sandbox-proxy:v1');
    for (const f of HARDENING) expect(proxy.args).toContain(f);
    const proxyName = flag(proxy.args, '--name')!;
    expect(calls.find((c) => c.args[0] === 'network' && c.args[1] === 'connect')!.args).toEqual(['network', 'connect', net, proxyName]);

    const install = calls.find((c) => isWorkloadRun(c.args))!;
    for (const f of HARDENING) expect(install.args).toContain(f);
    expect(flag(install.args, '--network')).toBe(net);
    expect(flag(install.args, '--name')).toMatch(/^vibesec-install-3f2b9c1e-[0-9a-f]{6}$/);
    expect(flag(install.args, '--label')).toBe(`vibesec.scan=${SCAN}`);
    expect(install.args).toContain('vibesec/sandbox-node:v1');
    // Only the staging /out dir is mounted: the repository itself is not visible during install.
    expect(flagValues(install.args, '--mount')).toHaveLength(1);
    expect(mountSource(install.args, '/src')).toBeUndefined();
    const script = install.args.at(-1)!;
    expect(script).toContain('npm ci --ignore-scripts --no-audit --no-fund');
    expect(script).toContain('npm ls --all --json --long=false > /out/tree.json');
    const env = flagValues(install.args, '--env');
    expect(env).toContain(`HTTPS_PROXY=http://${proxyName}:3128`);
    expect(env).toContain('npm_config_registry=https://registry.npmjs.org/');
    expect(env).toContain('npm_config_update_notifier=false');
    expect(env).toContain('HOME=/tmp');
    expect(env).toContain('COREPACK_ENABLE_NETWORK=0');

    // No host env leaks: not into any argv, and the CLI process itself only gets the allowlist.
    for (const c of calls) {
      expect(c.cmd).toBe('docker');
      expect(c.args.join(' ')).not.toMatch(/ghp_leak|sk-ant-leak|GITHUB_TOKEN|ANTHROPIC_API_KEY|AWS_/);
      expect(Object.keys(c.opts.env ?? {}).sort()).toEqual(['DOCKER_HOST', 'PATH']);
    }

    // Results: deps dir, parsed tree, denied egress surfaced as a warning.
    expect(r.depsDir.endsWith(join('work', 'node_modules'))).toBe(true);
    expect(existsSync(join(r.depsDir, 'lodash', 'package.json'))).toBe(true);
    expect(r.tree).toEqual({ name: 'web', dependencies: { lodash: { version: '4.17.21' } } });
    expect(r.warnings).toContain('sandbox proxy denied egress to evil.example');

    // Staging: .npmrc never copied; packageManager stripped (npm); lockfile copied.
    const staged = join(r.depsDir, '..');
    expect(existsSync(join(staged, '.npmrc'))).toBe(false);
    expect(existsSync(join(staged, 'package-lock.json'))).toBe(true);
    expect(JSON.parse(await readFile(join(staged, 'package.json'), 'utf8'))).not.toHaveProperty('packageManager');

    // Teardown: proxy container removed and network removed.
    expect(calls.some((c) => c.args[0] === 'rm' && c.args.includes(proxyName))).toBe(true);
    expect(calls.some((c) => c.args[0] === 'network' && c.args[1] === 'rm' && c.args[2] === net)).toBe(true);
  });

  it('pins corepack to our pnpm / yarn berry versions instead of the repo packageManager', async () => {
    await rm(join(repo, 'web', 'package-lock.json'));
    await writeFile(join(repo, 'web', 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n");
    let staged = '';
    const { run, calls } = fake(async (args) => {
      staged = await readFile(join(mountSource(args, '/out')!, 'work', 'package.json'), 'utf8');
      return ok();
    });
    await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(JSON.parse(staged).packageManager).toBe(`pnpm@${PNPM_VERSION}`);
    expect(calls.find((c) => isWorkloadRun(c.args))!.args.at(-1)).toContain('pnpm install --frozen-lockfile --ignore-scripts');

    await rm(join(repo, 'web', 'pnpm-lock.yaml'));
    await writeFile(join(repo, 'web', 'yarn.lock'), '__metadata:\n  version: 8\n');
    const second = fake(async (args) => {
      staged = await readFile(join(mountSource(args, '/out')!, 'work', 'package.json'), 'utf8');
      return ok();
    });
    await sandbox(second.run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(JSON.parse(staged).packageManager).toBe(`yarn@${YARN_BERRY_VERSION}`);
    expect(second.calls.find((c) => isWorkloadRun(c.args))!.args.at(-1)).toContain('yarn install --immutable --mode=skip-build');
  });

  it('without a lockfile, resolves with --package-lock-only first (still no scripts)', async () => {
    await rm(join(repo, 'web', 'package-lock.json'));
    const { run, calls } = fake();
    await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(calls.find((c) => isWorkloadRun(c.args))!.args.at(-1)).toMatch(/^npm install --ignore-scripts --package-lock-only .* && npm ci --ignore-scripts/);
  });

  it('refuses a manifestDir that escapes the repository', async () => {
    const { run, calls } = fake();
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: '../..', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED', message: expect.stringContaining('escapes') });
    expect(calls.some((c) => isRun(c.args))).toBe(false);
  });

  it('refuses a symlinked lockfile (could point at a host file)', async (ctx) => {
    await rm(join(repo, 'web', 'package-lock.json'));
    if (!await plantLink(join(work, 'outside.json'), join(repo, 'web', 'package-lock.json'))) {
      ctx.skip();
      return;
    }
    const { run } = fake();
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED', message: expect.stringContaining('not a regular file') });
  });

  it('on timeout: kills the container by name, tears down proxy + network, returns SANDBOX_TIMEOUT and deletes staging', async () => {
    const { run, calls } = fake(() => { throw new ProcessError('timeout', 'docker timed out', ''); });
    const sb = sandbox(run, { installTimeoutMs: 1234 });
    const r = await sb.install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_TIMEOUT' });
    const install = calls.find((c) => isWorkloadRun(c.args))!;
    expect(install.opts.timeoutMs).toBe(1234);
    const name = flag(install.args, '--name')!;
    const kill = calls.findIndex((c) => c.args[0] === 'kill' && c.args[1] === name);
    expect(kill).toBeGreaterThan(calls.indexOf(install));
    expect(calls.some((c) => c.args[0] === 'network' && c.args[1] === 'rm')).toBe(true);
    expect(calls.some((c) => c.args[0] === 'kill' && c.args[1]!.startsWith('vibesec-proxy-'))).toBe(true);
    expect(existsSync(sb.scanRoot(SCAN)) ? (await import('node:fs')).readdirSync(sb.scanRoot(SCAN)) : []).toEqual([]);
  });

  it('on cancel: kills the container, cleans up and throws AppError(cancelled)', async () => {
    const ac = new AbortController();
    const { run, calls } = fake(async (_args, opts) => {
      ac.abort();
      expect(opts.signal).toBe(ac.signal);
      throw new ProcessError('aborted', 'docker aborted', '');
    });
    const err = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: ac.signal })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect((err as AppError).kind).toBe('cancelled');
    const name = flag(calls.find((c) => isWorkloadRun(c.args))!.args, '--name');
    expect(calls.some((c) => c.args[0] === 'kill' && c.args[1] === name)).toBe(true);
    expect(calls.some((c) => c.args[0] === 'network' && c.args[1] === 'rm')).toBe(true);
    // cleanup commands must not reuse the aborted signal (they would be refused immediately)
    for (const c of calls.filter((x) => x.args[0] === 'kill' || x.args[0] === 'rm' || (x.args[0] === 'network' && x.args[1] === 'rm'))) {
      expect(c.opts.signal).toBeUndefined();
    }
  });

  it('throws cancelled up front for an already-aborted signal', async () => {
    const ac = new AbortController();
    ac.abort();
    const { run, calls } = fake();
    await expect(sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: ac.signal }))
      .rejects.toMatchObject({ kind: 'cancelled' });
    expect(calls).toHaveLength(0);
  });

  it('a failing install returns SANDBOX_INSTALL_FAILED with a sanitized tail and still tears down', async () => {
    const { run, calls } = fake(() => ({ code: 1, stdout: '', stderr: 'npm ERR! \u001b[31mcode E404\u001b[0m' }));
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED' });
    if (!r.ok) expect(r.message).not.toContain('\u001b');
    expect(calls.some((c) => c.args[0] === 'network' && c.args[1] === 'rm')).toBe(true);
  });

  it('docker run exit 125 (daemon refused) maps to SANDBOX_UNAVAILABLE', async () => {
    const { run } = fake(() => ({ code: 125, stdout: '', stderr: 'Unable to find image' }));
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_UNAVAILABLE' });
  });

  it('network creation failure maps to SANDBOX_UNAVAILABLE and starts no container', async () => {
    const { run, calls } = fake(undefined, { 'network create': () => ({ code: 1, stdout: '', stderr: 'boom' }) });
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_UNAVAILABLE' });
    expect(calls.some((c) => isWorkloadRun(c.args) || isDetachedRun(c.args))).toBe(false);
  });

  it('fails and deletes the install when the deps exceed the disk cap', async () => {
    const { run } = fake(npmInstallOk);
    const sb = sandbox(run, { maxDepsBytes: 10 });
    const r = await sb.install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED', message: expect.stringContaining('exceed') });
    expect((await import('node:fs')).readdirSync(sb.scanRoot(SCAN))).toEqual([]);
  });

  it('tolerates a missing tree.json with a warning', async () => {
    const { run } = fake(async (args) => {
      await mkdir(join(mountSource(args, '/out')!, 'work', 'node_modules'), { recursive: true });
      return ok();
    });
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: true, tree: null });
    if (r.ok) expect(r.warnings.join()).toContain('tree.json was not produced');
  });
});

describe('DockerSandbox.install (PyPI)', () => {
  it('installs binary wheels only from pypi via the proxy, from a validated requirement list', async () => {
    let requirementsFile = '';
    const { run, calls } = fake(async (args) => {
      requirementsFile = await readFile(join(mountSource(args, '/in')!, 'requirements.txt'), 'utf8');
      const out = mountSource(args, '/out')!;
      await mkdir(join(out, 'deps', 'requests'), { recursive: true });
      await writeFile(join(out, 'report.json'), JSON.stringify({ version: '1', install: [{ metadata: { name: 'requests', version: '2.32.3' } }] }));
      return ok();
    });
    const r = await sandbox(run).install({
      scanId: SCAN, ecosystem: 'PyPI', signal: signal(),
      requirements: [
        'requests==2.32.3', 'urllib3[socks]>=2.0,<3 ; python_version >= "3.8"',
        '--index-url https://evil.example/simple', '-r /etc/passwd', 'evil @ https://evil.example/x.whl',
        'pkg==1.0 --hash=sha256:abc', 'git+https://github.com/x/y', '',
      ],
    });
    expect(r).toMatchObject({ ok: true, ecosystem: 'PyPI' });
    expect(requirementsFile).toBe('requests==2.32.3\nurllib3[socks]>=2.0,<3 ; python_version >= "3.8"\n');
    if (r.ok) {
      expect(r.warnings.filter((w) => w.startsWith('skipped unsupported requirement'))).toHaveLength(5);
      expect(r.tree).toMatchObject({ install: [{ metadata: { name: 'requests' } }] });
      expect(r.depsDir.endsWith(join('out', 'deps'))).toBe(true);
    }
    const install = calls.find((c) => isWorkloadRun(c.args))!;
    expect(install.args).toContain('vibesec/sandbox-python:v1');
    expect(install.args).toEqual(expect.arrayContaining(['--only-binary=:all:', '--isolated', '--no-input', '--disable-pip-version-check', '--target', '/out/deps', '--report', '/out/report.json']));
    expect(flag(install.args, '--index-url')).toBe('https://pypi.org/simple');
    expect(flag(install.args, '--proxy')).toMatch(/^http:\/\/vibesec-proxy-3f2b9c1e-[0-9a-f]{6}:3128$/);
    expect(flagValues(install.args, '--mount').find((m) => m.includes('target=/in'))).toMatch(/,readonly$/);
    expect(install.args).not.toContain('sh');
  });

  it('fails without running anything when no requirement is installable', async () => {
    const { run, calls } = fake();
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'PyPI', requirements: ['-e .'], signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED' });
    expect(calls.some((c) => isRun(c.args))).toBe(false);
  });

  it('isSafeRequirement accepts pinned PEP 508 lines and rejects options, URLs and paths', () => {
    expect(isSafeRequirement('Django==4.2.11')).toBe(true);
    expect(isSafeRequirement('zope.interface===6.0')).toBe(true);
    expect(isSafeRequirement('pywin32==306 ; sys_platform == "win32"')).toBe(true);
    for (const bad of ['--extra-index-url x', './local', 'a @ file:///etc', 'x==1 # c', 'x==1\n-r y', 'a/b']) {
      expect(isSafeRequirement(bad)).toBe(false);
    }
  });
});

describe('DockerSandbox.analyze', () => {
  it('runs offline with read-only /src, /deps, /in and a writable /out, and returns parsed usages', async () => {
    const { run, calls } = fake(async (args) => {
      const pk = JSON.parse(await readFile(join(mountSource(args, '/in')!, 'packages.json'), 'utf8'));
      expect(pk).toEqual(['lodash', '@scope/x']);
      await writeFile(join(mountSource(args, '/out')!, 'usages.json'), JSON.stringify({ usages: [{ package: 'lodash', file: 'a.js', line: 1 }] }));
      return ok();
    });
    const sb = sandbox(run);
    const depsDir = join(sb.scanRoot(SCAN), 'install-npm-abc', 'out', 'work', 'node_modules');
    await mkdir(depsDir, { recursive: true });
    const r = await sb.analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, depsDir, packages: ['lodash', '@scope/x'], signal: signal() });
    expect(r).toEqual({ ok: true, usages: { usages: [{ package: 'lodash', file: 'a.js', line: 1 }] } });

    const a = calls.find((c) => isWorkloadRun(c.args))!;
    for (const f of HARDENING) expect(a.args).toContain(f);
    expect(flag(a.args, '--network')).toBe('none');
    expect(flag(a.args, '--name')).toMatch(/^vibesec-analyze-3f2b9c1e-/);
    const mounts = flagValues(a.args, '--mount');
    expect(mounts.find((m) => m.includes('target=/src'))).toMatch(/,readonly$/);
    expect(mounts.find((m) => m.includes('target=/deps'))).toMatch(/,readonly$/);
    expect(mounts.find((m) => m.includes('target=/in'))).toMatch(/,readonly$/);
    expect(mounts.find((m) => m.includes('target=/out'))).not.toMatch(/readonly/);
    expect(a.args.slice(-2)).toEqual(['node', '/opt/vibesec/analyze.mjs']);
    // No proxy / network setup in phase B.
    expect(calls.some((c) => c.args[0] === 'network' || isDetachedRun(c.args))).toBe(false);
  });

  it('uses the python image and script for PyPI', async () => {
    const { run, calls } = fake(async (args) => {
      await writeFile(join(mountSource(args, '/out')!, 'usages.json'), '[]');
      return ok();
    });
    const r = await sandbox(run).analyze({ scanId: SCAN, ecosystem: 'PyPI', srcDir: repo, packages: ['requests'], signal: signal() });
    expect(r).toEqual({ ok: true, usages: [] });
    const a = calls.find((c) => isWorkloadRun(c.args))!;
    expect(a.args).toContain('vibesec/sandbox-python:v1');
    expect(a.args.slice(-2)).toEqual(['python', '/opt/vibesec/analyze.py']);
  });

  it('refuses a depsDir outside this scan\'s sandbox dir (no arbitrary host mounts)', async () => {
    const { run, calls } = fake();
    const r = await sandbox(run).analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, depsDir: tmpdir(), packages: [], signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_ANALYZE_FAILED' });
    expect(calls.some((c) => isRun(c.args))).toBe(false);
  });

  it('missing usages.json → SANDBOX_ANALYZE_FAILED; timeout → kill + SANDBOX_TIMEOUT', async () => {
    const missing = fake();
    expect(await sandbox(missing.run).analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, packages: [], signal: signal() }))
      .toMatchObject({ ok: false, code: 'SANDBOX_ANALYZE_FAILED' });

    const slow = fake(() => { throw new ProcessError('timeout', 't', ''); });
    const r = await sandbox(slow.run, { analyzeTimeoutMs: 999 }).analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, packages: [], signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_TIMEOUT' });
    const a = slow.calls.find((c) => isWorkloadRun(c.args))!;
    expect(a.opts.timeoutMs).toBe(999);
    expect(slow.calls.some((c) => c.args[0] === 'kill' && c.args[1] === flag(a.args, '--name'))).toBe(true);
  });

  it('refuses a usages.json that is a symlink (could point at a host file)', async (ctx) => {
    const target = join(work, 'host-file.json');
    await writeFile(target, '{"stolen":true}');
    let linked = true;
    const { run } = fake(async (args) => {
      linked = await plantLink(target, join(mountSource(args, '/out')!, 'usages.json'));
      return ok();
    });
    const r = await sandbox(run).analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, packages: [], signal: signal() });
    if (!linked) { ctx.skip(); return; }
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: expect.stringContaining('not a regular file') });
  });

  it('caps usages.json size', async () => {
    const { run } = fake(async (args) => {
      await writeFile(join(mountSource(args, '/out')!, 'usages.json'), Buffer.alloc(51 * 1024 * 1024, 0x20));
      return ok();
    });
    const r = await sandbox(run).analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, packages: [], signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: expect.stringContaining('exceeds') });
  });
});

describe('DockerSandbox.sweep', () => {
  it('removes labeled containers, networks and volumes of one scan, plus its staging dir', async () => {
    const { run, calls } = fake(undefined, {
      ps: () => ok('aaaaaaaaaaaa\nbbbbbbbbbbbb\n'),
      'network ls': () => ok('cccccccccccc\n'),
      'volume ls': () => ok('$(rm -rf /)\n'),
    });
    const sb = sandbox(run);
    await mkdir(join(sb.scanRoot(SCAN), 'install-npm-x'), { recursive: true });
    await sb.sweep(SCAN);
    const filter = `label=vibesec.scan=${SCAN}`;
    expect(calls.find((c) => c.args[0] === 'ps')!.args).toEqual(['ps', '-aq', '--filter', filter]);
    expect(calls.find((c) => c.args[0] === 'rm')!.args).toEqual(['rm', '-f', 'aaaaaaaaaaaa', 'bbbbbbbbbbbb']);
    expect(calls.find((c) => c.args[0] === 'network' && c.args[1] === 'rm')!.args).toEqual(['network', 'rm', 'cccccccccccc']);
    // Garbage from docker output is never passed back as argv.
    expect(calls.some((c) => c.args[0] === 'volume' && c.args[1] === 'rm')).toBe(false);
    expect(existsSync(sb.scanRoot(SCAN))).toBe(false);
  });

  it('without a scan id sweeps everything labeled vibesec.scan and survives docker being down', async () => {
    const { run, calls } = fake(undefined, { ps: () => { throw new ProcessError('spawn', 'ENOENT', ''); } });
    await sandbox(run).sweep();
    expect(calls.find((c) => c.args[0] === 'ps')!.args).toEqual(['ps', '-aq', '--filter', 'label=vibesec.scan']);
  });

  it('rejects scan ids that are not plain identifiers', async () => {
    const { run } = fake();
    await expect(sandbox(run).sweep('x --filter label=y')).rejects.toThrow(/invalid scanId/);
  });
});

describe('sandbox config', () => {
  it('defaults: enabled, vibesec prefix, 180 s / 120 s timeouts, 1.5 GiB deps cap', () => {
    expect(loadConfig({}).sandbox).toEqual({
      enabled: true, imagePrefix: 'vibesec', installTimeoutMs: 180_000, analyzeTimeoutMs: 120_000, maxDepsBytes: 1536 * 1024 * 1024,
    });
    expect(loadConfig({ SANDBOX_ENABLED: 'false' }).sandbox.enabled).toBe(false);
    expect(() => loadConfig({ SANDBOX_IMAGE_PREFIX: 'Evil Prefix;' })).toThrow();
  });
});

describe('host never traverses container-written trees', () => {
  it('cleans up a failed install through an offline helper container, then removes the emptied dirs', async () => {
    const { run, calls } = fake(() => ({ code: 1, stdout: '', stderr: 'boom' }));
    const sb = sandbox(run);
    await sb.install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    const helper = calls.find((c) => isHelperRun(c.args))!;
    for (const f of HARDENING) expect(helper.args).toContain(f);
    expect(flag(helper.args, '--network')).toBe('none');
    expect(mountSource(helper.args, '/w')).toMatch(/install-npm-[0-9a-f]{6}$/);
    expect(helper.args.at(-1)).toContain('rm -rf');
    expect((await import('node:fs')).readdirSync(sb.scanRoot(SCAN))).toEqual([]);
  });

  it('leaves the dir in place (for a later sweep) when the helper reports leftovers or cannot run', async () => {
    for (const helper of [() => ok('LEFTOVER\n'), () => { throw new ProcessError('spawn', 'x', ''); }]) {
      const { run } = fake(() => ({ code: 1, stdout: '', stderr: 'boom' }), { helper });
      const sb = sandbox(run);
      await sb.install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
      expect((await import('node:fs')).readdirSync(sb.scanRoot(SCAN))).toHaveLength(1);
      await rm(sb.scanRoot(SCAN), { recursive: true, force: true });
    }
  });

  it('refuses an install whose node_modules was replaced by a link (could alias a host dir)', async (ctx) => {
    let planted = true;
    const { run } = fake(async (args) => {
      const work = join(mountSource(args, '/out')!, 'work');
      planted = await plantLink(join(repo, 'web', 'package.json'), join(work, 'node_modules'));
      return ok();
    });
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    if (!planted) { ctx.skip(); return; }
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED', message: expect.stringContaining('not a plain directory') });
  });

  it('analyze refuses a depsDir that is (or passes through) a link', async (ctx) => {
    const { run, calls } = fake();
    const sb = sandbox(run);
    const parent = join(sb.scanRoot(SCAN), 'install-npm-abc', 'out', 'work');
    await mkdir(parent, { recursive: true });
    if (!await plantLink(join(repo, 'web', 'package.json'), join(parent, 'node_modules'))) { ctx.skip(); return; }
    const r = await sb.analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, depsDir: join(parent, 'node_modules'), packages: [], signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_ANALYZE_FAILED' });
    expect(calls.some((c) => isWorkloadRun(c.args))).toBe(false);
  });

  it('the post-install helper drops caches and reports the size; its failure is SANDBOX_UNAVAILABLE', async () => {
    const good = fake(npmInstallOk);
    await sandbox(good.run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    const post = good.calls.find((c) => isHelperRun(c.args))!;
    expect(post.args.at(-1)).toContain('du -sk /w/work/node_modules');
    expect(post.args.at(-1)).toContain('/w/cache /w/tmp');

    const bad = fake(npmInstallOk, { helper: () => ({ code: 1, stdout: '', stderr: '' }) });
    const r = await sandbox(bad.run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_UNAVAILABLE' });
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Docker integration: runs the REAL hardened argv (hardenedRunArgs) against the local daemon. Builds and pulls
// nothing: uses alpine:3 or an already-built sandbox image; skipped automatically when neither / no docker.
// ---------------------------------------------------------------------------------------------------------------
const probe = (args: string[]) => spawnSync('docker', args, { encoding: 'utf8', timeout: 15_000, windowsHide: true, env: dockerCliEnv() });
const dockerUp = (() => {
  try {
    return probe(['version', '--format', '{{.Server.Version}}']).status === 0;
  } catch {
    return false;
  }
})();
const probeImage = dockerUp
  ? ['alpine:3', 'vibesec/sandbox-node:v1'].find((i) => probe(['image', 'inspect', '--format', '{{.Id}}', i]).status === 0)
  : undefined;

describe.skipIf(!probeImage)('hardened container on the real Docker daemon', () => {
  it('blocks egress, writes outside /tmp and /out, capabilities and exec from /tmp', async () => {
    const out = join(work, 'out');
    const src = join(work, 'repo');
    await mkdir(out, { recursive: true });
    const checks = [
      'id -u',
      '(wget -T 3 -q -O /dev/null http://1.1.1.1/ 2>/dev/null && echo NET_OPEN || echo NET_BLOCKED)',
      '(nslookup -timeout=2 registry.npmjs.org >/dev/null 2>&1 && echo DNS_OPEN || echo DNS_BLOCKED)',
      '(touch /etc/pwned 2>/dev/null && echo ROOTFS_WRITABLE || echo ROOTFS_RO)',
      '(touch /src/pwned 2>/dev/null && echo SRC_WRITABLE || echo SRC_RO)',
      '(touch /tmp/ok && echo TMP_OK)',
      '(touch /out/ok && echo OUT_OK)',
      'grep CapEff /proc/self/status',
      '(cp /bin/busybox /tmp/bb 2>/dev/null && /tmp/bb true 2>/dev/null && echo TMP_EXEC || echo TMP_NOEXEC)',
    ].join('; ');
    const args = hardenedRunArgs({
      name: `vibesec-itest-${Date.now().toString(36)}`, scanId: 'itest', image: probeImage!, network: 'none',
      mounts: [{ source: src, target: '/src', readonly: true }, { source: out, target: '/out', readonly: false }],
      env: {}, command: ['sh', '-c', checks],
    });
    const r = await runProcess('docker', args, { env: dockerCliEnv(), timeoutMs: 60_000 });
    expect(r.code, r.stderr).toBe(0);
    const lines = r.stdout.split('\n').map((l) => l.trim());
    expect(lines[0]).toBe('10001');
    expect(lines).toContain('NET_BLOCKED');
    expect(lines).toContain('DNS_BLOCKED');
    expect(lines).toContain('ROOTFS_RO');
    expect(lines).toContain('SRC_RO');
    expect(lines).toContain('TMP_OK');
    expect(lines).toContain('OUT_OK');
    expect(lines).toContain('TMP_NOEXEC');
    expect(r.stdout).toMatch(/CapEff:\s+0000000000000000/);
    expect(existsSync(join(out, 'ok'))).toBe(true); // Windows/Docker Desktop bind mount path conversion works
    expect(existsSync(join(src, 'pwned'))).toBe(false);
  }, 60_000);

  it('a runaway container is killed by name after the timeout (killing the CLI alone is not enough)', async () => {
    const sb = new DockerSandbox({ workDir: join(work, 'wd'), imagePrefix: 'vibesec' });
    const scanId = `itest-${Date.now().toString(36)}`;
    // runContainer is private; it is the one path install() and analyze() use to run (and kill) workloads.
    const runContainer = (sb as unknown as {
      runContainer: (spec: ContainerSpec, timeoutMs: number, signal: AbortSignal) => Promise<{ kind: string }>;
    }).runContainer.bind(sb);
    const t0 = Date.now();
    const outcome = await runContainer({
      name: `vibesec-itest-${scanId}`, scanId, image: probeImage!, network: 'none', mounts: [], env: {}, command: ['sleep', '600'],
    }, 3_000, new AbortController().signal);
    expect(outcome.kind).toBe('timeout');
    expect(Date.now() - t0).toBeLessThan(40_000);
    expect(probe(['ps', '-aq', '--filter', `label=vibesec.scan=${scanId}`]).stdout.trim()).toBe('');
  }, 60_000);
});
