import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { AppError } from '../src/errors/AppError';
import { ProcessError, runProcess, type RunOptions, type RunResult } from '../src/process/runProcess';
import {
  type ContainerSpec, DockerSandbox, dockerCliEnv, hardenedRunArgs, isSafeRequirement, PNPM_VERSION, PYPI_INSTALL_DRIVER, YARN_BERRY_VERSION,
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

/** Simulates the helper container: a successful cleanup. */
const helperResult = (_args: string[]): RunResult => ok('CLEAN\n');

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
    workDir: join(work, 'wd'), imagePrefix: 'vibesec', run, instanceId: 'inst-1',
    hostEnv: { PATH: '/usr/bin', GITHUB_TOKEN: 'ghp_leak', ANTHROPIC_API_KEY: 'sk-ant-leak', DOCKER_HOST: 'npipe:////./pipe/docker_engine', AWS_SECRET_ACCESS_KEY: 'x' },
    ...extra,
  });
}

/** Simulates a successful npm install container: the install itself stays in the tmpfs; only tree.json reaches /res. */
const npmInstallOk: Handler = async (args) => {
  await writeFile(join(mountSource(args, '/res')!, 'tree.json'), JSON.stringify({ name: 'web', dependencies: { lodash: { version: '4.17.21' } } }));
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

  it('adds size-capped, sandbox-owned tmpfs mounts and the instance label; refuses odd tmpfs targets', () => {
    const args = hardenedRunArgs({
      name: 'n', scanId: SCAN, instanceId: 'inst-1', image: 'i', network: 'none', env: {}, command: [], mounts: [],
      tmpfs: [{ target: '/out', sizeBytes: 1024 }],
    });
    expect(flagValues(args, '--tmpfs')).toContain('/out:rw,noexec,nosuid,nodev,size=1024,uid=10001,gid=10001,mode=0700');
    expect(flagValues(args, '--label')).toEqual([`vibesec.scan=${SCAN}`, 'vibesec.instance=inst-1']);
    for (const t of [{ target: '/out,size=0', sizeBytes: 1 }, { target: '/out', sizeBytes: 0 }]) {
      expect(() => hardenedRunArgs({ name: 'n', scanId: SCAN, image: 'i', network: 'none', env: {}, command: [], mounts: [], tmpfs: [t] })).toThrow(/tmpfs/);
    }
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

  it('refuses Docker Engine < 26 (CVE-2024-29018: internal networks leak DNS)', async () => {
    const { run, calls } = fake(undefined, { version: () => ok('25.0.5\n') });
    const r = await sandbox(run).availability(signal());
    expect(r).toEqual({ ok: false, reason: expect.stringContaining('CVE-2024-29018') });
    expect(calls.some((c) => c.args[0] === 'image')).toBe(false);
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
    const staged: Record<string, string> = {};
    const { run, calls } = fake(async (args, opts) => {
      const inDir = mountSource(args, '/in')!;
      for (const f of readdirSync(inDir)) staged[f] = await readFile(join(inDir, f), 'utf8');
      return npmInstallOk(args, opts);
    });
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
    // Only the read-only inputs and the results dir are mounted: the repository itself is not visible during
    // install, and the install lands in a size-capped tmpfs (the disk quota), never on the host.
    expect(flagValues(install.args, '--mount')).toHaveLength(2);
    expect(flagValues(install.args, '--mount').find((m) => m.includes('target=/in'))).toMatch(/,readonly$/);
    expect(flagValues(install.args, '--mount').find((m) => m.includes('target=/res'))).not.toMatch(/readonly/);
    expect(mountSource(install.args, '/src')).toBeUndefined();
    expect(mountSource(install.args, '/out')).toBeUndefined();
    expect(flagValues(install.args, '--tmpfs')).toContain(`/out:rw,noexec,nosuid,nodev,size=${1536 * 1024 * 1024},uid=10001,gid=10001,mode=0700`);
    expect(flag(install.args, '--memory')).toBe(`${2048 + 1536}m`);
    expect(flagValues(install.args, '--label')).toContain('vibesec.instance=inst-1');
    const script = install.args.at(-1)!;
    expect(script).toMatch(/^mkdir -p \/out\/work \/out\/tmp \/out\/cache && cp \/in\/\* \/out\/work\/ && cd \/out\/work && /);
    expect(script).toContain('npm ci --ignore-scripts --no-audit --no-fund');
    expect(script).toContain('npm ls --all --json --long=false > /res/tree.json');
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

    // Results: parsed tree, denied egress surfaced as a warning; nothing of the install is left on the host.
    expect(r).not.toHaveProperty('depsDir');
    expect(r.tree).toEqual({ name: 'web', dependencies: { lodash: { version: '4.17.21' } } });
    expect(r.warnings).toContain('sandbox proxy denied egress to evil.example');
    expect(readdirSync(sandbox(run).scanRoot(SCAN))).toEqual([]);

    // Staging: .npmrc never copied; packageManager stripped (npm); lockfile copied.
    expect(Object.keys(staged).sort()).toEqual(['package-lock.json', 'package.json']);
    expect(JSON.parse(staged['package.json']!)).not.toHaveProperty('packageManager');

    // Teardown: proxy container removed and network removed.
    expect(calls.some((c) => c.args[0] === 'rm' && c.args.includes(proxyName))).toBe(true);
    expect(calls.some((c) => c.args[0] === 'network' && c.args[1] === 'rm' && c.args[2] === net)).toBe(true);
  });

  it('pins corepack to our pnpm / yarn berry versions instead of the repo packageManager', async () => {
    await rm(join(repo, 'web', 'package-lock.json'));
    await writeFile(join(repo, 'web', 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n");
    let staged = '';
    const { run, calls } = fake(async (args) => {
      staged = await readFile(join(mountSource(args, '/in')!, 'package.json'), 'utf8');
      return ok();
    });
    await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(JSON.parse(staged).packageManager).toBe(`pnpm@${PNPM_VERSION}`);
    expect(calls.find((c) => isWorkloadRun(c.args))!.args.at(-1)).toContain('pnpm install --frozen-lockfile --ignore-scripts');

    await rm(join(repo, 'web', 'pnpm-lock.yaml'));
    await writeFile(join(repo, 'web', 'yarn.lock'), '__metadata:\n  version: 8\n');
    const second = fake(async (args) => {
      staged = await readFile(join(mountSource(args, '/in')!, 'package.json'), 'utf8');
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
    expect(calls.find((c) => isWorkloadRun(c.args))!.args.at(-1)).toMatch(/&& cd \/out\/work && npm install --ignore-scripts --package-lock-only .* && npm ci --ignore-scripts/);
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

  it('the tmpfs quota is the disk cap: ENOSPC during install fails it (and nothing is kept)', async () => {
    const { run, calls } = fake(() => ({ code: 1, stdout: '', stderr: 'npm ERR! code ENOSPC\nnpm ERR! nospc ENOSPC: no space left on device, write' }));
    const sb = sandbox(run, { maxDepsBytes: 10 * 1024 * 1024 });
    const r = await sb.install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: false, code: 'SANDBOX_INSTALL_FAILED', message: expect.stringContaining('exceed 10 MB') });
    expect(flagValues(calls.find((c) => isWorkloadRun(c.args))!.args, '--tmpfs')).toContain('/out:rw,noexec,nosuid,nodev,size=10485760,uid=10001,gid=10001,mode=0700');
    expect((await import('node:fs')).readdirSync(sb.scanRoot(SCAN))).toEqual([]);
  });

  it('tolerates a missing tree.json with a warning', async () => {
    const { run } = fake(() => ok());
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r).toMatchObject({ ok: true, tree: null });
    if (r.ok) expect(r.warnings.join()).toContain('tree.json was not produced');
  });
});

describe('DockerSandbox.install (PyPI)', () => {
  it('installs binary wheels only from pypi via the proxy, from a validated requirement list', async () => {
    let requirementsFile = '';
    let driver = '';
    const { run, calls } = fake(async (args) => {
      requirementsFile = await readFile(join(mountSource(args, '/in')!, 'requirements.txt'), 'utf8');
      driver = await readFile(join(mountSource(args, '/in')!, 'vibesec_install.py'), 'utf8');
      const res = mountSource(args, '/res')!;
      await writeFile(join(res, 'report.json'), JSON.stringify({ version: '1', install: [{ metadata: { name: 'requests', version: '2.32.3' } }] }));
      await writeFile(join(res, 'distmap.json'), JSON.stringify({ requests: ['requests'], PyYAML: ['yaml', '_yaml'] }));
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
      expect(r.distModules).toEqual({ requests: ['requests'], PyYAML: ['yaml', '_yaml'] });
    }
    expect(driver).toBe(PYPI_INSTALL_DRIVER);
    const install = calls.find((c) => isWorkloadRun(c.args))!;
    expect(install.args).toContain('vibesec/sandbox-python:v1');
    expect(install.args.slice(install.args.indexOf('vibesec/sandbox-python:v1') + 1, install.args.indexOf('vibesec/sandbox-python:v1') + 3)).toEqual(['python', '/in/vibesec_install.py']);
    expect(install.args).toEqual(expect.arrayContaining(['--only-binary=:all:', '--isolated', '--no-input', '--disable-pip-version-check', '--target', '/out/deps', '--report', '/res/report.json']));
    expect(flagValues(install.args, '--tmpfs').some((t) => t.startsWith('/out:'))).toBe(true);
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
  it('runs offline with read-only /src and /in and a writable /out (never installed deps), and returns parsed usages', async () => {
    const { run, calls } = fake(async (args) => {
      const pk = JSON.parse(await readFile(join(mountSource(args, '/in')!, 'packages.json'), 'utf8'));
      expect(pk).toEqual({
        ecosystem: 'npm',
        packages: [{ name: 'lodash', importNames: ['lodash'] }, { name: '@scope/x', importNames: ['@scope/x', '@scope/x-alias'] }],
      });
      await writeFile(join(mountSource(args, '/out')!, 'usages.json'), JSON.stringify({ usages: [{ package: 'lodash', file: 'a.js', line: 1 }] }));
      return ok();
    });
    const sb = sandbox(run);
    const r = await sb.analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, packages: ['lodash', { name: '@scope/x', importNames: ['@scope/x', '@scope/x-alias'] }], signal: signal() });
    expect(r).toEqual({ ok: true, usages: { usages: [{ package: 'lodash', file: 'a.js', line: 1 }] } });

    const a = calls.find((c) => isWorkloadRun(c.args))!;
    for (const f of HARDENING) expect(a.args).toContain(f);
    expect(flag(a.args, '--network')).toBe('none');
    expect(flag(a.args, '--name')).toMatch(/^vibesec-analyze-3f2b9c1e-/);
    const mounts = flagValues(a.args, '--mount');
    expect(mounts.find((m) => m.includes('target=/src'))).toMatch(/,readonly$/);
    expect(mounts.some((m) => m.includes('target=/deps'))).toBe(false);
    expect(mounts).toHaveLength(3);
    expect(mounts.find((m) => m.includes('target=/in'))).toMatch(/,readonly$/);
    expect(mounts.find((m) => m.includes('target=/out'))).not.toMatch(/readonly/);
    expect(a.args.slice(-2)).toEqual(['node', '/opt/vibesec/analyze.mjs']);
    // No proxy / network setup in phase B.
    expect(calls.some((c) => c.args[0] === 'network' || isDetachedRun(c.args))).toBe(false);
  });

  it('rejects a malformed package list before starting anything', async () => {
    const { run, calls } = fake();
    const bad = [{ name: 'x', importNames: 'x' }, { name: '', importNames: [] }, 'y'.repeat(301)] as unknown as string[];
    for (const p of bad) {
      expect(await sandbox(run).analyze({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, packages: [p], signal: signal() }))
        .toMatchObject({ ok: false, code: 'SANDBOX_ANALYZE_FAILED', message: 'invalid package list' });
    }
    expect(calls).toHaveLength(0);
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
    expect(calls.find((c) => c.args[0] === 'ps')!.args).toEqual(['ps', '-aq', '--filter', `label=vibesec.scan=${SCAN}`, '--filter', 'label=vibesec.instance=inst-1']);
    expect(calls.find((c) => c.args[0] === 'rm')!.args).toEqual(['rm', '-f', 'aaaaaaaaaaaa', 'bbbbbbbbbbbb']);
    expect(calls.find((c) => c.args[0] === 'network' && c.args[1] === 'rm')!.args).toEqual(['network', 'rm', 'cccccccccccc']);
    // Garbage from docker output is never passed back as argv.
    expect(calls.some((c) => c.args[0] === 'volume' && c.args[1] === 'rm')).toBe(false);
    expect(existsSync(sb.scanRoot(SCAN))).toBe(false);
  });

  it('without a scan id sweeps only THIS instance\'s leftovers and survives docker being down', async () => {
    const { run, calls } = fake(undefined, { ps: () => { throw new ProcessError('spawn', 'ENOENT', ''); } });
    await sandbox(run).sweep();
    expect(calls.find((c) => c.args[0] === 'ps')!.args).toEqual(['ps', '-aq', '--filter', 'label=vibesec.instance=inst-1']);
  });

  it('the default instance id is a UUID persisted under the work dir (stable across restarts)', async () => {
    const { run } = fake();
    const a = new DockerSandbox({ workDir: join(work, 'wd2'), imagePrefix: 'vibesec', run });
    const id = await a.instanceId();
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    const b = new DockerSandbox({ workDir: join(work, 'wd2'), imagePrefix: 'vibesec', run });
    expect(await b.instanceId()).toBe(id);
    expect(await new DockerSandbox({ workDir: join(work, 'wd3'), imagePrefix: 'vibesec', run }).instanceId()).not.toBe(id);
  });

  it('rejects scan ids that are not plain identifiers', async () => {
    const { run } = fake();
    await expect(sandbox(run).sweep('x --filter label=y')).rejects.toThrow(/invalid scanId/);
  });
});

describe('sandbox config', () => {
  it('defaults: enabled, install (phase A) off, vibesec prefix, 180 s / 120 s timeouts, 1.5 GiB deps cap', () => {
    expect(loadConfig({}).sandbox).toEqual({
      enabled: true, install: false, imagePrefix: 'vibesec', installTimeoutMs: 180_000, analyzeTimeoutMs: 120_000, maxDepsBytes: 1536 * 1024 * 1024,
    });
    expect(loadConfig({ SANDBOX_ENABLED: 'false' }).sandbox.enabled).toBe(false);
    expect(loadConfig({ SANDBOX_INSTALL: 'true' }).sandbox.install).toBe(true);
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

  it('refuses an install result file planted as a link (could point at a host file)', async (ctx) => {
    const target = join(work, 'host-file.json');
    await writeFile(target, '{"stolen":true}');
    let planted = true;
    const { run } = fake(async (args) => {
      planted = await plantLink(target, join(mountSource(args, '/res')!, 'tree.json'));
      return ok();
    });
    const r = await sandbox(run).install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    if (!planted) { ctx.skip(); return; }
    expect(r).toMatchObject({ ok: true, tree: null });
    if (r.ok) expect(r.warnings.join()).toMatch(/not a regular file/);
  });

  it('a successful install is cleaned up through the helper too (nothing of it stays on the host)', async () => {
    const { run, calls } = fake(npmInstallOk);
    const sb = sandbox(run);
    const r = await sb.install({ scanId: SCAN, ecosystem: 'npm', srcDir: repo, manifestDir: 'web', signal: signal() });
    expect(r.ok).toBe(true);
    expect(mountSource(calls.find((c) => isHelperRun(c.args))!.args, '/w')).toMatch(/install-npm-[0-9a-f]{6}$/);
    expect(readdirSync(sb.scanRoot(SCAN))).toEqual([]);
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

  it('the install tmpfs is owned by the sandbox user and enforces its size (the phase-A disk quota)', async () => {
    const args = hardenedRunArgs({
      name: `vibesec-itest-q-${Date.now().toString(36)}`, scanId: 'itest', instanceId: 'itest', image: probeImage!, network: 'none',
      mounts: [], env: {}, tmpfs: [{ target: '/out', sizeBytes: 8 * 1024 * 1024 }],
      command: ['sh', '-c', '(touch /out/ok && echo OUT_OK); (dd if=/dev/zero of=/out/big bs=1048576 count=16 2>&1 | grep -qi "no space" && echo QUOTA_HIT || echo QUOTA_MISSED)'],
    });
    const r = await runProcess('docker', args, { env: dockerCliEnv(), timeoutMs: 60_000 });
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain('OUT_OK');
    expect(r.stdout).toContain('QUOTA_HIT');
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
