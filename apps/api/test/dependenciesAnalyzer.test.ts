import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type Finding, type FixPlan, type ScanDto } from '@vibesec/shared';
import {
  computeSeverity, createDependenciesAnalyzer, parseSandboxUsages, type DependenciesAnalyzerDeps,
} from '../src/analyzers/dependencies/dependenciesAnalyzer';
import { dependencyReachabilityMockResponder } from '../src/analyzers/dependencies/reachabilityJudge';
import type { Ecosystem, OsvAdvisory } from '../src/analyzers/dependencies/types';
import type { AnalyzerContext } from '../src/analyzers/types';
import { AppError } from '../src/errors/AppError';
import type { ImportEdge, IndexedFile } from '../src/index/types';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import type { LlmRequest } from '../src/llm/transport';
import { npmProject } from './fixtures/npmProject';

let dir: string;
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vibesec-deps-analyzer-')); });
afterEach(async () => { await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); });

// ---------- fixture repo ----------

async function writeRepo(files: Record<string, string>): Promise<IndexedFile[]> {
  const out: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    out.push({ path, blobSha: 'b', size: content.length, language: 'other', category: 'source', tags: [], skipReason: null });
  }
  return out;
}

const APP_TS = [
  "import _ from 'lodash';",
  "import express from 'express';",
  "export const merged = _.merge({}, JSON.parse(process.argv[2] ?? '{}'));",
  'export const app = express();',
  '',
].join('\n');

function baseProject() {
  return npmProject({
    dependencies: { lodash: '^4.17.15', express: '4.17.1', axois: '1.0.0', 'fancy-native': '1.0.0' },
    devDependencies: { minimist: '1.2.0' },
    packages: {
      'node_modules/lodash': { version: '4.17.15' },
      'node_modules/express': { version: '4.17.1', dependencies: { qs: '6.7.0', send: '0.17.1' } },
      'node_modules/qs': { version: '6.7.0' },
      'node_modules/send': { version: '0.17.1' },
      'node_modules/axois': { version: '1.0.0' },
      'node_modules/fancy-native': { version: '1.0.0', hasInstallScript: true },
      'node_modules/minimist': { version: '1.2.0', dev: true },
    },
  });
}

async function baseRepo(extra: Record<string, string> = {}): Promise<IndexedFile[]> {
  const p = baseProject();
  return writeRepo({ 'package.json': p.packageJson, 'package-lock.json': p.packageLock, 'src/app.ts': APP_TS, ...extra });
}

const BASE_EDGES: ImportEdge[] = [
  { from: 'src/app.ts', specifier: 'lodash', kind: 'package', to: null, pkg: 'lodash', line: 1 },
  { from: 'src/app.ts', specifier: 'express', kind: 'package', to: null, pkg: 'express', line: 2 },
];

// ---------- advisories ----------

function adv(id: string, severity: OsvAdvisory['severity'], fixedVersions: string[], extra: Partial<OsvAdvisory> = {}): OsvAdvisory {
  return {
    id, aliases: [], summary: `${id} summary`, details: '', severity, cvss: null, cvssVector: null, fixedVersions, affectedRanges: [],
    affectedSymbols: [], cwes: [], url: `https://osv.dev/${id}`, published: null, malicious: id.startsWith('MAL-'), ...extra,
  };
}

const BASE_ADVISORIES: Record<string, OsvAdvisory[]> = {
  'lodash@4.17.15': [
    adv('GHSA-lod-1', 'critical', ['4.17.19'], { affectedSymbols: ['merge'], cwes: ['CWE-1321'], cvss: 9.1 }),
    adv('GHSA-lod-2', 'high', ['4.17.21'], { cwes: ['CWE-77'] }),
    adv('GHSA-lod-3', 'high', ['4.17.20']),
  ],
  'qs@6.7.0': [adv('GHSA-qs-1', 'high', ['6.7.3'])],
  'send@0.17.1': [adv('GHSA-send-1', 'medium', ['0.19.0'])],
  'minimist@1.2.0': [adv('GHSA-min-1', 'critical', ['1.2.6'])],
};

type OsvFailures = { errors?: (keys: string[]) => string[]; failedKeys?: (keys: string[]) => string[]; failedIds?: string[] };
function fakeOsv(advisories: Record<string, OsvAdvisory[]> = BASE_ADVISORIES, failures: OsvFailures = {}) {
  return {
    advisoriesFor: vi.fn(async (pkgs: ReadonlyArray<{ key: string; name: string; version: string }>, signal: AbortSignal) => {
      if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'cancelled');
      const byKey = new Map<string, OsvAdvisory[]>();
      for (const p of pkgs) byKey.set(p.key, advisories[`${p.name}@${p.version}`] ?? []);
      const keys = pkgs.map((p) => p.key);
      return { byKey, errors: failures.errors?.(keys) ?? [], failedKeys: failures.failedKeys?.(keys) ?? [], failedIds: failures.failedIds ?? [] };
    }),
  };
}

// ---------- other fakes ----------

const VERSIONS: Record<string, string[]> = {
  lodash: ['4.17.15', '4.17.19', '4.17.20', '4.17.21'], express: ['4.17.1', '4.21.0'], qs: ['6.7.0', '6.7.3', '6.13.0'],
  send: ['0.17.1', '0.19.0'], minimist: ['1.2.0', '1.2.6'],
};
const RANGES: Record<string, string> = {
  'express@4.17.1>qs': '6.7.0', 'express@4.17.1>send': '0.17.1', 'express@4.21.0>qs': '6.13.0', 'express@4.21.0>send': '0.19.0',
};
function fakeRegistry(): DependenciesAnalyzerDeps['registry'] {
  return {
    versions: async (_eco: Ecosystem, name: string) => VERSIONS[name] ?? [],
    dependencyRange: async (_eco: Ecosystem, name: string, version: string, child: string) => RANGES[`${name}@${version}>${child}`] ?? null,
  };
}

function stubLlm(responder: (req: LlmRequest) => unknown = dependencyReachabilityMockResponder) {
  const calls: StructuredCall<unknown>[] = [];
  const llm: Pick<LlmClient, 'structured'> = {
    async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
      calls.push(call as StructuredCall<unknown>);
      const req: LlmRequest = {
        model: 'mock', system: [{ type: 'text', text: call.system }],
        messages: [{ role: 'user', content: [{ type: 'text', text: call.prompt }] }], maxTokens: 100, thinking: false, schema: call.schema,
      };
      return {
        output: call.schema.parse(responder(req) ?? { results: [] }), model: 'mock',
        usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 }, costUsd: 0, callIds: [], degraded: false, fellBackOnRefusal: false,
      };
    },
  };
  return { llm, calls };
}

type SandboxFake = NonNullable<DependenciesAnalyzerDeps['sandbox']>;
function fakeSandbox(opts: {
  available?: boolean;
  installFails?: (manifestDir: string) => boolean;
  usages?: unknown;
} = {}) {
  return {
    availability: vi.fn(async () => (opts.available === false ? { ok: false as const, reason: 'docker not running' } : { ok: true as const, serverVersion: '27' })),
    install: vi.fn(async (o: Parameters<SandboxFake['install']>[0]) => {
      const md = o.ecosystem === 'npm' ? o.manifestDir : 'py';
      if (opts.installFails?.(md)) return { ok: false as const, code: 'SANDBOX_INSTALL_FAILED' as const, message: 'boom' };
      return { ok: true as const, ecosystem: o.ecosystem, depsDir: join(dir, '.deps', md || 'root'), tree: null, warnings: [] };
    }),
    analyze: vi.fn(async (_o: Parameters<SandboxFake['analyze']>[0]) => ({ ok: true as const, usages: opts.usages ?? { version: 1, usages: [] } })),
    sweep: vi.fn(async () => {}),
  };
}

function makeScan(): ScanDto {
  return {
    id: 'scan-1', repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false }, ref: null, commitSha: 'c'.repeat(40),
    state: 'ANALYZING', errorCode: null, errorMessage: null, cacheHit: 'none', options: ScanOptionsSchema.parse({}), costUsd: 0,
    createdAt: new Date().toISOString(), startedAt: null, finishedAt: null, warnings: [],
  };
}

function makeCtx(files: IndexedFile[], signal = new AbortController().signal) {
  const scan = makeScan();
  const warnings: Array<[string, string]> = [];
  const ctx: AnalyzerContext = {
    scanId: scan.id, scan, repoDir: dir, commitSha: scan.commitSha!, repo: scan.repo, files, signal,
    touch: () => {}, warn: (code, message) => { warnings.push([code, message]); }, progress: () => {},
  };
  return { ctx, warnings };
}

function setup(over: Partial<DependenciesAnalyzerDeps> & { edges?: ImportEdge[] } = {}) {
  const saved: FixPlan[] = [];
  const { llm, calls } = stubLlm();
  const deps: DependenciesAnalyzerDeps = {
    osv: fakeOsv(), registry: fakeRegistry(), sandbox: null,
    indexRepo: { imports: () => over.edges ?? BASE_EDGES },
    llm, fixPlans: { save: (p: FixPlan) => { saved.push(p); } }, sandboxEnabled: false,
    ...over,
  };
  return { analyzer: createDependenciesAnalyzer(deps), saved, llmCalls: calls, deps };
}

const vulnOf = (fs: Finding[], name: string) => fs.find((f) => f.ruleId === 'dependency/vulnerable-package' && f.dependency?.name === name);

// ---------- tests ----------

describe('computeSeverity (reachability-driven table)', () => {
  it.each([
    ['high', 'reachable', 'prod', 'high', 'high'],
    ['high', 'imported', 'prod', 'high', 'medium'],
    ['high', 'unknown', 'prod', 'medium', 'medium'],
    ['high', 'unreachable', 'prod', 'low', 'medium'],
    ['critical', 'unreachable', 'prod', 'medium', 'medium'],
    ['medium', 'unreachable', 'prod', 'low', 'medium'],
    ['low', 'unknown', 'prod', 'low', 'medium'],
    ['high', 'imported', 'dev', 'medium', 'medium'],
    ['critical', 'unreachable', 'dev', 'low', 'medium'],
    ['critical', 'reachable', 'dev', 'high', 'high'],
  ] as const)('%s + %s + %s -> %s (confidence %s)', (base, reach, scope, expected, confidence) => {
    const r = computeSeverity(base, reach, scope);
    expect(r.severity).toBe(expected);
    expect(r.confidence).toBe(confidence);
    expect(r.riskFactors.some((f) => f.factor === `reachability:${reach}`)).toBe(true);
    expect(r.riskFactors.some((f) => f.factor === 'devDependency')).toBe(scope === 'dev');
  });
});

describe('parseSandboxUsages', () => {
  it('drops invalid / path-traversing entries and rejects a malformed file', () => {
    const out = parseSandboxUsages({
      version: 1,
      usages: [
        { package: 'lodash', file: 'src/a.ts', line: 3, symbol: 'merge', kind: 'call' },
        { package: 'lodash', file: '../etc/passwd', line: 1, symbol: null, kind: 'import' },
        { package: 'lodash', file: 'src/a.ts', line: 0, symbol: null, kind: 'import' },
        { package: 'lodash', file: 'src/a.ts', line: 1, symbol: null, kind: 'weird' },
        'junk',
      ],
    }, 'npm');
    expect(out).toEqual([{ ecosystem: 'npm', package: 'lodash', file: 'src/a.ts', line: 3, symbol: 'merge', kind: 'call' }]);
    expect(parseSandboxUsages({ nope: true }, 'npm')).toBeNull();
  });
});

describe('createDependenciesAnalyzer', () => {
  it('no lockfiles/manifests -> no findings, no warnings, no fix plan', async () => {
    const files = await writeRepo({ 'src/a.ts': 'export {};\n' });
    const { analyzer, saved, deps } = setup();
    const { ctx, warnings } = makeCtx(files);
    expect(await analyzer.run(ctx)).toEqual([]);
    expect(warnings).toEqual([]);
    expect(saved).toEqual([]);
    expect(deps.osv.advisoriesFor).not.toHaveBeenCalled();
  });

  it('aggregates every advisory of one package@version into ONE finding (index evidence, judge upgrade)', async () => {
    const files = await baseRepo();
    const { analyzer, llmCalls } = setup();
    const { ctx } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    for (const f of findings) expect(() => FindingSchema.parse(f)).not.toThrow();

    const lodash = findings.filter((f) => f.dependency?.name === 'lodash');
    expect(lodash).toHaveLength(1);
    const f = lodash[0]!;
    expect(f.title).toBe('lodash@4.17.15 has 3 known vulnerabilities (1 critical, 2 high)');
    expect(f.cwe).toBe('CWE-1321');
    expect(f.dependency!.advisories.map((a) => a.id)).toEqual(['GHSA-lod-1', 'GHSA-lod-2', 'GHSA-lod-3']);
    expect(f.dependency!.advisories.map((a) => a.fixedIn)).toEqual(['4.17.19', '4.17.21', '4.17.20']);
    expect(f.dependency!.fixedIn).toBe('4.17.21');
    expect(f.dependency).toMatchObject({ ecosystem: 'npm', version: '4.17.15', scope: 'prod', direct: true, paths: [['lodash@4.17.15']] });
    // direct dep -> the manifest line declaring it
    expect(f.location.file).toBe('package.json');
    expect(f.location.snippet).toContain('"lodash"');
    expect(f.location.permalink).toBe(`https://github.com/acme/app/blob/${'c'.repeat(40)}/package.json#L${f.location.startLine}`);
    // index has no symbols; the judge saw `_.merge(` and upgraded imported -> reachable
    expect(llmCalls).toHaveLength(1);
    expect(llmCalls[0]!.prompt).toContain('_.merge(');
    expect(f.dependency!.reachability).toBe('reachable');
    expect(f.dependency!.reachabilityEvidence).toContainEqual({ file: 'src/app.ts', line: 3 });
    expect(f.severity).toBe('critical');
    expect(f.confidence).toBe('high');
    expect(f.producedBy).toEqual(['osv', 'index', 'llm']);
    expect(f.explanation).toContain('GHSA-lod-1');
    expect(f.explanation).toContain('direct dependency');
  });

  it('applies the severity table end to end: unknown transitive, unreachable dev dep', async () => {
    const files = await baseRepo();
    const { analyzer } = setup();
    const findings = await analyzer.run(makeCtx(files).ctx);

    const qs = vulnOf(findings, 'qs')!;
    expect(qs.dependency).toMatchObject({ direct: false, reachability: 'unknown', paths: [['express@4.17.1', 'qs@6.7.0']] });
    expect(qs.baseSeverity).toBe('high');
    expect(qs.severity).toBe('medium');
    expect(qs.location.file).toBe('package-lock.json');
    expect(qs.location.snippet).toContain('node_modules/qs');
    expect(qs.explanation).toContain('express@4.17.1 > qs@6.7.0');

    const minimist = vulnOf(findings, 'minimist')!;
    expect(minimist.dependency).toMatchObject({ scope: 'dev', direct: true, reachability: 'unreachable' });
    expect(minimist.severity).toBe('low'); // critical -2 (unreachable) = medium, -1 (dev) = low
    expect(minimist.riskFactors.map((r) => r.factor)).toEqual(['reachability:unreachable', 'devDependency']);
  });

  it('a malicious package is always critical, even unused and dev-only, and is reported once (supply-chain finding)', async () => {
    const files = await baseRepo();
    const { analyzer, saved } = setup({
      osv: fakeOsv({ ...BASE_ADVISORIES, 'minimist@1.2.0': [adv('MAL-2024-1', 'critical', [])] }),
    });
    const findings = await analyzer.run(makeCtx(files).ctx);
    const mm = findings.filter((f) => f.dependency?.name === 'minimist');
    expect(mm.map((f) => f.ruleId)).toEqual(['supply-chain/malicious-package']);
    expect(mm[0]).toMatchObject({ severity: 'critical', cwe: 'CWE-506' });
    expect(mm[0]!.dependency!.advisories.map((a) => a.id)).toEqual(['MAL-2024-1']);
    expect(mm[0]!.dependency!.reachability).toBe('unreachable');
    // no fixed version -> a 'remove' action, linked to the finding
    const remove = saved[0]!.actions.find((a) => a.kind === 'remove');
    expect(remove).toMatchObject({ package: 'minimist', command: 'npm uninstall minimist' });
    expect(mm[0]!.remediation.summary).toBe('npm uninstall minimist');
  });

  it('reports supply-chain signals (typosquat, install script) as findings', async () => {
    const files = await baseRepo();
    const { analyzer } = setup();
    const findings = await analyzer.run(makeCtx(files).ctx);
    const typo = findings.find((f) => f.ruleId === 'supply-chain/typosquat');
    expect(typo).toMatchObject({ severity: 'high', confidence: 'medium', title: 'axois looks like a typosquat of axios' });
    expect(typo!.dependency).toMatchObject({ name: 'axois', advisories: [], reachability: 'unreachable' });
    expect(typo!.location.file).toBe('package.json');
    const script = findings.find((f) => f.ruleId === 'supply-chain/install-script');
    expect(script).toMatchObject({ severity: 'medium', title: 'fancy-native@1.0.0 runs an install script' });
  });

  it('saves the fix plan and links each finding to the action that resolves it', async () => {
    const files = await baseRepo();
    const { analyzer, saved } = setup();
    const findings = await analyzer.run(makeCtx(files).ctx);
    expect(saved).toHaveLength(1);
    const plan = saved[0]!;
    const expressAction = plan.actions.find((a) => a.kind === 'upgrade-parent' && a.package === 'express')!;
    expect(expressAction).toMatchObject({ from: '4.17.1', to: '4.21.0', resolvedCount: 2, command: 'npm install express@4.21.0' });
    const qs = vulnOf(findings, 'qs')!;
    const send = vulnOf(findings, 'send')!;
    expect(new Set(expressAction.resolves.map((r) => r.findingId))).toEqual(new Set([qs.id, send.id]));
    expect(qs.remediation.summary).toBe('npm install express@4.21.0 (also resolves 1 other advisory in this action)');
    const lodashAction = plan.actions.find((a) => a.package === 'lodash')!;
    expect(lodashAction).toMatchObject({ kind: 'upgrade-direct', to: '4.17.21', resolvedCount: 3 });
    expect(vulnOf(findings, 'lodash')!.remediation.summary).toBe('npm install lodash@4.17.21');
  });

  it('registry failures degrade the fix plan with DEPENDENCY_FIX_PLAN_PARTIAL', async () => {
    const files = await baseRepo();
    const { analyzer, saved } = setup({
      registry: { versions: async () => { throw new AppError('INTERNAL', 'transient', 'registry down'); }, dependencyRange: async () => null },
    });
    const { ctx, warnings } = makeCtx(files);
    await analyzer.run(ctx);
    expect(warnings.map((w) => w[0])).toContain('DEPENDENCY_FIX_PLAN_PARTIAL');
    expect(saved[0]!.actions.length).toBeGreaterThan(0);
  });

  it('uses sandbox usages when available: symbol-level evidence proves reachability without the judge; sweeps', async () => {
    const files = await baseRepo();
    const sandbox = fakeSandbox({
      usages: { version: 1, usages: [
        { package: 'lodash', file: 'src/app.ts', line: 1, symbol: 'default', kind: 'import' },
        { package: 'lodash', file: 'src/app.ts', line: 3, symbol: 'merge', kind: 'call' },
        { package: 'express', file: 'src/app.ts', line: 2, symbol: 'default', kind: 'import' },
      ] },
    });
    const { analyzer, llmCalls } = setup({ sandbox, sandboxEnabled: true });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    expect(warnings).toEqual([]);
    expect(sandbox.install).toHaveBeenCalledTimes(1);
    expect(sandbox.install.mock.calls[0]![0]).toMatchObject({ ecosystem: 'npm', manifestDir: '', srcDir: dir, scanId: 'scan-1' });
    const pkgs = sandbox.analyze.mock.calls[0]![0].packages as Array<{ name: string }>;
    expect(pkgs.map((p) => p.name)).toEqual(expect.arrayContaining(['lodash', 'qs', 'send', 'express', 'minimist', 'axois', 'fancy-native']));
    expect(sandbox.sweep).toHaveBeenCalledWith('scan-1');
    const lodash = vulnOf(findings, 'lodash')!;
    expect(lodash.dependency!.reachability).toBe('reachable');
    expect(lodash.producedBy).toEqual(['osv', 'sandbox']);
    expect(llmCalls).toHaveLength(0);
  });

  it('sandbox unavailable -> index fallback with SANDBOX_UNAVAILABLE', async () => {
    const files = await baseRepo();
    const sandbox = fakeSandbox({ available: false });
    const { analyzer } = setup({ sandbox, sandboxEnabled: true });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    expect(warnings.map((w) => w[0])).toEqual(['SANDBOX_UNAVAILABLE']);
    expect(sandbox.install).not.toHaveBeenCalled();
    expect(sandbox.sweep).toHaveBeenCalledWith('scan-1');
    expect(vulnOf(findings, 'lodash')!.producedBy).toContain('index');
  });

  it('sandbox failure for one manifest dir -> that graph falls back to the index (SANDBOX_PARTIAL, once)', async () => {
    const svc = npmProject({ dependencies: { lodash: '4.17.15' }, packages: { 'node_modules/lodash': { version: '4.17.15' } } });
    const files = await baseRepo({ 'svc/package.json': svc.packageJson, 'svc/package-lock.json': svc.packageLock, 'svc/index.js': "const _ = require('lodash');\n" });
    const sandbox = fakeSandbox({
      installFails: (md) => md === 'svc',
      usages: { version: 1, usages: [{ package: 'lodash', file: 'src/app.ts', line: 3, symbol: 'merge', kind: 'call' }] },
    });
    const edges = [...BASE_EDGES, { from: 'svc/index.js', specifier: 'lodash', kind: 'package' as const, to: null, pkg: 'lodash', line: 1 }];
    const { analyzer } = setup({ sandbox, sandboxEnabled: true, edges, llm: { structured: async () => { throw new Error('no llm'); } } });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    const partial = warnings.filter((w) => w[0] === 'SANDBOX_PARTIAL');
    expect(partial).toHaveLength(1);
    expect(partial[0]![1]).toContain('svc/package-lock.json');
    const lodash = findings.filter((f) => f.dependency?.name === 'lodash' && f.ruleId === 'dependency/vulnerable-package');
    expect(lodash).toHaveLength(2);
    const root = lodash.find((f) => f.location.file === 'package.json')!;
    const sub = lodash.find((f) => f.location.file === 'svc/package.json')!;
    expect(root.producedBy).toEqual(['osv', 'sandbox']);
    expect(sub.producedBy).toEqual(['osv', 'index']);
    expect(sub.dependency!.reachability).toBe('imported'); // judge failed open
    expect(root.id).not.toBe(sub.id);
  });

  it('skips the sandbox when nothing is vulnerable, or when it is disabled', async () => {
    const files = await baseRepo();
    const sandbox = fakeSandbox();
    await setup({ sandbox, sandboxEnabled: true, osv: fakeOsv({}) }).analyzer.run(makeCtx(files).ctx);
    expect(sandbox.availability).not.toHaveBeenCalled();
    await setup({ sandbox, sandboxEnabled: false }).analyzer.run(makeCtx(files).ctx);
    expect(sandbox.install).not.toHaveBeenCalled();
  });

  it('OSV partially failing -> DEPENDENCY_ADVISORIES_PARTIAL, findings for what resolved', async () => {
    const files = await baseRepo();
    const { analyzer } = setup({ osv: fakeOsv(BASE_ADVISORIES, { errors: () => ['Failed to fetch OSV advisory GHSA-x: unavailable'], failedIds: ['GHSA-x'] }) });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    expect(warnings.map((w) => w[0])).toContain('DEPENDENCY_ADVISORIES_PARTIAL');
    expect(vulnOf(findings, 'lodash')).toBeDefined();
  });

  it('OSV completely unavailable -> DEPENDENCY_ADVISORIES_UNAVAILABLE and supply-chain findings only', async () => {
    const files = await baseRepo();
    const { analyzer, saved } = setup({ osv: fakeOsv(BASE_ADVISORIES, { errors: (keys) => keys.map(() => 'something went wrong'), failedKeys: (keys) => keys }) });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    expect(warnings.map((w) => w[0])).toEqual(['DEPENDENCY_ADVISORIES_UNAVAILABLE']);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.ruleId.startsWith('supply-chain/'))).toBe(true);
    expect(saved[0]!.actions).toEqual([]);
  });

  it('OSV errors that are not total outages (no failedKeys) never trigger UNAVAILABLE, whatever their wording', async () => {
    const files = await baseRepo();
    const { analyzer } = setup({ osv: fakeOsv(BASE_ADVISORIES, { errors: (keys) => keys.map((k) => `OSV querybatch failed for ${k}: x`) }) });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    expect(warnings.map((w) => w[0])).toEqual(['DEPENDENCY_ADVISORIES_PARTIAL']);
    expect(vulnOf(findings, 'lodash')).toBeDefined();
  });

  it('a package whose advisory details failed still gets a finding (details unavailable, medium)', async () => {
    const files = await baseRepo();
    const placeholder = adv('GHSA-gone', 'medium', [], { summary: 'Advisory details unavailable', detailsUnavailable: true });
    const { analyzer } = setup({ osv: fakeOsv({ ...BASE_ADVISORIES, 'minimist@1.2.0': [placeholder] }, { failedIds: ['GHSA-gone'], errors: () => ['Failed to fetch OSV advisory GHSA-gone: down'] }) });
    const { ctx, warnings } = makeCtx(files);
    const findings = await analyzer.run(ctx);
    const f = vulnOf(findings, 'minimist');
    expect(f).toBeDefined();
    expect(f!.dependency!.advisories.map((a) => a.id)).toEqual(['GHSA-gone']);
    expect(f!.explanation).toMatch(/details (are )?unavailable/i);
    expect(warnings.map((w) => w[0])).toContain('DEPENDENCY_ADVISORIES_PARTIAL');
  });

  it('is deterministic: same ids/fingerprints across runs', async () => {
    const files = await baseRepo();
    const a = await setup().analyzer.run(makeCtx(files).ctx);
    const b = await setup().analyzer.run(makeCtx(files).ctx);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(new Set(a.map((f) => f.fingerprint)).size).toBe(a.length);
  });

  it('propagates cancellation', async () => {
    const files = await baseRepo();
    const ac = new AbortController();
    const osv = {
      advisoriesFor: vi.fn(async () => { ac.abort(); throw new AppError('CANCELLED', 'cancelled', 'cancelled'); }),
    };
    const { analyzer } = setup({ osv });
    await expect(analyzer.run(makeCtx(files, ac.signal).ctx)).rejects.toMatchObject({ kind: 'cancelled' });
  });

  it('propagates cancellation from the sandbox phase and still sweeps', async () => {
    const files = await baseRepo();
    const ac = new AbortController();
    const sandbox = fakeSandbox();
    sandbox.install.mockImplementation(async () => { ac.abort(); throw new AppError('CANCELLED', 'cancelled', 'cancelled'); });
    const { analyzer } = setup({ sandbox, sandboxEnabled: true });
    await expect(analyzer.run(makeCtx(files, ac.signal).ctx)).rejects.toMatchObject({ kind: 'cancelled' });
    expect(sandbox.sweep).toHaveBeenCalledWith('scan-1');
  });
});
