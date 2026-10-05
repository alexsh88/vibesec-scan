// End-to-end: a real scan (RESOLVING -> CLONING -> INDEXING -> ANALYZING) over a local fixture repo
// with npm + PyPI dependencies, through the HTTP layer, in mock-LLM mode, sandbox disabled, with a
// fake fetch serving OSV (querybatch + vuln details) and the npm/PyPI registries from fixtures.
// Wired like credentialsPipeline.test.ts (own Container-shaped object so git/github point at the fixture).
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { FindingSchema, FixPlanSchema, type Finding } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { createCredentialsAnalyzer } from '../src/analyzers/credentials/credentialsAnalyzer';
import { credentialsFpMockResponder } from '../src/analyzers/credentials/fpFilter';
import { SecretVerifier } from '../src/analyzers/credentials/verifiers';
import { createDependenciesAnalyzer } from '../src/analyzers/dependencies/dependenciesAnalyzer';
import { OsvClient } from '../src/analyzers/dependencies/osv/osvClient';
import { dependencyReachabilityMockResponder } from '../src/analyzers/dependencies/reachabilityJudge';
import { RegistryClient } from '../src/analyzers/dependencies/registry';
import { loadConfig } from '../src/config';
import type { Container } from '../src/container';
import { AdvisoryCacheRepo } from '../src/db/advisoryCacheRepo';
import { EventRepo } from '../src/db/eventRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { FixPlanRepo } from '../src/db/fixPlanRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { SummaryRepo } from '../src/db/summaryRepo';
import { EventBus } from '../src/events/EventBus';
import { GitService } from '../src/git/GitService';
import type { GitHubClient, RepoMeta } from '../src/github/GitHubClient';
import { buildApp } from '../src/http/app';
import { RepoIndexer } from '../src/index/RepoIndexer';
import { JobRunner } from '../src/jobs/JobRunner';
import { BudgetTracker } from '../src/llm/budget';
import { createTransport } from '../src/llm/createTransport';
import { LlmClient } from '../src/llm/LlmClient';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import { createScanPipeline } from '../src/pipeline/scanPipeline';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { ScanService } from '../src/scans/ScanService';
import { createFixtureRepo, type FixtureRepo } from './fixtures/gitRepo';
import { npmProject } from './fixtures/npmProject';
import { memoryDb } from './helpers';

// ---------- fixture repo ----------

const project = npmProject({
  dependencies: { lodash: '4.17.15', express: '4.17.1', 'fancy-native': '1.0.0', axois: '1.0.0' },
  devDependencies: { minimist: '1.2.0' },
  packages: {
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/express': { version: '4.17.1', dependencies: { qs: '6.7.0', send: '0.17.1' } },
    'node_modules/qs': { version: '6.7.0' },
    'node_modules/send': { version: '0.17.1' },
    'node_modules/fancy-native': { version: '1.0.0', hasInstallScript: true },
    'node_modules/axois': { version: '1.0.0' },
    'node_modules/minimist': { version: '1.2.0', dev: true },
  },
});

const FILES: Record<string, string> = {
  'package.json': project.packageJson,
  'package-lock.json': project.packageLock,
  'src/server.ts': [
    "import _ from 'lodash';",
    "import express from 'express';",
    '',
    'const app = express();',
    "app.post('/settings', (req, res) => res.json(_.merge({}, req.body)));",
    'app.listen(3000);',
    '',
  ].join('\n'),
  'requirements.txt': 'pyyaml==5.3\n',
  'worker.py': ['import yaml', '', 'def load_config(path):', '    return yaml.load(open(path))', ''].join('\n'),
};

// ---------- OSV fixtures (raw OSV schema) ----------

const V = {
  critical91: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  critical98: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  high75: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  medium53: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
};

function osvRecord(id: string, eco: 'npm' | 'PyPI', name: string, fixed: string, vector: string, summary: string, cwe: string) {
  return {
    id, summary, details: `${summary}. Details.`, aliases: [`CVE-${id.slice(5)}`], modified: '2024-01-01T00:00:00Z', published: '2023-01-01T00:00:00Z',
    severity: [{ type: 'CVSS_V3', score: vector }],
    affected: [{ package: { ecosystem: eco, name }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }] }],
    references: [{ type: 'ADVISORY', url: `https://github.com/advisories/${id}` }],
    database_specific: { cwe_ids: [cwe] },
  };
}

const VULNS = [
  osvRecord('GHSA-0001-lodash', 'npm', 'lodash', '4.17.19', V.critical91, 'Prototype pollution in lodash merge()', 'CWE-1321'),
  osvRecord('GHSA-0002-lodash', 'npm', 'lodash', '4.17.21', V.high75, 'Command injection in lodash template', 'CWE-77'),
  osvRecord('GHSA-0003-lodash', 'npm', 'lodash', '4.17.21', V.medium53, 'ReDoS in lodash toNumber and trim', 'CWE-1333'),
  osvRecord('GHSA-0004-qs', 'npm', 'qs', '6.7.3', V.high75, 'qs vulnerable to prototype pollution', 'CWE-1321'),
  osvRecord('GHSA-0005-send', 'npm', 'send', '0.19.0', V.medium53, 'send vulnerable to template injection', 'CWE-79'),
  osvRecord('GHSA-0006-minimist', 'npm', 'minimist', '1.2.6', V.critical98, 'Prototype pollution in minimist', 'CWE-1321'),
  osvRecord('GHSA-0007-pyyaml', 'PyPI', 'PyYAML', '5.4', V.critical98, 'Arbitrary code execution in PyYAML `yaml.load` (full_load)', 'CWE-502'),
];
const VULN_BY_ID = new Map(VULNS.map((v) => [v.id, v]));
const IDS_BY_PACKAGE: Record<string, string[]> = {
  'npm:lodash@4.17.15': ['GHSA-0001-lodash', 'GHSA-0002-lodash', 'GHSA-0003-lodash'],
  'npm:qs@6.7.0': ['GHSA-0004-qs'],
  'npm:send@0.17.1': ['GHSA-0005-send'],
  'npm:minimist@1.2.0': ['GHSA-0006-minimist'],
  'PyPI:pyyaml@5.3': ['GHSA-0007-pyyaml'],
};

// ---------- registry fixtures ----------

const NPM_DOCS: Record<string, Record<string, { dependencies?: Record<string, string> }>> = {
  lodash: { '4.17.15': {}, '4.17.19': {}, '4.17.20': {}, '4.17.21': {} },
  express: { '4.17.1': { dependencies: { qs: '6.7.0', send: '0.17.1' } }, '4.21.2': { dependencies: { qs: '6.13.0', send: '0.19.0' } } },
  qs: { '6.7.0': {}, '6.7.3': {}, '6.13.0': {} },
  send: { '0.17.1': {}, '0.19.0': {} },
  minimist: { '1.2.0': {}, '1.2.6': {}, '1.2.8': {} },
};
const PYPI_RELEASES: Record<string, string[]> = { pyyaml: ['5.3', '5.4', '6.0'] };

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const fetchLog: string[] = [];

const fakeFetch: typeof fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
  fetchLog.push(url);
  if (url === 'https://api.osv.dev/v1/querybatch' && init?.method === 'POST') {
    const body = JSON.parse(String(init.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
    return json({
      results: body.queries.map((q) => {
        const ids = IDS_BY_PACKAGE[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? [];
        return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: '2024-01-01T00:00:00Z' })) } : {};
      }),
    });
  }
  const vuln = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
  if (vuln) {
    const rec = VULN_BY_ID.get(decodeURIComponent(vuln[1]!));
    return rec ? json(rec) : json({}, 404);
  }
  const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
  if (npm) {
    const doc = NPM_DOCS[decodeURIComponent(npm[1]!)];
    return doc ? json({ name: npm[1], versions: doc }) : json({}, 404);
  }
  const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
  if (pypi) {
    const rel = PYPI_RELEASES[decodeURIComponent(pypi[1]!).toLowerCase()];
    return rel ? json({ releases: Object.fromEntries(rel.map((v) => [v, []])) }) : json({}, 404);
  }
  return new Response('', { status: 404 });
};

// ---------- wiring ----------

let repo: FixtureRepo;
let workDir: string;
let app: FastifyInstance;
let container: Container;
let runner: JobRunner;

beforeAll(async () => {
  repo = await createFixtureRepo([{ files: FILES }]);
  workDir = await mkdtemp(join(tmpdir(), 'vibesec-dependencies-pipeline-'));

  const config = loadConfig({ DB_PATH: ':memory:', ALLOW_LOCAL_REPOS: 'true', SANDBOX_ENABLED: 'false' });
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);
  const git = new GitService({ workDir, cloneTimeoutMs: 60_000, stallMs: 20_000, allowFileProtocol: true, remoteUrlFor: () => repo.url });
  await git.init();
  const github = {
    getRepo: async (): Promise<RepoMeta> => ({ isPrivate: false, defaultBranch: 'main', sizeBytes: 1_000, htmlUrl: '', archived: false }),
  };
  const indexRepo = new IndexRepo(db);
  const findings = new FindingRepo(db);
  const fixPlans = new FixPlanRepo(db);
  const indexer = new RepoIndexer(git, { maxFiles: 10_000, maxFileBytes: 1024 * 1024 });
  const llmCalls = new LlmCallRepo(db);
  const budget = new BudgetTracker(config.scanBudgetUsd, (id) => scans.getDto(id)?.costUsd ?? 0);
  const llm = new LlmClient({
    transport: createTransport(config, [credentialsFpMockResponder, dependencyReachabilityMockResponder]),
    models: config.models,
    limiter: new RateLimiter({ requestsPerMinute: config.llmRequestsPerMinute, inputTokensPerMinute: config.llmInputTokensPerMinute }),
    semaphore: new Semaphore(config.llmConcurrency),
    budget, calls: llmCalls, scans,
    atomically: (fn) => db.transaction(fn)(),
    onUsage: () => {},
  });
  const verifier = new SecretVerifier({ audit, fetch: fakeFetch });
  const osv = new OsvClient({ cache: new AdvisoryCacheRepo(db), fetch: fakeFetch });
  const registry = new RegistryClient({ fetch: fakeFetch });

  const analyzers = [
    createCredentialsAnalyzer({ llm, git, verifier }),
    createDependenciesAnalyzer({ osv, registry, sandbox: null, indexRepo, llm, fixPlans, sandboxEnabled: false }),
  ];
  const pipeline = createScanPipeline({
    git, github, scans, indexRepo, indexer, maxRepoBytes: 1024 * 1024 * 1024, maxFiles: 10_000, analyzers, findings,
    onFinished: (id) => { budget.forget(id); verifier.forget(id); },
  });
  runner = new JobRunner({
    scans, lifecycle, bus, audit, pipeline,
    config: { maxConcurrentScans: 2, scanDeadlineMs: 60_000, heartbeatMs: 1_000, stuckAfterMs: 60_000, staleHeartbeatMs: 30_000, queueCapacity: 10 },
  });
  const service = new ScanService({ db, scans, lifecycle, audit, queue: runner, queueCapacity: 10 });
  container = {
    summaries: new SummaryRepo(db),
    config, db, scans, bus, audit, lifecycle, runner, service,
    git, github: github as unknown as GitHubClient, indexRepo, gitVersion: null, llm, llmCalls, budget, findings, fixPlans, sandbox: null,
  };
  app = await buildApp(container, { logger: false });
}, 60_000);

afterAll(async () => {
  await runner.shutdown(0);
  await app.close();
  container.db.close();
  await repo.cleanup();
  await rm(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

describe('dependencies analyzer, end to end through the real pipeline', () => {
  it('reports one finding per vulnerable library with reachability-aware severity, supply-chain findings and a ranked fix plan', async () => {
    const createRes = await app.inject({
      method: 'POST', url: '/api/scans', headers: { 'idempotency-key': randomUUID() },
      payload: { repoUrl: 'https://github.com/acme/app' },
    });
    expect(createRes.statusCode).toBe(202);
    const scanId = createRes.json().scanId as string;
    await runner.whenIdle();

    const scan = container.scans.getDto(scanId)!;
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    expect(scan.warnings.map((w) => w.code)).not.toContain('ANALYZER_FAILED');
    // No real network: every request went to the fake.
    expect(fetchLog.length).toBeGreaterThan(0);

    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?category=dependency&limit=200` });
    expect(res.statusCode).toBe(200);
    const items: Finding[] = (res.json() as { items: unknown[] }).items.map((i) => FindingSchema.parse(i));
    expect(items.every((f) => f.category === 'dependency')).toBe(true);

    const vuln = (name: string) => items.filter((f) => f.ruleId === 'dependency/vulnerable-package' && f.dependency?.name === name);
    for (const name of ['lodash', 'qs', 'send', 'minimist', 'pyyaml']) expect(vuln(name)).toHaveLength(1);

    const lodash = vuln('lodash')[0]!;
    expect(lodash.title).toBe('lodash@4.17.15 has 3 known vulnerabilities (1 critical, 1 high, 1 medium)');
    expect(lodash.dependency!.advisories).toHaveLength(3);
    expect(lodash.dependency).toMatchObject({ direct: true, scope: 'prod', reachability: 'reachable', fixedIn: '4.17.21' });
    expect(lodash.severity).toBe('critical');
    expect(lodash.location.file).toBe('package.json');
    expect(lodash.producedBy).toEqual(['osv', 'index', 'llm']);

    const qs = vuln('qs')[0]!;
    expect(qs.dependency).toMatchObject({ direct: false, reachability: 'unknown', paths: [['express@4.17.1', 'qs@6.7.0']] });
    expect(qs.severity).toBe('medium');
    expect(vuln('send')[0]!.severity).toBe('low');

    const minimist = vuln('minimist')[0]!;
    expect(minimist.dependency).toMatchObject({ scope: 'dev', reachability: 'unreachable' });
    expect(minimist.severity).toBe('low');

    const pyyaml = vuln('pyyaml')[0]!;
    expect(pyyaml.dependency).toMatchObject({ ecosystem: 'PyPI', version: '5.3', reachability: 'reachable' });
    expect(pyyaml.severity).toBe('critical');
    expect(pyyaml.cwe).toBe('CWE-502');
    expect(pyyaml.location).toMatchObject({ file: 'requirements.txt', startLine: 1, snippet: 'pyyaml==5.3' });

    expect(items.find((f) => f.ruleId === 'supply-chain/install-script')?.dependency?.name).toBe('fancy-native');
    expect(items.find((f) => f.ruleId === 'supply-chain/typosquat')?.dependency?.name).toBe('axois');

    const planRes = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/fix-plan` });
    expect(planRes.statusCode).toBe(200);
    const plan = FixPlanSchema.parse(planRes.json());
    expect(plan.actions.length).toBeGreaterThan(0);
    for (let i = 1; i < plan.actions.length; i++) expect(plan.actions[i - 1]!.priority).toBeGreaterThanOrEqual(plan.actions[i]!.priority);
    const expressAction = plan.actions.find((a) => a.kind === 'upgrade-parent' && a.package === 'express')!;
    expect(expressAction).toMatchObject({ to: '4.21.2', resolvedCount: 2 });
    expect(new Set(expressAction.resolves.map((r) => r.package))).toEqual(new Set(['qs', 'send']));
    expect(plan.actions.find((a) => a.package === 'lodash')).toMatchObject({ kind: 'upgrade-direct', to: '4.17.21', resolvedCount: 3 });
    expect(plan.actions.find((a) => a.package === 'pyyaml')).toMatchObject({ to: '5.4', command: 'set `pyyaml==5.4` in requirements.txt' });
    expect(qs.remediation.summary).toBe('npm install express@4.21.2 (also resolves 1 other advisory in this action)');
  }, 60_000);
});
