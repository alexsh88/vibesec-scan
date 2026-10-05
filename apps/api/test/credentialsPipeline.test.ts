// End-to-end: a real scan (RESOLVING -> CLONING -> INDEXING -> ANALYZING) over a local fixture repo,
// through the HTTP layer, in mock-LLM mode, with a fake fetch standing in for the liveness verifier's
// provider calls. Mirrors how scanPipeline.test.ts points GitService at a local bare repo and how
// http.test.ts drives scans through `app.inject`, but wires its own Container-shaped object (rather
// than `createContainer`) so the git/github dependencies can be pointed at the fixture instead of
// the real network.
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { AuditLogger } from '../src/audit/AuditLogger';
import { createCredentialsAnalyzer } from '../src/analyzers/credentials/credentialsAnalyzer';
import { credentialsFpMockResponder } from '../src/analyzers/credentials/fpFilter';
import { SecretVerifier } from '../src/analyzers/credentials/verifiers';
import { loadConfig } from '../src/config';
import type { Container } from '../src/container';
import { EventRepo } from '../src/db/eventRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { EventBus } from '../src/events/EventBus';
import { GitService } from '../src/git/GitService';
import type { GitHubClient, RepoMeta } from '../src/github/GitHubClient';
import { buildApp } from '../src/http/app';
import { RepoIndexer } from '../src/index/RepoIndexer';
import { JobRunner } from '../src/jobs/JobRunner';
import { createTransport } from '../src/llm/createTransport';
import { LlmClient } from '../src/llm/LlmClient';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import { BudgetTracker } from '../src/llm/budget';
import { createScanPipeline } from '../src/pipeline/scanPipeline';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { ScanService } from '../src/scans/ScanService';
import { fake } from './fakeCredentials';
import { createFixtureRepo, type FixtureRepo } from './fixtures/gitRepo';
import { memoryDb } from './helpers';

const GITHUB_TOKEN = fake.github();
const STRIPE_KEY = fake.stripeLive();
const AWS_ACCESS = fake.awsAccessKey();
const AWS_SECRET = fake.awsSecretKey();
const ANON_JWT = fake.supabaseAnonJwt();
const FIXTURE_PASSWORD = fake.genericSecretValue(24);
const PLANTED_RAW_VALUES = [GITHUB_TOKEN, STRIPE_KEY, AWS_ACCESS, AWS_SECRET, ANON_JWT, FIXTURE_PASSWORD];

let repo: FixtureRepo;
let workDir: string;
let app: FastifyInstance;
let container: Container;
let runner: JobRunner;

beforeAll(async () => {
  repo = await createFixtureRepo([
    {
      files: {
        'src/config.ts': `export const githubToken = "${GITHUB_TOKEN}";\n`,
        '.env': `STRIPE_SECRET_KEY=${STRIPE_KEY}\n`,
        'test/fixtures/sample.ts': `export const password = "${FIXTURE_PASSWORD}";\n`,
        'src/auth.ts': `export const supabaseAnonKey = "${ANON_JWT}";\n`,
        'infra/deploy.ts': `export const awsAccessKeyId = "${AWS_ACCESS}";\nexport const awsSecretAccessKey = "${AWS_SECRET}";\n`,
      },
    },
    { files: { 'infra/deploy.ts': null } }, // AWS key committed, then removed -> history-only
  ]);
  workDir = await mkdtemp(join(tmpdir(), 'vibesec-credentials-pipeline-'));

  const config = loadConfig({ DB_PATH: ':memory:', ALLOW_LOCAL_REPOS: 'true' });
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);

  const git = new GitService({
    workDir, cloneTimeoutMs: 60_000, stallMs: 20_000, allowFileProtocol: true, remoteUrlFor: () => repo.url,
  });
  await git.init();
  const github = {
    getRepo: async (): Promise<RepoMeta> => ({ isPrivate: false, defaultBranch: 'main', sizeBytes: 1_000, htmlUrl: '', archived: false }),
  };

  const indexRepo = new IndexRepo(db);
  const findings = new FindingRepo(db);
  const indexer = new RepoIndexer(git, { maxFiles: 10_000, maxFileBytes: 1024 * 1024 });

  const llmCalls = new LlmCallRepo(db);
  const budget = new BudgetTracker(config.scanBudgetUsd, (id) => scans.getDto(id)?.costUsd ?? 0);
  const llm = new LlmClient({
    transport: createTransport(config, [credentialsFpMockResponder]),
    models: config.models,
    limiter: new RateLimiter({ requestsPerMinute: config.llmRequestsPerMinute, inputTokensPerMinute: config.llmInputTokensPerMinute }),
    semaphore: new Semaphore(config.llmConcurrency),
    budget, calls: llmCalls, scans,
    atomically: (fn) => db.transaction(fn)(),
    onUsage: (id, t) => lifecycle.emit(id, {
      type: 'cost', inputTokens: t.inputTokens, outputTokens: t.outputTokens, cacheReadTokens: t.cacheReadTokens, usd: t.costUsd,
    }),
  });

  // GitHub /user -> 200 (so the planted GitHub token verifies live); every other provider -> 401.
  const fakeFetch: typeof fetch = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    if (url === 'https://api.github.com/user') return new Response(JSON.stringify({ login: 'octocat' }), { status: 200 });
    return new Response('', { status: 401 });
  };
  const verifier = new SecretVerifier({ audit, fetch: fakeFetch });

  const analyzers = [createCredentialsAnalyzer({ llm, git, verifier })];
  const pipeline = createScanPipeline({
    git, github, scans, indexRepo, indexer, maxRepoBytes: 1024 * 1024 * 1024, maxFiles: 10_000,
    analyzers, findings,
    onFinished: (id) => { budget.forget(id); verifier.forget(id); },
  });

  runner = new JobRunner({
    scans, lifecycle, bus, audit, pipeline,
    config: { maxConcurrentScans: 2, scanDeadlineMs: 60_000, heartbeatMs: 1_000, stuckAfterMs: 60_000, staleHeartbeatMs: 30_000, queueCapacity: 10 },
  });
  const service = new ScanService({ db, scans, lifecycle, audit, queue: runner, queueCapacity: 10 });

  container = {
    config, db, scans, bus, audit, lifecycle, runner, service,
    git, github: github as unknown as GitHubClient, indexRepo, gitVersion: null, llm, llmCalls, budget, findings,
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

describe('credentials analyzer, end to end through the real pipeline', () => {
  it('finds planted credentials, verifies liveness, drops test-code and anon-role false positives, and never stores a raw secret anywhere', async () => {
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/scans',
      headers: { 'idempotency-key': randomUUID() },
      payload: { repoUrl: 'https://github.com/acme/app', options: { verifySecrets: true } },
    });
    expect(createRes.statusCode).toBe(202);
    const scanId = createRes.json().scanId as string;

    await runner.whenIdle();

    const scanDto = container.scans.getDto(scanId)!;
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scanDto.state);

    const findingsRes = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?limit=200` });
    expect(findingsRes.statusCode).toBe(200);
    const findingsBody = findingsRes.json() as { items: Array<Record<string, any>> };
    const items = findingsBody.items;

    const github = items.find((f) => f.ruleId === 'secret/github-token');
    expect(github).toBeDefined();
    expect(github!.severity).toBe('critical');
    expect(github!.secret.liveness).toBe('live');
    expect(github!.secret.inHistoryOnly).toBe(false);

    const stripe = items.find((f) => f.ruleId === 'secret/stripe-secret-key');
    expect(stripe).toBeDefined();

    const aws = items.find((f) => f.ruleId === 'secret/aws-access-key');
    expect(aws).toBeDefined();
    expect(aws!.secret.inHistoryOnly).toBe(true);
    expect(aws!.secret.commit).toBeTruthy();

    // The Supabase anon JWT must never be reported (role is public by design).
    expect(items.some((f) => f.ruleId === 'secret/jwt' || f.ruleId === 'secret/supabase-service-role')).toBe(false);
    // I6: the fixture password is judged a false positive (test code) by the (mock) FP filter, but
    // the AI verdict must never make a finding disappear — it stays present, downgraded to 'info'.
    const fixtureFinding = items.find((f) => f.location.file === 'test/fixtures/sample.ts');
    expect(fixtureFinding).toBeDefined();
    expect(fixtureFinding!.severity).toBe('info');

    const auditItems = container.audit.list({ action: 'secret.verification_attempted' }).items;
    expect(auditItems.length).toBeGreaterThan(0);
    expect(auditItems.some((e) => e.details.provider === 'github')).toBe(true);

    // Dump EVERY table and column, plus every emitted event and the findings response itself: none of
    // the planted raw values may appear anywhere in persisted state or wire output.
    const tableNames = (container.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>)
      .map((r) => r.name);
    const dumps: string[] = [];
    for (const name of tableNames) {
      const rows = container.db.prepare(`SELECT * FROM "${name}"`).all();
      dumps.push(JSON.stringify(rows));
    }
    dumps.push(JSON.stringify(container.bus.replay(scanId, 0)));
    dumps.push(JSON.stringify(findingsBody));

    const haystack = dumps.join('\n');
    for (const raw of PLANTED_RAW_VALUES) {
      expect(haystack.includes(raw)).toBe(false);
    }
  }, 60_000);
});
