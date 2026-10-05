import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema, type Finding } from '@vibesec/shared';
import { AuditLogger } from '../src/audit/AuditLogger';
import { EventRepo } from '../src/db/eventRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { EventBus } from '../src/events/EventBus';
import { GitService } from '../src/git/GitService';
import type { RepoMeta } from '../src/github/GitHubClient';
import { RepoIndexer } from '../src/index/RepoIndexer';
import { JobRunner } from '../src/jobs/JobRunner';
import { createScanPipeline } from '../src/pipeline/scanPipeline';
import type { LlmClient } from '../src/llm/LlmClient';
import type { PipelineContext } from '../src/pipeline/types';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { createFixtureRepo, type FixtureRepo } from './fixtures/gitRepo';
import { memoryDb } from './helpers';
import { pipelineDeps } from './pipelineDeps';

/** A structured-output LLM that answers every call with a minimal valid scan summary (no analyzers → nothing else asks). */
const summaryLlm = {
  structured: async () => ({
    output: { riskGrade: 'A', headline: 'No significant security findings', overview: 'Nothing to report.', topRisks: [], nextActions: [], positiveObservations: [] },
    model: 'claude-test', usage: { inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 }, costUsd: 0, callIds: ['c'],
    degraded: false, fellBackOnRefusal: false,
  }),
} as never as Pick<LlmClient, 'structured'>;

let repo: FixtureRepo;
let workDir: string;
let git: GitService;

beforeAll(async () => {
  repo = await createFixtureRepo([
    { files: { 'src/server.ts': "import { db } from './db';\napp.get('/x', h);\n", 'src/db.ts': 'export const db = 1;\n', 'only-first.txt': 'x' } },
    { files: { 'only-first.txt': null, 'src/new.ts': 'export {};\n' } },
  ]);
  workDir = await mkdtemp(join(tmpdir(), 'vibesec-pipe-'));
  git = new GitService({ workDir, cloneTimeoutMs: 60_000, stallMs: 20_000, allowFileProtocol: true, remoteUrlFor: () => repo.url });
  await git.init();
}, 60_000);

afterAll(async () => {
  await repo.cleanup();
  await rm(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

function setup(opts: { meta?: Partial<RepoMeta> | AppError; maxRepoBytes?: number } = {}) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const events = new EventRepo(db);
  const bus = new EventBus(events);
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);
  const indexRepo = new IndexRepo(db);
  const findings = new FindingRepo(db);
  const github = {
    getRepo: vi.fn(async (): Promise<RepoMeta> => {
      if (opts.meta instanceof AppError) throw opts.meta;
      return { isPrivate: false, defaultBranch: 'main', sizeBytes: 1_000, htmlUrl: '', archived: false, ...opts.meta };
    }),
  };
  const p7 = pipelineDeps({ db, scans, findings, audit, llm: summaryLlm });
  const pipeline = createScanPipeline({
    git, github, scans, indexRepo,
    indexer: new RepoIndexer(git, { maxFiles: 1_000, maxFileBytes: 1024 * 1024 }),
    maxRepoBytes: opts.maxRepoBytes ?? 1024 * 1024 * 1024, maxFiles: 1_000,
    analyzers: [], findings, ...p7,
    retryDeps: { sleep: async () => {} },
  });
  const runner = new JobRunner({
    scans, lifecycle, bus, audit, pipeline,
    config: { maxConcurrentScans: 2, scanDeadlineMs: 60_000, heartbeatMs: 1_000, stuckAfterMs: 60_000, staleHeartbeatMs: 30_000, queueCapacity: 10 },
  });
  const repoRecord = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const newScan = (ref: string | null = null) => scans.insertScan({
    repoId: repoRecord.id, ref, options: ScanOptionsSchema.parse({}), optionsHash: randomUUID(), idempotencyKey: null, hasAuth: false,
  }).id;
  const run = async (id: string) => { runner.enqueue(id, {}); await runner.whenIdle(); return scans.getDto(id)!; };
  return { scans, events, indexRepo, github, repoRecord, newScan, run, findings, pipeline, summaries: p7.summaries };
}

describe('scan pipeline (real git)', () => {
  it('resolves, clones, indexes, persists and cleans up', async () => {
    const { newScan, run, scans, indexRepo, events, repoRecord } = setup();
    const id = newScan();
    const dto = await run(id);
    expect(dto.state).toBe('COMPLETED');
    expect(dto.commitSha).toBe(repo.shas[1]);
    expect(scans.getRepo(repoRecord.id)?.defaultBranch).toBe('main');
    expect(indexRepo.files(id).map((f) => f.path)).toEqual(['src/db.ts', 'src/new.ts', 'src/server.ts']);
    expect(indexRepo.imports(id)).toContainEqual({ from: 'src/server.ts', specifier: './db', kind: 'local', to: 'src/db.ts', pkg: null, line: 1 });
    expect(indexRepo.entrypoints(id)).toContainEqual({ path: 'src/server.ts', kind: 'http-route', line: 2, detail: 'GET /x' });
    const analyzers = events.listAfter(id, 0).flatMap((e) => (e.event.type === 'progress' ? [e.event.analyzer] : []));
    expect(analyzers).toEqual(expect.arrayContaining(['resolve', 'clone', 'index']));
    expect(existsSync(git.scanDir(id))).toBe(false);
  }, 60_000);

  it('scans the requested ref', async () => {
    const { newScan, run, indexRepo } = setup();
    const id = newScan('feature/x');
    expect((await run(id)).commitSha).toBe(repo.shas[0]);
    expect(indexRepo.files(id).map((f) => f.path)).toContain('only-first.txt');
  }, 60_000);

  it('rejects oversized repositories before cloning', async () => {
    const { newScan, run } = setup({ meta: { sizeBytes: 10 * 1024 * 1024 }, maxRepoBytes: 1024 * 1024 });
    const id = newScan();
    expect(await run(id)).toMatchObject({ state: 'FAILED', errorCode: 'REPO_TOO_LARGE' });
  });

  it('fails on permanent GitHub errors such as AUTH_REQUIRED', async () => {
    const { newScan, run } = setup({ meta: new AppError('AUTH_REQUIRED', 'permanent', 'private') });
    expect(await run(newScan())).toMatchObject({ state: 'FAILED', errorCode: 'AUTH_REQUIRED' });
  });

  it('fails without cloning when the GitHub API is unavailable', async () => {
    const { newScan, run } = setup({ meta: new AppError('INTERNAL', 'transient', 'GitHub is temporarily unavailable') });
    const id = newScan();
    const dto = await run(id);
    expect(dto).toMatchObject({ state: 'FAILED', errorCode: 'INTERNAL', commitSha: null });
    expect(existsSync(git.scanDir(id))).toBe(false);
  }, 60_000);

  it('fails with GITHUB_RATE_LIMITED without cloning when the GitHub API is rate-limited', async () => {
    const { newScan, run } = setup({ meta: new AppError('GITHUB_RATE_LIMITED', 'transient', 'rate limited') });
    const id = newScan();
    expect(await run(id)).toMatchObject({ state: 'FAILED', errorCode: 'GITHUB_RATE_LIMITED' });
    expect(existsSync(git.scanDir(id))).toBe(false);
  }, 60_000);

  it('fails with REF_NOT_FOUND for an unknown ref', async () => {
    const { newScan, run } = setup();
    expect(await run(newScan('nope'))).toMatchObject({ state: 'FAILED', errorCode: 'REF_NOT_FOUND' });
  });

  it('resumes after ANALYZING: runs only VERIFYING → SCORING → SYNTHESIZING, and every one of them is idempotent', async () => {
    const { newScan, run, scans, events, findings, pipeline, summaries } = setup();
    const id = newScan();
    const f: Finding = {
      id: 'f-1', scanId: id, fingerprint: 'fp-1', category: 'secret', ruleId: 'secret/x', title: 'Hardcoded key',
      baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [], confidence: 'high',
      location: { file: 'src/db.ts', startLine: 1, endLine: 1, snippet: 'x', permalink: '' },
      explanation: 'e', impact: 'i', remediation: { summary: 'r' }, scanStatus: 'new',
    };
    findings.replaceForAnalyzer(id, 'credentials', [f]);
    findings.saveAnalyzerResult(id, 'credentials', [f]);
    scans.setCheckpoint(id, { completedStages: ['RESOLVING', 'CLONING', 'INDEXING', 'ANALYZING'], data: { commitSha: repo.shas[1] } });

    const dto = await run(id);
    expect(dto.state).toBe('COMPLETED');
    const states = events.listAfter(id, 0).flatMap((e) => (e.event.type === 'state' ? [e.event.state] : []));
    expect(states).toEqual(['VERIFYING', 'SCORING', 'SYNTHESIZING', 'COMPLETED']);
    const after = findings.all(id, { includeFixed: true });
    expect(after).toHaveLength(1);
    expect(after[0]!.finding.riskFactors.length + after[0]!.finding.riskScore).toBeGreaterThan(0);
    expect(summaries.get(id)?.riskGrade).toBe('A');

    // Re-running the post-analysis stages (as a crash + resume would) changes nothing.
    const ctx: PipelineContext = {
      scanId: id, scan: dto, secrets: {}, signal: new AbortController().signal, checkpointData: { commitSha: repo.shas[1] },
      emit: () => {}, warn: () => {}, touch: () => {},
    };
    for (const name of ['VERIFYING', 'SCORING', 'SYNTHESIZING'] as const) await pipeline.stages.find((s) => s.name === name)!.run(ctx);
    expect(findings.all(id, { includeFixed: true })).toEqual(after);
    expect(summaries.get(id)?.riskGrade).toBe('A');
  }, 60_000);

  it('re-clones when resuming after CLONING with the workspace gone', async () => {
    const { newScan, run, scans, indexRepo } = setup();
    const id = newScan();
    scans.setCheckpoint(id, { completedStages: ['RESOLVING', 'CLONING'], data: { commitSha: repo.shas[0] } });
    expect(existsSync(git.scanDir(id))).toBe(false);
    expect((await run(id)).state).toBe('COMPLETED');
    expect(indexRepo.files(id).map((f) => f.path)).toContain('only-first.txt');
  }, 60_000);
});

describe('createScanPipeline stages', () => {
  it('runs every real stage in order: RESOLVING → CLONING → INDEXING → ANALYZING → VERIFYING → SCORING → SYNTHESIZING', () => {
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const findings = new FindingRepo(db);
    const pipeline = createScanPipeline({
      git, github: { getRepo: vi.fn() }, scans, indexRepo: new IndexRepo(db),
      indexer: new RepoIndexer(git, { maxFiles: 1, maxFileBytes: 1 }), maxRepoBytes: 1, maxFiles: 1,
      analyzers: [], findings, ...pipelineDeps({ db, scans, findings, audit: new AuditLogger(db), llm: summaryLlm }),
    });
    expect(pipeline.stages.map((s) => s.name)).toEqual(['RESOLVING', 'CLONING', 'INDEXING', 'ANALYZING', 'VERIFYING', 'SCORING', 'SYNTHESIZING']);
    expect(pipeline.stages.map((s) => s.fatal)).toEqual([true, true, true, true, false, false, false]);
  });
});
