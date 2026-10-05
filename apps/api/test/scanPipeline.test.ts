import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
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
import { createStubPipeline } from '../src/pipeline/stubPipeline';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { createFixtureRepo, type FixtureRepo } from './fixtures/gitRepo';
import { memoryDb } from './helpers';

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
  const github = {
    getRepo: vi.fn(async (): Promise<RepoMeta> => {
      if (opts.meta instanceof AppError) throw opts.meta;
      return { isPrivate: false, defaultBranch: 'main', sizeBytes: 1_000, htmlUrl: '', archived: false, ...opts.meta };
    }),
  };
  const pipeline = createScanPipeline({
    git, github, scans, indexRepo,
    indexer: new RepoIndexer(git, { maxFiles: 1_000, maxFileBytes: 1024 * 1024 }),
    maxRepoBytes: opts.maxRepoBytes ?? 1024 * 1024 * 1024, maxFiles: 1_000,
    stub: createStubPipeline(1), retryDeps: { sleep: async () => {} },
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
  return { scans, events, indexRepo, github, repoRecord, newScan, run };
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

  it('re-clones when resuming after CLONING with the workspace gone', async () => {
    const { newScan, run, scans, indexRepo } = setup();
    const id = newScan();
    scans.setCheckpoint(id, { completedStages: ['RESOLVING', 'CLONING'], data: { commitSha: repo.shas[0] } });
    expect(existsSync(git.scanDir(id))).toBe(false);
    expect((await run(id)).state).toBe('COMPLETED');
    expect(indexRepo.files(id).map((f) => f.path)).toContain('only-first.txt');
  }, 60_000);
});

describe('createScanPipeline ANALYZING stage selection', () => {
  function minimalDeps() {
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const indexRepo = new IndexRepo(db);
    const fakeGit = {
      remoteUrl: () => '', resolveRef: async () => '0'.repeat(40), ensureCheckout: async () => '0'.repeat(40),
      removeScanDir: async () => {}, repoDir: (id: string) => `/x/${id}`,
    };
    const fakeGithub = { getRepo: async () => ({ isPrivate: false, defaultBranch: 'main', sizeBytes: 0, htmlUrl: '', archived: false }) };
    const fakeIndexer = {
      index: async () => ({
        files: [], imports: [], entrypoints: [],
        stats: { totalFiles: 0, indexedFiles: 0, skipped: {}, byLanguage: {}, imports: 0, entrypoints: 0, truncated: false },
      }),
    };
    return { git: fakeGit, github: fakeGithub, scans, indexRepo, indexer: fakeIndexer, maxRepoBytes: 1, maxFiles: 1 };
  }

  it('uses the real analyzer stage when both analyzers and findings are given', () => {
    const deps = minimalDeps();
    const pipeline = createScanPipeline({ ...deps, analyzers: [], findings: new FindingRepo(memoryDb()) });
    const analyzing = pipeline.stages.find((s) => s.name === 'ANALYZING');
    expect(analyzing?.fatal).toBe(true);
  });

  it('keeps the stub ANALYZING stage when analyzers/findings are not given', () => {
    const deps = minimalDeps();
    const pipeline = createScanPipeline(deps);
    const analyzing = pipeline.stages.find((s) => s.name === 'ANALYZING');
    expect(analyzing?.fatal).toBe(false);
  });
});
