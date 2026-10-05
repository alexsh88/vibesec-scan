import { AuditLogger } from './audit/AuditLogger';
import type { Config } from './config';
import { openDatabase, type Db } from './db/database';
import { EventRepo } from './db/eventRepo';
import { FindingRepo } from './db/findingRepo';
import { IndexRepo } from './db/indexRepo';
import { LlmCallRepo } from './db/llmCallRepo';
import { ScanRepo } from './db/scanRepo';
import { EventBus } from './events/EventBus';
import { GitService } from './git/GitService';
import { GitHubClient } from './github/GitHubClient';
import { RepoIndexer } from './index/RepoIndexer';
import { JobRunner } from './jobs/JobRunner';
import { BudgetTracker } from './llm/budget';
import { createTransport } from './llm/createTransport';
import { LlmClient } from './llm/LlmClient';
import { RateLimiter, Semaphore } from './llm/rateLimiter';
import { createScanPipeline } from './pipeline/scanPipeline';
import type { Pipeline } from './pipeline/types';
import { ScanLifecycle } from './scans/ScanLifecycle';
import { ScanService } from './scans/ScanService';

export type Container = {
  config: Config; db: Db; scans: ScanRepo; bus: EventBus; audit: AuditLogger;
  lifecycle: ScanLifecycle; runner: JobRunner; service: ScanService;
  git: GitService; github: GitHubClient; indexRepo: IndexRepo; gitVersion: string | null;
  llm: LlmClient; llmCalls: LlmCallRepo; budget: BudgetTracker; findings: FindingRepo;
};

/** Composition root: the only place that wires concrete implementations together. */
export function createContainer(config: Config, overrides: { pipeline?: Pipeline } = {}): Container {
  const db = openDatabase(config.dbPath);
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);

  const git = new GitService({
    workDir: config.workDir, cloneTimeoutMs: config.cloneTimeoutMs, stallMs: config.gitStallMs, allowFileProtocol: config.allowLocalRepos,
  });
  const github = new GitHubClient({ apiUrl: config.githubApiUrl, serverToken: config.githubToken });
  const indexRepo = new IndexRepo(db);
  const findings = new FindingRepo(db);
  const indexer = new RepoIndexer(git, { maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes });

  const llmCalls = new LlmCallRepo(db);
  const budget = new BudgetTracker(config.scanBudgetUsd, (scanId) => scans.getDto(scanId)?.costUsd ?? 0);
  const llm = new LlmClient({
    transport: createTransport(config),
    models: config.models,
    limiter: new RateLimiter({ requestsPerMinute: config.llmRequestsPerMinute, inputTokensPerMinute: config.llmInputTokensPerMinute }),
    semaphore: new Semaphore(config.llmConcurrency),
    budget, calls: llmCalls, scans,
    atomically: (fn) => db.transaction(fn)(),
    onUsage: (scanId, t) => lifecycle.emit(scanId, {
      type: 'cost', inputTokens: t.inputTokens, outputTokens: t.outputTokens, cacheReadTokens: t.cacheReadTokens, usd: t.costUsd,
    }),
  });

  const pipeline = overrides.pipeline ?? createScanPipeline({
    git, github, scans, indexRepo, indexer, maxRepoBytes: config.maxRepoBytes, maxFiles: config.maxFiles,
    onFinished: (scanId) => budget.forget(scanId),
  });

  const runner = new JobRunner({
    scans, lifecycle, bus, audit,
    pipeline,
    config,
  });
  const service = new ScanService({ db, scans, lifecycle, audit, queue: runner, queueCapacity: config.queueCapacity });
  return { config, db, scans, bus, audit, lifecycle, runner, service, git, github, indexRepo, gitVersion: null, llm, llmCalls, budget, findings };
}
