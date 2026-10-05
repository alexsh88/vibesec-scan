import { AuditLogger } from './audit/AuditLogger';
import { createCredentialsAnalyzer } from './analyzers/credentials/credentialsAnalyzer';
import { credentialsFpMockResponder } from './analyzers/credentials/fpFilter';
import { SecretVerifier } from './analyzers/credentials/verifiers';
import { createDependenciesAnalyzer } from './analyzers/dependencies/dependenciesAnalyzer';
import { OsvClient } from './analyzers/dependencies/osv/osvClient';
import { dependencyReachabilityMockResponder } from './analyzers/dependencies/reachabilityJudge';
import { RegistryClient } from './analyzers/dependencies/registry';
import { AdvisoryCacheRepo } from './db/advisoryCacheRepo';
import { DockerSandbox } from './sandbox/dockerSandbox';
import type { Config } from './config';
import { openDatabase, type Db } from './db/database';
import { EventRepo } from './db/eventRepo';
import { FindingRepo } from './db/findingRepo';
import { FixPlanRepo } from './db/fixPlanRepo';
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
  llm: LlmClient; llmCalls: LlmCallRepo; budget: BudgetTracker; findings: FindingRepo; fixPlans: FixPlanRepo;
  /** Docker sandbox for dependency install/usage analysis; null/absent when disabled. */
  sandbox?: ContainerSandbox | null;
};

export type ContainerSandbox = Pick<DockerSandbox, 'availability' | 'install' | 'analyze' | 'sweep'>;

export type ContainerOverrides = {
  pipeline?: Pipeline;
  /** Replaces global fetch for every outbound HTTP client (credential verifier, OSV, npm/PyPI registry). */
  fetch?: typeof fetch;
  /** Replaces the Docker sandbox; null disables it regardless of config.sandbox.enabled. */
  sandbox?: ContainerSandbox | null;
};

/** Composition root: the only place that wires concrete implementations together. */
export function createContainer(config: Config, overrides: ContainerOverrides = {}): Container {
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
  const fixPlans = new FixPlanRepo(db);
  const indexer = new RepoIndexer(git, { maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes });

  const llmCalls = new LlmCallRepo(db);
  const budget = new BudgetTracker(config.scanBudgetUsd, (scanId) => scans.getDto(scanId)?.costUsd ?? 0);
  const llm = new LlmClient({
    transport: createTransport(config, [credentialsFpMockResponder, dependencyReachabilityMockResponder]),
    models: config.models,
    limiter: new RateLimiter({ requestsPerMinute: config.llmRequestsPerMinute, inputTokensPerMinute: config.llmInputTokensPerMinute }),
    semaphore: new Semaphore(config.llmConcurrency),
    budget, calls: llmCalls, scans,
    atomically: (fn) => db.transaction(fn)(),
    onUsage: (scanId, t) => lifecycle.emit(scanId, {
      type: 'cost', inputTokens: t.inputTokens, outputTokens: t.outputTokens, cacheReadTokens: t.cacheReadTokens, usd: t.costUsd,
    }),
  });

  const verifier = new SecretVerifier({ audit, ...(overrides.fetch ? { fetch: overrides.fetch } : {}) });
  const fetchOverride = overrides.fetch ? { fetch: overrides.fetch } : {};
  const osv = new OsvClient({ cache: new AdvisoryCacheRepo(db), ...fetchOverride });
  const registry = new RegistryClient(fetchOverride);
  const sandbox: ContainerSandbox | null = overrides.sandbox !== undefined
    ? overrides.sandbox
    : config.sandbox.enabled
      ? new DockerSandbox({
        workDir: config.workDir, imagePrefix: config.sandbox.imagePrefix, installTimeoutMs: config.sandbox.installTimeoutMs,
        analyzeTimeoutMs: config.sandbox.analyzeTimeoutMs, maxDepsBytes: config.sandbox.maxDepsBytes,
      })
      : null;
  const analyzers = [
    createCredentialsAnalyzer({ llm, git, verifier }),
    createDependenciesAnalyzer({ osv, registry, sandbox, indexRepo, llm, fixPlans, sandboxEnabled: sandbox !== null }),
  ];

  const pipeline = overrides.pipeline ?? createScanPipeline({
    git, github, scans, indexRepo, indexer, maxRepoBytes: config.maxRepoBytes, maxFiles: config.maxFiles,
    analyzers, findings,
    onFinished: (scanId) => {
      budget.forget(scanId);
      verifier.forget(scanId);
      // Best-effort: the analyzer already sweeps in its own finally; this covers cancelled/crashed scans.
      if (sandbox) void sandbox.sweep(scanId).catch(() => undefined);
    },
  });

  const runner = new JobRunner({
    scans, lifecycle, bus, audit,
    pipeline,
    config,
  });
  const service = new ScanService({ db, scans, lifecycle, audit, queue: runner, queueCapacity: config.queueCapacity });
  return { config, db, scans, bus, audit, lifecycle, runner, service, git, github, indexRepo, gitVersion: null, llm, llmCalls, budget, findings, fixPlans, sandbox };
}
