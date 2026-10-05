import { AuditLogger } from './audit/AuditLogger';
import { CONFIG_PROMPT_VERSION, configMockResponder, createConfigAnalyzer } from './analyzers/code/config/configAnalyzer';
import { createQualityAnalyzer, QUALITY_PROMPT_VERSION, qualityMockResponder } from './analyzers/code/quality/qualityAnalyzer';
import { createSastAnalyzer, sastMockResponder } from './analyzers/code/sast';
import { SAST_PROMPT_VERSION } from './analyzers/code/sastPrompt';
import { createTaintAnalyzer, TAINT_PROMPT_VERSION, taintMockResponder } from './analyzers/code/taint';
import { codeTriageMockResponder, TRIAGE_PROMPT_VERSION, TriageService } from './analyzers/code/triage';
import { createCredentialsAnalyzer } from './analyzers/credentials/credentialsAnalyzer';
import { createCredentialHunter, CREDENTIAL_HUNTER_PROMPT_VERSION, credentialHunterMockResponder } from './analyzers/credentials/hunter';
import { credentialsFpMockResponder, FP_FILTER_PROMPT_VERSION } from './analyzers/credentials/fpFilter';
import { SecretVerifier } from './analyzers/credentials/verifiers';
import { createDependenciesAnalyzer } from './analyzers/dependencies/dependenciesAnalyzer';
import { OsvClient } from './analyzers/dependencies/osv/osvClient';
import { dependencyReachabilityMockResponder, REACHABILITY_JUDGE_PROMPT_VERSION } from './analyzers/dependencies/reachabilityJudge';
import { skepticMockResponder } from './findings/skeptic';
import { SKEPTIC_PROMPT_VERSION } from './findings/skepticPrompt';
import { scanCacheKeys } from './scans/cacheKeys';
import { SYNTHESIS_PROMPT_VERSION, synthesisMockResponder } from './synthesis/synthesisPrompt';
import { RegistryClient } from './analyzers/dependencies/registry';
import { AdvisoryCacheRepo } from './db/advisoryCacheRepo';
import { CoverageRepo } from './db/coverageRepo';
import { SastCacheRepo } from './db/sastCacheRepo';
import { TriageCacheRepo } from './db/triageCacheRepo';
import { DockerSandbox } from './sandbox/dockerSandbox';
import type { Config } from './config';
import { openDatabase, type Db } from './db/database';
import { EventRepo } from './db/eventRepo';
import { FindingRepo } from './db/findingRepo';
import { FixPlanRepo } from './db/fixPlanRepo';
import { IndexRepo } from './db/indexRepo';
import { LlmCallRepo } from './db/llmCallRepo';
import { ScanRepo } from './db/scanRepo';
import { SummaryRepo } from './db/summaryRepo';
import { EventBus } from './events/EventBus';
import { GitService } from './git/GitService';
import { GitHubClient } from './github/GitHubClient';
import { RepoIndexer } from './index/RepoIndexer';
import { JobRunner } from './jobs/JobRunner';
import { BudgetTracker } from './llm/budget';
import { createBudgetLanes } from './llm/budgetLanes';
import { createTransport } from './llm/createTransport';
import { LlmClient } from './llm/LlmClient';
import type { MockResponder } from './llm/mockTransport';
import { RateLimiter, Semaphore } from './llm/rateLimiter';
import type { LlmTransport } from './llm/transport';
import { createScanPipeline } from './pipeline/scanPipeline';
import type { Pipeline } from './pipeline/types';
import { ScanLifecycle } from './scans/ScanLifecycle';
import { ScanService } from './scans/ScanService';
import { SuppressionRepo } from './suppressions/suppressionRepo';
import { SuppressionService } from './suppressions/suppressionService';

export type Container = {
  config: Config; db: Db; scans: ScanRepo; bus: EventBus; audit: AuditLogger;
  lifecycle: ScanLifecycle; runner: JobRunner; service: ScanService;
  git: GitService; github: GitHubClient; indexRepo: IndexRepo; gitVersion: string | null;
  llm: LlmClient; llmCalls: LlmCallRepo; budget: BudgetTracker; findings: FindingRepo; fixPlans: FixPlanRepo;
  summaries: SummaryRepo;
  suppressions: SuppressionService;
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
  /** In-process scans of a local repo (tests, eval script): where to clone from, and the GitHub repo metadata. */
  remoteUrlFor?: (owner: string, name: string) => string;
  github?: GitHubClient;
  /** Wraps the LLM transport (e.g. a fake cost model in tests). */
  wrapTransport?: (transport: LlmTransport) => LlmTransport;
};

/** Every deterministic mock-mode responder (each keys on its analyzer's task marker; ignored in live/record). */
export const MOCK_RESPONDERS: MockResponder[] = [
  credentialsFpMockResponder, dependencyReachabilityMockResponder, codeTriageMockResponder, sastMockResponder,
  taintMockResponder, qualityMockResponder, configMockResponder, credentialHunterMockResponder,
  skepticMockResponder, synthesisMockResponder,
];

/** Every prompt version that shapes a scan result: part of the cache keys (scans/cacheKeys.ts). */
export const PROMPT_VERSIONS: readonly string[] = [
  TRIAGE_PROMPT_VERSION, SAST_PROMPT_VERSION, TAINT_PROMPT_VERSION, QUALITY_PROMPT_VERSION, CONFIG_PROMPT_VERSION,
  CREDENTIAL_HUNTER_PROMPT_VERSION, FP_FILTER_PROMPT_VERSION, REACHABILITY_JUDGE_PROMPT_VERSION, SKEPTIC_PROMPT_VERSION,
  SYNTHESIS_PROMPT_VERSION,
];

/** Composition root: the only place that wires concrete implementations together. */
export function createContainer(config: Config, overrides: ContainerOverrides = {}): Container {
  const db = openDatabase(config.dbPath);
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);

  const git = new GitService({
    workDir: config.workDir, cloneTimeoutMs: config.cloneTimeoutMs, stallMs: config.gitStallMs, allowFileProtocol: config.allowLocalRepos,
    ...(overrides.remoteUrlFor ? { remoteUrlFor: overrides.remoteUrlFor } : {}),
  });
  const github = overrides.github ?? new GitHubClient({ apiUrl: config.githubApiUrl, serverToken: config.githubToken });
  const indexRepo = new IndexRepo(db);
  const findings = new FindingRepo(db);
  const fixPlans = new FixPlanRepo(db);
  const summaries = new SummaryRepo(db);
  const suppressions = new SuppressionService(new SuppressionRepo(db), findings, scans, audit);
  const indexer = new RepoIndexer(git, { maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes });

  const llmCalls = new LlmCallRepo(db);
  const budget = new BudgetTracker(
    config.scanBudgetUsd, (scanId) => scans.getDto(scanId)?.costUsd ?? 0, (scanId) => scans.getDto(scanId)?.options.budgetUsd,
  );
  const llm = new LlmClient({
    transport: (overrides.wrapTransport ?? ((t: LlmTransport) => t))(createTransport(config, MOCK_RESPONDERS)),
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
  // Claude code analyzers: one shared, per-scan-memoized Haiku triage feeds SAST, taint and the hunter.
  // Tier-1 analyzers hold budget leases so lower tiers (SAST fast pass, quality) only spend what they
  // don't need (llm/budget.ts). Analyzer categories gate them via scan.options.categories.
  const lanes = createBudgetLanes(budget, config.models);
  const triage = new TriageService({ llm, cache: new TriageCacheRepo(db), model: () => config.models.fast });
  const sastCache = new SastCacheRepo(db);
  const analyzers = [
    createCredentialsAnalyzer({ llm, git, verifier }),
    createDependenciesAnalyzer({ osv, registry, sandbox, indexRepo, llm, fixPlans, sandboxEnabled: sandbox !== null, sandboxInstall: config.sandbox.install }),
    createSastAnalyzer({ llm, triage, indexRepo, lanes, cache: { store: sastCache, model: (pass) => config.models[pass] } }),
    createTaintAnalyzer({ llm, triage, indexRepo, lanes }),
    createQualityAnalyzer({ llm }),
    createConfigAnalyzer({ llm, lanes }),
    createCredentialHunter({ llm, triage, lanes }),
  ];

  const resultConfig = {
    analyzers: analyzers.map((a) => ({ id: a.id, version: a.version })),
    promptVersions: PROMPT_VERSIONS, models: config.models, llmMode: config.scanMode,
    defaultBudgetUsd: config.scanBudgetUsd,
    environment: {
      maxFiles: config.maxFiles, maxFileBytes: config.maxFileBytes, maxRepoBytes: config.maxRepoBytes,
      sandboxEnabled: sandbox !== null, sandboxInstall: config.sandbox.install,
    },
  };
  const pipeline = overrides.pipeline ?? createScanPipeline({
    git, github, scans, indexRepo, indexer, maxRepoBytes: config.maxRepoBytes, maxFiles: config.maxFiles,
    analyzers, findings, coverage: new CoverageRepo(db), fixPlans, summaries, llmCalls, llm, suppressions,
    cacheKeys: (options) => scanCacheKeys(options, resultConfig),
    fullCacheTtlMs: config.fullCacheTtlMs,
    atomically: (fn) => lifecycle.atomically(fn),
    onFinished: (scanId) => {
      budget.forget(scanId);
      triage.forget(scanId);
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
  return { config, db, scans, bus, audit, lifecycle, runner, service, git, github, indexRepo, gitVersion: null, llm, llmCalls, budget, findings, fixPlans, summaries, suppressions, sandbox };
}
