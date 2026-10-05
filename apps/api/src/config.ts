import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

// apps/api/src/config.ts -> apps/api/src -> apps/api -> apps -> <repo root>. Anchoring on
// import.meta.url (not process.cwd()) keeps LLM_RECORDINGS_DIR stable no matter where the
// process is launched from (#M-6).
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * Loads `<repo root>/.env` (gitignored) into process.env for entry points (server, scripts).
 * Variables already set in the environment win. Not called by loadConfig, so tests stay hermetic.
 */
export function loadDotEnv(path = join(REPO_ROOT, '.env')): boolean {
  if (!existsSync(path)) return false;
  const before = { ...process.env };
  process.loadEnvFile(path);
  for (const [k, v] of Object.entries(before)) process.env[k] = v;
  return true;
}

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4000),
  HOST: z.string().default('127.0.0.1'),
  DB_PATH: z.string().default('vibesec.db'),
  ANTHROPIC_API_KEY: z.string().optional(),
  SCAN_MODE: z.enum(['live', 'record', 'mock']).optional(),
  MAX_CONCURRENT_SCANS: z.coerce.number().int().positive().default(3),
  QUEUE_CAPACITY: z.coerce.number().int().positive().default(50),
  SCAN_DEADLINE_MS: z.coerce.number().int().positive().default(30 * 60_000),
  SCAN_BUDGET_USD: z.coerce.number().positive().default(10),
  HEARTBEAT_MS: z.coerce.number().int().positive().default(10_000),
  STALE_HEARTBEAT_MS: z.coerce.number().int().positive().default(60_000),
  STUCK_AFTER_MS: z.coerce.number().int().positive().default(5 * 60_000),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  ALLOW_LOCAL_REPOS: z.enum(['true', 'false']).default('false'),
  GITHUB_TOKEN: z.string().min(1).optional(),
  GITHUB_API_URL: z.string().url().default('https://api.github.com'),
  WORK_DIR: z.string().optional(),
  MAX_REPO_MB: z.coerce.number().int().positive().default(500),
  MAX_FILES: z.coerce.number().int().positive().default(20_000),
  MAX_FILE_KB: z.coerce.number().int().positive().default(1024),
  CLONE_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
  GIT_STALL_MS: z.coerce.number().int().positive().default(30_000),
  LLM_MODEL_FAST: z.string().min(1).default('claude-haiku-4-5'),
  LLM_MODEL_DEEP: z.string().min(1).default('claude-sonnet-5'),
  LLM_MODEL_SYNTHESIS: z.string().min(1).default('claude-opus-5'),
  LLM_CONCURRENCY: z.coerce.number().int().positive().default(8),
  LLM_REQUESTS_PER_MINUTE: z.coerce.number().int().positive().default(50),
  LLM_INPUT_TOKENS_PER_MINUTE: z.coerce.number().int().positive().default(200_000),
  // Non-streaming has an SDK-enforced "streaming required" cliff around 10 min for large
  // max_tokens; this is the per-request total cap for the now-streamed send() (#I-2).
  LLM_TIMEOUT_MS: z.coerce.number().int().positive().default(600_000),
  LLM_RECORDINGS_DIR: z.string().default(join('fixtures', 'llm-recordings')),
  SANDBOX_ENABLED: z.enum(['true', 'false']).default('true'),
  SANDBOX_IMAGE_PREFIX: z.string().regex(/^[a-z0-9][a-z0-9._\/-]*$/).default('vibesec'),
  SANDBOX_INSTALL_TIMEOUT_MS: z.coerce.number().int().positive().default(180_000),
  SANDBOX_ANALYZE_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
  SANDBOX_MAX_DEPS_MB: z.coerce.number().int().positive().default(1536),
  /** Opt-in phase A (dependency install behind the egress proxy); phase B never needs it. */
  SANDBOX_INSTALL: z.enum(['true', 'false']).default('false'),
  /**
   * Full-scan cache lifetime. A cached result is served for the same commit + configuration only while it
   * is younger than this: dependency advisories (OSV) and credential liveness change without any commit,
   * so an old result must be recomputed rather than frozen forever.
   */
  FULL_CACHE_TTL_HOURS: z.coerce.number().positive().default(24),
});

export type Config = {
  port: number; host: string; dbPath: string;
  anthropicApiKey: string | undefined; scanMode: 'live' | 'record' | 'mock';
  maxConcurrentScans: number; queueCapacity: number; scanDeadlineMs: number; scanBudgetUsd: number;
  heartbeatMs: number; staleHeartbeatMs: number; stuckAfterMs: number; corsOrigin: string; allowLocalRepos: boolean;
  githubToken: string | undefined; githubApiUrl: string; workDir: string;
  maxRepoBytes: number; maxFiles: number; maxFileBytes: number; cloneTimeoutMs: number; gitStallMs: number;
  models: { fast: string; deep: string; synthesis: string };
  llmConcurrency: number; llmRequestsPerMinute: number; llmInputTokensPerMinute: number; llmTimeoutMs: number; llmRecordingsDir: string;
  /** Docker sandbox for dependency install (phase A) and offline usage analysis (phase B). */
  sandbox: { enabled: boolean; install: boolean; imagePrefix: string; installTimeoutMs: number; analyzeTimeoutMs: number; maxDepsBytes: number };
  /** FULL_CACHE_TTL_HOURS in ms: the full-scan cache only serves results younger than this. */
  fullCacheTtlMs: number;
};

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const e = EnvSchema.parse(env);
  if (e.HEARTBEAT_MS >= e.STALE_HEARTBEAT_MS) {
    throw new Error(
      `Invalid config: HEARTBEAT_MS (${e.HEARTBEAT_MS}) must be less than STALE_HEARTBEAT_MS (${e.STALE_HEARTBEAT_MS}), `
      + 'otherwise live scans look orphaned and get resumed by another process',
    );
  }
  if (e.STUCK_AFTER_MS <= e.HEARTBEAT_MS) {
    throw new Error(
      `Invalid config: STUCK_AFTER_MS (${e.STUCK_AFTER_MS}) must be greater than HEARTBEAT_MS (${e.HEARTBEAT_MS})`,
    );
  }
  if (e.GIT_STALL_MS >= e.CLONE_TIMEOUT_MS) {
    throw new Error(`Invalid config: GIT_STALL_MS (${e.GIT_STALL_MS}) must be less than CLONE_TIMEOUT_MS (${e.CLONE_TIMEOUT_MS})`);
  }
  const scanMode = e.SCAN_MODE ?? (e.ANTHROPIC_API_KEY ? 'live' : 'mock');
  if (scanMode !== 'mock' && !e.ANTHROPIC_API_KEY) {
    throw new Error(`Invalid config: SCAN_MODE=${scanMode} requires ANTHROPIC_API_KEY (use SCAN_MODE=mock to run without a key)`);
  }
  return {
    port: e.PORT, host: e.HOST, dbPath: e.DB_PATH,
    anthropicApiKey: e.ANTHROPIC_API_KEY,
    scanMode,
    maxConcurrentScans: e.MAX_CONCURRENT_SCANS, queueCapacity: e.QUEUE_CAPACITY,
    scanDeadlineMs: e.SCAN_DEADLINE_MS, scanBudgetUsd: e.SCAN_BUDGET_USD,
    heartbeatMs: e.HEARTBEAT_MS, staleHeartbeatMs: e.STALE_HEARTBEAT_MS, stuckAfterMs: e.STUCK_AFTER_MS,
    corsOrigin: e.CORS_ORIGIN, allowLocalRepos: e.ALLOW_LOCAL_REPOS === 'true',
    githubToken: e.GITHUB_TOKEN, githubApiUrl: e.GITHUB_API_URL,
    workDir: e.WORK_DIR ?? join(tmpdir(), 'vibesec'),
    maxRepoBytes: e.MAX_REPO_MB * 1024 * 1024, maxFiles: e.MAX_FILES, maxFileBytes: e.MAX_FILE_KB * 1024,
    cloneTimeoutMs: e.CLONE_TIMEOUT_MS, gitStallMs: e.GIT_STALL_MS,
    models: { fast: e.LLM_MODEL_FAST, deep: e.LLM_MODEL_DEEP, synthesis: e.LLM_MODEL_SYNTHESIS },
    llmConcurrency: e.LLM_CONCURRENCY, llmRequestsPerMinute: e.LLM_REQUESTS_PER_MINUTE,
    llmInputTokensPerMinute: e.LLM_INPUT_TOKENS_PER_MINUTE, llmTimeoutMs: e.LLM_TIMEOUT_MS,
    // Relative overrides (and the relative default) resolve against the repo root, not cwd;
    // an absolute override is used as-is (#M-6).
    llmRecordingsDir: isAbsolute(e.LLM_RECORDINGS_DIR) ? e.LLM_RECORDINGS_DIR : resolve(REPO_ROOT, e.LLM_RECORDINGS_DIR),
    sandbox: {
      enabled: e.SANDBOX_ENABLED === 'true', install: e.SANDBOX_INSTALL === 'true', imagePrefix: e.SANDBOX_IMAGE_PREFIX,
      installTimeoutMs: e.SANDBOX_INSTALL_TIMEOUT_MS, analyzeTimeoutMs: e.SANDBOX_ANALYZE_TIMEOUT_MS,
      maxDepsBytes: e.SANDBOX_MAX_DEPS_MB * 1024 * 1024,
    },
    fullCacheTtlMs: Math.round(e.FULL_CACHE_TTL_HOURS * 3_600_000),
  };
}
