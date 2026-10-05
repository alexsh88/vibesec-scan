import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4000),
  HOST: z.string().default('127.0.0.1'),
  DB_PATH: z.string().default('vibesec.db'),
  ANTHROPIC_API_KEY: z.string().optional(),
  SCAN_MODE: z.enum(['live', 'record', 'mock']).optional(),
  MAX_CONCURRENT_SCANS: z.coerce.number().int().positive().default(3),
  QUEUE_CAPACITY: z.coerce.number().int().positive().default(50),
  SCAN_DEADLINE_MS: z.coerce.number().int().positive().default(30 * 60_000),
  SCAN_BUDGET_USD: z.coerce.number().positive().default(5),
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
});

export type Config = {
  port: number; host: string; dbPath: string;
  anthropicApiKey: string | undefined; scanMode: 'live' | 'record' | 'mock';
  maxConcurrentScans: number; queueCapacity: number; scanDeadlineMs: number; scanBudgetUsd: number;
  heartbeatMs: number; staleHeartbeatMs: number; stuckAfterMs: number; corsOrigin: string; allowLocalRepos: boolean;
  githubToken: string | undefined; githubApiUrl: string; workDir: string;
  maxRepoBytes: number; maxFiles: number; maxFileBytes: number; cloneTimeoutMs: number; gitStallMs: number;
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
  return {
    port: e.PORT, host: e.HOST, dbPath: e.DB_PATH,
    anthropicApiKey: e.ANTHROPIC_API_KEY,
    scanMode: e.SCAN_MODE ?? (e.ANTHROPIC_API_KEY ? 'live' : 'mock'),
    maxConcurrentScans: e.MAX_CONCURRENT_SCANS, queueCapacity: e.QUEUE_CAPACITY,
    scanDeadlineMs: e.SCAN_DEADLINE_MS, scanBudgetUsd: e.SCAN_BUDGET_USD,
    heartbeatMs: e.HEARTBEAT_MS, staleHeartbeatMs: e.STALE_HEARTBEAT_MS, stuckAfterMs: e.STUCK_AFTER_MS,
    corsOrigin: e.CORS_ORIGIN, allowLocalRepos: e.ALLOW_LOCAL_REPOS === 'true',
    githubToken: e.GITHUB_TOKEN, githubApiUrl: e.GITHUB_API_URL,
    workDir: e.WORK_DIR ?? join(tmpdir(), 'vibesec'),
    maxRepoBytes: e.MAX_REPO_MB * 1024 * 1024, maxFiles: e.MAX_FILES, maxFileBytes: e.MAX_FILE_KB * 1024,
    cloneTimeoutMs: e.CLONE_TIMEOUT_MS, gitStallMs: e.GIT_STALL_MS,
  };
}
