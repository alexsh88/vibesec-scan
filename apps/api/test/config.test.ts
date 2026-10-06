import { isAbsolute, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';

// apps/api/test/config.test.ts -> apps/api/test -> apps/api -> apps -> <repo root>
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

describe('loadConfig', () => {
  it('defaults to mock mode without an API key', () => {
    const c = loadConfig({});
    expect(c.scanMode).toBe('mock');
    expect(c.port).toBe(4000);
    expect(c.maxConcurrentScans).toBe(3);
    expect(c.scanDeadlineMs).toBe(30 * 60_000);
    expect(c.stuckAfterMs).toBe(5 * 60_000);
  });

  it('defaults to live mode with an API key', () => {
    expect(loadConfig({ ANTHROPIC_API_KEY: 'sk-ant-x' }).scanMode).toBe('live');
  });

  it('respects explicit SCAN_MODE', () => {
    expect(loadConfig({ ANTHROPIC_API_KEY: 'k', SCAN_MODE: 'record' }).scanMode).toBe('record');
  });

  it('rejects invalid numbers', () => {
    expect(() => loadConfig({ PORT: 'abc' })).toThrow();
  });

  it('FIX_PLAN_MAX_REGISTRY_LOOKUPS defaults to 200, can be raised, and must be a positive integer', () => {
    expect(loadConfig({}).fixPlanMaxRegistryLookups).toBe(200);
    expect(loadConfig({ FIX_PLAN_MAX_REGISTRY_LOOKUPS: '1000' }).fixPlanMaxRegistryLookups).toBe(1000);
    expect(() => loadConfig({ FIX_PLAN_MAX_REGISTRY_LOOKUPS: '0' })).toThrow();
    expect(() => loadConfig({ FIX_PLAN_MAX_REGISTRY_LOOKUPS: '2.5' })).toThrow();
  });
});

describe('loadConfig timing invariants (#10)', () => {
  it('rejects HEARTBEAT_MS >= STALE_HEARTBEAT_MS', () => {
    expect(() => loadConfig({ HEARTBEAT_MS: '60000', STALE_HEARTBEAT_MS: '60000' })).toThrow(/HEARTBEAT_MS.*STALE_HEARTBEAT_MS/);
  });

  it('rejects STUCK_AFTER_MS <= HEARTBEAT_MS', () => {
    expect(() => loadConfig({ HEARTBEAT_MS: '10000', STUCK_AFTER_MS: '10000' })).toThrow(/STUCK_AFTER_MS.*HEARTBEAT_MS/);
  });

  it('accepts a consistent configuration', () => {
    expect(loadConfig({ HEARTBEAT_MS: '1000', STALE_HEARTBEAT_MS: '5000', STUCK_AFTER_MS: '2000' }).heartbeatMs).toBe(1000);
  });
});

describe('git & workspace config', () => {
  it('has safe defaults', () => {
    const c = loadConfig({});
    expect(c.githubToken).toBeUndefined();
    expect(c.githubApiUrl).toBe('https://api.github.com');
    expect(c.workDir).toMatch(/vibesec$/);
    expect(c.maxRepoBytes).toBe(500 * 1024 * 1024);
    expect(c.maxFiles).toBe(20_000);
    expect(c.maxFileBytes).toBe(1024 * 1024);
    expect(c.cloneTimeoutMs).toBe(120_000);
    expect(c.gitStallMs).toBe(30_000);
  });

  it('reads overrides', () => {
    const c = loadConfig({ GITHUB_TOKEN: 'ghp_x', WORK_DIR: '/tmp/w', MAX_REPO_MB: '10', MAX_FILES: '5', CLONE_TIMEOUT_MS: '5000', GIT_STALL_MS: '1000' });
    expect(c).toMatchObject({ githubToken: 'ghp_x', workDir: '/tmp/w', maxRepoBytes: 10 * 1024 * 1024, maxFiles: 5, cloneTimeoutMs: 5000, gitStallMs: 1000 });
  });

  it('rejects a stall window that is not shorter than the clone timeout', () => {
    expect(() => loadConfig({ CLONE_TIMEOUT_MS: '1000', GIT_STALL_MS: '1000' })).toThrow(/GIT_STALL_MS/);
  });
});

describe('LLM config', () => {
  it('has tiered model defaults and limits', () => {
    const c = loadConfig({});
    expect(c.models).toEqual({ fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' });
    // Long generations with adaptive thinking need a cap well above the SDK's own
    // non-streaming timeout sizing, not the old 120s (#I-2).
    expect(c).toMatchObject({ llmConcurrency: 8, llmRequestsPerMinute: 50, llmInputTokensPerMinute: 200_000, llmTimeoutMs: 600_000 });
    expect(c.llmRecordingsDir).toMatch(/llm-recordings$/);
  });

  it('allows overriding models', () => {
    expect(loadConfig({ LLM_MODEL_DEEP: 'claude-opus-5' }).models.deep).toBe('claude-opus-5');
  });

  it('requires an API key for live and record modes', () => {
    expect(() => loadConfig({ SCAN_MODE: 'live' })).toThrow(/ANTHROPIC_API_KEY/);
    expect(() => loadConfig({ SCAN_MODE: 'record' })).toThrow(/ANTHROPIC_API_KEY/);
    expect(loadConfig({ SCAN_MODE: 'mock' }).scanMode).toBe('mock');
  });
});

describe('LLM recordings dir (#M-6)', () => {
  it('defaults to an absolute, repo-root-anchored path regardless of cwd', () => {
    const c = loadConfig({});
    expect(isAbsolute(c.llmRecordingsDir)).toBe(true);
    expect(c.llmRecordingsDir).toBe(resolve(REPO_ROOT, 'fixtures', 'llm-recordings'));
  });

  it('resolves a relative override against the repo root, not the process cwd', () => {
    const c = loadConfig({ LLM_RECORDINGS_DIR: 'rec' });
    expect(c.llmRecordingsDir).toBe(resolve(REPO_ROOT, 'rec'));
  });

  it('uses an absolute override as-is', () => {
    const abs = resolve(REPO_ROOT, 'somewhere', 'else');
    expect(loadConfig({ LLM_RECORDINGS_DIR: abs }).llmRecordingsDir).toBe(abs);
  });
});
