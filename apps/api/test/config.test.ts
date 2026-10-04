import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';

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
