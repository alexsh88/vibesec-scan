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
