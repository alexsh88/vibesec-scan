import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { analyzerVersionsHash, resultOptionsHash } from '../src/scans/cacheKeys';

describe('cache keys', () => {
  const cfg = { analyzers: [{ id: 'sast', version: '2' }, { id: 'taint', version: '2' }], promptVersions: ['sast-v2'], models: { fast: 'h', deep: 's' }, llmMode: 'mock' };

  it('analyzerVersionsHash changes with any analyzer version, prompt version, model or LLM mode', () => {
    const h = analyzerVersionsHash(cfg);
    expect(analyzerVersionsHash({ ...cfg, analyzers: [...cfg.analyzers].reverse() })).toBe(h);
    expect(analyzerVersionsHash({ ...cfg, analyzers: [{ id: 'sast', version: '3' }, { id: 'taint', version: '2' }] })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, promptVersions: ['sast-v3'] })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, models: { fast: 'h', deep: 's2' } })).not.toBe(h);
    expect(analyzerVersionsHash({ ...cfg, llmMode: 'live' })).not.toBe(h);
  });

  it('resultOptionsHash ignores category order but not the options themselves', () => {
    const a = ScanOptionsSchema.parse({ categories: ['secret', 'sast'] });
    expect(resultOptionsHash(a)).toBe(resultOptionsHash(ScanOptionsSchema.parse({ categories: ['sast', 'secret'] })));
    expect(resultOptionsHash(a)).not.toBe(resultOptionsHash({ ...a, budgetUsd: 2 }));
  });
});
