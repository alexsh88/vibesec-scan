import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import type { Entrypoint, ImportEdge } from '../src/index/types';
import { computeAffected } from '../src/pipeline/incremental';
import { analyzerVersionsHash, resultOptionsHash } from '../src/scans/cacheKeys';

const local = (from: string, to: string): ImportEdge => ({ from, specifier: `./${to}`, kind: 'local', to, pkg: null, line: 1 });
const ep = (path: string): Entrypoint => ({ path, kind: 'http-route', line: 1, detail: null });

describe('computeAffected', () => {
  // server → routes/a → services/x → db ;  routes/b → services/y ; cli → util
  const imports = [
    local('server.ts', 'routes/a.ts'), local('server.ts', 'routes/b.ts'), local('routes/a.ts', 'services/x.ts'),
    local('services/x.ts', 'db.ts'), local('routes/b.ts', 'services/y.ts'), local('cli.ts', 'util.ts'),
  ];
  const entrypoints = [ep('server.ts'), ep('routes/a.ts'), ep('routes/b.ts'), ep('cli.ts')];

  it('is C ∪ reverse imports (depth 2) ∪ entrypoints whose import closure reaches C', () => {
    const affected = computeAffected({ changed: new Set(['db.ts']), deleted: new Set(), imports, entrypoints });
    // depth 1: services/x, depth 2: routes/a; server.ts only via its forward closure (depth 3)
    expect([...affected].sort()).toEqual(['db.ts', 'routes/a.ts', 'server.ts', 'services/x.ts']);
  });

  it('leaves unrelated entrypoints out and counts deleted files as seeds (not as affected files)', () => {
    const affected = computeAffected({ changed: new Set(), deleted: new Set(['services/y.ts']), imports, entrypoints });
    expect([...affected].sort()).toEqual(['routes/b.ts', 'server.ts']);
  });
});

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
