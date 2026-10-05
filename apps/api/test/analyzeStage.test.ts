import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { Category, Finding, ScanEvent } from '@vibesec/shared';
import type { Analyzer } from '../src/analyzers/types';
import { CoverageRepo } from '../src/db/coverageRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { IndexRepo } from '../src/db/indexRepo';
import { ScanRepo, type ScanWarning } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { analyzeStage } from '../src/pipeline/stages/analyzeStage';
import type { PipelineContext } from '../src/pipeline/types';
import { memoryDb } from './helpers';

const fakeGit = { repoDir: (scanId: string) => `/fake/${scanId}/repo` };

let findingSeq = 0;
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  findingSeq += 1;
  return {
    id: `f-${findingSeq}`,
    scanId: 'scan-1',
    fingerprint: `fp-${findingSeq}`,
    category: 'secret',
    ruleId: 'rule.test',
    title: 'Test finding',
    baseSeverity: 'high',
    riskScore: 80,
    severity: 'high',
    riskFactors: [],
    confidence: 'high',
    location: { file: 'src/a.ts', startLine: 1, endLine: 1, snippet: 'const x = 1;', permalink: 'https://example.com' },
    explanation: 'because reasons that must never leak into the finding summary event',
    impact: 'bad things',
    remediation: { summary: 'fix it' },
    scanStatus: 'new',
    ...overrides,
  };
}

function makeAnalyzer(opts: { id: string; category: Category; run: Analyzer['run'] }): Analyzer {
  return { id: opts.id, version: '1', category: opts.category, run: opts.run };
}

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

function setup(categories: Category[] = ['secret']) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const findings = new FindingRepo(db);
  const indexRepo = new IndexRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null,
    options: { verifySecrets: false, historyDepth: 50, categories },
    optionsHash: randomUUID(), idempotencyKey: null, hasAuth: false,
  }).id;
  scans.setCommitSha(scanId, '0'.repeat(40));
  const scan = scans.getDto(scanId)!;
  const controller = new AbortController();
  const warnings: ScanWarning[] = [];
  const events: ScanEvent[] = [];
  const ctx: PipelineContext = {
    scanId,
    scan,
    secrets: {},
    signal: controller.signal,
    checkpointData: { commitSha: '0'.repeat(40) },
    emit: (event) => { events.push(event); },
    warn: (w) => { warnings.push(w); },
    touch: () => {},
  };
  return { ctx, findings, indexRepo, warnings, events, controller, scanId, db };
}

describe('analyzeStage', () => {
  it('runs only analyzers whose category is enabled, persists findings, and emits summary-only events', async () => {
    const { ctx, findings, indexRepo, events } = setup(['secret']);
    const secretFinding = makeFinding({ scanId: ctx.scanId, category: 'secret' });
    const secretsAnalyzer = makeAnalyzer({ id: 'credentials', category: 'secret', run: async () => [secretFinding] });
    const sastRan = vi.fn();
    const sastAnalyzer = makeAnalyzer({ id: 'sast', category: 'sast', run: async () => { sastRan(); return []; } });
    const stage = analyzeStage({ analyzers: [secretsAnalyzer, sastAnalyzer], findings, indexRepo, git: fakeGit });

    await stage.run(ctx);

    expect(sastRan).not.toHaveBeenCalled();
    expect(findings.list(ctx.scanId, {}).items.map((f) => f.id)).toEqual([secretFinding.id]);

    const findingEvents = events.filter((e): e is Extract<ScanEvent, { type: 'finding' }> => e.type === 'finding');
    expect(findingEvents).toHaveLength(1);
    const payload = findingEvents[0]!.finding;
    expect(Object.keys(payload).sort()).toEqual(['category', 'id', 'location', 'severity', 'title']);
    expect(payload).not.toHaveProperty('explanation');
    expect(payload).not.toHaveProperty('impact');
    expect(payload).not.toHaveProperty('remediation');
  });

  it('completes as a no-op, with no warnings or events, when no analyzer category is enabled', async () => {
    const { ctx, findings, indexRepo, warnings, events } = setup([]);
    const analyzer = makeAnalyzer({ id: 'credentials', category: 'secret', run: async () => { throw new Error('must not run'); } });
    const stage = analyzeStage({ analyzers: [analyzer], findings, indexRepo, git: fakeGit });

    await expect(stage.run(ctx)).resolves.toBeUndefined();

    expect(warnings).toHaveLength(0);
    expect(events).toHaveLength(0);
  });

  it('runs enabled analyzers concurrently (both start before either resolves)', async () => {
    const { ctx, findings, indexRepo } = setup(['secret', 'sast']);
    const startOrder: string[] = [];
    const defA = deferred<Finding[]>();
    const defB = deferred<Finding[]>();
    const a = makeAnalyzer({ id: 'a', category: 'secret', run: async () => { startOrder.push('a'); return defA.promise; } });
    const b = makeAnalyzer({ id: 'b', category: 'sast', run: async () => { startOrder.push('b'); return defB.promise; } });
    const stage = analyzeStage({ analyzers: [a, b], findings, indexRepo, git: fakeGit });

    const runPromise = stage.run(ctx);
    expect(startOrder).toEqual(['a', 'b']); // both started before either deferred settles

    defA.resolve([]);
    defB.resolve([]);
    await runPromise;
  });

  it('warns and persists the other analyzer when one analyzer throws, and the stage still succeeds', async () => {
    const { ctx, findings, indexRepo, warnings } = setup(['secret', 'sast']);
    const goodFinding = makeFinding({ scanId: ctx.scanId, category: 'sast' });
    const good = makeAnalyzer({ id: 'sast', category: 'sast', run: async () => [goodFinding] });
    const bad = makeAnalyzer({
      id: 'credentials', category: 'secret',
      run: async () => { throw new AppError('INTERNAL', 'permanent', 'The credentials analyzer failed safely'); },
    });
    const stage = analyzeStage({ analyzers: [bad, good], findings, indexRepo, git: fakeGit });

    await expect(stage.run(ctx)).resolves.toBeUndefined();

    expect(findings.list(ctx.scanId, {}).items.map((f) => f.id)).toEqual([goodFinding.id]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ code: 'ANALYZER_FAILED', stage: 'ANALYZING' });
    expect(warnings[0]!.message).toContain('credentials');
    expect(warnings[0]!.message).toContain('The credentials analyzer failed safely');
  });

  it('rejects with a fatal error when every enabled analyzer fails', async () => {
    const { ctx, findings, indexRepo, warnings } = setup(['secret', 'sast']);
    const a = makeAnalyzer({ id: 'a', category: 'secret', run: async () => { throw new Error('boom a'); } });
    const b = makeAnalyzer({ id: 'b', category: 'sast', run: async () => { throw new Error('boom b'); } });
    const stage = analyzeStage({ analyzers: [a, b], findings, indexRepo, git: fakeGit });

    await expect(stage.run(ctx)).rejects.toMatchObject({ code: 'ALL_ANALYZERS_FAILED', kind: 'permanent', userMessage: 'All analyzers failed' });
    expect(warnings).toHaveLength(2);
    expect(warnings.every((w) => w.code === 'ANALYZER_FAILED')).toBe(true);
  });

  it('treats an analyzer returning an invalid finding as a failure (warning), not a crash', async () => {
    const { ctx, findings, indexRepo, warnings } = setup(['secret', 'sast']);
    const invalidFinding = { id: 'bad-finding' } as unknown as Finding; // missing required fields
    const bad = makeAnalyzer({ id: 'credentials', category: 'secret', run: async () => [invalidFinding] });
    const goodFinding = makeFinding({ scanId: ctx.scanId, category: 'sast' });
    const good = makeAnalyzer({ id: 'sast', category: 'sast', run: async () => [goodFinding] });
    const stage = analyzeStage({ analyzers: [bad, good], findings, indexRepo, git: fakeGit });

    await expect(stage.run(ctx)).resolves.toBeUndefined();

    expect(findings.list(ctx.scanId, {}).items.map((f) => f.id)).toEqual([goodFinding.id]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ code: 'ANALYZER_FAILED' });
  });

  it('propagates cancellation as a rejection and never records a warning for it', async () => {
    const { ctx, findings, indexRepo, warnings, controller } = setup(['secret']);
    const cancellable = makeAnalyzer({
      id: 'credentials', category: 'secret',
      run: async (actx) => new Promise<Finding[]>((_, reject) => {
        actx.signal.addEventListener('abort', () => reject(new AppError('CANCELLED', 'cancelled', 'Scan aborted')), { once: true });
      }),
    });
    const stage = analyzeStage({ analyzers: [cancellable], findings, indexRepo, git: fakeGit });

    const runPromise = stage.run(ctx);
    controller.abort();

    await expect(runPromise).rejects.toMatchObject({ kind: 'cancelled' });
    expect(warnings).toHaveLength(0);
  });

  it('does not duplicate findings when the stage re-runs (idempotent resume)', async () => {
    const { ctx, findings, indexRepo } = setup(['secret']);
    const finding = makeFinding({ scanId: ctx.scanId, category: 'secret' });
    const analyzer = makeAnalyzer({ id: 'credentials', category: 'secret', run: async () => [finding] });
    const stage = analyzeStage({ analyzers: [analyzer], findings, indexRepo, git: fakeGit });

    await stage.run(ctx);
    await stage.run(ctx);

    expect(findings.list(ctx.scanId, {}).items).toHaveLength(1);
  });

  it('I5: dedupes by fingerprint before emitting finding events (safety net for an analyzer that returns duplicates)', async () => {
    const { ctx, findings, indexRepo, events } = setup(['secret']);
    const dupFingerprint = 'dup-fp';
    const f1 = makeFinding({
      scanId: ctx.scanId, category: 'secret', id: 'dup-1', fingerprint: dupFingerprint,
      location: { file: 'a.ts', startLine: 1, endLine: 1, snippet: 's', permalink: 'p' },
    });
    const f2 = makeFinding({
      scanId: ctx.scanId, category: 'secret', id: 'dup-2', fingerprint: dupFingerprint,
      location: { file: 'a.ts', startLine: 2, endLine: 2, snippet: 's', permalink: 'p' },
    });
    const analyzer = makeAnalyzer({ id: 'credentials', category: 'secret', run: async () => [f1, f2] });
    const stage = analyzeStage({ analyzers: [analyzer], findings, indexRepo, git: fakeGit });

    await stage.run(ctx);

    // DB also dedupes via ON CONFLICT (scan_id, fingerprint) DO NOTHING -> only the first row persists.
    expect(findings.list(ctx.scanId, {}).items).toHaveLength(1);
    const findingEvents = events.filter((e): e is Extract<ScanEvent, { type: 'finding' }> => e.type === 'finding');
    expect(findingEvents).toHaveLength(1);
    expect(findingEvents[0]!.finding.id).toBe('dup-1');
  });

  it('uses a generic message in the warning when the thrown error is not an AppError', async () => {
    const { ctx, findings, indexRepo, warnings } = setup(['secret', 'sast']);
    const leaky = makeAnalyzer({ id: 'credentials', category: 'secret', run: async () => { throw new Error('token=super-secret-value'); } });
    const good = makeAnalyzer({ id: 'sast', category: 'sast', run: async () => [] });
    const stage = analyzeStage({ analyzers: [leaky, good], findings, indexRepo, git: fakeGit });

    await expect(stage.run(ctx)).resolves.toBeUndefined();

    expect(warnings).toHaveLength(1);
    expect(warnings[0]!.message).not.toContain('token=super-secret-value');
    expect(warnings[0]!.message).toContain('credentials');
  });
});

describe('analyzeStage progress', () => {
  it('emits a structured progress event per reportProgress call, throttled to <=4/s but always including the final done===total', async () => {
    const { ctx, findings, indexRepo, events } = setup(['sast']);
    vi.useFakeTimers();
    try {
      const analyzer = makeAnalyzer({
        id: 'sast', category: 'sast',
        run: async (actx) => {
          for (let i = 1; i <= 10; i++) {
            actx.reportProgress?.(i, 10);
            vi.advanceTimersByTime(10); // well under the 250ms throttle window
          }
          return [];
        },
      });
      await analyzeStage({ analyzers: [analyzer], findings, indexRepo, git: fakeGit }).run(ctx);
    } finally {
      vi.useRealTimers();
    }

    const progress = events.filter((e): e is Extract<ScanEvent, { type: 'progress' }> => e.type === 'progress' && e.analyzer === 'sast');
    // Throttled: far fewer than the 10 calls made (only the first, and the forced final, got through).
    expect(progress.length).toBeLessThan(10);
    expect(progress[0]).toMatchObject({ done: 1, total: 10 });
    expect(progress[progress.length - 1]).toMatchObject({ done: 10, total: 10 });
    for (let i = 1; i < progress.length; i++) {
      expect(progress[i]!.done).toBeGreaterThanOrEqual(progress[i - 1]!.done);
      expect(progress[i]!.done).toBeLessThanOrEqual(progress[i]!.total);
    }
  });

  it('always emits the final done===total call even when it arrives within the throttle window', async () => {
    const { ctx, findings, indexRepo, events } = setup(['sast']);
    const analyzer = makeAnalyzer({
      id: 'sast', category: 'sast',
      run: async (actx) => {
        actx.reportProgress?.(1, 3);
        actx.reportProgress?.(2, 3); // same tick: throttled away
        actx.reportProgress?.(3, 3); // final: forced through regardless
        return [];
      },
    });
    await analyzeStage({ analyzers: [analyzer], findings, indexRepo, git: fakeGit }).run(ctx);

    const progress = events.filter((e): e is Extract<ScanEvent, { type: 'progress' }> => e.type === 'progress');
    expect(progress).toEqual([
      { type: 'progress', analyzer: 'sast', done: 1, total: 3 },
      { type: 'progress', analyzer: 'sast', done: 3, total: 3 },
    ]);
  });

  it('lets an analyzer report under a different label (the shared triage pass always reports as "triage")', async () => {
    const { ctx, findings, indexRepo, events } = setup(['sast']);
    const analyzer = makeAnalyzer({
      id: 'sast', category: 'sast',
      run: async (actx) => {
        actx.reportProgress?.(1, 2, 'triage');
        actx.reportProgress?.(2, 2, 'triage');
        actx.reportProgress?.(1, 1); // defaults to this analyzer's own id
        return [];
      },
    });
    await analyzeStage({ analyzers: [analyzer], findings, indexRepo, git: fakeGit }).run(ctx);

    const progress = events.filter((e): e is Extract<ScanEvent, { type: 'progress' }> => e.type === 'progress');
    expect(progress).toEqual([
      { type: 'progress', analyzer: 'triage', done: 1, total: 2 },
      { type: 'progress', analyzer: 'triage', done: 2, total: 2 },
      { type: 'progress', analyzer: 'sast', done: 1, total: 1 },
    ]);
  });

  it('keeps each analyzer\'s progress independent (one analyzer finishing fast never throttles another)', async () => {
    const { ctx, findings, indexRepo, events } = setup(['secret', 'sast']);
    const a = makeAnalyzer({ id: 'credentials', category: 'secret', run: async (actx) => { actx.reportProgress?.(1, 1); return []; } });
    const b = makeAnalyzer({ id: 'sast', category: 'sast', run: async (actx) => { actx.reportProgress?.(1, 1); return []; } });
    await analyzeStage({ analyzers: [a, b], findings, indexRepo, git: fakeGit }).run(ctx);

    const progress = events.filter((e): e is Extract<ScanEvent, { type: 'progress' }> => e.type === 'progress');
    expect(progress.map((p) => p.analyzer).sort()).toEqual(['credentials', 'sast']);
  });
});

describe('analyzeStage coverage', () => {
  it('collects per-file coverage from every analyzer, persists it and warns BUDGET_COVERAGE_PARTIAL with counts', async () => {
    const { ctx, findings, indexRepo, warnings, scanId, db } = setup(['sast', 'quality']);
    const coverage = new CoverageRepo(db);
    const sast = makeAnalyzer({
      id: 'sast', category: 'sast',
      run: async (actx) => {
        actx.recordCoverage?.('triage', 'a.ts', 'reviewed');
        actx.recordCoverage?.('sast', 'a.ts', 'reviewed');
        actx.recordCoverage?.('sast', 'b.ts', 'budget-skipped');
        return [];
      },
    });
    const quality = makeAnalyzer({
      id: 'quality', category: 'quality',
      run: async (actx) => {
        actx.recordCoverage?.('quality', 'a.ts', 'failed');
        actx.recordCoverage?.('quality', 'a.ts', 'budget-skipped'); // last write wins
        actx.recordCoverage?.('quality', 'b.ts', 'budget-skipped');
        return [];
      },
    });
    await analyzeStage({ analyzers: [sast, quality], findings, indexRepo, git: fakeGit, coverage }).run(ctx);

    const summary = coverage.summary(scanId);
    expect(summary.totals).toMatchObject({ reviewed: 2, 'budget-skipped': 3, failed: 0 });
    expect(summary.byAnalyzer.sast).toMatchObject({ reviewed: 1, 'budget-skipped': 1 });
    expect(summary.budgetSkipped).toEqual([
      { analyzer: 'quality', path: 'a.ts' }, { analyzer: 'quality', path: 'b.ts' }, { analyzer: 'sast', path: 'b.ts' },
    ]);
    expect(warnings).toEqual([expect.objectContaining({ code: 'BUDGET_COVERAGE_PARTIAL', stage: 'ANALYZING' })]);
    expect(warnings[0]!.message).toContain('3 file review(s) were skipped (quality: 2, sast: 1)');
    expect(warnings[0]!.message).toContain('budgetUsd');
  });

  it('does not warn when nothing was budget-skipped, and replaces a previous run', async () => {
    const { ctx, findings, indexRepo, warnings, scanId, db } = setup(['sast']);
    const coverage = new CoverageRepo(db);
    coverage.replaceForScan(scanId, [{ analyzer: 'sast', path: 'old.ts', status: 'budget-skipped' }]);
    const sast = makeAnalyzer({ id: 'sast', category: 'sast', run: async (actx) => { actx.recordCoverage?.('sast', 'a.ts', 'cached'); return []; } });
    await analyzeStage({ analyzers: [sast], findings, indexRepo, git: fakeGit, coverage }).run(ctx);
    expect(warnings).toEqual([]);
    expect(coverage.list(scanId)).toEqual([{ analyzer: 'sast', path: 'a.ts', status: 'cached' }]);
  });

  it('persists coverage incrementally as each analyzer finishes, not only once the whole stage ends', async () => {
    const { ctx, findings, indexRepo, scanId, db } = setup(['secret', 'sast']);
    const coverage = new CoverageRepo(db);
    const defSlow = deferred<Finding[]>();
    const fast = makeAnalyzer({
      id: 'credentials', category: 'secret',
      run: async (actx) => { actx.recordCoverage?.('credentials', 'a.ts', 'reviewed'); return []; },
    });
    const slow = makeAnalyzer({
      id: 'sast', category: 'sast',
      run: async (actx) => {
        await defSlow.promise; // still running (and hasn't recorded anything yet) when `fast` settles
        actx.recordCoverage?.('sast', 'b.ts', 'reviewed');
        return [];
      },
    });
    const runPromise = analyzeStage({ analyzers: [fast, slow], findings, indexRepo, git: fakeGit, coverage }).run(ctx);

    // `fast` settles on its own microtask queue turn; give it a chance to flush before `slow` resolves.
    await Promise.resolve();
    await Promise.resolve();
    expect(coverage.list(scanId)).toEqual([{ analyzer: 'credentials', path: 'a.ts', status: 'reviewed' }]);

    defSlow.resolve([]);
    await runPromise;
    expect(coverage.list(scanId)).toEqual([
      { analyzer: 'credentials', path: 'a.ts', status: 'reviewed' },
      { analyzer: 'sast', path: 'b.ts', status: 'reviewed' },
    ]);
  });
});

describe('analyzeStage coverage of a failed analyzer', () => {
  it('never persists coverage for an analyzer whose results were not persisted (a later rescan must not trust it)', async () => {
    const { ctx, findings, indexRepo, scanId, db } = setup(['sast', 'quality']);
    const coverage = new CoverageRepo(db);
    const sast = makeAnalyzer({ id: 'sast', category: 'sast', run: async (actx) => { actx.recordCoverage?.('sast', 'a.ts', 'reviewed'); return []; } });
    const crashed = makeAnalyzer({
      id: 'quality', category: 'quality',
      run: async (actx) => { actx.recordCoverage?.('quality', 'a.ts', 'reviewed'); throw new Error('boom after reviewing'); },
    });
    const unpersistable = makeAnalyzer({
      id: 'config', category: 'quality',
      run: async (actx) => { actx.recordCoverage?.('config', 'a.ts', 'reviewed'); return [{ bogus: true } as unknown as Finding]; },
    });
    await analyzeStage({ analyzers: [sast, crashed, unpersistable], findings, indexRepo, git: fakeGit, coverage }).run(ctx);
    expect(coverage.list(scanId)).toEqual([{ analyzer: 'sast', path: 'a.ts', status: 'reviewed' }]);
  });
});
