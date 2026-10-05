import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { Category, Finding, ScanEvent } from '@vibesec/shared';
import type { Analyzer } from '../src/analyzers/types';
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
  return { ctx, findings, indexRepo, warnings, events, controller, scanId };
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

    await expect(stage.run(ctx)).rejects.toMatchObject({ kind: 'permanent', userMessage: 'All analyzers failed' });
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
