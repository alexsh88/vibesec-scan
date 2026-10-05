import { describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema, ScanSummarySchema, type Finding, type FixPlan, type ScanEvent } from '@vibesec/shared';
import { CoverageRepo } from '../src/db/coverageRepo';
import { FindingRepo } from '../src/db/findingRepo';
import { FixPlanRepo } from '../src/db/fixPlanRepo';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo, type ScanWarning } from '../src/db/scanRepo';
import { SummaryRepo } from '../src/db/summaryRepo';
import { AppError } from '../src/errors/AppError';
import { BudgetTracker } from '../src/llm/budget';
import { LlmClient, type StructuredCall } from '../src/llm/LlmClient';
import { MockTransport } from '../src/llm/mockTransport';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import { createSynthesizeStage } from '../src/pipeline/stages/synthesizeStage';
import type { PipelineContext } from '../src/pipeline/types';
import { fallbackSummary, synthesizeSummary, validateReferences } from '../src/synthesis/synthesize';
import {
  buildDigest, DIGEST_MAX_FINDINGS, gradeFor, SYNTHESIS_TASK_MARKER, synthesisMockResponder, type SynthesisInput, type SynthesisOutput,
} from '../src/synthesis/synthesisPrompt';
import { fake } from './fakeCredentials';
import { memoryDb } from './helpers';

let n = 0;
function finding(over: Partial<Finding> = {}): Finding {
  n++;
  return {
    id: `f${n}`, scanId: 's1', fingerprint: `fp${n}`, category: 'sast', ruleId: 'sast/sqli', cwe: 'CWE-89', title: 'SQL injection in user lookup',
    baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [{ factor: 'internet-exposed', effect: 10, reason: 'route handler' }],
    confidence: 'high',
    location: { file: 'src/users.ts', startLine: 3, endLine: 3, snippet: 'db.query("SELECT " + id)', permalink: 'https://x/p' },
    explanation: 'User input is concatenated into a SQL query.', impact: 'Database read.', remediation: { summary: 'Use bound parameters.' },
    scanStatus: 'new', ...over,
  };
}

const okOutput = (over: Partial<SynthesisOutput> = {}): SynthesisOutput => ({
  riskGrade: 'C', headline: 'One high issue', overview: 'One issue. Fix it.',
  topRisks: [], nextActions: [], positiveObservations: [], ...over,
});

function stubLlm(respond: (call: StructuredCall<unknown>) => unknown) {
  const calls: StructuredCall<unknown>[] = [];
  const llm = {
    structured: vi.fn(async (call: StructuredCall<unknown>) => {
      calls.push(call);
      const output = respond(call);
      return { output, model: 'claude-opus-5', usage: { inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 }, costUsd: 0, callIds: ['c'], degraded: false, fellBackOnRefusal: false };
    }),
  };
  return { llm: llm as never as Pick<LlmClient, 'structured'>, calls };
}

const failingLlm = (err: AppError) => ({ structured: vi.fn(async () => { throw err; }) }) as never as Pick<LlmClient, 'structured'>;

const signal = new AbortController().signal;

const fixPlan = (scanId: string, findingId: string): FixPlan => ({
  scanId,
  actions: [{
    id: 'fx_1', scanId, ecosystem: 'npm', manifestDir: '', lockfile: 'package-lock.json', kind: 'upgrade-direct', package: 'lodash',
    from: '4.17.20', to: '4.17.21', semverJump: 'patch', breakingRisk: false,
    resolves: [{ findingId, advisoryId: 'GHSA-1', severity: 'high', package: 'lodash', version: '4.17.20' }],
    resolvedCount: 1, riskReduced: 70, effort: 1, priority: 70, command: 'npm install lodash@4.17.21', notes: [],
  }],
  unfixable: [],
});

describe('synthesis digest (findings-only input)', () => {
  it('never sends snippets, code, patches, impact prose or credential values to the model', async () => {
    const MARK = 'ZZMARKERZZ';
    const findings = [
      finding({
        location: { file: 'src/a.ts', startLine: 1, endLine: 2, snippet: `const q = "${MARK}snippet"`, permalink: 'p' },
        taintTrace: [{ kind: 'source', file: 'src/a.ts', line: 1, code: `req.query.${MARK}trace`, note: 'n' }],
        remediation: { summary: 'Fix it.', patch: `- ${MARK}patch` }, impact: `${MARK}impact`,
        explanation: `Calls \`run(${MARK}inline)\` with key AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ0123 in it.`,
      }),
      finding({
        category: 'secret', ruleId: 'secret/aws', severity: 'critical', riskScore: 95,
        secret: { type: 'aws', redacted: `AKIA${MARK}redacted`, liveness: 'live', inHistoryOnly: false },
        location: { file: 'config.js', startLine: 4, endLine: 4, snippet: `key = "${MARK}value"`, permalink: 'p' },
      }),
      finding({ severity: 'info', title: `${MARK} info title`, riskScore: 1 }),
    ];
    const { llm, calls } = stubLlm(() => okOutput());
    await synthesizeSummary({ llm }, { scanId: 's1', findings }, { signal });
    const call = calls[0]!;
    expect(call.role).toBe('synthesis');
    expect(call.purpose).toBe('scan-summary');
    expect(call.system).toContain(SYNTHESIS_TASK_MARKER);
    expect(call.prompt).not.toContain(MARK);
    expect(call.prompt).not.toContain('AKIAABCDEF');
    expect(call.prompt).toContain('<untrusted_text source="findings-digest">');
    expect(call.prompt).toContain(findings[0]!.id);
    expect(call.prompt).not.toContain(`"id":"${findings[2]!.id}"`); // info is counted, not listed
    expect(call.prompt).toContain('Info-level findings excluded from the digest: 1');
    expect(call.prompt).toContain('"liveness":"live"');
  });

  it('scrubs ruleId and file too, and short (16–20 char) key ids anywhere in the digest', async () => {
    const key = fake.awsAccessKey(); // AKIA + 16
    const f = finding({
      ruleId: `sast/${key}`, title: `Key ${key} exposed`, explanation: 'Uses client id 9f8e7d6c5b4a3f2e1d0c in the call.',
      location: { file: `config/${key}/creds.ts`, startLine: 1, endLine: 1, snippet: 'x', permalink: 'p' },
    });
    const { llm, calls } = stubLlm(() => okOutput());
    await synthesizeSummary({ llm }, { scanId: 's1', findings: [f, finding({ ruleId: 'x'.repeat(500), location: { ...f.location, file: `${'d/'.repeat(300)}a.ts` } })] }, { signal });
    const prompt = String(calls[0]!.prompt);
    expect(prompt).not.toContain(key);
    expect(prompt).not.toContain('9f8e7d6c5b4a3f2e1d0c');
    expect(prompt).toContain('config/[redacted]/creds.ts');
    expect(prompt).not.toContain('x'.repeat(200)); // ruleId capped
    expect(prompt).not.toContain('d/'.repeat(200)); // file capped
  });

  it(`caps the digest at ${DIGEST_MAX_FINDINGS} findings by riskScore and summarizes the rest as counts`, () => {
    const findings = Array.from({ length: DIGEST_MAX_FINDINGS + 10 }, (_, i) => finding({ riskScore: i % 100, severity: 'medium' }));
    const d = buildDigest({ scanId: 's1', findings });
    expect(d.entries).toHaveLength(DIGEST_MAX_FINDINGS);
    expect(d.omitted).toMatchObject({ total: 10, bySeverity: { medium: 10 } });
    expect(d.entries[0]!.riskScore).toBe(99);
  });
});

describe('id validation', () => {
  it('drops unknown finding / fix-action ids, empty risks and unreferenced actions; recomputes risk severity', () => {
    const byId = new Map([['f1', { severity: 'critical' as const }], ['f2', { severity: 'low' as const }]]);
    const out = validateReferences(okOutput({
      topRisks: [
        { title: 'a', whyItMatters: 'w', findingIds: ['f1', 'ghost'], severity: 'low' },
        { title: 'b', whyItMatters: 'w', findingIds: ['ghost'], severity: 'high' },
      ],
      nextActions: [
        { title: 'x', detail: 'd', effort: 'minutes', fixActionId: 'fx_ghost', findingIds: [] },
        { title: 'y', detail: 'd', effort: 'minutes', fixActionId: 'fx_1', findingIds: ['ghost'] },
        { title: 'z', detail: 'd', effort: 'hours', fixActionId: 'fx_ghost', findingIds: ['f2'] },
      ],
    }), byId, new Set(['fx_1']));
    expect(out.topRisks).toEqual([{ title: 'a', whyItMatters: 'w', findingIds: ['f1'], severity: 'critical' }]);
    expect(out.nextActions).toEqual([
      { title: 'y', detail: 'd', effort: 'minutes', fixActionId: 'fx_1', findingIds: [] },
      { title: 'z', detail: 'd', effort: 'hours', findingIds: ['f2'] },
    ]);
  });

  it('only accepts ids that were in the digest, and adds stats + generatedBy llm', async () => {
    const f = finding();
    const { llm } = stubLlm(() => okOutput({
      topRisks: [{ title: 'SQLi', whyItMatters: 'w', findingIds: [f.id, 'f-invented'], severity: 'high' }],
      nextActions: [{ title: 'Fix', detail: 'd', effort: 'hours', findingIds: [f.id] }],
    }));
    const { summary, fallbackReason } = await synthesizeSummary({ llm }, { scanId: 's1', findings: [f] }, { signal });
    expect(fallbackReason).toBeUndefined();
    expect(summary.generatedBy).toBe('llm');
    expect(summary.model).toBe('claude-opus-5');
    expect(summary.topRisks[0]!.findingIds).toEqual([f.id]);
    expect(summary.stats).toMatchObject({ total: 1, bySeverity: { high: 1, critical: 0 }, byCategory: { sast: 1 } });
  });
});

describe('deterministic grade floor and triage', () => {
  it('never lets the model grade a scan better than the rubric applied to its findings', async () => {
    const live = finding({ category: 'secret', ruleId: 'secret/github-pat', severity: 'critical', secret: { type: 'github-pat', redacted: 'ghp_…', liveness: 'live', inHistoryOnly: false } });
    const { llm } = stubLlm(() => okOutput({ riskGrade: 'A' }));
    const { summary } = await synthesizeSummary({ llm }, { scanId: 's1', findings: [live] }, { signal });
    expect(summary.riskGrade).toBe('F');
  });

  it('keeps a model grade that is worse than the rubric', async () => {
    const { llm } = stubLlm(() => okOutput({ riskGrade: 'D' }));
    const { summary } = await synthesizeSummary({ llm }, { scanId: 's1', findings: [finding({ severity: 'medium' })] }, { signal });
    expect(summary.riskGrade).toBe('D');
  });

  it('leaves findings triaged false_positive out of the digest, stats and grade (accepted_risk / wont_fix still count)', async () => {
    const fp = finding({ severity: 'critical', triage: { status: 'false_positive', reason: 'test fixture', at: '2026-01-01T00:00:00.000Z' } });
    const expired = finding({ severity: 'high', confidence: 'medium', triage: { status: 'false_positive', reason: 'old', at: '2026-01-01T00:00:00.000Z', expiresAt: '2026-02-01T00:00:00.000Z' } });
    const accepted = finding({ severity: 'medium', triage: { status: 'accepted_risk', reason: 'known', at: '2026-01-01T00:00:00.000Z' } });
    const { llm, calls } = stubLlm(() => okOutput({ riskGrade: 'A' }));
    const { summary } = await synthesizeSummary({ llm }, { scanId: 's1', findings: [fp, expired, accepted], now: '2026-10-01T00:00:00.000Z' }, { signal });
    expect(String(calls[0]!.prompt)).not.toContain(`"id":"${fp.id}"`);
    expect(summary.stats.total).toBe(2);
    expect(summary.riskGrade).toBe('C'); // the expired-FP high counts again; the triaged critical does not
    expect(fallbackSummary({ scanId: 's1', findings: [fp], now: '2026-10-01T00:00:00.000Z' })).toMatchObject({ riskGrade: 'A', stats: { total: 0 } });
  });
});

describe('fallback', () => {
  it.each([
    new AppError('LLM_UNAVAILABLE', 'transient', 'down'),
    new AppError('BUDGET_EXHAUSTED', 'budget', 'no money'),
    new AppError('LLM_REFUSAL', 'permanent', 'declined'),
  ])('uses a deterministic summary on %s', async (err) => {
    const f = finding({ severity: 'critical', riskScore: 95 });
    const { summary, fallbackReason } = await synthesizeSummary({ llm: failingLlm(err) }, { scanId: 's1', findings: [f] }, { signal });
    expect(fallbackReason).toContain(err.code);
    expect(summary.generatedBy).toBe('fallback');
    expect(summary.riskGrade).toBe('F');
    expect(ScanSummarySchema.parse(summary)).toEqual(summary);
  });

  it('rethrows cancellation', async () => {
    const llm = failingLlm(new AppError('CANCELLED', 'cancelled', 'x'));
    await expect(synthesizeSummary({ llm }, { scanId: 's1', findings: [] }, { signal })).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('builds top risks per category, fix-plan actions first, and evidenced positives only', () => {
    const dep = finding({ category: 'dependency', ruleId: 'dep/ghsa', severity: 'high', riskScore: 80 });
    const sqli = finding({ severity: 'high', riskScore: 75 });
    const low = finding({ category: 'quality', severity: 'low', riskScore: 10 });
    const input: SynthesisInput = {
      scanId: 's1', findings: [dep, sqli, low], fixPlan: fixPlan('s1', dep.id),
      scannedCategories: ['secret', 'sast', 'dependency', 'quality'], coverage: { reviewed: 3 },
    };
    const s = fallbackSummary(input);
    expect(s.topRisks.map((r) => r.findingIds)).toEqual([[dep.id], [sqli.id], [low.id]]);
    expect(s.nextActions[0]).toMatchObject({ fixActionId: 'fx_1', findingIds: [dep.id], effort: 'minutes' });
    expect(s.nextActions.filter((a) => a.findingIds.includes(dep.id))).toHaveLength(1);
    expect(s.positiveObservations).toEqual(['No hard-coded credentials were found in the code or the scanned git history.']);
    expect(s.headline).toContain('2 high-priority issues');
  });

  it('handles a clean scan', () => {
    const s = fallbackSummary({ scanId: 's1', findings: [finding({ severity: 'info' })] });
    expect(s).toMatchObject({ riskGrade: 'A', topRisks: [], nextActions: [], headline: 'No significant security issues found' });
    expect(s.stats.bySeverity.info).toBe(1);
  });
});

describe('grade rubric', () => {
  const g = (over: Partial<Parameters<typeof gradeFor>[0][number]>) => ({ severity: 'low' as const, category: 'sast' as const, confidence: 'high' as const, ...over });
  it('grades by worst severity, with exploitability deciding F vs D', () => {
    expect(gradeFor([])).toBe('A');
    expect(gradeFor([g({ severity: 'low' })])).toBe('A');
    expect(gradeFor([g({ severity: 'medium' })])).toBe('B');
    expect(gradeFor([g({ severity: 'high', confidence: 'medium' })])).toBe('C');
    expect(gradeFor([g({ severity: 'high' })])).toBe('D');
    expect(gradeFor([g({ severity: 'critical', category: 'dependency', reachability: 'unreachable' })])).toBe('D');
    expect(gradeFor([g({ severity: 'critical', category: 'dependency', reachability: 'reachable' })])).toBe('F');
    expect(gradeFor([g({ severity: 'critical', category: 'secret', liveness: 'not_checked' })])).toBe('D');
    expect(gradeFor([g({ severity: 'critical', category: 'secret', liveness: 'live' })])).toBe('F');
  });
});

function realClient() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  const llm = new LlmClient({
    transport: new MockTransport({ responders: [synthesisMockResponder] }),
    models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
    limiter: new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 }), semaphore: new Semaphore(4),
    budget: new BudgetTracker(5, (id) => scans.getDto(id)?.costUsd ?? 0), calls: new LlmCallRepo(db), scans,
    retryDeps: { sleep: async () => {} }, atomically: (fn) => db.transaction(fn)(),
  });
  return { scanId, llm };
}

describe('synthesisMockResponder', () => {
  it('produces a valid summary citing only ids from the prompt', async () => {
    const { llm, scanId } = realClient();
    const findings = [finding({ scanId, severity: 'critical', riskScore: 90 }), finding({ scanId, category: 'dependency', riskScore: 60 })];
    const { summary, fallbackReason } = await synthesizeSummary({ llm }, { scanId, findings, fixPlan: fixPlan(scanId, findings[1]!.id) }, { signal });
    expect(fallbackReason).toBeUndefined();
    expect(summary.generatedBy).toBe('llm');
    expect(summary.riskGrade).toBe('F');
    const ids = new Set(findings.map((f) => f.id));
    expect(summary.topRisks.length).toBeGreaterThan(0);
    for (const r of summary.topRisks) for (const id of r.findingIds) expect(ids.has(id)).toBe(true);
    expect(summary.nextActions.some((a) => a.fixActionId === 'fx_1')).toBe(true);
  });

  it('ignores requests without the task marker', () => {
    expect(synthesisMockResponder({ system: [{ type: 'text', text: 'other' }], messages: [] } as never)).toBeUndefined();
  });
});

describe('SYNTHESIZING stage', () => {
  function setup(llm: Pick<LlmClient, 'structured'>) {
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
    const scanId = scans.insertScan({
      repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
    }).id;
    const findings = new FindingRepo(db);
    findings.replaceForAnalyzer(scanId, 'sast', [finding({ scanId })]);
    const summaries = new SummaryRepo(db);
    const warnings: ScanWarning[] = [];
    const events: ScanEvent[] = [];
    const ctx: PipelineContext = {
      scanId, scan: scans.getDto(scanId)!, secrets: {}, signal, checkpointData: {},
      emit: (e) => { events.push(e); }, warn: (w) => { warnings.push(w); }, touch: () => {},
    };
    const stage = createSynthesizeStage({ llm, findings, fixPlans: new FixPlanRepo(db), summaries, coverage: new CoverageRepo(db), scans });
    return { stage, ctx, summaries, warnings, events, scanId };
  }

  it('stores the LLM summary and emits a summary event', async () => {
    const { llm } = stubLlm(() => okOutput());
    const { stage, ctx, summaries, warnings, events, scanId } = setup(llm);
    expect(stage).toMatchObject({ name: 'SYNTHESIZING', fatal: false });
    await stage.run(ctx);
    expect(summaries.get(scanId)?.generatedBy).toBe('llm');
    expect(warnings).toEqual([]);
    // The model said C; a high-confidence high finding floors the grade at D (rubric).
    expect(events).toEqual([{ type: 'summary', riskGrade: 'D', headline: 'One high issue', generatedBy: 'llm' }]);
  });

  it('falls back with a SYNTHESIS_FALLBACK warning when the model is unavailable', async () => {
    const { stage, ctx, summaries, warnings, scanId } = setup(failingLlm(new AppError('LLM_UNAVAILABLE', 'transient', 'down')));
    await stage.run(ctx);
    expect(summaries.get(scanId)?.generatedBy).toBe('fallback');
    expect(warnings.map((w) => w.code)).toEqual(['SYNTHESIS_FALLBACK']);
  });
});
