import { describe, expect, it } from 'vitest';
import { FindingSchema } from '@vibesec/shared';
import { AppError } from '../src/errors/AppError';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import { buildRequestParts } from '../src/llm/prompt';
import type { LlmRequest } from '../src/llm/transport';
import { applyVerdict, partialSummary, planBatches, runSkeptic, skepticMockResponder, SKEPTIC_TASK_MARKER } from '../src/findings/skeptic';
import type { SkepticOutput } from '../src/findings/skepticPrompt';
import { mkFinding } from './findingFactory';

const ZERO = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

function ok<T>(output: T, degraded = false): StructuredResult<T> {
  return { output, model: 'mock', usage: ZERO, costUsd: 0, callIds: [], degraded, fellBackOnRefusal: false };
}

function stubLlm(impl: (call: StructuredCall<SkepticOutput>, n: number) => Promise<StructuredResult<SkepticOutput>>) {
  const calls: StructuredCall<SkepticOutput>[] = [];
  const llm = {
    structured: (async (call: StructuredCall<SkepticOutput>) => {
      calls.push(call);
      return impl(call, calls.length);
    }) as unknown as LlmClient['structured'],
  };
  return { llm, calls };
}

function responderLlm() {
  const calls: StructuredCall<SkepticOutput>[] = [];
  const llm = {
    async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
      calls.push(call as unknown as StructuredCall<SkepticOutput>);
      const parts = buildRequestParts(call);
      const req: LlmRequest = { model: 'mock', system: parts.system, messages: parts.messages, maxTokens: 100, thinking: false, schema: call.schema };
      return ok(call.schema.parse(skepticMockResponder(req)));
    },
  };
  return { llm, calls };
}

const fileOf = (lines: number) => Array.from({ length: lines }, (_, i) => `line ${i + 1}`).join('\n');
const files = (map: Record<string, string>) => async (p: string) => map[p] ?? null;
const ctx = (signal = new AbortController().signal) => ({ scanId: 'scan-1', signal, touch: () => {} });
const allVerdicts = (n: number, verdict: 'upheld' | 'weakened' | 'refuted' = 'upheld'): SkepticOutput => ({
  verdicts: Array.from({ length: n }, (_, i) => ({ findingIndex: i, verdict, reason: `r${i}` })),
});

describe('applyVerdict', () => {
  const base = mkFinding({ severity: 'high', confidence: 'high' });

  it('upheld: unchanged except producedBy marker', () => {
    const f = applyVerdict(base, { findingIndex: 0, verdict: 'upheld', reason: 'real' });
    expect(f).toEqual({ ...base, producedBy: ['sast:llm', 'skeptic:upheld'] });
  });

  it('weakened: one confidence step lower + skeptic_weakened (effect 0)', () => {
    const f = applyVerdict(base, { findingIndex: 0, verdict: 'weakened', reason: 'unclear source', evidenceLines: [4] });
    expect(f.severity).toBe('high');
    expect(f.confidence).toBe('medium');
    expect(f.riskFactors).toEqual([{ factor: 'skeptic_weakened', effect: 0, reason: 'unclear source (evidence: line 4)' }]);
    expect(f.producedBy).toContain('skeptic:weakened');
    expect(applyVerdict({ ...base, confidence: 'low' }, { findingIndex: 0, verdict: 'weakened', reason: 'x' }).confidence).toBe('low');
  });

  it('refuted: stays visible at info/low with ai_refuted (negative steps) and an explanation sentence', () => {
    const f = applyVerdict(mkFinding({ severity: 'critical' }), { findingIndex: 0, verdict: 'refuted', reason: 'parameterized' });
    expect(f.severity).toBe('info');
    expect(f.confidence).toBe('low');
    expect(f.riskFactors).toEqual([{ factor: 'ai_refuted', effect: -4, reason: 'parameterized' }]);
    expect(f.explanation).toMatch(/AI skeptic review judged this a likely false positive: parameterized$/);
    expect(f.producedBy).toContain('skeptic:refuted');
    expect(applyVerdict(base, { findingIndex: 0, verdict: 'refuted', reason: 'x' }).riskFactors[0]!.effect).toBe(-3);
    expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('a degraded reply cannot refute (applied as weakened)', () => {
    const f = applyVerdict(base, { findingIndex: 0, verdict: 'refuted', reason: 'x' }, true);
    expect(f.severity).toBe('high');
    expect(f.riskFactors[0]!.factor).toBe('skeptic_weakened');
  });
});

describe('planBatches', () => {
  it('batches up to 4 findings per file in risk order', () => {
    const a = Array.from({ length: 5 }, (_, i) => mkFinding({ file: 'a.ts', line: i + 1 }));
    const b = [mkFinding({ file: 'b.ts', severity: 'critical' })];
    const batches = planBatches([...a, ...b]);
    expect(batches.map((x) => x.length)).toEqual([1, 4, 1]);
    expect(batches[0]![0]!.location.file).toBe('b.ts');
    for (const batch of batches) expect(new Set(batch.map((f) => f.location.file)).size).toBe(1);
  });
});

describe('runSkeptic', () => {
  it('reviews only critical/high sast/taint findings not yet reviewed, one call per file batch', async () => {
    const fs = [
      mkFinding({ file: 'a.ts', line: 3 }),
      mkFinding({ file: 'a.ts', line: 50 }),
      mkFinding({ file: 'b.ts', category: 'taint', severity: 'critical', producedBy: ['taint:agent'] }),
      mkFinding({ file: 'a.ts', severity: 'medium' }),
      mkFinding({ file: 'a.ts', category: 'config' }),
      mkFinding({ file: 'a.ts', producedBy: ['sast:llm', 'skeptic:upheld'] }),
    ];
    const { llm, calls } = stubLlm(async (call) => ok(allVerdicts((call.prompt.match(/FINDING findingIndex=/g) ?? []).length)));
    const r = await runSkeptic(fs, ctx(), { llm, readFile: files({ 'a.ts': fileOf(100), 'b.ts': fileOf(20) }) });
    expect(calls).toHaveLength(2);
    expect(r.reviewed).toBe(3);
    expect(r.changed.map((f) => f.id).sort()).toEqual([fs[0]!.id, fs[1]!.id, fs[2]!.id].sort());
    const c = calls[0]!;
    expect(c.role).toBe('deep');
    expect(c.tier).toBe(1);
    expect(c.purpose).toBe('skeptic');
    expect(c.system).toContain(SKEPTIC_TASK_MARKER);
    expect(c.promptVersion).toBe('skeptic-v1');
    expect(partialSummary(r)).toBeNull();
  });

  it('wraps findings and code as untrusted and sends ±40 lines around the location and ±10 around trace steps', async () => {
    const f = mkFinding({
      category: 'taint', file: 'a.ts', line: 60, producedBy: ['taint:agent'],
      taintTrace: [{ kind: 'source', file: 'r.ts', line: 30, code: 'req.query.x', note: 'n' }, { kind: 'sink', file: 'a.ts', line: 60, code: 'q', note: 'n' }],
    });
    const { llm, calls } = stubLlm(async () => ok(allVerdicts(1)));
    await runSkeptic([f], ctx(), { llm, readFile: files({ 'a.ts': fileOf(200), 'r.ts': fileOf(200) }) });
    const p = calls[0]!.prompt;
    expect(p).toContain('<untrusted_text source="finding-0">');
    expect(p).toContain('<untrusted_file path="a.ts">');
    expect(p).toMatch(/^20: line 20$/m);
    expect(p).toMatch(/^100: line 100$/m);
    expect(p).not.toMatch(/^19: line 19$/m);
    expect(p).not.toMatch(/^101: line 101$/m);
    expect(p).toContain('<untrusted_file path="r.ts">');
    const rLines = p.split('<untrusted_file path="r.ts">\n')[1]!.split('\n</untrusted_file>')[0]!.split('\n');
    expect(rLines[0]).toBe('20: line 20');
    expect(rLines.at(-1)).toBe('40: line 40');
  });

  it('fails open: a failed call leaves findings unchanged and is counted by safe reason', async () => {
    const fs = [mkFinding({ file: 'a.ts' }), mkFinding({ file: 'b.ts' })];
    const { llm } = stubLlm(async (call) => {
      if (call.prompt.includes('"a.ts"')) throw new AppError('LLM_OUTPUT_INVALID', 'permanent', 'bad output: secret-ish raw text');
      return ok(allVerdicts(1, 'refuted'));
    });
    const r = await runSkeptic(fs, { ...ctx() }, { llm, readFile: files({ 'a.ts': fileOf(5), 'b.ts': fileOf(5) }), concurrency: 1 });
    expect(r.changed.map((f) => f.id)).toEqual([fs[1]!.id]);
    expect(r.failures.get('validation')).toBe(1);
    const msg = partialSummary(r)!;
    expect(msg).toContain('1 failed (1 validation)');
    expect(msg).not.toContain('secret-ish');
  });

  it('counts missing verdicts as validation failures and ignores duplicate indexes', async () => {
    const fs = [mkFinding({ line: 1 }), mkFinding({ line: 2 })];
    const { llm } = stubLlm(async () => ok({ verdicts: [{ findingIndex: 0, verdict: 'refuted', reason: 'a' }, { findingIndex: 0, verdict: 'upheld', reason: 'b' }] }));
    const r = await runSkeptic(fs, ctx(), { llm, readFile: files({ 'src/a.ts': fileOf(5) }) });
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]!.severity).toBe('info');
    expect(r.failures.get('validation')).toBe(1);
  });

  it('stops on budget exhaustion and reports the rest as budget-skipped', async () => {
    const fs = [mkFinding({ file: 'a.ts', severity: 'critical' }), mkFinding({ file: 'b.ts' }), mkFinding({ file: 'c.ts' })];
    const { llm, calls } = stubLlm(async (_c, n) => {
      if (n === 1) return ok(allVerdicts(1));
      throw new AppError('BUDGET_EXHAUSTED', 'budget', 'budget');
    });
    const r = await runSkeptic(fs, ctx(), { llm, readFile: files({ 'a.ts': 'x', 'b.ts': 'x', 'c.ts': 'x' }), concurrency: 1 });
    expect(calls).toHaveLength(2);
    expect(r.reviewed).toBe(1);
    expect(r.budgetSkipped).toBe(2);
    expect(partialSummary(r)).toContain('2 skipped: AI budget exhausted');
  });

  it('honours maxSkeptic (risk-ordered) and reports the cap', async () => {
    const fs = [mkFinding({ file: 'a.ts' }), mkFinding({ file: 'b.ts', severity: 'critical' })];
    const { llm, calls } = stubLlm(async () => ok(allVerdicts(1)));
    const r = await runSkeptic(fs, ctx(), { llm, readFile: files({ 'a.ts': 'x', 'b.ts': 'x' }), maxSkeptic: 1 });
    expect(calls).toHaveLength(1);
    expect(r.changed[0]!.id).toBe(fs[1]!.id);
    expect(r.capSkipped).toBe(1);
  });

  it('skips findings whose code cannot be read (no call)', async () => {
    const { llm, calls } = stubLlm(async () => ok(allVerdicts(1)));
    const r = await runSkeptic([mkFinding({ file: 'gone.ts' })], ctx(), { llm, readFile: files({}) });
    expect(calls).toHaveLength(0);
    expect(r.codeUnavailable).toBe(1);
  });

  it('propagates cancellation', async () => {
    const controller = new AbortController();
    const { llm } = stubLlm(async () => {
      controller.abort();
      throw new AppError('CANCELLED', 'cancelled', 'cancelled');
    });
    await expect(runSkeptic([mkFinding()], ctx(controller.signal), { llm, readFile: files({ 'src/a.ts': 'x' }) }))
      .rejects.toMatchObject({ kind: 'cancelled' });
  });
});

describe('skepticMockResponder', () => {
  const vulnApp = [
    "import { Router } from 'express';",
    '',
    'export const redirectRouter = Router();',
    '',
    "redirectRouter.get('/go', (req, res) => {",
    '  const target = req.query.to as string;',
    '  res.redirect(target);',
    '});',
    '',
    "redirectRouter.get('/go-safe', (req, res) => {",
    '  const target = req.query.to as string;',
    "  if (!target.startsWith('/')) return res.status(400).end();",
    '  res.redirect(target);',
    '});',
  ].join('\n');

  it('refutes the sanitized same-site redirect, upholds the raw one (vuln-app sample)', async () => {
    const raw = mkFinding({ file: 'api/src/routes/redirect.ts', line: 7, ruleId: 'sast/open-redirect', cwe: 'CWE-601' });
    const safe = mkFinding({ file: 'api/src/routes/redirect.ts', line: 13, ruleId: 'sast/open-redirect', cwe: 'CWE-601' });
    const { llm, calls } = responderLlm();
    const r = await runSkeptic([raw, safe], ctx(), { llm, readFile: files({ 'api/src/routes/redirect.ts': vulnApp }) });
    expect(calls).toHaveLength(1);
    const byId = new Map(r.changed.map((f) => [f.id, f]));
    expect(byId.get(raw.id)!.severity).toBe('high');
    expect(byId.get(raw.id)!.producedBy).toContain('skeptic:upheld');
    const s = byId.get(safe.id)!;
    expect(s.severity).toBe('info');
    expect(s.riskFactors[0]).toMatchObject({ factor: 'ai_refuted', effect: -3 });
    expect(s.riskFactors[0]!.reason).toContain('line 12');
  });

  it('refutes parameterized queries, basename and sanitize; weakens test/examples code', async () => {
    const code = [
      'const id = req.params.id;',
      "db.query('SELECT * FROM u WHERE id = $1', [id]);",
      'const name = path.basename(req.query.f);',
      'fs.readFileSync(name);',
      'const html = sanitizeHtml(req.body.h);',
      'el.innerHTML = html;',
    ].join('\n');
    const pad = Array.from({ length: 20 }, () => '//').join('\n');
    const src = `${code}\n${pad}\nexec(req.query.c);`;
    const fs = [
      mkFinding({ file: 's.ts', line: 2 }),
      mkFinding({ file: 's.ts', line: 4, ruleId: 'sast/path-traversal', cwe: 'CWE-22' }),
      mkFinding({ file: 's.ts', line: 27, ruleId: 'sast/command-injection', cwe: 'CWE-78' }),
      mkFinding({ file: 'examples/demo.ts', line: 1, ruleId: 'sast/command-injection', cwe: 'CWE-78' }),
    ];
    const { llm } = responderLlm();
    const r = await runSkeptic(fs, ctx(), { llm, readFile: files({ 's.ts': src, 'examples/demo.ts': 'exec(cmd)' }) });
    const v = new Map(r.changed.map((f) => [f.id, f]));
    expect(v.get(fs[0]!.id)!.severity).toBe('info');
    expect(v.get(fs[1]!.id)!.severity).toBe('info');
    expect(v.get(fs[2]!.id)!.producedBy).toContain('skeptic:upheld');
    expect(v.get(fs[3]!.id)!.riskFactors[0]!.factor).toBe('skeptic_weakened');
    for (const f of r.changed) expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('ignores requests without the task marker', () => {
    const req: LlmRequest = { model: 'm', system: [{ type: 'text', text: 'other' }], messages: [], maxTokens: 1, thinking: false };
    expect(skepticMockResponder(req)).toBeUndefined();
  });
});

