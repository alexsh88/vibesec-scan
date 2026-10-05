import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type Anthropic from '@anthropic-ai/sdk';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type ScanDto } from '@vibesec/shared';
import type { ReportFlowInput } from '../src/analyzers/code/repoTools';
import { createTaintAnalyzer, TAINT_TASK_MARKER, taintMockResponder, toTaintRuleId, type TaintAnalyzerDeps } from '../src/analyzers/code/taint';
import { codeTriageMockResponder, TriageService } from '../src/analyzers/code/triage';
import type { FileTriage, TraceStep, TriageResult } from '../src/analyzers/code/types';
import type { AnalyzerContext } from '../src/analyzers/types';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { TriageCacheRepo } from '../src/db/triageCacheRepo';
import { AppError } from '../src/errors/AppError';
import type { Entrypoint, ImportEdge, IndexedFile } from '../src/index/types';
import { BudgetTracker } from '../src/llm/budget';
import { LlmClient } from '../src/llm/LlmClient';
import { MockTransport, mockText, mockToolUse, mockToolUses, mockTurnIndex, type MockReply, type MockResponder } from '../src/llm/mockTransport';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import type { LlmRequest } from '../src/llm/transport';
import { memoryDb } from './helpers';

// --- temp repo: route.ts → service.ts → db.ts (SQL concat) ------------------------------------------

const ROUTE = [
  "import express from 'express';",
  "import { getUser } from './service';",
  'const app = express();',
  "app.get('/users/:id', async (req, res) => {",
  '  const id = req.params.id;',
  '  const user = await getUser(id);',
  '  res.json(user);',
  '});',
  'export default app;',
].join('\n');
const SERVICE = [
  "import { findUser } from './db';",
  'export async function getUser(id: string) {',
  '  // business logic',
  '  return findUser(id);',
  '}',
].join('\n');
const DB = [
  "import { pool } from 'pg-pool';",
  'export async function findUser(id: string) {',
  '  const sql = "SELECT * FROM users WHERE id = \'" + id + "\'";',
  '  return pool.query(sql);',
  '}',
].join('\n');
const OTHER = (n: string) => `app.post('/${n}', (req, res) => res.send(req.body.${n}));\n`;

let dir: string;
const files: IndexedFile[] = [];
const imports: ImportEdge[] = [
  { from: 'src/route.ts', specifier: 'express', kind: 'package', to: null, pkg: 'express', line: 1 },
  { from: 'src/route.ts', specifier: './service', kind: 'local', to: 'src/service.ts', pkg: null, line: 2 },
  { from: 'src/service.ts', specifier: './db', kind: 'local', to: 'src/db.ts', pkg: null, line: 1 },
  { from: 'src/db.ts', specifier: 'pg-pool', kind: 'package', to: null, pkg: 'pg-pool', line: 1 },
];
const ROUTE_EP: Entrypoint = { path: 'src/route.ts', kind: 'http-route', line: 4, detail: 'GET /users/:id' };

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-taint-'));
  const put = async (path: string, content: string) => {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    files.push({ path, blobSha: 'b', size: Buffer.byteLength(content), language: 'typescript', category: 'source', tags: [], skipReason: null });
  };
  await put('src/route.ts', ROUTE);
  await put('src/service.ts', SERVICE);
  await put('src/db.ts', DB);
  await put('src/a.ts', OTHER('a'));
  await put('src/b.ts', OTHER('b'));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

// --- helpers -------------------------------------------------------------------------------------

function makeScan(): ScanDto {
  return {
    id: 'scan-1', repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false }, ref: null,
    commitSha: 'c'.repeat(40), state: 'ANALYZING', errorCode: null, errorMessage: null, cacheHit: 'none',
    options: ScanOptionsSchema.parse({}), costUsd: 0, createdAt: new Date().toISOString(),
    startedAt: null, finishedAt: null, warnings: [],
  };
}

function makeCtx(scanId: string, signal = new AbortController().signal) {
  const warnings: Array<{ code: string; message: string }> = [];
  const touch = vi.fn();
  const scan = { ...makeScan(), id: scanId };
  const ctx: AnalyzerContext = {
    scanId, scan, repoDir: dir, commitSha: scan.commitSha!, repo: scan.repo, files,
    signal, touch, warn: (code, message) => warnings.push({ code, message }), progress: () => {},
  };
  return { ctx, warnings, touch };
}

function llmSetup(responders: MockResponder[]) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({ repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false }).id;
  const seen: LlmRequest[] = [];
  const inner = new MockTransport({ responders });
  const llm = new LlmClient({
    transport: { mode: 'mock', send: async (req, signal) => { seen.push({ ...req, schema: undefined }); return inner.send(req, signal); } },
    models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
    limiter: new RateLimiter({ requestsPerMinute: 10_000, inputTokensPerMinute: 100_000_000 }), semaphore: new Semaphore(4),
    budget: new BudgetTracker(50, (id) => scans.getDto(id)?.costUsd ?? 0), calls: new LlmCallRepo(db), scans,
    retryDeps: { sleep: async () => {} }, atomically: (fn) => db.transaction(fn)(),
  });
  return { llm, seen, scanId, db };
}

const triageOf = (entries: Array<Partial<FileTriage> & { path: string }>): Pick<TriageService, 'forScan'> => {
  const result: TriageResult = {
    files: new Map(entries.map((e) => [e.path, { relevance: 3, sources: ['req.params.id (line 5)'], sinks: [], securityTopics: [], credentialRisk: false, ...e }])),
    skipped: [], warnings: [],
  };
  return { forScan: async () => result };
};

function analyzer(llm: TaintAnalyzerDeps['llm'], over: Partial<TaintAnalyzerDeps> = {}) {
  return createTaintAnalyzer({
    llm, triage: triageOf([{ path: 'src/route.ts' }]),
    indexRepo: { imports: () => imports, entrypoints: () => [ROUTE_EP] }, ...over,
  });
}

/** Scripted agent: turn i → turns[i] (only for taint requests); afterwards end_turn. */
function script(turns: Array<MockReply | ((req: LlmRequest) => MockReply)>): MockResponder {
  return (req) => {
    if (!req.system.some((b) => b.text.includes(TAINT_TASK_MARKER))) return undefined;
    const t = turns[mockTurnIndex(req)];
    return t === undefined ? mockText('Done.') : typeof t === 'function' ? t(req) : t;
  };
}

const step = (kind: TraceStep['kind'], file: string, line: number, code: string, note = `${kind} step`): TraceStep => ({ kind, file, line, code, note });
const FULL_TRACE: TraceStep[] = [
  step('source', 'src/route.ts', 5, 'const id = req.params.id;', 'route param'),
  step('propagator', 'src/route.ts', 6, 'const user = await getUser(id);'),
  step('propagator', 'src/service.ts', 2, 'export async function getUser(id: string) {'),
  step('propagator', 'src/service.ts', 4, 'return findUser(id);'),
  step('propagator', 'src/db.ts', 3, 'const sql = "SELECT * FROM users WHERE id = \'" + id + "\'";', 'string concat'),
  step('sink', 'src/db.ts', 4, 'return pool.query(sql);', 'raw query'),
];
const flow = (over: Partial<ReportFlowInput> = {}): ReportFlowInput => ({
  title: 'SQL injection in GET /users/:id', ruleId: 'taint/sql-injection', cwe: 'CWE-89', severity: 'high',
  verdict: 'exploitable', confidence: 'high', trace: FULL_TRACE, sanitizersSeen: [],
  explanation: 'id flows into a concatenated SQL string.', impact: 'Database read/write.', remediation: 'Use a parameterized query.', ...over,
});

function toolResults(req: LlmRequest): Anthropic.ToolResultBlockParam[] {
  const last = req.messages.at(-1)!;
  return (last.content as Anthropic.ContentBlockParam[]).filter((b): b is Anthropic.ToolResultBlockParam => b.type === 'tool_result');
}

// --- tests -----------------------------------------------------------------------------------------

describe('taint analyzer', () => {
  it('turns a multi-file verified trace into one finding at the sink carrying the full trace', async () => {
    const { llm, seen, scanId } = llmSetup([script([
      mockToolUses([{ name: 'get_imports', input: { path: 'src/route.ts' } }, { name: 'read_file', input: { path: 'src/service.ts' } }]),
      mockToolUse('report_flow', flow()),
    ])]);
    const { ctx, warnings, touch } = makeCtx(scanId);
    const findings = await analyzer(llm).run(ctx);

    expect(findings).toHaveLength(1);
    const f = FindingSchema.parse(findings[0]);
    expect(f).toMatchObject({
      category: 'taint', ruleId: 'taint/sql-injection', cwe: 'CWE-89', severity: 'high', confidence: 'high', producedBy: ['taint:agent'],
      location: { file: 'src/db.ts', startLine: 4, endLine: 4, snippet: '  return pool.query(sql);' },
    });
    expect(f.taintTrace!.map((s) => `${s.kind}@${s.file}:${s.line}`)).toEqual([
      'source@src/route.ts:5', 'propagator@src/route.ts:6', 'propagator@src/service.ts:2',
      'propagator@src/service.ts:4', 'propagator@src/db.ts:3', 'sink@src/db.ts:4',
    ]);
    expect(f.taintTrace![0]!.code).toBe('  const id = req.params.id;'); // real file text
    expect(warnings).toEqual([]);
    expect(touch).toHaveBeenCalled();

    // agent request: deep role, tools incl. report_flow, seed with the numbered entrypoint and triage hints
    const first = seen[0]!;
    expect(first.model).toBe('claude-sonnet-5');
    expect(first.tools!.map((t) => t.name)).toEqual(['list_dir', 'read_file', 'grep', 'find_references', 'get_imports', 'report_flow']);
    const seed = (first.messages[0]!.content as Anthropic.TextBlockParam[]).map((b) => b.text).join('');
    expect(seed).toContain('Entrypoint: src/route.ts');
    expect(seed).toContain('http-route GET /users/:id');
    expect(seed).toContain('req.params.id (line 5)');
    expect(seed).toContain('<untrusted_file path="src/route.ts">');
    expect(seed).toContain('5    const id = req.params.id;');
    // the model's tool calls really ran: turn 2 sees get_imports + read_file results
    const results = toolResults(seen[1]!);
    expect(results).toHaveLength(2);
    expect(String(results[0]!.content)).toContain('src/service.ts');
    expect(String(results[1]!.content)).toContain('export async function getUser');
  });

  it('drops sanitized flows', async () => {
    const { llm, scanId } = llmSetup([script([mockToolUse('report_flow', flow({ verdict: 'sanitized', sanitizersSeen: ['parseInt'] }))])]);
    const { ctx, warnings } = makeCtx(scanId);
    expect(await analyzer(llm).run(ctx)).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it('reports uncertain flows with low confidence', async () => {
    const { llm, scanId } = llmSetup([script([mockToolUse('report_flow', flow({ verdict: 'uncertain', confidence: 'high' }))])]);
    const { ctx } = makeCtx(scanId);
    const findings = await analyzer(llm).run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe('low');
  });

  it('drops flows whose sink is fabricated, and strips fabricated intermediate steps', async () => {
    const fakeSink = [...FULL_TRACE.slice(0, -1), step('sink', 'src/db.ts', 4, 'db.query("SELECT * FROM t WHERE x=" + req.query.x)')];
    const fakeMiddle = [FULL_TRACE[0]!, step('propagator', 'src/service.ts', 3, 'const q = sanitizeNothing(id);'), FULL_TRACE[5]!];
    const outside = [step('source', '../outside.ts', 1, 'req.query.x'), FULL_TRACE[5]!];
    const { llm, scanId } = llmSetup([script([mockToolUses([
      { name: 'report_flow', input: flow({ trace: fakeSink }) },
      { name: 'report_flow', input: flow({ trace: fakeMiddle, ruleId: 'taint/other' }) },
      { name: 'report_flow', input: flow({ trace: outside, ruleId: 'taint/third' }) },
    ])])]);
    const { ctx, warnings } = makeCtx(scanId);
    const findings = await analyzer(llm).run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('taint/other');
    expect(findings[0]!.taintTrace!.map((s) => s.kind)).toEqual(['source', 'sink']);
    expect(warnings).toEqual([{ code: 'TAINT_UNVERIFIED_DROPPED', message: expect.stringContaining('2 reported taint flow(s)') }]);
  });

  it('traces every entrypoint with sources (no cap), risk first, recording coverage and a shrinking budget projection', async () => {
    const { llm, seen, scanId } = llmSetup([script([mockText('Nothing to report.')])]);
    const eps: Entrypoint[] = ['src/route.ts', 'src/a.ts', 'src/b.ts', 'src/db.ts'].map((path) => ({ path, kind: 'http-route', line: 1, detail: null }));
    const triage = triageOf([
      { path: 'src/b.ts', relevance: 2, sources: ['req.body.b (line 1)'] },
      { path: 'src/a.ts', relevance: 2, sources: ['req.body.a (line 1)', 'req.query (line 1)'] },
      { path: 'src/route.ts', relevance: 3 },
      { path: 'src/db.ts', relevance: 3, sources: [] },
    ]);
    const { ctx, warnings } = makeCtx(scanId);
    const coverage = new Map<string, string>();
    ctx.recordCoverage = (a, path, status) => { expect(a).toBe('taint'); coverage.set(path, status); };
    const projections: number[] = [];
    const lanes = { open: () => ({ project: (usd: number) => { projections.push(usd); }, close: () => {} }), estimateUsd: () => 1 };
    await analyzer(llm, { triage, lanes, concurrency: 1, indexRepo: { imports: () => imports, entrypoints: () => eps } }).run(ctx);
    const traced = seen.map((r) => (r.messages[0]!.content as Anthropic.TextBlockParam[])[0]!.text.match(/^Entrypoint: (.+)$/m)![1]);
    expect(traced).toEqual(['src/route.ts', 'src/a.ts', 'src/b.ts']);
    expect(warnings).toEqual([]);
    expect(Object.fromEntries(coverage)).toEqual({ 'src/route.ts': 'reviewed', 'src/a.ts': 'reviewed', 'src/b.ts': 'reviewed', 'src/db.ts': 'not-relevant' });
    expect(projections).toEqual([3, 2, 1, 0]);
  });

  it('keeps partial results when the agent hits max_turns', async () => {
    const { llm, scanId } = llmSetup([script([
      mockToolUse('report_flow', flow()),
      mockToolUse('read_file', { path: 'src/db.ts' }),
      mockToolUse('read_file', { path: 'src/db.ts' }),
    ])]);
    const { ctx, warnings } = makeCtx(scanId);
    const findings = await analyzer(llm, { maxTurns: 2 }).run(ctx);
    expect(findings).toHaveLength(1);
    expect(warnings).toEqual([{ code: 'TAINT_PARTIAL', message: expect.stringMatching(/src\/route\.ts.*max_turns/) }]);
  });

  it('confines tools: a ../ path gets an error result and the loop continues', async () => {
    const { llm, seen, scanId } = llmSetup([script([
      mockToolUses([{ name: 'read_file', input: { path: '../vibesec-taint-outside.txt' } }, { name: 'list_dir', input: { path: '/etc' } }]),
      mockToolUse('report_flow', flow()),
    ])]);
    const { ctx } = makeCtx(scanId);
    const findings = await analyzer(llm).run(ctx);
    const results = toolResults(seen[1]!);
    expect(results.map((r) => r.is_error)).toEqual([true, true]);
    expect(String(results[0]!.content)).toContain('must not contain ".."');
    expect(String(results[0]!.content)).not.toContain('outside');
    expect(findings).toHaveLength(1);
  });

  it('propagates cancellation', async () => {
    const controller = new AbortController();
    const { llm, scanId } = llmSetup([script([
      () => { controller.abort(); return mockToolUse('read_file', { path: 'src/db.ts' }); },
      mockToolUse('report_flow', flow()),
    ])]);
    const { ctx } = makeCtx(scanId, controller.signal);
    await expect(analyzer(llm).run(ctx)).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('fails open per entrypoint', async () => {
    const eps: Entrypoint[] = [ROUTE_EP, { path: 'src/a.ts', kind: 'http-route', line: 1, detail: null }];
    const agent = vi.fn(async (call: { prompt: string }) => {
      if (call.prompt.includes('Entrypoint: src/a.ts')) throw new AppError('LLM_OUTPUT_INVALID', 'permanent', 'boom');
      return { finished: [flow()], turns: 1, stopReason: 'end_turn' as const, model: 'm', costUsd: 0, usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 }, callIds: [], degraded: false };
    });
    const { ctx, warnings } = makeCtx('scan-x');
    const findings = await createTaintAnalyzer({
      llm: { agent } as unknown as TaintAnalyzerDeps['llm'],
      triage: triageOf([{ path: 'src/route.ts' }, { path: 'src/a.ts', relevance: 2 }]),
      indexRepo: { imports: () => imports, entrypoints: () => eps },
    }).run(ctx);
    expect(agent).toHaveBeenCalledTimes(2);
    expect(findings).toHaveLength(1);
    expect(warnings.map((w) => w.code)).toEqual(['TAINT_ENTRYPOINT_FAILED']);
  });

  it('dedupes flows with the same sink line and rule: shortest trace wins, notes merged', async () => {
    const short = [step('source', 'src/route.ts', 5, 'const id = req.params.id;', 'path parameter'), step('sink', 'src/db.ts', 4, 'return pool.query(sql);', 'raw query')];
    const { llm, scanId } = llmSetup([script([mockToolUses([
      { name: 'report_flow', input: flow({ confidence: 'medium' }) },
      { name: 'report_flow', input: flow({ trace: short, ruleId: 'SqlInjection', severity: 'critical' }) },
    ])])]);
    const { ctx } = makeCtx(scanId);
    const findings = await analyzer(llm).run(ctx);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe('taint/sql-injection');
    expect(f.severity).toBe('critical');
    expect(f.confidence).toBe('high');
    expect(f.taintTrace!).toHaveLength(2);
    expect(f.taintTrace![0]!.note).toBe('path parameter / route param');
    expect(toTaintRuleId('sast/Command Injection')).toBe('taint/command-injection');
    expect(toTaintRuleId('///')).toBe('taint/tainted-flow');
  });

  it('mock responder: end-to-end mock scan on the temp repo yields a verified multi-file trace', async () => {
    const { llm, seen, scanId } = llmSetup([codeTriageMockResponder, taintMockResponder]);
    const triage = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => 'claude-haiku-4-5' });
    const { ctx, warnings } = makeCtx(scanId);
    const findings = await createTaintAnalyzer({
      llm, triage, indexRepo: { imports: () => imports, entrypoints: () => [ROUTE_EP] },
    }).run(ctx);
    expect(warnings).toEqual([]);
    expect(findings).toHaveLength(1);
    const f = FindingSchema.parse(findings[0]);
    expect(f).toMatchObject({ ruleId: 'taint/sql-injection', cwe: 'CWE-89', location: { file: 'src/db.ts', startLine: 4 } });
    expect(f.taintTrace!.map((s) => `${s.kind}@${s.file}:${s.line}`)).toEqual([
      'source@src/route.ts:5', 'propagator@src/route.ts:6', 'propagator@src/service.ts:2',
      'propagator@src/service.ts:4', 'propagator@src/db.ts:2', 'sink@src/db.ts:4',
    ]);
    const taintTurns = seen.filter((r) => r.system.some((b) => b.text.includes(TAINT_TASK_MARKER)));
    expect(taintTurns.length).toBeGreaterThan(3);
    expect(taintTurns.length).toBeLessThanOrEqual(8);
  });

  it('mock responder: no sink reachable → no flows', () => {
    const req = {
      model: 'm', maxTokens: 1, thinking: false,
      system: [{ type: 'text', text: TAINT_TASK_MARKER }],
      messages: [{ role: 'user', content: [{ type: 'text', text: 'Entrypoint: src/a.ts\n' }] }],
    } as LlmRequest;
    expect(taintMockResponder(req)).toMatchObject({ content: [{ type: 'tool_use', name: 'read_file' }, { type: 'tool_use', name: 'get_imports' }] });
    expect(taintMockResponder({ ...req, system: [{ type: 'text', text: 'other' }] })).toBeUndefined();
  });
});
