import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type ScanDto } from '@vibesec/shared';
import { createSastAnalyzer, sastMockResponder, SAST_PROMPT_VERSION, SAST_TASK_MARKER, type CachedSastIssue, type SastResultCache } from '../src/analyzers/code/sast';
import { SAST_SYSTEM_PROMPT, SastOutputSchema, type SastIssue, type SastOutput } from '../src/analyzers/code/sastPrompt';
import type { FileTriage, TriageResult } from '../src/analyzers/code/types';
import type { AnalyzerContext, CoverageStatus } from '../src/analyzers/types';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import type { Entrypoint, ImportEdge, IndexedFile } from '../src/index/types';
import { BudgetTracker } from '../src/llm/budget';
import { LlmClient, type StructuredCall, type StructuredResult } from '../src/llm/LlmClient';
import { MockTransport } from '../src/llm/mockTransport';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import { memoryDb } from './helpers';

const ZERO_USAGE = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-sast-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

async function writeFiles(files: Record<string, string>, tags: Record<string, IndexedFile['tags']> = {}): Promise<IndexedFile[]> {
  const indexed: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    const language: IndexedFile['language'] = path.endsWith('.py') ? 'python' : path.endsWith('.json') ? 'json' : path.endsWith('.sql') ? 'sql' : 'typescript';
    const category: IndexedFile['category'] = path.endsWith('package.json') ? 'config' : 'source';
    indexed.push({ path, blobSha: 'deadbeef', size: Buffer.byteLength(content), language, category, tags: tags[path] ?? [], skipReason: null });
  }
  return indexed;
}

function makeCtx(files: IndexedFile[], opts: { warn?: (code: string, message: string) => void; signal?: AbortSignal; scanId?: string; coverage?: Map<string, CoverageStatus> } = {}): AnalyzerContext {
  const scan: ScanDto = {
    id: opts.scanId ?? 'scan-1', repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false }, ref: null,
    commitSha: 'c'.repeat(40), state: 'ANALYZING', errorCode: null, errorMessage: null, cacheHit: 'none',
    options: ScanOptionsSchema.parse({}), costUsd: 0, createdAt: new Date().toISOString(),
    startedAt: null, finishedAt: null, warnings: [],
  };
  return {
    scanId: scan.id, scan, repoDir: dir, commitSha: scan.commitSha!, repo: scan.repo, files,
    signal: opts.signal ?? new AbortController().signal, touch: () => {}, warn: opts.warn ?? (() => {}), progress: () => {},
    recordCoverage: (analyzer, path, status) => { expect(analyzer).toBe('sast'); opts.coverage?.set(path, status); },
  };
}

function tri(path: string, relevance: FileTriage['relevance'], over: Partial<FileTriage> = {}): FileTriage {
  return { path, relevance, sources: [], sinks: [], securityTopics: [], credentialRisk: false, ...over };
}

function triageOf(...files: FileTriage[]): { forScan: () => Promise<TriageResult> } {
  const result: TriageResult = { files: new Map(files.map((f) => [f.path, f])), skipped: [], warnings: [] };
  return { forScan: async () => result };
}

function indexRepoOf(entrypoints: Entrypoint[] = [], imports: ImportEdge[] = []) {
  return { entrypoints: () => entrypoints, imports: () => imports };
}

function ok(issues: SastIssue[], over: Partial<StructuredResult<SastOutput>> = {}): StructuredResult<SastOutput> {
  return { output: { issues }, model: 'claude-sonnet-5', usage: ZERO_USAGE, costUsd: 0, callIds: [], degraded: false, fellBackOnRefusal: false, ...over };
}

function stubLlm(impl: (call: StructuredCall<SastOutput>) => Promise<StructuredResult<SastOutput>>) {
  const calls: StructuredCall<SastOutput>[] = [];
  const structured = async (call: StructuredCall<SastOutput>) => {
    calls.push(call);
    return impl(call);
  };
  return { llm: { structured: structured as unknown as LlmClient['structured'] }, calls };
}

/** The target path of a SAST call (from the TARGET FILE header). */
function targetOf(call: StructuredCall<SastOutput>): string {
  return JSON.parse(/^TARGET FILE: (".*?") —/.exec(call.prompt)![1]!) as string;
}

function issue(file: string, over: Partial<SastIssue> = {}): SastIssue {
  return {
    ruleId: 'sast/sql-injection', title: 'SQL injection in user lookup', cwe: 'CWE-89', severity: 'high', confidence: 'high',
    file, startLine: 3, endLine: 3, snippet: 'db.query("SELECT * FROM users WHERE id = " + req.query.id);',
    explanation: 'req.query.id is concatenated into SQL.', impact: 'Database read/write.', remediation: 'Use a parameterized query.',
    ...over,
  };
}

const ROUTE = [
  "import { db } from './db';",
  "app.get('/u', (req, res) => {",
  '  db.query("SELECT * FROM users WHERE id = " + req.query.id);',
  '  res.send("ok");',
  '});',
  '',
].join('\n');

describe('SAST analyzer — file selection', () => {
  it('reviews triaged relevance>=2 / sink / entrypoint files and skips irrelevant and test files', async () => {
    const files = await writeFiles({
      'src/a.ts': 'a', 'src/b.ts': 'b', 'src/c.ts': 'c', 'src/d.ts': 'd', 'src/e.ts': 'e', 'src/f.ts': 'f', 'test/t.ts': 't',
    }, { 'test/t.ts': ['test'] });
    const { llm, calls } = stubLlm(async () => ok([]));
    const analyzer = createSastAnalyzer({
      llm,
      triage: triageOf(tri('src/a.ts', 3), tri('src/b.ts', 2), tri('src/c.ts', 1), tri('src/d.ts', 0), tri('src/e.ts', 1, { sinks: ['eval (line 1)'] }), tri('src/f.ts', 1), tri('test/t.ts', 3)),
      indexRepo: indexRepoOf([{ path: 'src/f.ts', kind: 'http-route', line: 1, detail: 'GET /f' }]),
    });
    expect(analyzer).toMatchObject({ id: 'sast', version: '2', category: 'sast' });
    const coverage = new Map<string, CoverageStatus>();
    await analyzer.run(makeCtx(files, { coverage }));
    expect(calls.filter((c) => c.role === 'deep').map(targetOf).sort()).toEqual(['src/a.ts', 'src/b.ts', 'src/e.ts', 'src/f.ts']);
    // Relevance 1 → the cheaper fast pass (tier 2); relevance 0 and test files → not reviewed, but recorded.
    expect(calls.filter((c) => c.role === 'fast').map(targetOf)).toEqual(['src/c.ts']);
    expect(Object.fromEntries(coverage)).toEqual({
      'src/a.ts': 'reviewed', 'src/b.ts': 'reviewed', 'src/e.ts': 'reviewed', 'src/f.ts': 'reviewed',
      'src/c.ts': 'reviewed-fast', 'src/d.ts': 'not-relevant', 'test/t.ts': 'not-relevant',
    });
  });

  it('also reviews Supabase migrations and Firebase rules (never triaged)', async () => {
    const files = await writeFiles({ 'supabase/migrations/001_init.sql': 'create table notes (id int);', 'firestore.rules': 'allow read, write: if true;', 'docs/x.sql': 'select 1;' });
    const { llm, calls } = stubLlm(async () => ok([]));
    await createSastAnalyzer({ llm, triage: triageOf(), indexRepo: indexRepoOf() }).run(makeCtx(files));
    expect(calls.map(targetOf).sort()).toEqual(['firestore.rules', 'supabase/migrations/001_init.sql']);
  });

  it('has no file cap: reviews every candidate in risk order, deep pass before the fast pass', async () => {
    const paths = Array.from({ length: 70 }, (_, i) => `f${String(i).padStart(2, '0')}.ts`);
    const files = await writeFiles({ ...Object.fromEntries(paths.map((p) => [p, p])), 'ep.ts': 'e', 'low.ts': 'l' });
    const { llm, calls } = stubLlm(async () => ok([]));
    const triaged = [...paths.map((p, i) => tri(p, i % 2 === 0 ? 3 : 2, { sinks: i === 1 ? ['exec (line 1)', 'eval (line 2)'] : [] })), tri('ep.ts', 2), tri('low.ts', 1)];
    const warnings: string[] = [];
    await createSastAnalyzer({
      llm, concurrency: 1, triage: triageOf(...triaged),
      indexRepo: indexRepoOf([{ path: 'ep.ts', kind: 'http-route', line: 1, detail: 'GET /' }]),
    }).run(makeCtx(files, { warn: (c) => warnings.push(c) }));
    const order = calls.map(targetOf);
    expect(order).toHaveLength(72);
    expect(warnings).toEqual([]);
    expect(order.slice(0, 35).every((p) => paths.indexOf(p) % 2 === 0)).toBe(true); // relevance 3 first
    expect(order[35]).toBe('ep.ts'); // then relevance 2, entrypoints first…
    expect(order[36]).toBe('f01.ts'); // …then by number of sinks
    expect(order.at(-1)).toBe('low.ts');
    expect(calls.at(-1)).toMatchObject({ role: 'fast', tier: 2, purpose: 'sast-file-fast' });
  });

  it('fast-pass findings are marked sast:llm-fast with confidence capped at medium', async () => {
    const files = await writeFiles({ 'src/route.ts': ROUTE });
    const { llm } = stubLlm(async () => ok([issue('src/route.ts', { confidence: 'high' })]));
    const [finding] = await createSastAnalyzer({ llm, triage: triageOf(tri('src/route.ts', 1)), indexRepo: indexRepoOf() }).run(makeCtx(files));
    expect(finding).toMatchObject({ producedBy: ['sast:llm-fast'], confidence: 'medium' });
  });

  it('holds a tier-1 budget lease for the deep pass, projecting its remaining cost until it is done', async () => {
    const files = await writeFiles({ 'a.ts': 'a'.repeat(3_500), 'b.ts': 'b', 'c.ts': 'c' });
    const projections: number[] = [];
    let closed = 0;
    const lanes = {
      open: () => ({ project: (usd: number) => { projections.push(usd); }, close: () => { closed++; } }),
      estimateUsd: (_role: string, input: number, output: number) => (input + output) / 1_000_000,
    };
    const { llm } = stubLlm(async () => ok([]));
    await createSastAnalyzer({ llm, lanes, concurrency: 1, triage: triageOf(tri('a.ts', 3), tri('b.ts', 2), tri('c.ts', 1)), indexRepo: indexRepoOf() })
      .run(makeCtx(files));
    expect(projections[0]).toBeCloseTo((1_000 + 6_000 + 1_500 + 1 + 6_000 + 1_500) / 1_000_000, 9);
    expect(projections[1]).toBeCloseTo((1 + 6_000 + 1_500) / 1_000_000, 9);
    expect(closed).toBeGreaterThanOrEqual(1);
  });
});

describe('SAST analyzer — prompt', () => {
  it('sends the untrusted, numbered target file + local context + hints, and shared repo context', async () => {
    const files = await writeFiles({
      'package.json': JSON.stringify({ dependencies: { express: '^4', pg: '^8' } }),
      'src/route.ts': ROUTE,
      'src/db.ts': 'import pg from "pg";\nconst pool = new pg.Pool();\nexport function rawQuery(sql: string) { return pool.query(sql); }\n',
    });
    const { llm, calls } = stubLlm(async () => ok([]));
    await createSastAnalyzer({
      llm,
      triage: triageOf(tri('src/route.ts', 3, { sources: ['req.query.id (line 3)'], sinks: ['db.query with string concat (line 3)'], securityTopics: ['sql'] })),
      indexRepo: indexRepoOf(
        [{ path: 'src/route.ts', kind: 'http-route', line: 2, detail: 'GET /u' }],
        [{ from: 'src/route.ts', specifier: './db', kind: 'local', to: 'src/db.ts', pkg: null, line: 1 }],
      ),
    }).run(makeCtx(files));
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call).toMatchObject({ analyzer: 'sast', purpose: 'sast-file', promptVersion: SAST_PROMPT_VERSION, role: 'deep', effort: 'medium', system: SAST_SYSTEM_PROMPT });
    expect(call.system).toContain(SAST_TASK_MARKER);
    expect(call.prompt).toContain('<untrusted_file path="src/route.ts">\n1: import { db } from \'./db\';');
    expect(call.prompt).toContain('3:   db.query("SELECT * FROM users WHERE id = " + req.query.id);');
    expect(call.prompt).toContain('<untrusted_file path="src/db.ts">');
    expect(call.prompt).toContain('3: export function rawQuery(sql: string)');
    expect(call.prompt).toContain('<untrusted_text source="triage-hints">');
    expect(call.prompt).toContain('db.query with string concat (line 3)');
    expect(call.context).toContain('Express');
    expect(call.context).toContain('node-postgres');
    expect(call.context).toContain('src/route.ts (http-route, line 2: GET /u)');
  });

  it('passes deterministic client-exposure rule hints for the target file, to confirm or refute', async () => {
    const files = await writeFiles({
      'web/lib/admin.ts': "import { createClient } from '@supabase/supabase-js';\nexport const c = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,\n);\n",
      'web/lib/anon.ts': "export const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;\n",
    });
    const { llm, calls } = stubLlm(async () => ok([]));
    await createSastAnalyzer({ llm, triage: triageOf(tri('web/lib/admin.ts', 2), tri('web/lib/anon.ts', 2)), indexRepo: indexRepoOf() }).run(makeCtx(files));
    const admin = calls.find((c) => targetOf(c) === 'web/lib/admin.ts')!;
    expect(admin.prompt).toContain('RULE HINTS');
    expect(admin.prompt).toContain('<untrusted_text source="rule-hints">');
    expect(admin.prompt).toMatch(/line 4: vibesec\/client-exposed-credential\b.*NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY/);
    expect(admin.prompt).not.toMatch(/line 3: vibesec\/client-exposed-credential/); // the URL is not a credential
    const anon = calls.find((c) => targetOf(c) === 'web/lib/anon.ts')!;
    expect(anon.prompt).not.toContain('vibesec/client-exposed-credential');
    expect(SAST_SYSTEM_PROMPT).toMatch(/rule hints/i);
  });

  it('reviews a relevance-0 file anyway (deep pass) when it has a rule hint; test files stay not-relevant', async () => {
    const hinted = 'export const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY!;\n';
    const files = await writeFiles({ 'web/lib/keys.ts': hinted, 'web/lib/plain.ts': 'export const a = 1;\n', 'test/keys.test.ts': hinted }, { 'test/keys.test.ts': ['test'] });
    const { llm, calls } = stubLlm(async () => ok([]));
    const coverage = new Map<string, CoverageStatus>();
    await createSastAnalyzer({
      llm, triage: triageOf(tri('web/lib/keys.ts', 0), tri('web/lib/plain.ts', 0), tri('test/keys.test.ts', 0)), indexRepo: indexRepoOf(),
    }).run(makeCtx(files, { coverage }));
    expect(calls.map((c) => [targetOf(c), c.role])).toEqual([['web/lib/keys.ts', 'deep']]);
    expect(Object.fromEntries(coverage)).toEqual({ 'web/lib/keys.ts': 'reviewed', 'web/lib/plain.ts': 'not-relevant', 'test/keys.test.ts': 'not-relevant' });
  });

  it('system prompt lists the rule catalogue, rubrics and the injection rule', () => {
    for (const s of ['vibesec/idor', 'vibesec/supabase-missing-rls', 'vibesec/prompt-injection-attempt', 'sast/ssrf', 'critical:', 'Confidence rubric', 'EXACT code']) {
      expect(SAST_SYSTEM_PROMPT).toContain(s);
    }
  });
});

describe('SAST analyzer — verification', () => {
  async function runWith(issues: SastIssue[], over: Partial<StructuredResult<SastOutput>> = {}) {
    const files = await writeFiles({ 'src/route.ts': ROUTE, 'src/other.ts': 'export const x = 1;\n' });
    const { llm } = stubLlm(async () => ok(issues, over));
    const warnings: Array<[string, string]> = [];
    const findings = await createSastAnalyzer({ llm, triage: triageOf(tri('src/route.ts', 3)), indexRepo: indexRepoOf() })
      .run(makeCtx(files, { warn: (c, m) => warnings.push([c, m]) }));
    return { findings, warnings };
  }

  it('turns a schema-valid issue into a verified Finding at the right location', async () => {
    const parsed = SastOutputSchema.parse({ issues: [issue('src/route.ts')] });
    const { findings, warnings } = await runWith(parsed.issues);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(() => FindingSchema.parse(f)).not.toThrow();
    expect(f).toMatchObject({ category: 'sast', ruleId: 'sast/sql-injection', cwe: 'CWE-89', severity: 'high', confidence: 'high', producedBy: ['sast:llm'] });
    expect(f.location).toMatchObject({ file: 'src/route.ts', startLine: 3, endLine: 3 });
    expect(f.location.snippet).toContain('db.query(');
    expect(f.location.permalink).toContain('src/route.ts#L3');
    expect(warnings).toEqual([]);
  });

  it('drops a hallucinated snippet and an issue for another file, warning once with the count', async () => {
    const { findings, warnings } = await runWith([
      issue('src/route.ts', { snippet: 'child_process.exec(userInput)', ruleId: 'sast/command-injection' }),
      issue('src/other.ts'),
      issue('src/route.ts'),
    ]);
    expect(findings).toHaveLength(1);
    const dropped = warnings.filter(([c]) => c === 'SAST_UNVERIFIED_DROPPED');
    expect(dropped).toHaveLength(1);
    expect(dropped[0]![1]).toMatch(/^2 /);
  });

  it('relocates an issue whose line numbers are off', async () => {
    const { findings } = await runWith([issue('src/route.ts', { startLine: 1, endLine: 1 }), issue('src/route.ts', { startLine: 50, endLine: 50, ruleId: 'sast/other' })]);
    expect(findings).toHaveLength(2);
    for (const f of findings) expect(f.location.startLine).toBe(3);
  });

  it('dedupes identical issues by fingerprint, keeping the higher severity', async () => {
    const { findings } = await runWith([issue('src/route.ts', { severity: 'medium' }), issue('src/route.ts', { severity: 'critical', startLine: 4, endLine: 4 })]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
  });

  it('lowers confidence when the call was served by a degraded tier', async () => {
    const { findings } = await runWith([issue('src/route.ts')], { degraded: true });
    expect(findings[0]!.confidence).toBe('medium');
  });
});

describe('SAST analyzer — resilience', () => {
  it('fails open per file: one failed call → SAST_PARTIAL once, other files still reported', async () => {
    const files = await writeFiles({ 'a.ts': ROUTE, 'b.ts': ROUTE, 'c.ts': ROUTE });
    const { llm } = stubLlm(async (call) => {
      if (targetOf(call) !== 'a.ts') throw new AppError('LLM_UNAVAILABLE', 'transient', 'down');
      return ok([issue('a.ts')]);
    });
    const warnings: string[] = [];
    const findings = await createSastAnalyzer({ llm, concurrency: 1, triage: triageOf(tri('a.ts', 3), tri('b.ts', 3), tri('c.ts', 3)), indexRepo: indexRepoOf() })
      .run(makeCtx(files, { warn: (c) => warnings.push(c) }));
    expect(findings.map((f) => f.location.file)).toEqual(['a.ts']);
    expect(warnings.filter((w) => w === 'SAST_PARTIAL')).toHaveLength(1);
  });

  it('stops calling once the budget is exhausted and records every remaining file as budget-skipped', async () => {
    const files = await writeFiles({ 'a.ts': ROUTE, 'b.ts': ROUTE, 'c.ts': ROUTE, 'd.ts': ROUTE });
    const { llm, calls } = stubLlm(async () => { throw new AppError('BUDGET_EXHAUSTED', 'budget', 'out'); });
    const warnings: string[] = [];
    const coverage = new Map<string, CoverageStatus>();
    const findings = await createSastAnalyzer({ llm, concurrency: 1, triage: triageOf(tri('a.ts', 3), tri('b.ts', 3), tri('c.ts', 3), tri('d.ts', 1)), indexRepo: indexRepoOf() })
      .run(makeCtx(files, { warn: (c) => warnings.push(c), coverage }));
    expect(findings).toEqual([]);
    expect(calls).toHaveLength(1);
    expect(warnings).toEqual([]); // the pipeline reports BUDGET_COVERAGE_PARTIAL from the coverage instead
    expect(Object.fromEntries(coverage)).toEqual({ 'a.ts': 'budget-skipped', 'b.ts': 'budget-skipped', 'c.ts': 'budget-skipped', 'd.ts': 'budget-skipped' });
  });

  it('propagates cancellation from the LLM and stops other workers', async () => {
    const files = await writeFiles({ 'a.ts': ROUTE, 'b.ts': ROUTE, 'c.ts': ROUTE });
    const ac = new AbortController();
    const { llm, calls } = stubLlm(async () => {
      ac.abort();
      throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    });
    const run = createSastAnalyzer({ llm, concurrency: 1, triage: triageOf(tri('a.ts', 3), tri('b.ts', 3), tri('c.ts', 3)), indexRepo: indexRepoOf() })
      .run(makeCtx(files, { signal: ac.signal }));
    await expect(run).rejects.toMatchObject({ kind: 'cancelled' });
    expect(calls).toHaveLength(1);
  });

  it('rejects immediately when already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    const { llm, calls } = stubLlm(async () => ok([]));
    await expect(createSastAnalyzer({ llm, triage: triageOf(tri('a.ts', 3)), indexRepo: indexRepoOf() }).run(makeCtx([], { signal: ac.signal })))
      .rejects.toBeInstanceOf(AppError);
    expect(calls).toHaveLength(0);
  });

  it('serves an unchanged file from the result cache without an LLM call', async () => {
    const files = await writeFiles({ 'src/route.ts': ROUTE });
    const map = new Map<string, CachedSastIssue[]>();
    const store: SastResultCache = { get: (k) => map.get(k), set: (k, v) => void map.set(k, v) };
    const { llm, calls } = stubLlm(async () => ok([issue('src/route.ts')]));
    const deps = { llm, cache: { store, model: (pass: 'deep' | 'fast') => (pass === 'deep' ? 'claude-sonnet-5' : 'claude-haiku-4-5') }, triage: triageOf(tri('src/route.ts', 3)), indexRepo: indexRepoOf() };
    const first = await createSastAnalyzer(deps).run(makeCtx(files));
    const coverage = new Map<string, CoverageStatus>();
    const second = await createSastAnalyzer(deps).run(makeCtx(files, { coverage }));
    expect(calls).toHaveLength(1);
    expect([...map.keys()][0]).toMatch(new RegExp(`^[0-9a-f]{64}:${SAST_PROMPT_VERSION}:claude-sonnet-5$`));
    expect(second.map((f) => f.fingerprint)).toEqual(first.map((f) => f.fingerprint));
    expect(second.map((f) => f.location)).toEqual(first.map((f) => f.location));
    expect(coverage.get('src/route.ts')).toBe('cached');
    // Only verified locations + prose are cached — never repository code.
    expect(JSON.stringify([...map.values()])).not.toContain('SELECT * FROM users');
  });
});

describe('sastMockResponder', () => {
  const SAMPLE_JS = [
    "const { exec } = require('child_process');",
    "app.get('/run', (req, res) => {",
    '  const cmd = req.query.cmd;',
    '  exec(cmd, () => {});',
    '  db.query("SELECT * FROM t WHERE id = " + req.params.id);',
    '  const v = eval(req.body.expr);',
    '  el.innerHTML = req.body.html;',
    '  res.redirect(req.query.next);',
    "  const h = crypto.createHash('md5');",
    '});',
    '',
  ].join('\n');
  const SAMPLE_PY = [
    'import pickle, yaml, requests',
    'def handler(request):',
    '    data = pickle.loads(request.body)',
    '    cfg = yaml.load(request.body)',
    '    ok = yaml.load(request.body, Loader=yaml.SafeLoader)',
    "    r = requests.get(request.args['url'])",
    '',
  ].join('\n');

  it('ignores requests without the task marker', () => {
    expect(sastMockResponder({ model: 'm', system: [{ type: 'text', text: 'other' }], messages: [], maxTokens: 1 } as never)).toBeUndefined();
  });

  it('produces plausible verified findings end-to-end through the real LlmClient + MockTransport', async () => {
    const files = await writeFiles({ 'src/run.js': SAMPLE_JS, 'app/views.py': SAMPLE_PY, 'src/safe.ts': 'export const add = (a: number, b: number) => a + b;\n' });
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
    const scanId = scans.insertScan({ repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false }).id;
    const client = new LlmClient({
      transport: new MockTransport({ responders: [sastMockResponder] }),
      models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
      limiter: new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 }), semaphore: new Semaphore(4),
      budget: new BudgetTracker(5, (id) => scans.getDto(id)?.costUsd ?? 0), calls: new LlmCallRepo(db), scans,
      retryDeps: { sleep: async () => {} }, atomically: (fn) => db.transaction(fn)(),
    });
    const warnings: string[] = [];
    const findings = await createSastAnalyzer({
      llm: client, triage: triageOf(tri('src/run.js', 3), tri('app/views.py', 3), tri('src/safe.ts', 2)), indexRepo: indexRepoOf(),
    }).run(makeCtx(files, { scanId, warn: (c) => warnings.push(c) }));

    expect(warnings).toEqual([]);
    for (const f of findings) expect(() => FindingSchema.parse(f)).not.toThrow();
    const got = findings.map((f) => `${f.location.file}:${f.location.startLine}:${f.ruleId}`).sort();
    expect(got).toEqual([
      'app/views.py:3:sast/unsafe-deserialization',
      'app/views.py:4:sast/unsafe-deserialization',
      'app/views.py:6:sast/ssrf',
      'src/run.js:4:sast/command-injection',
      'src/run.js:5:sast/sql-injection',
      'src/run.js:6:sast/code-injection',
      'src/run.js:7:sast/xss',
      'src/run.js:8:sast/open-redirect',
      'src/run.js:9:sast/weak-crypto',
    ]);
  });

  it('confirms a client-exposed-credential rule hint (mock stands in for Claude deciding)', async () => {
    const files = await writeFiles({
      'web/lib/supabaseAdmin.ts': "import { createClient } from '@supabase/supabase-js';\n\nexport const supabaseAdmin = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,\n);\n",
    });
    const db = memoryDb();
    const scans = new ScanRepo(db);
    const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
    const scanId = scans.insertScan({ repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false }).id;
    const client = new LlmClient({
      transport: new MockTransport({ responders: [sastMockResponder] }),
      models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
      limiter: new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 }), semaphore: new Semaphore(4),
      budget: new BudgetTracker(5, (id) => scans.getDto(id)?.costUsd ?? 0), calls: new LlmCallRepo(db), scans,
      retryDeps: { sleep: async () => {} }, atomically: (fn) => db.transaction(fn)(),
    });
    const findings = await createSastAnalyzer({
      llm: client, triage: triageOf(tri('web/lib/supabaseAdmin.ts', 1)), indexRepo: indexRepoOf(),
    }).run(makeCtx(files, { scanId }));
    expect(findings.map((f) => `${f.location.file}:${f.location.startLine}:${f.ruleId}:${f.cwe}`)).toEqual([
      'web/lib/supabaseAdmin.ts:5:vibesec/client-exposed-credential:CWE-200',
    ]);
    expect(() => FindingSchema.parse(findings[0])).not.toThrow();
  });
});
