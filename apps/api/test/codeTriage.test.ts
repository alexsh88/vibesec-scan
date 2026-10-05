import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import { ScanOptionsSchema, type ScanDto } from '@vibesec/shared';
import type { AnalyzerContext } from '../src/analyzers/types';
import {
  codeTriageMockResponder, selectForSast, selectForTaint, TRIAGE_PROMPT_VERSION, TriageService,
} from '../src/analyzers/code/triage';
import type { FileTriage, TriageResult } from '../src/analyzers/code/types';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { TriageCacheRepo } from '../src/db/triageCacheRepo';
import { AppError } from '../src/errors/AppError';
import type { IndexedFile } from '../src/index/types';
import { BudgetTracker } from '../src/llm/budget';
import { LlmClient, type StructuredCall, type StructuredResult } from '../src/llm/LlmClient';
import { estimateTokens, untrustedFile } from '../src/llm/prompt';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import type { LlmRequest, LlmTransport } from '../src/llm/transport';
import { memoryDb } from './helpers';

type TriageFile = { path: string; relevance: 0 | 1 | 2 | 3; sources: string[]; sinks: string[]; securityTopics: string[]; credentialRisk: boolean };
type TriageOutput = { files: TriageFile[] };

const ZERO_USAGE = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
const MODEL = 'claude-haiku-4-5';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-triage-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

async function writeFiles(files: Record<string, string>): Promise<IndexedFile[]> {
  const indexed: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    const language: IndexedFile['language'] = path.endsWith('.py') ? 'python' : 'typescript';
    indexed.push({ path, blobSha: 'deadbeef', size: Buffer.byteLength(content), language, category: 'source', tags: [], skipReason: null });
  }
  return indexed;
}

function makeScan(): ScanDto {
  return {
    id: 'scan-1', repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false }, ref: null,
    commitSha: 'c'.repeat(40), state: 'ANALYZING', errorCode: null, errorMessage: null, cacheHit: 'none',
    options: ScanOptionsSchema.parse({}), costUsd: 0, createdAt: new Date().toISOString(),
    startedAt: null, finishedAt: null, warnings: [],
  };
}

function makeCtx(files: IndexedFile[], opts: { warn?: (code: string, message: string) => void; signal?: AbortSignal } = {}): AnalyzerContext {
  const scan = makeScan();
  return {
    scanId: scan.id, scan, repoDir: dir, commitSha: scan.commitSha!, repo: scan.repo, files,
    signal: opts.signal ?? new AbortController().signal, touch: () => {}, warn: opts.warn ?? (() => {}), progress: () => {},
  };
}

function stubLlm(impl: (call: StructuredCall<TriageOutput>) => Promise<StructuredResult<TriageOutput>>): {
  llm: Pick<LlmClient, 'structured'>; calls: StructuredCall<TriageOutput>[];
} {
  const calls: StructuredCall<TriageOutput>[] = [];
  const structured = async (call: StructuredCall<TriageOutput>) => {
    calls.push(call);
    return impl(call);
  };
  return { llm: { structured: structured as unknown as LlmClient['structured'] }, calls };
}

function okResult(files: TriageFile[]): StructuredResult<TriageOutput> {
  return { output: { files }, model: MODEL, usage: ZERO_USAGE, costUsd: 0, callIds: ['c'], degraded: false, fellBackOnRefusal: false };
}

function cacheKeyFor(content: string, model: string): string {
  const hash = createHash('sha256').update(content, 'utf8').digest('hex');
  return `${hash}:${TRIAGE_PROMPT_VERSION}:${model}`;
}

function capturingTransport(respond: (req: LlmRequest) => unknown): { transport: LlmTransport; seen: LlmRequest[] } {
  const seen: LlmRequest[] = [];
  const transport: LlmTransport = {
    mode: 'mock',
    send: vi.fn(async (req: LlmRequest) => {
      seen.push(req);
      const text = JSON.stringify(respond(req));
      return {
        id: 'm', type: 'message', role: 'assistant', model: req.model,
        content: [{ type: 'text', text, citations: null }],
        stop_reason: 'end_turn', stop_sequence: null,
        usage: { input_tokens: 10, output_tokens: 10, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
      } as unknown as Anthropic.Message;
    }),
  };
  return { transport, seen };
}

/** A minimal real LlmClient (DB-backed) wired to a given transport. */
function buildRealClient(transport: LlmTransport) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  const calls = new LlmCallRepo(db);
  const limiter = new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 });
  const budget = new BudgetTracker(5, (id) => scans.getDto(id)?.costUsd ?? 0);
  const client = new LlmClient({
    transport, models: { fast: MODEL, deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
    limiter, semaphore: new Semaphore(4), budget, calls, scans, retryDeps: { sleep: async () => {} },
    atomically: (fn) => db.transaction(fn)(),
  });
  return { client, scanId };
}

describe('TriageService batching', () => {
  it('packs files that fit the token budget into a single batch', async () => {
    const files = await writeFiles({ 'a.ts': 'const a = 1;\n', 'b.ts': 'const b = 1;\n', 'c.ts': 'const c = 1;\n' });
    const { llm, calls } = stubLlm(async () => okResult([]));
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });

    await service.forScan(makeCtx(files));

    expect(calls).toHaveLength(1);
    for (const f of files) expect(calls[0]!.prompt).toContain(`path="${f.path}"`);
  });

  it('splits into multiple batches once the token budget is exceeded', async () => {
    // Identical-length paths/content (no trailing newline, so numberLines() produces exactly one
    // numbered line), long enough that the per-file truncation reserve never kicks in, so every
    // block has exactly the same, exactly-predictable estimated token count.
    const content = 'x'.repeat(300);
    const files = await writeFiles({ 'a.ts': content, 'b.ts': content, 'c.ts': content });
    const blockTokens = estimateTokens(untrustedFile('a.ts', `1: ${content}`));
    const { llm, calls } = stubLlm(async () => okResult([]));
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL, batchTokens: blockTokens * 2 });

    await service.forScan(makeCtx(files));

    expect(calls).toHaveLength(2);
    expect(calls[0]!.prompt).toContain('path="a.ts"');
    expect(calls[0]!.prompt).toContain('path="b.ts"');
    expect(calls[1]!.prompt).toContain('path="c.ts"');
  });

  it('truncates a single huge file to fit the batch budget and notes the truncation', async () => {
    const huge = `const x = "${'y'.repeat(50_000)}";\n`;
    const files = await writeFiles({ 'huge.ts': huge });
    const { llm, calls } = stubLlm(async () => okResult([]));
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL, batchTokens: 200 });

    await service.forScan(makeCtx(files));

    expect(calls).toHaveLength(1);
    expect(calls[0]!.prompt).toContain('TRUNCATED');
    expect(calls[0]!.prompt.length).toBeLessThan(huge.length);
  });
});

describe('TriageService caching', () => {
  it('skips the LLM entirely on a cache hit, keyed by content + prompt version + model', async () => {
    const content = 'const a = 1;\n';
    const files = await writeFiles({ 'a.ts': content });
    const cache = new TriageCacheRepo(memoryDb());
    const cached: FileTriage = { path: 'a.ts', relevance: 3, sources: [], sinks: ['sink (line 1)'], securityTopics: ['sql'], credentialRisk: false };
    cache.set(cacheKeyFor(content, MODEL), { relevance: cached.relevance, sources: cached.sources, sinks: cached.sinks, securityTopics: cached.securityTopics, credentialRisk: cached.credentialRisk });
    const { llm, calls } = stubLlm(async () => { throw new Error('must not be called'); });
    const service = new TriageService({ llm, cache, model: () => MODEL });

    const result = await service.forScan(makeCtx(files));

    expect(calls).toHaveLength(0);
    expect(result.files.get('a.ts')).toEqual(cached);
  });

  it('a different model id misses the cache (model is part of the key)', async () => {
    const content = 'const a = 1;\n';
    const files = await writeFiles({ 'a.ts': content });
    const cache = new TriageCacheRepo(memoryDb());
    cache.set(cacheKeyFor(content, 'claude-haiku-OLD'), { relevance: 3, sources: [], sinks: [], securityTopics: [], credentialRisk: false });
    const { llm, calls } = stubLlm(async () => okResult([{ path: 'a.ts', relevance: 1, sources: [], sinks: [], securityTopics: [], credentialRisk: false }]));
    const service = new TriageService({ llm, cache, model: () => MODEL });

    const result = await service.forScan(makeCtx(files));

    expect(calls).toHaveLength(1);
    expect(result.files.get('a.ts')?.relevance).toBe(1);
  });

  it('caches a freshly-triaged file so a later run (even a fresh service instance) hits the cache', async () => {
    const content = 'const a = 1;\n';
    const files = await writeFiles({ 'a.ts': content });
    const cache = new TriageCacheRepo(memoryDb());
    const { llm: llm1 } = stubLlm(async () => okResult([{ path: 'a.ts', relevance: 2, sources: ['req.query (line 1)'], sinks: [], securityTopics: ['auth'], credentialRisk: false }]));
    await new TriageService({ llm: llm1, cache, model: () => MODEL }).forScan(makeCtx(files));

    const { llm: llm2, calls: calls2 } = stubLlm(async () => { throw new Error('must not be called'); });
    const result2 = await new TriageService({ llm: llm2, cache, model: () => MODEL }).forScan(makeCtx(files));

    expect(calls2).toHaveLength(0);
    expect(result2.files.get('a.ts')?.relevance).toBe(2);
  });
});

describe('TriageService memoization', () => {
  it('shares one in-flight run across concurrent forScan calls for the same scan', async () => {
    const files = await writeFiles({ 'a.ts': 'const a = 1;\n' });
    let callCount = 0;
    const { llm } = stubLlm(async () => { callCount++; return okResult([]); });
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });
    const ctx = makeCtx(files);

    const [r1, r2] = await Promise.all([service.forScan(ctx), service.forScan(ctx)]);

    expect(callCount).toBe(1);
    expect(r1).toBe(r2);
  });

  it('forget() allows a later call to re-run', async () => {
    const files = await writeFiles({ 'a.ts': 'const a = 1;\n' });
    let callCount = 0;
    const { llm } = stubLlm(async () => { callCount++; return okResult([]); });
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });
    const ctx = makeCtx(files);

    await service.forScan(ctx);
    service.forget(ctx.scanId);
    await service.forScan(ctx);

    expect(callCount).toBe(2);
  });
});

describe('TriageService prioritization / maxFiles', () => {
  it('keeps entrypoints, then path-heuristic matches, within maxFiles; drops the rest with a warning', async () => {
    const files = await writeFiles({
      'src/routes/users.ts': "app.get('/users', (req, res) => { res.send('ok'); });\n",
      'src/controllers/orders.ts': 'export function listOrders(ids) { return ids.map((id) => id); }\n',
      'src/util/big.ts': `export const big = "${'z'.repeat(5_000)}";\n`,
      'src/util/small.ts': 'export const small = 1;\n',
    });
    const { llm } = stubLlm(async () => okResult([]));
    const warn = vi.fn();
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL, maxFiles: 2 });

    const result = await service.forScan(makeCtx(files, { warn }));

    expect([...result.files.keys()].sort()).toEqual(['src/controllers/orders.ts', 'src/routes/users.ts']);
    expect(result.skipped.sort()).toEqual(['src/util/big.ts', 'src/util/small.ts']);
    expect(result.warnings).toContain('TRIAGE_FILE_LIMIT');
    expect(warn).toHaveBeenCalledWith('TRIAGE_FILE_LIMIT', expect.any(String));
  });
});

describe('TriageService fail-open', () => {
  it('defaults a failed batch to conservative relevance 2 and warns once', async () => {
    const files = await writeFiles({ 'a.ts': 'const x = 1;\n', 'b.ts': 'const y = 1;\n' });
    const { llm } = stubLlm(async () => { throw new AppError('LLM_UNAVAILABLE', 'transient', 'overloaded'); });
    const warn = vi.fn();
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });

    const result = await service.forScan(makeCtx(files, { warn }));

    for (const f of files) {
      expect(result.files.get(f.path)).toEqual({ path: f.path, relevance: 2, sources: [], sinks: [], securityTopics: ['untriaged'], credentialRisk: false });
    }
    expect(result.warnings.filter((w) => w === 'TRIAGE_PARTIAL')).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith('TRIAGE_PARTIAL', expect.any(String));
  });

  it('never caches the fail-open default', async () => {
    const content = 'const x = 1;\n';
    const files = await writeFiles({ 'a.ts': content });
    const cache = new TriageCacheRepo(memoryDb());
    const { llm: failing } = stubLlm(async () => { throw new AppError('LLM_UNAVAILABLE', 'transient', 'overloaded'); });
    await new TriageService({ llm: failing, cache, model: () => MODEL }).forScan(makeCtx(files));
    expect(cache.get(cacheKeyFor(content, MODEL))).toBeUndefined();
  });

  it('rethrows cancellation instead of failing open', async () => {
    const files = await writeFiles({ 'a.ts': 'const x = 1;\n' });
    const { llm } = stubLlm(async () => { throw new AppError('CANCELLED', 'cancelled', 'stop'); });
    const warn = vi.fn();
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });

    await expect(service.forScan(makeCtx(files, { warn }))).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(warn).not.toHaveBeenCalled();
  });

  it('rejects immediately when the context signal is already aborted', async () => {
    const files = await writeFiles({ 'a.ts': 'const x = 1;\n' });
    const controller = new AbortController();
    controller.abort();
    const { llm, calls } = stubLlm(async () => okResult([]));
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });

    await expect(service.forScan(makeCtx(files, { signal: controller.signal }))).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(calls).toHaveLength(0);
  });
});

describe('TriageService response handling', () => {
  it('ignores a path the batch never requested, and only the first entry for a duplicated path', async () => {
    const files = await writeFiles({ 'a.ts': 'const x = 1;\n' });
    const { llm } = stubLlm(async () => okResult([
      { path: 'a.ts', relevance: 3, sources: [], sinks: ['s (line 1)'], securityTopics: [], credentialRisk: false },
      { path: 'a.ts', relevance: 0, sources: [], sinks: [], securityTopics: [], credentialRisk: false },
      { path: 'not-requested.ts', relevance: 3, sources: [], sinks: [], securityTopics: [], credentialRisk: true },
    ]));
    const service = new TriageService({ llm, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });

    const result = await service.forScan(makeCtx(files));

    expect(result.files.size).toBe(1);
    expect(result.files.get('a.ts')?.relevance).toBe(3);
    expect(result.files.has('not-requested.ts')).toBe(false);
  });
});

describe('selectForSast / selectForTaint', () => {
  function result(entries: Record<string, Partial<FileTriage>>): TriageResult {
    const files = new Map<string, FileTriage>();
    for (const [path, over] of Object.entries(entries)) {
      files.set(path, { path, relevance: 1, sources: [], sinks: [], securityTopics: [], credentialRisk: false, ...over });
    }
    return { files, skipped: [], warnings: [] };
  }

  it('selectForSast: relevance >= 2, or any sink, or a known entrypoint; ordered by relevance desc then path', () => {
    const r = result({
      'low.ts': { relevance: 1 },
      'mid.ts': { relevance: 2 },
      'high.ts': { relevance: 3 },
      'sinkOnly.ts': { relevance: 1, sinks: ['dangerous call (line 1)'] },
      'entrypointOnly.ts': { relevance: 0 },
      'other.ts': { relevance: 0 },
    });
    const selected = selectForSast(r, new Set(['entrypointOnly.ts']));
    expect(selected).toEqual(['high.ts', 'mid.ts', 'sinkOnly.ts', 'entrypointOnly.ts']);
  });

  it('selectForTaint: entrypoints with at least one source, ordered by path', () => {
    const r = result({
      'b-entry.ts': { sources: ['req.query (line 1)'] },
      'a-entry.ts': { sources: ['req.params (line 2)'] },
      'noSource.ts': { sources: [] },
      'notEntry.ts': { sources: ['req.body (line 1)'] },
    });
    const selected = selectForTaint(r, new Set(['b-entry.ts', 'a-entry.ts', 'noSource.ts']));
    expect(selected).toEqual(['a-entry.ts', 'b-entry.ts']);
  });
});

describe('codeTriageMockResponder', () => {
  it('ignores requests whose system prompt does not carry the triage task marker', () => {
    const req: LlmRequest = {
      model: MODEL, system: [{ type: 'text', text: 'some other task' }],
      messages: [{ role: 'user', content: [{ type: 'text', text: untrustedFile('a.ts', '1: const a = 1;') }] }],
      maxTokens: 100, thinking: false, schema: z.object({}),
    };
    expect(codeTriageMockResponder(req)).toBeUndefined();
  });

  it('produces schema-valid, heuristic-correct verdicts end-to-end through createTransport, with content wrapped as untrusted', async () => {
    const files = await writeFiles({
      'src/db/query.ts': "export function find(id) { return db.query('SELECT * FROM t WHERE id = ' + id); }\n",
      'src/routes/handler.ts': 'export function handle(req, res) { return res.send(req.params.id); }\n',
      'src/types.ts': 'export type Id = string;\nexport const MAX = 10;\n',
      'src/config/secrets.ts': 'const password = "hardcoded-value-123";\n',
    });
    const { transport, seen } = capturingTransport(codeTriageMockResponder);
    const { client, scanId } = buildRealClient(transport);
    const service = new TriageService({ llm: client, cache: new TriageCacheRepo(memoryDb()), model: () => MODEL });

    const result = await service.forScan({
      scanId, scan: makeScan(), repoDir: dir, commitSha: 'c'.repeat(40), repo: { owner: 'acme', name: 'app' },
      files, signal: new AbortController().signal, touch: () => {}, warn: () => {}, progress: () => {},
    });

    expect(result.files.get('src/db/query.ts')?.relevance).toBe(3);
    expect(result.files.get('src/db/query.ts')?.sinks.length).toBeGreaterThan(0);
    expect(result.files.get('src/routes/handler.ts')?.relevance).toBe(2);
    expect(result.files.get('src/routes/handler.ts')?.sources.length).toBeGreaterThan(0);
    expect(result.files.get('src/types.ts')?.relevance).toBe(0);
    expect(result.files.get('src/config/secrets.ts')?.credentialRisk).toBe(true);

    expect(seen.length).toBeGreaterThan(0);
    const allText = seen.map((r) => JSON.stringify(r.messages)).join('\n');
    expect(allText).toContain('untrusted_file');
    for (const f of files) expect(allText).toContain(`path=\\"${f.path}\\"`);
  });
});
